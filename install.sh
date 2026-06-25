#!/usr/bin/env bash
set -Eeuo pipefail

PANEL_VERSION="0.11.2"
PANEL_REPOSITORY="${WDTT_PANEL_REPOSITORY:-lebrit/wdtt-control-panel}"
PANEL_BRANCH="${WDTT_PANEL_BRANCH:-main}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/wdtt-panel"
CONFIG_DIR="/etc/wdtt-panel"
STATE_DIR="/var/lib/wdtt-panel"
PRIVATE_STATE_DIR="/var/lib/wdtt-panel-private"
CONFIG_FILE="$CONFIG_DIR/config.json"
NGINX_FILE="/etc/nginx/conf.d/wdtt-panel.conf"
PANEL_SERVICE="wdtt-panel.service"
ADMIN_WRAPPER="/usr/local/sbin/wdtt-panel-admin"
SUDOERS_FILE="/etc/sudoers.d/wdtt-panel"
UPDATE_WRAPPER="/usr/local/sbin/wdtt-panel-update"
UNINSTALL_WRAPPER="/usr/local/sbin/wdtt-panel-uninstall"
STATUS_WRAPPER="/usr/local/sbin/wdtt-panel-status"
GEOFILES_UPDATE_WRAPPER="/usr/local/sbin/wdtt-panel-geofiles-update"
BACKUP_RUNNER="/usr/local/sbin/wdtt-panel-backup"
CASCADE_RULES_WRAPPER="/usr/local/sbin/wdtt-panel-cascade-rules"
GATEWAY_RULES_WRAPPER="/usr/local/sbin/wdtt-panel-xray-gateway"
MANAGER_WRAPPER="/usr/local/sbin/wdtt-panel"
XRAY_SERVICE="wdtt-xray.service"
LEGACY_CASCADE_SERVICE="wdtt-cascade.service"
XRAY_CONFIG="$PRIVATE_STATE_DIR/xray-config.json"
XRAY_SETTINGS="$PRIVATE_STATE_DIR/xray-settings.json"
XRAY_ASSETS="$PRIVATE_STATE_DIR/xray-assets"
XRAY_CASCADE_SETTINGS="$PRIVATE_STATE_DIR/xray-cascade.json"
XRAY_CASCADE_SERVICE="wdtt-xray-cascade.service"
XRAY_GATEWAY_SERVICE="wdtt-xray-gateway.service"
WARP_DIR="$PRIVATE_STATE_DIR/warp"
LOG_FILE="/var/log/wdtt-panel-install.log"

PANEL_USER="${PANEL_USER:-admin}"
PANEL_PASSWORD="${PANEL_PASSWORD:-}"
PANEL_PATH="${PANEL_PATH:-}"
PANEL_HOST="${PANEL_HOST:-}"
PANEL_HTTPS_PORT="${PANEL_HTTPS_PORT:-8443}"
PANEL_LISTEN_PORT="${PANEL_LISTEN_PORT:-8787}"
PANEL_EMAIL="${PANEL_EMAIL:-}"
INSTALL_WDTT="${INSTALL_WDTT:-auto}"
WDTT_MAIN_PASSWORD="${WDTT_MAIN_PASSWORD:-}"
WDTT_REF="${WDTT_REF:-main}"
GO_VERSION="${GO_VERSION:-1.25.0}"
WDTT_SERVICE="wdtt.service"
WDTT_EXTENSIONS_SERVICE="wdtt-panel-wdtt-extensions.service"
WDTT_EXTENSIONS_TIMER="wdtt-panel-wdtt-extensions.timer"
WDTT_EXTENSION_MARKER="wdtt-panel-extension-v4"

log() { printf '[wdtt-panel] %s\n' "$*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 1; }
command_exists() { command -v "$1" >/dev/null 2>&1; }
random_token() { python3 -c "import secrets; print(secrets.token_urlsafe(${1:-24}))"; }
random_password() { python3 -c 'import secrets,string; a=string.ascii_letters+string.digits+"._~-"; print("".join(secrets.choice(a) for _ in range(24)))'; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "Запустите установщик от root: sudo bash install.sh"
  mkdir -p "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"
}

detect_os() {
  [ -r /etc/os-release ] || die "Не найден /etc/os-release"
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  case "$OS_ID" in
    ubuntu|debian|linuxmint|pop) PKG="apt" ;;
    fedora|rhel|centos|rocky|almalinux|oracle) command_exists dnf && PKG="dnf" || PKG="yum" ;;
    arch|manjaro|endeavouros) PKG="pacman" ;;
    *) die "Неподдерживаемый дистрибутив: $OS_ID" ;;
  esac
  log "ОС: ${PRETTY_NAME:-$OS_ID}"
  if command_exists nginx; then NGINX_WAS_INSTALLED=1; else NGINX_WAS_INSTALLED=0; fi
}

install_packages() {
  log "Установка системных зависимостей"
  case "$PKG" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y >>"$LOG_FILE" 2>&1
      apt-get install -y -qq python3 python3-venv python3-pip nginx sudo curl ca-certificates openssl iproute2 iptables conntrack unzip >>"$LOG_FILE" 2>&1
      ;;
    dnf|yum)
      "$PKG" install -y python3 python3-pip nginx sudo curl ca-certificates openssl iproute iptables conntrack-tools unzip tar gzip >>"$LOG_FILE" 2>&1
      ;;
    pacman)
      pacman -Sy --noconfirm --needed python python-pip nginx sudo curl ca-certificates openssl iproute2 iptables conntrack-tools unzip tar gzip >>"$LOG_FILE" 2>&1
      ;;
  esac
}

validate_inputs() {
  [[ "$PANEL_HTTPS_PORT" =~ ^[0-9]+$ ]] && [ "$PANEL_HTTPS_PORT" -ge 1 ] && [ "$PANEL_HTTPS_PORT" -le 65535 ] || die "Некорректный PANEL_HTTPS_PORT"
  [ "$PANEL_HTTPS_PORT" -ne 80 ] || die "PANEL_HTTPS_PORT=80 зарезервирован для ACME; выберите другой порт"
  [[ "$PANEL_LISTEN_PORT" =~ ^[0-9]+$ ]] && [ "$PANEL_LISTEN_PORT" -ge 1024 ] && [ "$PANEL_LISTEN_PORT" -le 65535 ] || die "Некорректный PANEL_LISTEN_PORT"
  [ "$PANEL_HTTPS_PORT" != "$PANEL_LISTEN_PORT" ] || die "Внешний и внутренний порты панели должны отличаться"
  [[ "$PANEL_USER" =~ ^[A-Za-z0-9_.-]{3,32}$ ]] || die "Некорректный PANEL_USER"
  [[ "$WDTT_REF" =~ ^[A-Za-z0-9._-]+$ ]] || die "Некорректный WDTT_REF"
  [[ "$GO_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Некорректный GO_VERSION"
}

validate_port_availability() {
  local listeners
  listeners="$(ss -ltnp "( sport = :$PANEL_LISTEN_PORT )" 2>/dev/null || true)"
  if grep -q LISTEN <<<"$listeners" && ! systemctl is-active --quiet "$PANEL_SERVICE"; then
    die "Внутренний порт $PANEL_LISTEN_PORT уже занят"
  fi
  listeners="$(ss -ltnp "( sport = :$PANEL_HTTPS_PORT )" 2>/dev/null || true)"
  if grep -q LISTEN <<<"$listeners" && ! grep -qi nginx <<<"$listeners"; then
    die "Внешний порт $PANEL_HTTPS_PORT занят не Nginx; задайте PANEL_HTTPS_PORT"
  fi
}

discover_host() {
  if [ -z "$PANEL_HOST" ]; then
    PANEL_HOST="$(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  fi
  if [ -z "$PANEL_HOST" ] && [ -t 0 ]; then
    read -r -p "Домен или публичный IPv4 панели: " PANEL_HOST
  fi
  [ -n "$PANEL_HOST" ] || die "Укажите домен или публичный IPv4 через интерактивный установщик"
  [[ "$PANEL_HOST" != *:* ]] || die "Автоматическая настройка IPv6 пока не поддерживается; используйте домен или IPv4"
  PANEL_HOST="$(python3 - "$PANEL_HOST" <<'PY'
import ipaddress, re, sys
value = sys.argv[1].strip().rstrip(".").lower()
try:
    address = ipaddress.ip_address(value)
    if address.version != 4:
        raise ValueError
    print(value)
    raise SystemExit
except ValueError:
    pass
labels = value.split(".")
pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
if len(labels) < 2 or len(value) > 253 or not all(pattern.fullmatch(label) for label in labels):
    raise SystemExit(2)
print(value)
PY
)" || die "Некорректный PANEL_HOST"
}

prepare_secrets() {
  [ -n "$PANEL_PASSWORD" ] || PANEL_PASSWORD="$(random_password)"
  [ "${#PANEL_PASSWORD}" -ge 12 ] || die "PANEL_PASSWORD должен содержать не менее 12 символов"
  [ -n "$PANEL_PATH" ] || PANEL_PATH="$(random_token 18)"
  PANEL_PATH="/${PANEL_PATH#/}"
  PANEL_PATH="${PANEL_PATH%/}/"
  [[ "$PANEL_PATH" =~ ^/[A-Za-z0-9_-]{16,80}/$ ]] || die "PANEL_PATH должен быть случайным путем из 16-80 символов"
  SESSION_SECRET="$(random_token 48)"
  if [ -n "$WDTT_MAIN_PASSWORD" ]; then
    [[ "$WDTT_MAIN_PASSWORD" =~ ^[A-Za-z0-9._~-]{12,64}$ ]] || die "WDTT_MAIN_PASSWORD: 12-64 безопасных символа без пробелов и двоеточия"
  fi
}

load_panel_config() {
  [ -r "$CONFIG_FILE" ] || die "Панель не установлена: $CONFIG_FILE не найден"
  mapfile -t PANEL_CONFIG_VALUES < <(python3 - "$CONFIG_FILE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
for key, default in (
    ("username", "admin"),
    ("base_path", "/"),
    ("public_host", ""),
    ("https_port", 8443),
    ("listen_port", 8787),
    ("certificate_path", ""),
    ("tls_mode", "self-signed"),
    ("certificate_email", ""),
):
    print(d.get(key, default))
PY
  )
  [ "${#PANEL_CONFIG_VALUES[@]}" -eq 8 ] || die "Не удалось прочитать конфигурацию панели"
  PANEL_USER="${PANEL_CONFIG_VALUES[0]}"
  PANEL_PATH="${PANEL_CONFIG_VALUES[1]}"
  PANEL_HOST="${PANEL_CONFIG_VALUES[2]}"
  PANEL_HTTPS_PORT="${PANEL_CONFIG_VALUES[3]}"
  PANEL_LISTEN_PORT="${PANEL_CONFIG_VALUES[4]}"
  CERTIFICATE_PATH="${PANEL_CONFIG_VALUES[5]}"
  TLS_MODE="${PANEL_CONFIG_VALUES[6]}"
  PANEL_EMAIL="${PANEL_CONFIG_VALUES[7]}"
  if [ "$TLS_MODE" = "letsencrypt" ]; then
    PRIVATE_KEY_PATH="/etc/letsencrypt/live/$PANEL_HOST/privkey.pem"
  else
    PRIVATE_KEY_PATH="$CONFIG_DIR/tls/privkey.pem"
  fi
}

wdtt_installed() {
  systemctl cat wdtt.service >/dev/null 2>&1 || [ -x /usr/local/bin/wdtt-server ]
}

wdtt_extensions_binary_is_current() {
  [ -x /usr/local/bin/wdtt-server ] || return 1
  LC_ALL=C grep -aFq "$WDTT_EXTENSION_MARKER" /usr/local/bin/wdtt-server
}

wdtt_extensions_are_enabled() {
  wdtt_extensions_binary_is_current || return 1
  python3 - "$PRIVATE_STATE_DIR/wdtt-extensions.json" "$WDTT_EXTENSION_MARKER" <<'PY'
import json
import sys
try:
    state = json.load(open(sys.argv[1], encoding="utf-8"))
    features = state.get("features", [])
    raise SystemExit(0 if {"labels", "main_traffic", "activity"}.issubset(features) and state.get("marker") == sys.argv[2] else 1)
except (OSError, ValueError, AttributeError):
    raise SystemExit(1)
PY
}

install_clean_wdtt() {
  case "$INSTALL_WDTT" in
    0|false|no) log "Установка WDTT отключена"; return ;;
    auto) wdtt_installed && { log "Обнаружен существующий WDTT, его файлы не изменяются"; return; } ;;
    1|true|yes) wdtt_installed && { log "Обнаружен существующий WDTT, повторный деплой пропущен"; return; } ;;
    *) die "INSTALL_WDTT должен быть auto, yes или no" ;;
  esac

  log "Чистый сервер: сборка неизмененного WDTT из официального репозитория"
  [ -n "$WDTT_MAIN_PASSWORD" ] || WDTT_MAIN_PASSWORD="$(random_password)"
  BUILD_DIR="$(mktemp -d)"
  trap 'rm -rf "${BUILD_DIR:-}"' RETURN

  case "$(uname -m)" in
    x86_64|amd64) GO_ARCH="amd64" ;;
    aarch64|arm64) GO_ARCH="arm64" ;;
    *) die "Сборка WDTT поддержана для amd64 и arm64" ;;
  esac

  GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
  curl -fsSL "https://go.dev/dl/${GO_TARBALL}" -o "$BUILD_DIR/$GO_TARBALL"
  curl -fsSL "https://dl.google.com/go/${GO_TARBALL}.sha256" -o "$BUILD_DIR/$GO_TARBALL.sha256"
  GO_CHECKSUM="$(awk 'NR == 1 { print $1; exit }' "$BUILD_DIR/$GO_TARBALL.sha256")"
  [[ "$GO_CHECKSUM" =~ ^[a-fA-F0-9]{64}$ ]] || die "Некорректная контрольная сумма Go"
  printf '%s  %s\n' "$GO_CHECKSUM" "$BUILD_DIR/$GO_TARBALL" | sha256sum -c - >>"$LOG_FILE"
  tar -xzf "$BUILD_DIR/$GO_TARBALL" -C "$BUILD_DIR"
  install -d "$BUILD_DIR/gopath/pkg/mod" "$BUILD_DIR/go-cache"

  curl -fsSL "https://github.com/amurcanov/proxy-turn-vk-android/archive/refs/heads/${WDTT_REF}.zip" -o "$BUILD_DIR/wdtt.zip"
  unzip -q "$BUILD_DIR/wdtt.zip" -d "$BUILD_DIR/source"
  WDTT_SOURCE="$(find "$BUILD_DIR/source" -mindepth 1 -maxdepth 1 -type d | head -1)"
  [ -f "$WDTT_SOURCE/server.go" ] || die "В архиве WDTT не найден server.go"
  (
    cd "$WDTT_SOURCE"
    PATH="$BUILD_DIR/go/bin:$PATH" GOPATH="$BUILD_DIR/gopath" GOMODCACHE="$BUILD_DIR/gopath/pkg/mod" GOCACHE="$BUILD_DIR/go-cache" CGO_ENABLED=0 "$BUILD_DIR/go/bin/go" build -mod=mod -trimpath -ldflags='-s -w' -o /tmp/wdtt-server ./server.go
  ) >>"$LOG_FILE" 2>&1
  chmod 0755 /tmp/wdtt-server
  WDTT_ARGS="-password $WDTT_MAIN_PASSWORD" bash "$WDTT_SOURCE/app/src/main/assets/deploy.sh" install >>"$LOG_FILE" 2>&1
  log "WDTT установлен официальным deploy.sh"
}

install_wdtt_extensions() {
  require_root
  if wdtt_extensions_are_enabled; then
    log "Расширение WDTT уже установлено"
    return 0
  fi
  wdtt_installed || die "WDTT не найден: сначала установите или разверните WDTT"
  [ -x /usr/local/bin/wdtt-server ] || die "Не найден /usr/local/bin/wdtt-server"

  local work source go_arch go_tarball go_checksum backup database_backup target was_active=0
  work="$(mktemp -d)"
  trap 'rm -rf "${work:-}"' RETURN
  target="/usr/local/bin/wdtt-server"

  case "$(uname -m)" in
    x86_64|amd64) go_arch="amd64" ;;
    aarch64|arm64) go_arch="arm64" ;;
    *) die "Сборка WDTT поддержана для amd64 и arm64" ;;
  esac

  log "Сборка расширения WDTT: общие метки Telegram и счётчики главного пароля"
  go_tarball="go${GO_VERSION}.linux-${go_arch}.tar.gz"
  curl -fsSL --retry 3 "https://go.dev/dl/${go_tarball}" -o "$work/$go_tarball"
  curl -fsSL --retry 3 "https://dl.google.com/go/${go_tarball}.sha256" -o "$work/$go_tarball.sha256"
  go_checksum="$(awk 'NR == 1 { print $1; exit }' "$work/$go_tarball.sha256")"
  [[ "$go_checksum" =~ ^[a-fA-F0-9]{64}$ ]] || die "Некорректная контрольная сумма Go"
  printf '%s  %s\n' "$go_checksum" "$work/$go_tarball" | sha256sum -c - >>"$LOG_FILE"
  tar -xzf "$work/$go_tarball" -C "$work"
  install -d "$work/gopath/pkg/mod" "$work/go-cache"
  curl -fsSL --retry 3 "https://github.com/amurcanov/proxy-turn-vk-android/archive/refs/heads/${WDTT_REF}.zip" -o "$work/wdtt.zip"
  unzip -q "$work/wdtt.zip" -d "$work/source"
  source="$(find "$work/source" -mindepth 1 -maxdepth 1 -type d | head -1)"
  [ -f "$source/server.go" ] || die "В архиве WDTT не найден server.go"

  python3 - "$source/server.go" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")

def replace_once(old, new, title):
    global source
    if old not in source:
        raise SystemExit(f"WDTT source changed: cannot apply {title}")
    source = source.replace(old, new, 1)

replace_once(
    'func main() {\n',
    'const wdttPanelExtensionMarker = "wdtt-panel-extension-v4"\n\nfunc main() {\n\tlog.Printf("[WDTT Panel] extension %s enabled", wdttPanelExtensionMarker)\n',
    "extension marker",
)

replace_once(
    '\tIsDeactivated bool   `json:"is_deactivated,omitempty"`\n}',
    '\tIsDeactivated bool   `json:"is_deactivated,omitempty"`\n\tLabel         string `json:"label,omitempty"`\n\tLastUploadAt  int64  `json:"last_upload_at,omitempty"`\n\tLastDownloadAt int64  `json:"last_download_at,omitempty"`\n}',
    "user label field",
)
replace_once(
    '\tMainPassword string                    `json:"main_password"`\n',
    '\tMainPassword string                    `json:"main_password"`\n\tMainDownBytes int64                     `json:"main_down_bytes,omitempty"`\n\tMainUpBytes   int64                     `json:"main_up_bytes,omitempty"`\n\tMainLastUploadAt int64                  `json:"main_last_upload_at,omitempty"`\n\tMainLastDownloadAt int64                `json:"main_last_download_at,omitempty"`\n',
    "main traffic fields",
)
replace_once(
    '\tvar waitingForHash bool\n',
    '\tvar waitingForHash bool\n\tvar waitingForLabel bool\n',
    "label input state",
)
replace_once(
    '\t\t\t\t\ttxt := fmt.Sprintf("🔑 *Пароль:* `%s`\\n", pass)\n',
    '\t\t\t\t\ttxt := fmt.Sprintf("🔑 *Пароль:* `%s`\\n", pass)\n\t\t\t\t\tif entry.Label != "" {\n\t\t\t\t\t\ttxt += fmt.Sprintf("🏷 *Метка:* %s\\n", telegramLabel(entry.Label))\n\t\t\t\t\t}\n',
    "label in Telegram details",
)
replace_once(
    '\t\t\t\t\tif entry.DeviceID == "" {\n',
    '\t\t\t\t\tkb = append(kb, map[string]interface{}{\n\t\t\t\t\t\t"text":          "🏷 Изменить метку",\n\t\t\t\t\t\t"callback_data": "label_" + pass,\n\t\t\t\t\t})\n\t\t\t\t\tif entry.DeviceID == "" {\n',
    "label button",
)
replace_once(
    '\t\t\t\t} else if strings.HasPrefix(data, "deact_") {\n',
    '\t\t\t\t} else if strings.HasPrefix(data, "label_") {\n\t\t\t\t\tpass := strings.TrimPrefix(data, "label_")\n\t\t\t\t\tdbMutex.Lock()\n\t\t\t\t\t_, exists := db.Passwords[pass]\n\t\t\t\t\tdbMutex.Unlock()\n\t\t\t\t\tif !exists {\n\t\t\t\t\t\tsendTelegram(token, adminID, "❌ Пароль не найден", nil)\n\t\t\t\t\t\tcontinue\n\t\t\t\t\t}\n\t\t\t\t\ttargetPassword = pass\n\t\t\t\t\twaitingForLabel = true\n\t\t\t\t\tsendTelegram(token, adminID, "🏷 Отправьте метку до 64 символов. Отправьте - чтобы очистить.", nil)\n\n\t\t\t\t} else if strings.HasPrefix(data, "deact_") {\n',
    "label callback",
)
replace_once(
    '\t\t\t// Обработка ввода количества дней\n\t\t\tif waitingForDays {\n',
    '\t\t\tif waitingForLabel {\n\t\t\t\twaitingForLabel = false\n\t\t\t\tlabel, labelErr := normalizeUserLabel(cmd)\n\t\t\t\tif labelErr != nil {\n\t\t\t\t\tsendTelegram(token, adminID, "❌ Метка должна быть не длиннее 64 символов и без служебных символов.", nil)\n\t\t\t\t\tcontinue\n\t\t\t\t}\n\t\t\t\tdbMutex.Lock()\n\t\t\t\tentry, exists := db.Passwords[targetPassword]\n\t\t\t\tif exists && entry != nil {\n\t\t\t\t\tentry.Label = label\n\t\t\t\t\tsaveDB()\n\t\t\t\t}\n\t\t\t\tdbMutex.Unlock()\n\t\t\t\tif !exists || entry == nil {\n\t\t\t\t\tsendTelegram(token, adminID, "❌ Пароль не найден", nil)\n\t\t\t\t} else if label == "" {\n\t\t\t\t\tsendTelegram(token, adminID, "✅ Метка очищена", nil)\n\t\t\t\t} else {\n\t\t\t\t\tsendTelegram(token, adminID, fmt.Sprintf("✅ Метка сохранена: %s", telegramLabel(label)), nil)\n\t\t\t\t}\n\t\t\t\ttargetPassword = ""\n\t\t\t\tcontinue\n\t\t\t}\n\n\t\t\t// Обработка ввода количества дней\n\t\t\tif waitingForDays {\n',
    "label input",
)
replace_once(
    '\t\t\ttxt += fmt.Sprintf("%s `%s` (%s)\\n", status, p, expiry)\n\t\t\tinlineKb = append(inlineKb, map[string]interface{}{\n\t\t\t\t"text":          "🔍 " + p,\n',
    '\t\t\tlabelSuffix := ""\n\t\t\tif entry.Label != "" {\n\t\t\t\tlabelSuffix = " — " + telegramLabel(entry.Label)\n\t\t\t}\n\t\t\ttxt += fmt.Sprintf("%s `%s`%s (%s)\\n", status, p, labelSuffix, expiry)\n\t\t\tbuttonText := "🔍 " + p\n\t\t\tif entry.Label != "" {\n\t\t\t\tbuttonText = "🔍 " + entry.Label\n\t\t\t}\n\t\t\tinlineKb = append(inlineKb, map[string]interface{}{\n\t\t\t\t"text":          buttonText,\n',
    "label in Telegram list",
)
replace_once(
    '\t\t\t// Per-password upload tracking\n\t\t\tif connPassword != "" && !connIsMainPass {\n\t\t\t\tdbMutex.Lock()\n\t\t\t\te, ok := db.Passwords[connPassword]\n\t\t\t\tif !ok || e == nil || isPasswordExpired(e) || e.IsDeactivated {\n\t\t\t\t\tdbMutex.Unlock()\n\t\t\t\t\treturn\n\t\t\t\t}\n\t\t\t\te.UpBytes += int64(nn)\n\t\t\t\tdbMutex.Unlock()\n\t\t\t}\n',
    '\t\t\t// Per-password and main-password upload tracking\n\t\t\tif connPassword != "" {\n\t\t\t\tdbMutex.Lock()\n\t\t\t\tnow := time.Now().Unix()\n\t\t\t\tif connIsMainPass {\n\t\t\t\t\tdb.MainUpBytes += int64(nn)\n\t\t\t\t\tdb.MainLastUploadAt = now\n\t\t\t\t} else {\n\t\t\t\t\te, ok := db.Passwords[connPassword]\n\t\t\t\t\tif !ok || e == nil || isPasswordExpired(e) || e.IsDeactivated {\n\t\t\t\t\t\tdbMutex.Unlock()\n\t\t\t\t\t\treturn\n\t\t\t\t\t}\n\t\t\t\t\te.UpBytes += int64(nn)\n\t\t\t\t\te.LastUploadAt = now\n\t\t\t\t}\n\t\t\t\tdbMutex.Unlock()\n\t\t\t}\n',
    "main upload counter",
)
replace_once(
    '\t\t\t// Per-password download tracking\n\t\t\tif connPassword != "" && !connIsMainPass {\n\t\t\t\tdbMutex.Lock()\n\t\t\t\te, ok := db.Passwords[connPassword]\n\t\t\t\tif !ok || e == nil || isPasswordExpired(e) || e.IsDeactivated {\n\t\t\t\t\tdbMutex.Unlock()\n\t\t\t\t\treturn\n\t\t\t\t}\n\t\t\t\te.DownBytes += int64(nn)\n\t\t\t\tdbMutex.Unlock()\n\t\t\t}\n',
    '\t\t\t// Per-password and main-password download tracking\n\t\t\tif connPassword != "" {\n\t\t\t\tdbMutex.Lock()\n\t\t\t\tnow := time.Now().Unix()\n\t\t\t\tif connIsMainPass {\n\t\t\t\t\tdb.MainDownBytes += int64(nn)\n\t\t\t\t\tdb.MainLastDownloadAt = now\n\t\t\t\t} else {\n\t\t\t\t\te, ok := db.Passwords[connPassword]\n\t\t\t\t\tif !ok || e == nil || isPasswordExpired(e) || e.IsDeactivated {\n\t\t\t\t\t\tdbMutex.Unlock()\n\t\t\t\t\t\treturn\n\t\t\t\t\t}\n\t\t\t\t\te.DownBytes += int64(nn)\n\t\t\t\t\te.LastDownloadAt = now\n\t\t\t\t}\n\t\t\t\tdbMutex.Unlock()\n\t\t\t}\n',
    "main download counter",
)
replace_once(
    '\t\t\tnumDevices := len(db.Devices)\n\t\t\tdbMutex.Unlock()\n',
    '\t\t\tnumDevices := len(db.Devices)\n\t\t\tsaveDB()\n\t\t\tdbMutex.Unlock()\n',
    "periodic counter persistence",
)
replace_once(
    '\tvar waitingForHash bool\n\tvar waitingForLabel bool\n',
    '\tvar waitingForHash bool\n\tvar waitingForLabel bool\n\tvar tempLabel string\n',
    "Telegram creation label state",
)
replace_once(
    '\t\tcmds := `{"commands":[{"command":"start","description":"Главное меню"},{"command":"new","description":"Создать временный пароль"},{"command":"list","description":"Управление доступами"}]}`\n',
    '\t\tcmds := `{"commands":[{"command":"start","description":"Главное меню"},{"command":"new","description":"Создать пользователя"},{"command":"list","description":"Управление доступами"},{"command":"settings","description":"Настройки сервера"}]}`\n',
    "Telegram settings command",
)
replace_once(
    '\t\t\tif waitingForLabel {\n\t\t\t\twaitingForLabel = false\n\t\t\t\tlabel, labelErr := normalizeUserLabel(cmd)\n\t\t\t\tif labelErr != nil {\n\t\t\t\t\tsendTelegram(token, adminID, "❌ Метка должна быть не длиннее 64 символов и без служебных символов.", nil)\n\t\t\t\t\tcontinue\n\t\t\t\t}\n\t\t\t\tdbMutex.Lock()\n',
    '\t\t\tif waitingForLabel {\n\t\t\t\twaitingForLabel = false\n\t\t\t\tlabel, labelErr := normalizeUserLabel(cmd)\n\t\t\t\tif labelErr != nil {\n\t\t\t\t\tsendTelegram(token, adminID, "❌ Метка должна быть не длиннее 64 символов и без служебных символов.", nil)\n\t\t\t\t\tcontinue\n\t\t\t\t}\n\t\t\t\tif targetPassword == "__new_label__" {\n\t\t\t\t\ttempLabel = label\n\t\t\t\t\ttargetPassword = ""\n\t\t\t\t\twaitingForDays = true\n\t\t\t\t\tsendTelegram(token, adminID, "📅 Введите срок действия в днях (1–365):", nil)\n\t\t\t\t\tcontinue\n\t\t\t\t}\n\t\t\t\tdbMutex.Lock()\n',
    "Telegram creation label input",
)
replace_once(
    '\t\t\ttxt += fmt.Sprintf("%s `%s`%s (%s)\\n", status, p, labelSuffix, expiry)\n\t\t\tbuttonText := "🔍 " + p\n',
    '\t\t\tlabelPrefix := ""\n\t\t\tif entry.Label != "" {\n\t\t\t\tlabelPrefix = telegramLabel(entry.Label) + " · "\n\t\t\t}\n\t\t\ttxt += fmt.Sprintf("%s %s`%s` (%s)\\n", status, labelPrefix, p, expiry)\n\t\t\tbuttonText := "🔍 " + p\n',
    "label before password in Telegram list",
)
replace_once(
    '\t\t\t\tdb.Passwords[newPass] = &PasswordEntry{\n\t\t\t\t\tExpiresAt: expiresAt,\n\t\t\t\t\tVkHash:    hash,\n\t\t\t\t\tPorts:     tempPorts,\n\t\t\t\t}\n',
    '\t\t\t\tdb.Passwords[newPass] = &PasswordEntry{\n\t\t\t\t\tExpiresAt: expiresAt,\n\t\t\t\t\tVkHash:    hash,\n\t\t\t\t\tPorts:     tempPorts,\n\t\t\t\t\tLabel:     tempLabel,\n\t\t\t\t}\n',
    "label on Telegram creation",
)
replace_once(
    '\t\t\t\tdbMutex.Unlock()\n\t\t\t\twaitingForDays = true\n\t\t\t\tsendTelegram(token, adminID, "📅 Введите срок действия пароля в днях (1–365):\\n\\n_Примеры: 30 = месяц, 365 = год_", nil)\n',
    '\t\t\t\tdbMutex.Unlock()\n\t\t\t\ttargetPassword = "__new_label__"\n\t\t\t\twaitingForLabel = true\n\t\t\t\tsendTelegram(token, adminID, "🏷 Отправьте метку нового пользователя до 64 символов. Отправьте - без метки.", nil)\n',
    "label prompt on Telegram creation",
)
replace_once(
    '\t\t\tif cmd == "/start" || cmd == "/help" {\n\t\t\t\tsendTelegram(token, adminID, "🤖 *WDTT VPN Manager*\\n\\n/new — Создать пароль\\n/list — Список паролей", nil)\n\n\t\t\t} else if cmd == "/new" {\n',
    '\t\t\tif cmd == "/start" || cmd == "/help" {\n\t\t\t\tsendTelegram(token, adminID, "🤖 *WDTT VPN Manager*\\n\\n/new — Создать пользователя\\n/list — Список пользователей\\n/settings — Настройки сервера", nil)\n\n\t\t\t} else if cmd == "/settings" {\n\t\t\t\tsendTelegram(token, adminID, fmt.Sprintf("⚙️ *Настройки сервера*\\n\\n• DNS: `%s`\\n• MTU: `%d`\\n• Keepalive WireGuard: `%d сек.`\\n\\nНастройки маршрутизации и доступа меняются в WDTT Control Panel.", dns, wgMTU, keepalive), nil)\n\n\t\t\t} else if cmd == "/new" {\n',
    "Telegram settings response",
)
replace_once(
    '\t\t\tlabelSuffix := ""\n\t\t\tif entry.Label != "" {\n\t\t\t\tlabelSuffix = " — " + telegramLabel(entry.Label)\n\t\t\t}\n\t\t\tlabelPrefix := ""\n',
    '\t\t\tlabelPrefix := ""\n',
    "remove password-first Telegram label formatting",
)
marker = 'func getNextIP() string {'
if marker not in source:
    raise SystemExit("WDTT source changed: cannot add label validation")
helpers = '''func normalizeUserLabel(value string) (string, error) {
\tlabel := strings.TrimSpace(value)
\tif label == "-" {
\t\treturn "", nil
\t}
\tif len([]rune(label)) > 64 {
\t\treturn "", errors.New("label is too long")
\t}
\tfor _, char := range label {
\t\tif char < 32 || char == 127 {
\t\t\treturn "", errors.New("label contains a control character")
\t\t}
\t}
\treturn label, nil
}

func telegramLabel(value string) string {
\treplacer := strings.NewReplacer("\\\\", "\\\\\\\\", "_", "\\\\_", "*", "\\\\*", "`", "\\\\`", "[", "\\\\[")
\treturn replacer.Replace(value)
}

'''
source = source.replace(marker, helpers + marker, 1)
path.write_text(source, encoding="utf-8")
PY

  (
    cd "$source"
    PATH="$work/go/bin:$PATH" GOPATH="$work/gopath" GOMODCACHE="$work/gopath/pkg/mod" GOCACHE="$work/go-cache" CGO_ENABLED=0 "$work/go/bin/go" build -mod=mod -trimpath -ldflags='-s -w' -o "$work/wdtt-server" ./server.go
  ) >>"$LOG_FILE" 2>&1 || die "Не удалось собрать расширенный WDTT; действующий сервер не изменён"

  install -d -m 0700 "$PRIVATE_STATE_DIR"
  backup="$PRIVATE_STATE_DIR/wdtt-server-before-extension-$(date +%Y%m%d-%H%M%S)"
  install -m 0700 "$target" "$backup"
  if systemctl is-active --quiet "$WDTT_SERVICE"; then
    was_active=1
    systemctl stop "$WDTT_SERVICE" >>"$LOG_FILE" 2>&1 || die "Не удалось остановить WDTT перед обновлением"
  fi
  if [ -f /etc/wdtt/passwords.json ]; then
    database_backup="$PRIVATE_STATE_DIR/passwords-before-extension-$(date +%Y%m%d-%H%M%S).json"
    install -m 0600 /etc/wdtt/passwords.json "$database_backup"
    python3 - /etc/wdtt/passwords.json "$PRIVATE_STATE_DIR/user-labels.json" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
panel_labels_path = Path(sys.argv[2])
data = json.loads(path.read_text(encoding="utf-8"))
try:
    panel_labels = json.loads(panel_labels_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    panel_labels = {}
if not isinstance(panel_labels, dict):
    panel_labels = {}
entry_label_fields = ("label", "remark", "name", "comment", "tag", "mark", "user_label", "userLabel", "user_name", "userName", "note", "description")
mapping_label_fields = ("labels", "remarks", "user_labels", "userLabels", "names", "comments", "tags", "marks")


def saved_label(source, password, entry):
    if not isinstance(source, dict) or not isinstance(entry, dict):
        return ""
    for key in entry_label_fields:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key in mapping_label_fields:
        values = source.get(key)
        value = values.get(password) if isinstance(values, dict) else None
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


sources = [data]
backup_roots = (panel_labels_path.parent, panel_labels_path.parent / "backups")
backup_paths = sorted(
    {candidate for root in backup_roots if root.is_dir() for candidate in root.glob("passwords-*.json")},
    reverse=True,
)
for candidate in backup_paths:
    try:
        backup = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        continue
    if isinstance(backup, dict):
        sources.append(backup)

recovered_labels = {}
for source in sources:
    for password, entry in (source.get("passwords") or {}).items():
        label = saved_label(source, password, entry)
        if label and password not in recovered_labels:
            recovered_labels[password] = label

changed = False
for password, entry in (data.get("passwords") or {}).items():
    if not isinstance(entry, dict) or str(entry.get("label") or "").strip():
        continue
    value = panel_labels.get(password)
    if not isinstance(value, str) or not value.strip():
        value = recovered_labels.get(password)
    if isinstance(value, str) and value.strip():
        entry["label"] = value.strip()
        changed = True
if changed:
    fd, temporary = tempfile.mkstemp(prefix="passwords.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
PY
  fi
  install -m 0755 "$work/wdtt-server" "$target.new"
  mv -f "$target.new" "$target"
  if [ "$was_active" = "1" ] && ! systemctl start "$WDTT_SERVICE" >>"$LOG_FILE" 2>&1; then
    install -m 0755 "$backup" "$target"
    if [ -n "$database_backup" ]; then install -m 0600 "$database_backup" /etc/wdtt/passwords.json; fi
    systemctl start "$WDTT_SERVICE" >>"$LOG_FILE" 2>&1 || true
    die "Обновлённый WDTT не запустился; прежний бинарный файл восстановлен"
  fi
  if ! wdtt_extensions_binary_is_current; then
    install -m 0755 "$backup" "$target"
    if [ -n "$database_backup" ]; then install -m 0600 "$database_backup" /etc/wdtt/passwords.json; fi
    if [ "$was_active" = "1" ]; then systemctl restart "$WDTT_SERVICE" >>"$LOG_FILE" 2>&1 || true; fi
    die "Собранный WDTT не прошёл проверку расширений; прежний бинарный файл восстановлен"
  fi
  rm -f "$PRIVATE_STATE_DIR/user-labels.json"
  printf '{"enabled_at": %s, "marker": "%s", "features": ["labels", "main_traffic", "activity"]}\n' "$(date +%s)" "$WDTT_EXTENSION_MARKER" > "$PRIVATE_STATE_DIR/wdtt-extensions.json"
  chmod 0600 "$PRIVATE_STATE_DIR/wdtt-extensions.json"
  log "Расширение WDTT включено: метки общие с Telegram-ботом, трафик и последняя активность пользователей учитываются"
}

schedule_wdtt_extensions() {
  if wdtt_extensions_are_enabled; then
    log "Расширение WDTT уже установлено"
    return 0
  fi
  systemctl restart --no-block "$WDTT_EXTENSIONS_SERVICE" >>"$LOG_FILE" 2>&1 || die "Не удалось запустить автоматическое обновление WDTT"
  log "Автоматическое обновление WDTT запущено; при временной ошибке оно повторится автоматически"
}

install_panel_files() {
  [ -d "$SCRIPT_DIR/wdtt_panel" ] || die "Каталог wdtt_panel не найден рядом с install.sh"
  id -u wdtt-panel >/dev/null 2>&1 || useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin wdtt-panel
  install -d -m 0755 "$INSTALL_DIR" "$CONFIG_DIR"
  install -d -o wdtt-panel -g wdtt-panel -m 0750 "$STATE_DIR"
  install -d -o root -g root -m 0700 "$PRIVATE_STATE_DIR" "$PRIVATE_STATE_DIR/backups"
  install -d -m 0755 "$STATE_DIR/acme"
  rm -rf "$INSTALL_DIR/wdtt_panel"
  cp -a "$SCRIPT_DIR/wdtt_panel" "$INSTALL_DIR/wdtt_panel"
  install -m 0755 "$SCRIPT_DIR/install.sh" "$INSTALL_DIR/install.sh"
  install -m 0755 "$SCRIPT_DIR/bootstrap.sh" "$INSTALL_DIR/bootstrap.sh"
  install -m 0755 "$SCRIPT_DIR/update.sh" "$INSTALL_DIR/update.sh"
  install -m 0755 "$SCRIPT_DIR/uninstall.sh" "$INSTALL_DIR/uninstall.sh"
  chown -R root:root "$INSTALL_DIR/wdtt_panel"
  find "$INSTALL_DIR/wdtt_panel" -type d -exec chmod 0755 {} +
  find "$INSTALL_DIR/wdtt_panel" -type f -exec chmod 0644 {} +

  cat > "$ADMIN_WRAPPER" <<'EOF'
#!/bin/sh
cd /opt/wdtt-panel || exit 1
exec /usr/bin/python3 -m wdtt_panel.admin
EOF
  chown root:root "$ADMIN_WRAPPER"
  chmod 0755 "$ADMIN_WRAPPER"

  printf 'wdtt-panel ALL=(root) NOPASSWD: %s\n' "$ADMIN_WRAPPER" > "$SUDOERS_FILE"
  chown root:root "$SUDOERS_FILE"
  chmod 0440 "$SUDOERS_FILE"
  visudo -cf "$SUDOERS_FILE" >>"$LOG_FILE"
}

write_maintenance_scripts() {
  rm -f "$MANAGER_WRAPPER" /usr/local/sbin/wddt-panel /usr/local/sbin/wdtt-pane
  install -m 0755 "$INSTALL_DIR/bootstrap.sh" "$MANAGER_WRAPPER"
  ln -sfn "$INSTALL_DIR/update.sh" "$UPDATE_WRAPPER"
  ln -sfn "$INSTALL_DIR/uninstall.sh" "$UNINSTALL_WRAPPER"
  cat > "$STATUS_WRAPPER" <<EOF
#!/bin/sh
exec /bin/bash $INSTALL_DIR/install.sh status
EOF
  chmod 0755 "$STATUS_WRAPPER"
  cat > "$GEOFILES_UPDATE_WRAPPER" <<EOF
#!/bin/sh
printf '%s\n' '{"action":"xray.geofiles.refresh_auto","payload":{}}' | $ADMIN_WRAPPER
EOF
  chmod 0755 "$GEOFILES_UPDATE_WRAPPER"
  cat > "$BACKUP_RUNNER" <<EOF
#!/bin/sh
case "\${1:-full}" in
  full) printf '%s\n' '{"action":"backups.create","payload":{"type":"full","scheduled":true}}' | $ADMIN_WRAPPER ;;
  users) printf '%s\n' '{"action":"backups.create","payload":{"type":"users","scheduled":true}}' | $ADMIN_WRAPPER ;;
  *) exit 2 ;;
esac
EOF
  chmod 0755 "$BACKUP_RUNNER"
  cat > "$CASCADE_RULES_WRAPPER" <<EOF
#!/bin/sh
case "\${1:-apply}" in
  apply) printf '%s\n' '{"action":"cascade.apply","payload":{}}' | $ADMIN_WRAPPER ;;
  remove) printf '%s\n' '{"action":"cascade.remove","payload":{}}' | $ADMIN_WRAPPER ;;
  *) exit 2 ;;
esac
EOF
  chmod 0755 "$CASCADE_RULES_WRAPPER"
  cat > "$GATEWAY_RULES_WRAPPER" <<EOF
#!/bin/sh
case "\${1:-apply}" in
  apply) printf '%s\n' '{"action":"xray.gateway.apply","payload":{}}' | $ADMIN_WRAPPER ;;
  remove) printf '%s\n' '{"action":"xray.gateway.remove","payload":{}}' | $ADMIN_WRAPPER ;;
  *) exit 2 ;;
esac
EOF
  chmod 0755 "$GATEWAY_RULES_WRAPPER"
}

backup_wdtt_database_before_update() {
  [ -f /etc/wdtt/passwords.json ] || return 0
  install -d -m 0700 "$PRIVATE_STATE_DIR"
  local snapshot="$PRIVATE_STATE_DIR/passwords-before-panel-update-$(date +%Y%m%d-%H%M%S).json"
  install -m 0600 /etc/wdtt/passwords.json "$snapshot"
  log "Создан снимок базы WDTT перед обновлением: $(basename "$snapshot")"
}

write_xray_services() {
  systemctl disable --now "$LEGACY_CASCADE_SERVICE" wdtt-panel-geofiles-update.timer wdtt-panel-geofiles-update.service 2>/dev/null || true
  rm -f "/etc/systemd/system/$LEGACY_CASCADE_SERVICE"
  install -d -m 0700 "$XRAY_ASSETS"

  cat > "/etc/systemd/system/$XRAY_SERVICE" <<EOF
[Unit]
Description=WDTT Xray Routing Runtime
After=network-online.target wdtt.service
Wants=network-online.target
ConditionPathExists=$XRAY_CONFIG

[Service]
Type=simple
User=root
Environment=XRAY_LOCATION_ASSET=$XRAY_ASSETS
ExecStartPre=/usr/local/bin/xray run -test -c $XRAY_CONFIG
ExecStart=/usr/local/bin/xray run -c $XRAY_CONFIG
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$PRIVATE_STATE_DIR /run

[Install]
WantedBy=multi-user.target
EOF

  cat > "/etc/systemd/system/$XRAY_CASCADE_SERVICE" <<EOF
[Unit]
Description=WDTT Xray RU to EU Cascade Rules
After=network-online.target wdtt.service $XRAY_SERVICE
Wants=network-online.target
ConditionPathExists=$XRAY_CASCADE_SETTINGS

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$CASCADE_RULES_WRAPPER apply
ExecStop=$CASCADE_RULES_WRAPPER remove

[Install]
WantedBy=multi-user.target
EOF

  cat > "/etc/systemd/system/$XRAY_GATEWAY_SERVICE" <<EOF
[Unit]
Description=WDTT traffic gateway to Xray
After=network-online.target wdtt.service $XRAY_SERVICE
Wants=network-online.target
ConditionPathExists=$XRAY_SETTINGS

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$GATEWAY_RULES_WRAPPER apply
ExecStop=$GATEWAY_RULES_WRAPPER remove

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/wdtt-panel-geofiles-update.service <<EOF
[Unit]
Description=Update WDTT Panel Xray GeoFiles
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$GEOFILES_UPDATE_WRAPPER
EOF
  cat > /etc/systemd/system/wdtt-panel-geofiles-update.timer <<'EOF'
[Unit]
Description=Automatic WDTT Panel Xray GeoFiles updates

[Timer]
OnBootSec=20min
OnUnitActiveSec=6h
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now wdtt-panel-geofiles-update.timer >>"$LOG_FILE" 2>&1
}

github_asset_url() {
  local repository="$1" pattern="$2"
  python3 - "$repository" "$pattern" <<'PY'
import json, re, sys, urllib.request
repo, pattern = sys.argv[1:]
request = urllib.request.Request(
    f"https://api.github.com/repos/{repo}/releases/latest",
    headers={"User-Agent": "wdtt-control-panel"},
)
with urllib.request.urlopen(request, timeout=30) as response:
    release = json.load(response)
for asset in release.get("assets", []):
    if re.search(pattern, asset.get("name", "")):
        print(asset["browser_download_url"])
        raise SystemExit
raise SystemExit(2)
PY
}

install_xray_runtime() {
  require_root
  local machine asset_pattern work xray_url bundled_asset
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64) asset_pattern='Xray-linux-64\.zip$' ;;
    aarch64|arm64) asset_pattern='Xray-linux-arm64-v8a\.zip$' ;;
    *) die "Xray поддержан для amd64 и arm64" ;;
  esac
  work="$(mktemp -d)"
  trap 'rm -rf "${work:-}"' RETURN

  log "Установка Xray Core"
  xray_url="$(github_asset_url XTLS/Xray-core "$asset_pattern")" || die "Не найден релиз Xray Core"
  curl -fsSL --retry 3 "$xray_url" -o "$work/xray.zip"
  unzip -q "$work/xray.zip" -d "$work/xray"
  install -m 0755 "$(find "$work/xray" -type f \( -name Xray -o -name xray \) | head -1)" /usr/local/bin/xray
  install -d -m 0700 "$XRAY_ASSETS"
  for bundled_asset in geoip.dat geosite.dat; do
    if [ ! -f "$XRAY_ASSETS/$bundled_asset" ] && [ -f "$work/xray/$bundled_asset" ]; then
      install -m 0600 "$work/xray/$bundled_asset" "$XRAY_ASSETS/$bundled_asset"
    fi
  done
  write_xray_services
  if [ -r "$XRAY_SETTINGS" ] && python3 -c 'import json,sys; raise SystemExit(0 if json.load(open(sys.argv[1])).get("enabled") else 1)' "$XRAY_SETTINGS"; then
    systemctl enable --now "$XRAY_SERVICE" >>"$LOG_FILE" 2>&1
  fi
  log "Xray Core установлен"
  /usr/local/bin/xray version | head -1
}

install_warp_runtime() {
  require_root
  local machine asset_pattern warp_url work
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64) asset_pattern='wgcf_[^/]*_linux_amd64$' ;;
    aarch64|arm64) asset_pattern='wgcf_[^/]*_linux_arm64$' ;;
    *) die "Cloudflare WARP поддержан для amd64 и arm64" ;;
  esac
  work="$(mktemp -d)"
  trap 'rm -rf "${work:-}"' RETURN
  log "Установка wgcf для Cloudflare WARP"
  warp_url="$(github_asset_url ViRb3/wgcf "$asset_pattern")" || die "Не найден релиз wgcf"
  curl -fsSL --retry 3 "$warp_url" -o "$work/wgcf"
  install -m 0755 "$work/wgcf" /usr/local/bin/wgcf
  install -d -m 0700 "$WARP_DIR"
  log "Компонент Cloudflare WARP установлен"
  /usr/local/bin/wgcf --version || true
}

write_panel_config() {
  PASSWORD_HASH="$(PYTHONPATH="$INSTALL_DIR" python3 -c 'import sys; from wdtt_panel.security import hash_password; print(hash_password(sys.argv[1]))' "$PANEL_PASSWORD")"
  python3 - "$CONFIG_FILE" "$PANEL_VERSION" "$PANEL_USER" "$PASSWORD_HASH" "$SESSION_SECRET" "$PANEL_PATH" "$PANEL_HOST" "$PANEL_HTTPS_PORT" "$PANEL_LISTEN_PORT" "$CERTIFICATE_PATH" "$TLS_MODE" "$PANEL_EMAIL" <<'PY'
import json, os, sys
path, version, username, password_hash, session_secret, base_path, public_host, https_port, listen_port, certificate_path, tls_mode, certificate_email = sys.argv[1:]
data = {
    "version": version,
    "username": username,
    "password_hash": password_hash,
    "session_secret": session_secret,
    "base_path": base_path,
    "public_host": public_host,
    "https_port": int(https_port),
    "listen_host": "127.0.0.1",
    "listen_port": int(listen_port),
    "certificate_path": certificate_path,
    "tls_mode": tls_mode,
    "certificate_email": certificate_email,
}
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(data, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
os.chmod(tmp, 0o640)
os.replace(tmp, path)
PY
  chown root:wdtt-panel "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
}

update_panel_config_metadata() {
  python3 - "$CONFIG_FILE" "$PANEL_VERSION" "${CERTIFICATE_PATH:-}" "${TLS_MODE:-}" "${PANEL_EMAIL:-}" <<'PY'
import json, os, sys
path, version, certificate_path, tls_mode, certificate_email = sys.argv[1:]
data = json.load(open(path, encoding="utf-8"))
data["version"] = version
if certificate_path:
    data["certificate_path"] = certificate_path
if tls_mode:
    data["tls_mode"] = tls_mode
if certificate_email:
    data["certificate_email"] = certificate_email
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(data, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
os.chmod(tmp, 0o640)
os.replace(tmp, path)
PY
  chown root:wdtt-panel "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
}

write_panel_service() {
  cat > "/etc/systemd/system/$PANEL_SERVICE" <<EOF
[Unit]
Description=WDTT Web Control Panel
After=network.target wdtt.service
Wants=network-online.target

[Service]
Type=simple
User=wdtt-panel
Group=wdtt-panel
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 -m wdtt_panel.app
Restart=on-failure
RestartSec=3
UMask=0027
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$STATE_DIR $PRIVATE_STATE_DIR -/etc/wdtt
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$PANEL_SERVICE" >>"$LOG_FILE" 2>&1
}

remove_obsolete_fleet_agent() {
  systemctl disable --now wdtt-fleet-agent.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/wdtt-fleet-agent.service "$STATE_DIR/fleet-agent.json"
  systemctl daemon-reload
}

port_80_available_for_nginx() {
  local listeners
  listeners="$(ss -ltnp '( sport = :80 )' 2>/dev/null || true)"
  ! grep -q LISTEN <<<"$listeners" && return 0
  grep -qi nginx <<<"$listeners"
}

write_acme_nginx() {
  cat > "$NGINX_FILE" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $PANEL_HOST;
    location ^~ /.well-known/acme-challenge/ { root $STATE_DIR/acme; }
    location / { return 404; }
}
EOF
  nginx -t >>"$LOG_FILE" 2>&1 || { log "Nginx не принял временную ACME-конфигурацию"; return 1; }
  systemctl enable --now nginx >>"$LOG_FILE" 2>&1 || { log "Не удалось запустить Nginx для ACME"; return 1; }
  systemctl reload nginx >>"$LOG_FILE" 2>&1 || { log "Не удалось применить временную ACME-конфигурацию Nginx"; return 1; }
}

open_acme_firewall() {
  if command_exists ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow 80/tcp comment 'WDTT Panel ACME' >/dev/null || true
  elif command_exists firewall-cmd && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=80/tcp >/dev/null || true
    firewall-cmd --reload >/dev/null || true
  elif command_exists iptables; then
    iptables -C INPUT -p tcp --dport 80 -m comment --comment WDTT_PANEL -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p tcp --dport 80 -m comment --comment WDTT_PANEL -j ACCEPT || true
  fi
}

install_certbot() {
  if [ ! -x "$INSTALL_DIR/certbot/bin/certbot" ]; then
    python3 -m venv "$INSTALL_DIR/certbot" >>"$LOG_FILE" 2>&1 || return 1
    "$INSTALL_DIR/certbot/bin/pip" install --upgrade pip >>"$LOG_FILE" 2>&1 || return 1
    "$INSTALL_DIR/certbot/bin/pip" install 'certbot>=5.4,<6' >>"$LOG_FILE" 2>&1 || return 1
  fi
}

request_certificate() {
  CERTIFICATE_PATH=""
  TLS_MODE="self-signed"
  port_80_available_for_nginx || { log "Порт 80 занят не Nginx: публичный сертификат пропущен"; return 1; }
  write_acme_nginx || return 1
  open_acme_firewall
  if ! run_certbot_request; then
    log "Не удалось получить Let's Encrypt: убедитесь, что $PANEL_HOST доступен из интернета по TCP 80; подробности в $LOG_FILE"
    return 1
  fi
}

run_certbot_request() {
  local nginx_was_active=0 certificate_ok=0
  local -a CERTBOT_OPTIONS
  install_certbot || return 1
  CERTBOT_OPTIONS=(--non-interactive --agree-tos)
  if [ -n "$PANEL_EMAIL" ]; then CERTBOT_OPTIONS+=(--email "$PANEL_EMAIL"); else CERTBOT_OPTIONS+=(--register-unsafely-without-email); fi
  if [[ "$PANEL_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    CERTBOT_OPTIONS+=(--preferred-profile shortlived --ip-address "$PANEL_HOST" --cert-name "$PANEL_HOST")
  else
    CERTBOT_OPTIONS+=(-d "$PANEL_HOST")
  fi

  CERTBOT=("$INSTALL_DIR/certbot/bin/certbot" certonly "${CERTBOT_OPTIONS[@]}" --webroot --webroot-path "$STATE_DIR/acme")
  if "${CERTBOT[@]}" >>"$LOG_FILE" 2>&1; then
    CERTIFICATE_PATH="/etc/letsencrypt/live/$PANEL_HOST/fullchain.pem"
    PRIVATE_KEY_PATH="/etc/letsencrypt/live/$PANEL_HOST/privkey.pem"
    [ -f "$CERTIFICATE_PATH" ] && [ -f "$PRIVATE_KEY_PATH" ] || return 1
    TLS_MODE="letsencrypt"
    return 0
  fi

  log "Webroot-проверка Let's Encrypt не прошла; используется временный standalone режим на TCP 80"
  if systemctl is-active --quiet nginx; then
    nginx_was_active=1
    systemctl stop nginx >>"$LOG_FILE" 2>&1 || { log "Не удалось временно остановить Nginx для Certbot"; return 1; }
  fi
  CERTBOT=("$INSTALL_DIR/certbot/bin/certbot" certonly "${CERTBOT_OPTIONS[@]}" --standalone --preferred-challenges http)
  if "${CERTBOT[@]}" >>"$LOG_FILE" 2>&1; then
    CERTIFICATE_PATH="/etc/letsencrypt/live/$PANEL_HOST/fullchain.pem"
    PRIVATE_KEY_PATH="/etc/letsencrypt/live/$PANEL_HOST/privkey.pem"
    if [ -f "$CERTIFICATE_PATH" ] && [ -f "$PRIVATE_KEY_PATH" ]; then
      TLS_MODE="letsencrypt"
      certificate_ok=1
    fi
  fi
  if [ "$nginx_was_active" = "1" ]; then
    systemctl start nginx >>"$LOG_FILE" 2>&1 || { log "Не удалось вернуть Nginx после standalone проверки Certbot"; return 1; }
  fi
  [ "$certificate_ok" = "1" ]
}

try_upgrade_certificate() {
  port_80_available_for_nginx || { log "Публичный сертификат не запрошен: TCP 80 занят не Nginx"; return 1; }
  [ -r "$NGINX_FILE" ] || { log "Публичный сертификат не запрошен: не найден $NGINX_FILE"; return 1; }
  grep -q '/.well-known/acme-challenge/' "$NGINX_FILE" || { log "Публичный сертификат не запрошен: в Nginx отсутствует ACME location"; return 1; }
  open_acme_firewall
  if ! run_certbot_request; then
    log "Не удалось получить Let's Encrypt: проверьте DNS и публичную доступность $PANEL_HOST:80; подробности в $LOG_FILE"
    return 1
  fi
}

create_self_signed_certificate() {
  install -d -m 0700 "$CONFIG_DIR/tls"
  CERTIFICATE_PATH="$CONFIG_DIR/tls/fullchain.pem"
  PRIVATE_KEY_PATH="$CONFIG_DIR/tls/privkey.pem"
  if [[ "$PANEL_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then SAN="IP:$PANEL_HOST"; else SAN="DNS:$PANEL_HOST"; fi
  openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
    -keyout "$PRIVATE_KEY_PATH" -out "$CERTIFICATE_PATH" \
    -subj "/CN=$PANEL_HOST" -addext "subjectAltName=$SAN" >>"$LOG_FILE" 2>&1
  chmod 0600 "$PRIVATE_KEY_PATH"
  chmod 0644 "$CERTIFICATE_PATH"
  TLS_MODE="self-signed"
}

write_final_nginx() {
  HTTP_BLOCK=""
  HSTS_HEADER=""
  HTTP_ENABLED=0
  if [ "$TLS_MODE" = "letsencrypt" ]; then
    HSTS_HEADER='    add_header Strict-Transport-Security "max-age=31536000" always;'
  fi
  if port_80_available_for_nginx; then
    HTTP_ENABLED=1
    HTTP_BLOCK="server {
    listen 80;
    listen [::]:80;
    server_name $PANEL_HOST;
    location ^~ /.well-known/acme-challenge/ { root $STATE_DIR/acme; }
    location / { return 302 https://$PANEL_HOST:$PANEL_HTTPS_PORT$PANEL_PATH; }
}"
  fi
  cat > "$NGINX_FILE" <<EOF
$HTTP_BLOCK
server {
    listen $PANEL_HTTPS_PORT ssl;
    listen [::]:$PANEL_HTTPS_PORT ssl;
    server_name $PANEL_HOST;

    ssl_certificate $CERTIFICATE_PATH;
    ssl_certificate_key $PRIVATE_KEY_PATH;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_timeout 1d;
    ssl_session_cache shared:WDTTTLS:10m;
$HSTS_HEADER

    location = ${PANEL_PATH%/} { return 302 $PANEL_PATH; }
    location ^~ $PANEL_PATH {
        proxy_pass http://127.0.0.1:$PANEL_LISTEN_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 75s;
        client_max_body_size 90m;
    }
    location / { return 404; }
}
EOF
  nginx -t >>"$LOG_FILE" 2>&1 || die "Ошибка конфигурации Nginx, см. $LOG_FILE"
  systemctl enable --now nginx >>"$LOG_FILE" 2>&1
  systemctl reload nginx >>"$LOG_FILE" 2>&1
}

write_renew_timer() {
  cat > /etc/systemd/system/wdtt-panel-cert-renew.service <<EOF
[Unit]
Description=Renew WDTT Panel TLS certificate
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_DIR/install.sh renew-cert
EOF
  cat > /etc/systemd/system/wdtt-panel-cert-renew.timer <<'EOF'
[Unit]
Description=Frequent renewal check for WDTT Panel certificates

[Timer]
OnBootSec=15min
OnUnitActiveSec=12h
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now wdtt-panel-cert-renew.timer >>"$LOG_FILE" 2>&1
}

renew_certificates() {
  local renewal_file nginx_was_active=0 renewal_ok=0
  require_root
  load_panel_config

  if [ "$TLS_MODE" = "letsencrypt" ]; then
    install_certbot || die "Не удалось подготовить Certbot"
    open_acme_firewall
    renewal_file="/etc/letsencrypt/renewal/$PANEL_HOST.conf"
    if [ -r "$renewal_file" ] && grep -q '^authenticator = standalone$' "$renewal_file"; then
      if systemctl is-active --quiet nginx; then
        nginx_was_active=1
        systemctl stop nginx >>"$LOG_FILE" 2>&1 || die "Не удалось временно остановить Nginx для продления сертификата"
      fi
    fi
    if "$INSTALL_DIR/certbot/bin/certbot" renew --quiet --deploy-hook "systemctl reload nginx" >>"$LOG_FILE" 2>&1; then
      renewal_ok=1
    fi
    if [ "$nginx_was_active" = "1" ]; then
      systemctl start nginx >>"$LOG_FILE" 2>&1 || die "Не удалось вернуть Nginx после продления сертификата"
    fi
    [ "$renewal_ok" = "1" ] || die "Не удалось проверить или обновить сертификат Let's Encrypt"
    log "Проверка сертификата Let's Encrypt завершена"
    return 0
  fi

  if try_upgrade_certificate; then
    update_panel_config_metadata
    write_final_nginx
    log "Self-signed сертификат заменен публичным сертификатом Let's Encrypt"
    return 0
  fi

  if [ -r "$CERTIFICATE_PATH" ] && openssl x509 -checkend 2592000 -noout -in "$CERTIFICATE_PATH" >/dev/null 2>&1; then
    log "Self-signed сертификат действителен более 30 дней; замена не требуется"
    return 0
  fi

  create_self_signed_certificate
  update_panel_config_metadata
  write_final_nginx
  log "Self-signed сертификат автоматически обновлен"
}

open_firewall() {
  [ "${HTTP_ENABLED:-0}" = "1" ] && open_acme_firewall
  if command_exists ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow "$PANEL_HTTPS_PORT/tcp" comment 'WDTT Panel HTTPS' >/dev/null || true
  elif command_exists firewall-cmd && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port="$PANEL_HTTPS_PORT/tcp" >/dev/null || true
    firewall-cmd --reload >/dev/null || true
  elif command_exists iptables; then
    iptables -C INPUT -p tcp --dport "$PANEL_HTTPS_PORT" -m comment --comment WDTT_PANEL -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p tcp --dport "$PANEL_HTTPS_PORT" -m comment --comment WDTT_PANEL -j ACCEPT || true
  fi
}

write_wdtt_extensions_timer() {
  cat > "/etc/systemd/system/$WDTT_EXTENSIONS_SERVICE" <<EOF
[Unit]
Description=Install WDTT Panel traffic and label extensions
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
TimeoutStartSec=20min
Restart=on-failure
RestartSec=10min
ExecStart=/bin/bash $INSTALL_DIR/install.sh enable-wdtt-extensions
EOF
  cat > "/etc/systemd/system/$WDTT_EXTENSIONS_TIMER" <<EOF
[Unit]
Description=Retry WDTT Panel traffic and label extensions

[Timer]
OnBootSec=20s
OnUnitActiveSec=10min
OnUnitInactiveSec=10min
RandomizedDelaySec=30s
Persistent=true
Unit=$WDTT_EXTENSIONS_SERVICE

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$WDTT_EXTENSIONS_TIMER" >>"$LOG_FILE" 2>&1
}

change_panel_password() {
  require_root
  load_panel_config
  [ -n "$PANEL_PASSWORD" ] || die "Укажите новый пароль через меню или PANEL_PASSWORD"
  [ "${#PANEL_PASSWORD}" -ge 12 ] || die "PANEL_PASSWORD должен содержать не менее 12 символов"

  PASSWORD_HASH="$(PYTHONPATH="$INSTALL_DIR" python3 -c 'import sys; from wdtt_panel.security import hash_password; print(hash_password(sys.argv[1]))' "$PANEL_PASSWORD")"
  SESSION_SECRET="$(random_token 48)"
  python3 - "$CONFIG_FILE" "$PASSWORD_HASH" "$SESSION_SECRET" <<'PY'
import json, os, sys
path, password_hash, session_secret = sys.argv[1:]
data = json.load(open(path, encoding="utf-8"))
data["password_hash"] = password_hash
data["session_secret"] = session_secret
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(data, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
os.chmod(tmp, 0o640)
os.replace(tmp, path)
PY
  chown root:wdtt-panel "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
  systemctl restart "$PANEL_SERVICE" >>"$LOG_FILE" 2>&1 || die "Не удалось перезапустить панель после смены пароля"
  log "Пароль входа в панель изменен; все активные сессии завершены"
}

status_panel() {
  local attempt
  systemctl --no-pager --full status "$PANEL_SERVICE" || true
  [ -r "$CONFIG_FILE" ] && python3 - "$CONFIG_FILE" <<'PY'
import json, sys
d=json.load(open(sys.argv[1], encoding="utf-8"))
print(f"Version: {d.get('version', 'unknown')}")
print(f"URL: https://{d['public_host']}:{d['https_port']}{d['base_path']}")
print(f"TLS: {d.get('tls_mode', 'unknown')}")
PY
  if [ -n "${PANEL_HTTPS_PORT:-}" ]; then
    for ((attempt = 1; attempt <= 10; attempt++)); do
      if curl --noproxy '*' -kfsS --connect-timeout 2 --max-time 5 "https://127.0.0.1:$PANEL_HTTPS_PORT$PANEL_PATH" >/dev/null 2>&1; then
        echo "HTTPS local check: OK"
        break
      fi
      sleep 0.5
    done
    if [ "$attempt" -gt 10 ]; then
      echo "HTTPS local check: FAILED (проверьте nginx и journalctl -u nginx)"
    fi
  else
    echo "HTTPS local check: FAILED (не найден HTTPS-порт панели)"
  fi
  [ "${TLS_MODE:-}" != "self-signed" ] || echo "Browser trust: self-signed требует ручного доверия; шифрование при этом работает"
}

remove_firewall_rule() {
  local port="$1"
  [ -n "$port" ] || return 0
  if command_exists ufw; then
    ufw --force delete allow "$port/tcp" >/dev/null 2>&1 || true
  fi
  if command_exists firewall-cmd && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --remove-port="$port/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
  if command_exists iptables; then
    while iptables -C INPUT -p tcp --dport "$port" -m comment --comment WDTT_PANEL -j ACCEPT 2>/dev/null; do
      iptables -D INPUT -p tcp --dport "$port" -m comment --comment WDTT_PANEL -j ACCEPT || break
    done
  fi
}

uninstall_panel() {
  local panel_port=""
  if [ -r "$CONFIG_FILE" ]; then
    panel_port="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("https_port", ""))' "$CONFIG_FILE" 2>/dev/null || true)"
  fi
  log "Удаление только web-панели; WDTT не затрагивается"
  systemctl disable --now "$PANEL_SERVICE" wdtt-fleet-agent.service wdtt-panel-cert-renew.timer wdtt-panel-cert-renew.service "$WDTT_EXTENSIONS_TIMER" "$WDTT_EXTENSIONS_SERVICE" wdtt-panel-backup.timer wdtt-panel-backup.service 2>/dev/null || true
  rm -f "/etc/systemd/system/$PANEL_SERVICE" /etc/systemd/system/wdtt-fleet-agent.service /etc/systemd/system/wdtt-panel-cert-renew.service /etc/systemd/system/wdtt-panel-cert-renew.timer "/etc/systemd/system/$WDTT_EXTENSIONS_SERVICE" "/etc/systemd/system/$WDTT_EXTENSIONS_TIMER" /etc/systemd/system/wdtt-panel-backup.service /etc/systemd/system/wdtt-panel-backup.timer "$STATE_DIR/fleet-agent.json"
  systemctl disable --now "$LEGACY_CASCADE_SERVICE" "$XRAY_SERVICE" "$XRAY_CASCADE_SERVICE" "$XRAY_GATEWAY_SERVICE" wdtt-panel-geofiles-update.timer wdtt-panel-geofiles-update.service 2>/dev/null || true
  rm -f "/etc/systemd/system/$LEGACY_CASCADE_SERVICE" "/etc/systemd/system/$XRAY_SERVICE" "/etc/systemd/system/$XRAY_CASCADE_SERVICE" "/etc/systemd/system/$XRAY_GATEWAY_SERVICE" /etc/systemd/system/wdtt-panel-geofiles-update.service /etc/systemd/system/wdtt-panel-geofiles-update.timer
  rm -f "$NGINX_FILE" "$ADMIN_WRAPPER" "$SUDOERS_FILE" "$MANAGER_WRAPPER" /usr/local/sbin/wddt-panel /usr/local/sbin/wdtt-pane "$UPDATE_WRAPPER" "$UNINSTALL_WRAPPER" "$STATUS_WRAPPER" "$GEOFILES_UPDATE_WRAPPER" "$BACKUP_RUNNER" "$CASCADE_RULES_WRAPPER" "$GATEWAY_RULES_WRAPPER"
  rm -rf "$INSTALL_DIR" "$CONFIG_DIR"
  remove_firewall_rule "$panel_port"
  systemctl daemon-reload
  nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
  log "Панель удалена. Аудит оставлен в $STATE_DIR, резервные копии в $PRIVATE_STATE_DIR"
}

update_panel() {
  require_root
  load_panel_config
  log "Обновление панели до версии $PANEL_VERSION"
  remove_obsolete_fleet_agent
  backup_wdtt_database_before_update
  install_panel_files
  write_maintenance_scripts
  update_panel_config_metadata
  write_panel_service
  write_final_nginx
  write_renew_timer
  write_wdtt_extensions_timer
  write_xray_services
  schedule_wdtt_extensions
  systemctl restart "$PANEL_SERVICE"
  log "Панель обновлена; адрес, пароль, сертификаты и данные сохранены"
  status_panel
}

install_panel() {
  require_root
  detect_os
  install_packages
  if [ "$NGINX_WAS_INSTALLED" = "0" ] && ! port_80_available_for_nginx; then
    rm -f /etc/nginx/sites-enabled/default
  fi
  validate_inputs
  validate_port_availability
  discover_host
  prepare_secrets
  install_clean_wdtt
  install_panel_files
  remove_obsolete_fleet_agent
  install_wdtt_extensions
  write_maintenance_scripts

  if request_certificate; then
    log "Получен публично доверенный сертификат Let's Encrypt"
  else
    log "Let's Encrypt недоступен, создается автоматический self-signed сертификат"
    create_self_signed_certificate
  fi

  write_panel_config
  write_panel_service
  write_final_nginx
  write_renew_timer
  write_wdtt_extensions_timer
  write_xray_services
  open_firewall
  systemctl restart "$PANEL_SERVICE"

  printf '\n'
  log "Установка завершена"
  printf 'URL: https://%s:%s%s\n' "$PANEL_HOST" "$PANEL_HTTPS_PORT" "$PANEL_PATH"
  printf 'Login: %s\n' "$PANEL_USER"
  printf 'Password: %s\n' "$PANEL_PASSWORD"
  printf 'TLS: %s\n' "$TLS_MODE"
  if [ -n "$WDTT_MAIN_PASSWORD" ]; then printf 'WDTT main password: %s\n' "$WDTT_MAIN_PASSWORD"; fi
  printf 'Install log: %s\n' "$LOG_FILE"
}

case "${1:-install}" in
  install|--install|-i) install_panel ;;
  update|--update) update_panel ;;
  renew-cert|--renew-cert) renew_certificates ;;
  status|--status|-s) require_root; load_panel_config; status_panel ;;
  change-password|--change-password) change_panel_password ;;
  uninstall|--uninstall|-u) require_root; uninstall_panel ;;
  install-xray-runtime) install_xray_runtime ;;
  install-warp-runtime) install_warp_runtime ;;
  enable-wdtt-extensions) install_wdtt_extensions ;;
  *) die "Использование: $0 [install|update|renew-cert|status|change-password|uninstall|install-xray-runtime|install-warp-runtime|enable-wdtt-extensions]" ;;
esac
