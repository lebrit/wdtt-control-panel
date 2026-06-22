#!/usr/bin/env bash
set -Eeuo pipefail

PANEL_VERSION="0.5.2"
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
MANAGER_WRAPPER="/usr/local/sbin/wdtt-panel"
MANAGER_ALIAS_ONE="/usr/local/sbin/wddt-panel"
MANAGER_ALIAS_TWO="/usr/local/sbin/wdtt-pane"
CASCADE_SERVICE="wdtt-cascade.service"
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
  curl -fsSL "https://go.dev/dl/${GO_TARBALL}.sha256" -o "$BUILD_DIR/$GO_TARBALL.sha256"
  printf '%s  %s\n' "$(tr -d '[:space:]' < "$BUILD_DIR/$GO_TARBALL.sha256")" "$BUILD_DIR/$GO_TARBALL" | sha256sum -c - >>"$LOG_FILE"
  tar -xzf "$BUILD_DIR/$GO_TARBALL" -C "$BUILD_DIR"

  curl -fsSL "https://github.com/amurcanov/proxy-turn-vk-android/archive/refs/heads/${WDTT_REF}.zip" -o "$BUILD_DIR/wdtt.zip"
  unzip -q "$BUILD_DIR/wdtt.zip" -d "$BUILD_DIR/source"
  WDTT_SOURCE="$(find "$BUILD_DIR/source" -mindepth 1 -maxdepth 1 -type d | head -1)"
  [ -f "$WDTT_SOURCE/server.go" ] || die "В архиве WDTT не найден server.go"
  (
    cd "$WDTT_SOURCE"
    PATH="$BUILD_DIR/go/bin:$PATH" CGO_ENABLED=0 "$BUILD_DIR/go/bin/go" build -trimpath -ldflags='-s -w' -o /tmp/wdtt-server ./server.go
  ) >>"$LOG_FILE" 2>&1
  chmod 0755 /tmp/wdtt-server
  WDTT_ARGS="-password $WDTT_MAIN_PASSWORD" bash "$WDTT_SOURCE/app/src/main/assets/deploy.sh" install >>"$LOG_FILE" 2>&1
  log "WDTT установлен официальным deploy.sh"
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
  ln -sfn "$INSTALL_DIR/bootstrap.sh" "$MANAGER_WRAPPER"
  ln -sfn "$INSTALL_DIR/bootstrap.sh" "$MANAGER_ALIAS_ONE"
  ln -sfn "$INSTALL_DIR/bootstrap.sh" "$MANAGER_ALIAS_TWO"
  ln -sfn "$INSTALL_DIR/update.sh" "$UPDATE_WRAPPER"
  ln -sfn "$INSTALL_DIR/uninstall.sh" "$UNINSTALL_WRAPPER"
  cat > "$STATUS_WRAPPER" <<EOF
#!/bin/sh
exec /bin/bash $INSTALL_DIR/install.sh status
EOF
  chmod 0755 "$STATUS_WRAPPER"
  cat > "$GEOFILES_UPDATE_WRAPPER" <<EOF
#!/bin/sh
printf '%s\n' '{"action":"geofiles.refresh_auto","payload":{}}' | $ADMIN_WRAPPER
EOF
  chmod 0755 "$GEOFILES_UPDATE_WRAPPER"
}

write_cascade_services() {
  cat > "/etc/systemd/system/$CASCADE_SERVICE" <<EOF
[Unit]
Description=WDTT Cascade Routing (sing-box)
After=network-online.target wdtt.service
Wants=network-online.target wdtt.service
ConditionPathExists=$PRIVATE_STATE_DIR/sing-box.json

[Service]
Type=simple
User=root
ExecStartPre=/usr/local/bin/sing-box check -c $PRIVATE_STATE_DIR/sing-box.json
ExecStart=/usr/local/bin/sing-box run -c $PRIVATE_STATE_DIR/sing-box.json
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

  cat > /etc/systemd/system/wdtt-panel-geofiles-update.service <<EOF
[Unit]
Description=Update WDTT Panel GeoFiles
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$GEOFILES_UPDATE_WRAPPER
EOF
  cat > /etc/systemd/system/wdtt-panel-geofiles-update.timer <<'EOF'
[Unit]
Description=Automatic WDTT Panel GeoFiles updates

[Timer]
OnBootSec=20min
OnUnitActiveSec=1h
RandomizedDelaySec=15min
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

install_cascade_runtime() {
  require_root
  local machine runtime_arch work sing_url wgcf_url go_arch go_tarball
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64) runtime_arch="amd64"; go_arch="amd64" ;;
    aarch64|arm64) runtime_arch="arm64"; go_arch="arm64" ;;
    *) die "Компоненты каскада поддержаны для amd64 и arm64" ;;
  esac
  work="$(mktemp -d)"
  trap 'rm -rf "${work:-}"' RETURN

  log "Установка sing-box для каскадной маршрутизации"
  sing_url="$(github_asset_url SagerNet/sing-box "linux-${runtime_arch}\\.tar\\.gz$")" || die "Не найден релиз sing-box"
  curl -fsSL --retry 3 "$sing_url" -o "$work/sing-box.tar.gz"
  tar -xzf "$work/sing-box.tar.gz" -C "$work"
  install -m 0755 "$(find "$work" -type f -name sing-box | head -1)" /usr/local/bin/sing-box

  log "Установка генератора профиля Cloudflare WARP"
  wgcf_url="$(github_asset_url ViRb3/wgcf "linux_${runtime_arch}$")" || die "Не найден релиз wgcf"
  curl -fsSL --retry 3 "$wgcf_url" -o /usr/local/bin/wgcf
  chmod 0755 /usr/local/bin/wgcf

  if ! command_exists geodat2srs; then
    log "Сборка конвертера GeoFiles (.dat -> .srs)"
    if command_exists go; then
      GOBIN=/usr/local/bin go install github.com/runetfreedom/geodat2srs@latest >>"$LOG_FILE" 2>&1
    else
      go_tarball="go${GO_VERSION}.linux-${go_arch}.tar.gz"
      curl -fsSL "https://go.dev/dl/$go_tarball" -o "$work/$go_tarball"
      tar -xzf "$work/$go_tarball" -C "$work"
      GOBIN=/usr/local/bin "$work/go/bin/go" install github.com/runetfreedom/geodat2srs@latest >>"$LOG_FILE" 2>&1
    fi
  fi
  write_cascade_services
  if [ -r "$PRIVATE_STATE_DIR/cascade.json" ] && python3 -c 'import json,sys; raise SystemExit(0 if json.load(open(sys.argv[1])).get("enabled") else 1)' "$PRIVATE_STATE_DIR/cascade.json"; then
    systemctl enable --now "$CASCADE_SERVICE"
  fi
  log "Компоненты каскада установлены"
  /usr/local/bin/sing-box version | head -1
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
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$PANEL_SERVICE" >>"$LOG_FILE" 2>&1
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
  install_certbot || return 1
  CERTBOT=("$INSTALL_DIR/certbot/bin/certbot" certonly --non-interactive --agree-tos --webroot --webroot-path "$STATE_DIR/acme")
  if [ -n "$PANEL_EMAIL" ]; then CERTBOT+=(--email "$PANEL_EMAIL"); else CERTBOT+=(--register-unsafely-without-email); fi
  if [[ "$PANEL_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    CERTBOT+=(--preferred-profile shortlived --ip-address "$PANEL_HOST" --cert-name "$PANEL_HOST")
  else
    CERTBOT+=(-d "$PANEL_HOST")
  fi
  if "${CERTBOT[@]}" >>"$LOG_FILE" 2>&1; then
    CERTIFICATE_PATH="/etc/letsencrypt/live/$PANEL_HOST/fullchain.pem"
    PRIVATE_KEY_PATH="/etc/letsencrypt/live/$PANEL_HOST/privkey.pem"
    [ -f "$CERTIFICATE_PATH" ] && [ -f "$PRIVATE_KEY_PATH" ] || return 1
    TLS_MODE="letsencrypt"
    return 0
  fi
  return 1
}

try_upgrade_certificate() {
  port_80_available_for_nginx || return 1
  [ -r "$NGINX_FILE" ] || return 1
  grep -q '/.well-known/acme-challenge/' "$NGINX_FILE" || return 1
  open_acme_firewall
  run_certbot_request
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
  HTTP_ENABLED=0
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
    add_header Strict-Transport-Security "max-age=31536000" always;

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
  require_root
  load_panel_config

  if [ "$TLS_MODE" = "letsencrypt" ]; then
    install_certbot || die "Не удалось подготовить Certbot"
    open_acme_firewall
    "$INSTALL_DIR/certbot/bin/certbot" renew --quiet --deploy-hook "systemctl reload nginx" >>"$LOG_FILE" 2>&1 || \
      die "Не удалось проверить или обновить сертификат Let's Encrypt"
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
  systemctl --no-pager --full status "$PANEL_SERVICE" || true
  [ -r "$CONFIG_FILE" ] && python3 - "$CONFIG_FILE" <<'PY'
import json, sys
d=json.load(open(sys.argv[1], encoding="utf-8"))
print(f"Version: {d.get('version', 'unknown')}")
print(f"URL: https://{d['public_host']}:{d['https_port']}{d['base_path']}")
print(f"TLS: {d.get('tls_mode', 'unknown')}")
PY
  if [ -n "${PANEL_HTTPS_PORT:-}" ] && curl --noproxy '*' -kfsS --connect-timeout 2 --max-time 5 "https://127.0.0.1:$PANEL_HTTPS_PORT$PANEL_PATH" >/dev/null 2>&1; then
    echo "HTTPS local check: OK"
  else
    echo "HTTPS local check: FAILED (проверьте nginx и journalctl -u nginx)"
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
  systemctl disable --now "$PANEL_SERVICE" wdtt-panel-cert-renew.timer wdtt-panel-cert-renew.service 2>/dev/null || true
  rm -f "/etc/systemd/system/$PANEL_SERVICE" /etc/systemd/system/wdtt-panel-cert-renew.service /etc/systemd/system/wdtt-panel-cert-renew.timer
  systemctl disable --now "$CASCADE_SERVICE" wdtt-panel-geofiles-update.timer wdtt-panel-geofiles-update.service 2>/dev/null || true
  rm -f "/etc/systemd/system/$CASCADE_SERVICE" /etc/systemd/system/wdtt-panel-geofiles-update.service /etc/systemd/system/wdtt-panel-geofiles-update.timer
  rm -f "$NGINX_FILE" "$ADMIN_WRAPPER" "$SUDOERS_FILE" "$MANAGER_WRAPPER" "$MANAGER_ALIAS_ONE" "$MANAGER_ALIAS_TWO" "$UPDATE_WRAPPER" "$UNINSTALL_WRAPPER" "$STATUS_WRAPPER" "$GEOFILES_UPDATE_WRAPPER"
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
  install_panel_files
  write_maintenance_scripts
  update_panel_config_metadata
  write_panel_service
  write_final_nginx
  write_renew_timer
  write_cascade_services
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
  write_cascade_services
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
  install-cascade-runtime) install_cascade_runtime ;;
  *) die "Использование: $0 [install|update|renew-cert|status|uninstall|install-cascade-runtime]" ;;
esac
