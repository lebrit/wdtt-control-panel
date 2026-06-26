#!/usr/bin/env bash
set -Eeuo pipefail

RUSTDESK_DIR="${RUSTDESK_DIR:-/opt/rustdesk}"
RUSTDESK_DATA_DIR="${RUSTDESK_DATA_DIR:-$RUSTDESK_DIR/data}"
RUSTDESK_PUBLIC_IP="${RUSTDESK_PUBLIC_IP:-77.91.90.239}"
RUSTDESK_PUBLIC_KEY="${RUSTDESK_PUBLIC_KEY:-ih54eZYWbBxcq9kvS8kUJ4oBMOUtdRHM5HZM4WXKqyA=}"
RUSTDESK_IMAGE_TAG="${RUSTDESK_IMAGE_TAG:-latest}"
RUSTDESK_PRIVATE_KEY_FILE="${RUSTDESK_PRIVATE_KEY_FILE:-}"
RUSTDESK_REQUIRE_PRIVATE_KEY="${RUSTDESK_REQUIRE_PRIVATE_KEY:-${RUSTDESK_STRICT_EXISTING_KEY:-0}}"
RUSTDESK_OPEN_WEB_CLIENT_PORTS="${RUSTDESK_OPEN_WEB_CLIENT_PORTS:-1}"
RUSTDESK_INSTALL_REPOSITORY="${RUSTDESK_INSTALL_REPOSITORY:-lebrit/wdtt-control-panel}"
RUSTDESK_INSTALL_BRANCH="${RUSTDESK_INSTALL_BRANCH:-main}"
RUSTDESK_INSTALL_URL="${RUSTDESK_INSTALL_URL:-https://raw.githubusercontent.com/${RUSTDESK_INSTALL_REPOSITORY}/${RUSTDESK_INSTALL_BRANCH}/install-rustdesk-server.sh}"
RUSTDESK_MANAGER="${RUSTDESK_MANAGER:-/usr/local/sbin/rustdesk-server}"
COMPOSE_FILE="$RUSTDESK_DIR/compose.yml"

log() { printf '[rustdesk-install] %s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "Запустите от root: sudo bash install-rustdesk-server.sh"
}

detect_os() {
  [ -r /etc/os-release ] || die "Не найден /etc/os-release"
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_LIKE="${ID_LIKE:-}"
  log "ОС: ${PRETTY_NAME:-$OS_ID}"
}

install_docker_debian() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl gnupg lsb-release
  if ! command_exists docker; then
    apt-get install -y docker.io
  fi
  if ! compose_available; then
    apt-get install -y docker-compose-plugin >/dev/null 2>&1 || \
      apt-get install -y docker-compose-v2 >/dev/null 2>&1 || \
      apt-get install -y docker-compose >/dev/null 2>&1 || true
  fi
}

install_docker_rhel() {
  local installer="dnf"
  command_exists dnf || installer="yum"
  if ! command_exists docker; then
    "$installer" install -y docker docker-compose-plugin >/dev/null 2>&1 || \
      "$installer" install -y moby-engine docker-compose-plugin >/dev/null 2>&1 || \
      "$installer" install -y docker >/dev/null 2>&1 || true
  fi
  if ! compose_available; then
    "$installer" install -y docker-compose-plugin >/dev/null 2>&1 || \
      "$installer" install -y docker-compose >/dev/null 2>&1 || true
  fi
}

install_docker_arch() {
  pacman -Sy --noconfirm docker docker-compose
}

compose_available() {
  docker compose version >/dev/null 2>&1 || command_exists docker-compose
}

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    docker compose -f "$COMPOSE_FILE" "$@"
  elif command_exists docker-compose; then
    docker-compose -f "$COMPOSE_FILE" "$@"
  else
    die "Docker Compose не установлен"
  fi
}

install_docker() {
  if command_exists docker && compose_available; then
    log "Docker и Compose уже установлены"
  else
    case "$OS_ID $OS_LIKE" in
      *debian*|*ubuntu*) install_docker_debian ;;
      *rhel*|*fedora*|*centos*) install_docker_rhel ;;
      *arch*) install_docker_arch ;;
      *) die "Не знаю, как автоматически установить Docker на эту ОС. Установите Docker и Docker Compose вручную, затем запустите скрипт снова." ;;
    esac
  fi

  command_exists docker || die "Docker не установлен"
  compose_available || die "Docker Compose не установлен"

  if command_exists systemctl; then
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
}

validate_public_key() {
  if ! printf '%s' "$RUSTDESK_PUBLIC_KEY" | grep -Eq '^[A-Za-z0-9+/]{43}=$'; then
    die "RUSTDESK_PUBLIC_KEY должен быть base64-публичным ключом RustDesk длиной 44 символа"
  fi
}

import_private_key() {
  mkdir -p "$RUSTDESK_DATA_DIR"
  chmod 700 "$RUSTDESK_DATA_DIR"

  if [ -n "${RUSTDESK_PRIVATE_KEY:-}" ]; then
    log "Импортирую приватный ключ из RUSTDESK_PRIVATE_KEY"
    umask 077
    printf '%s\n' "$RUSTDESK_PRIVATE_KEY" > "$RUSTDESK_DATA_DIR/id_ed25519"
  elif [ -n "$RUSTDESK_PRIVATE_KEY_FILE" ]; then
    [ -r "$RUSTDESK_PRIVATE_KEY_FILE" ] || die "Не могу прочитать RUSTDESK_PRIVATE_KEY_FILE=$RUSTDESK_PRIVATE_KEY_FILE"
    log "Импортирую приватный ключ из $RUSTDESK_PRIVATE_KEY_FILE"
    install -m 600 "$RUSTDESK_PRIVATE_KEY_FILE" "$RUSTDESK_DATA_DIR/id_ed25519"
  elif [ -r "$PWD/id_ed25519" ] && [ ! -r "$RUSTDESK_DATA_DIR/id_ed25519" ]; then
    log "Импортирую приватный ключ из $PWD/id_ed25519"
    install -m 600 "$PWD/id_ed25519" "$RUSTDESK_DATA_DIR/id_ed25519"
  fi

  if [ -r "$PWD/id_ed25519.pub" ] && [ ! -r "$RUSTDESK_DATA_DIR/id_ed25519.pub" ]; then
    install -m 644 "$PWD/id_ed25519.pub" "$RUSTDESK_DATA_DIR/id_ed25519.pub"
  fi

  printf '%s\n' "$RUSTDESK_PUBLIC_KEY" > "$RUSTDESK_DATA_DIR/expected_id_ed25519.pub"
  chmod 600 "$RUSTDESK_DATA_DIR/id_ed25519" 2>/dev/null || true
}

derive_public_key_from_private() {
  local private_key="$1"
  if command_exists python3; then
    python3 - "$private_key" <<'PY'
import base64
import sys

try:
    secret = base64.b64decode(sys.argv[1], validate=True)
except Exception:
    print("invalid-base64", file=sys.stderr)
    sys.exit(1)

if len(secret) != 64:
    print(f"invalid-secret-length:{len(secret)}", file=sys.stderr)
    sys.exit(1)

print(base64.b64encode(secret[32:]).decode("ascii"))
PY
    return
  fi

  command_exists base64 || die "Нужен python3 или base64 для проверки приватного ключа"
  local tmp size
  tmp="$(mktemp)"
  if ! printf '%s' "$private_key" | base64 -d > "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    die "Приватный ключ id_ed25519 не является корректным base64"
  fi
  size="$(wc -c < "$tmp" | tr -d ' ')"
  if [ "$size" != "64" ]; then
    rm -f "$tmp"
    die "Приватный ключ id_ed25519 должен декодироваться в 64 байта, сейчас: $size"
  fi
  tail -c 32 "$tmp" | base64 | tr -d '\r\n'
  rm -f "$tmp"
}

validate_imported_keypair() {
  [ -r "$RUSTDESK_DATA_DIR/id_ed25519" ] || return

  local private_key derived_key
  private_key="$(tr -d '\r\n' < "$RUSTDESK_DATA_DIR/id_ed25519")"
  derived_key="$(derive_public_key_from_private "$private_key")"

  if [ "$derived_key" != "$RUSTDESK_PUBLIC_KEY" ]; then
    cat >&2 <<EOF
[rustdesk-install] Приватный id_ed25519 не соответствует указанному публичному ключу.
[rustdesk-install] Ожидался: $RUSTDESK_PUBLIC_KEY
[rustdesk-install] Из приватного получился: $derived_key
EOF
    exit 1
  fi

  printf '%s\n' "$derived_key" > "$RUSTDESK_DATA_DIR/id_ed25519.pub"
  chmod 644 "$RUSTDESK_DATA_DIR/id_ed25519.pub"
  log "Пара ключей проверена"
}

prepare_server_key_mode() {
  if [ -r "$RUSTDESK_DATA_DIR/id_ed25519" ]; then
    return
  fi

  printf '%s\n' "$RUSTDESK_PUBLIC_KEY" > "$RUSTDESK_DATA_DIR/id_ed25519.pub"
  chmod 644 "$RUSTDESK_DATA_DIR/id_ed25519.pub"

  if [ "$RUSTDESK_REQUIRE_PRIVATE_KEY" = "1" ]; then
    cat >&2 <<EOF
[rustdesk-install] Указанный ключ похож на публичный ключ клиента:
[rustdesk-install]   $RUSTDESK_PUBLIC_KEY
[rustdesk-install]
[rustdesk-install] Чтобы сервер работал именно с этим ключом, нужен соответствующий приватный файл id_ed25519.
[rustdesk-install] Положите id_ed25519 рядом со скриптом или запустите так:
[rustdesk-install]   sudo RUSTDESK_PRIVATE_KEY_FILE=/root/id_ed25519 bash install-rustdesk-server.sh
[rustdesk-install]
[rustdesk-install] Если нужно поднять сервер по ключу из установщика без приватного id_ed25519, запустите:
[rustdesk-install]   sudo RUSTDESK_REQUIRE_PRIVATE_KEY=0 bash install-rustdesk-server.sh
EOF
    exit 1
  fi

  log "Приватный id_ed25519 не найден. Запускаю RustDesk с shared Key из установщика: $RUSTDESK_PUBLIC_KEY"
}

write_compose() {
  mkdir -p "$RUSTDESK_DIR" "$RUSTDESK_DATA_DIR"
  local key_arg="$RUSTDESK_PUBLIC_KEY"
  if [ -r "$RUSTDESK_DATA_DIR/id_ed25519" ]; then
    key_arg="_"
  fi
  cat > "$COMPOSE_FILE" <<EOF
services:
  hbbs:
    container_name: rustdesk-hbbs
    image: rustdesk/rustdesk-server:${RUSTDESK_IMAGE_TAG}
    command:
      - hbbs
      - -r
      - ${RUSTDESK_PUBLIC_IP}:21117
      - -k
      - "${key_arg}"
    volumes:
      - ./data:/root
    network_mode: "host"
    depends_on:
      - hbbr
    restart: unless-stopped

  hbbr:
    container_name: rustdesk-hbbr
    image: rustdesk/rustdesk-server:${RUSTDESK_IMAGE_TAG}
    command:
      - hbbr
      - -k
      - "${key_arg}"
    volumes:
      - ./data:/root
    network_mode: "host"
    restart: unless-stopped
EOF
}

open_firewall() {
  local tcp_ports=(21115 21116 21117)
  local udp_ports=(21116)
  if [ "$RUSTDESK_OPEN_WEB_CLIENT_PORTS" = "1" ]; then
    tcp_ports+=(21118 21119)
  fi

  if command_exists ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
    log "Открываю порты в UFW"
    local port
    for port in "${tcp_ports[@]}"; do ufw allow "$port/tcp" comment 'RustDesk Server' >/dev/null || true; done
    for port in "${udp_ports[@]}"; do ufw allow "$port/udp" comment 'RustDesk Server' >/dev/null || true; done
  elif command_exists firewall-cmd && systemctl is-active --quiet firewalld 2>/dev/null; then
    log "Открываю порты в firewalld"
    local port
    for port in "${tcp_ports[@]}"; do firewall-cmd --permanent --add-port="$port/tcp" >/dev/null || true; done
    for port in "${udp_ports[@]}"; do firewall-cmd --permanent --add-port="$port/udp" >/dev/null || true; done
    firewall-cmd --reload >/dev/null || true
  else
    log "Активный UFW/firewalld не найден. Если внешний firewall включен у провайдера, откройте TCP 21115-21119 и UDP 21116."
  fi
}

install_manager_command() {
  mkdir -p "$(dirname "$RUSTDESK_MANAGER")"

  local tmp
  tmp="$(mktemp)"
  if command_exists curl && curl -fsSL --retry 3 "$RUSTDESK_INSTALL_URL" -o "$tmp"; then
    install -m 755 "$tmp" "$RUSTDESK_MANAGER"
    rm -f "$tmp"
    log "Команда управления установлена: $RUSTDESK_MANAGER"
    return
  fi
  rm -f "$tmp"

  if [ -n "${BASH_SOURCE[0]:-}" ] && [ -r "${BASH_SOURCE[0]}" ]; then
    install -m 755 "${BASH_SOURCE[0]}" "$RUSTDESK_MANAGER"
    log "Команда управления установлена из локального файла: $RUSTDESK_MANAGER"
    return
  fi

  log "Не удалось сохранить команду управления. Для управления можно повторно запускать GitHub-установщик с аргументами status/logs/restart/uninstall."
}

warn_port_conflicts() {
  command_exists ss || return
  local conflicts
  conflicts="$(ss -H -lntu 2>/dev/null | awk '{print $5}' | grep -E ':(21115|21116|21117|21118|21119)$' || true)"
  if [ -n "$conflicts" ]; then
    log "Внимание: некоторые RustDesk-порты уже слушаются:"
    printf '%s\n' "$conflicts"
  fi
}

start_server() {
  log "Скачиваю образ rustdesk/rustdesk-server:${RUSTDESK_IMAGE_TAG}"
  compose_cmd pull
  log "Запускаю hbbs и hbbr"
  compose_cmd up -d
}

verify_public_key() {
  local generated_key=""
  for _ in $(seq 1 20); do
    if [ -s "$RUSTDESK_DATA_DIR/id_ed25519.pub" ]; then
      generated_key="$(tr -d '\r\n' < "$RUSTDESK_DATA_DIR/id_ed25519.pub")"
      break
    fi
    sleep 1
  done

  [ -n "$generated_key" ] || die "Сервер запустился, но $RUSTDESK_DATA_DIR/id_ed25519.pub не появился"

  if [ -n "$RUSTDESK_PUBLIC_KEY" ] && [ "$generated_key" != "$RUSTDESK_PUBLIC_KEY" ]; then
    cat >&2 <<EOF
[rustdesk-install] Серверный публичный ключ не совпал с указанным.
[rustdesk-install] Ожидался: $RUSTDESK_PUBLIC_KEY
[rustdesk-install] Получился: $generated_key
[rustdesk-install]
[rustdesk-install] Для сохранения старого ключа нужен соответствующий приватный id_ed25519.
EOF
    if [ "$RUSTDESK_REQUIRE_PRIVATE_KEY" = "1" ]; then
      compose_cmd down
      exit 1
    fi
  fi

  log "Публичный ключ сервера: $generated_key"
}

print_summary() {
  cat <<EOF

RustDesk Server установлен.

Настройки клиента RustDesk:
  ID Server:    ${RUSTDESK_PUBLIC_IP}
  Relay Server: ${RUSTDESK_PUBLIC_IP}:21117
  Key:          $(tr -d '\r\n' < "$RUSTDESK_DATA_DIR/id_ed25519.pub")

Файлы:
  compose: $COMPOSE_FILE
  data:    $RUSTDESK_DATA_DIR

Команды:
  статус:  sudo rustdesk-server status
  логи:    sudo rustdesk-server logs
  рестарт: sudo rustdesk-server restart

GitHub-запуск:
  curl -fsSL $RUSTDESK_INSTALL_URL | sudo bash
EOF
}

install_server() {
  require_root
  detect_os
  validate_public_key
  install_docker
  import_private_key
  validate_imported_keypair
  prepare_server_key_mode
  write_compose
  warn_port_conflicts
  open_firewall
  install_manager_command
  start_server
  verify_public_key
  print_summary
}

status_server() {
  require_root
  [ -r "$COMPOSE_FILE" ] || die "Не найден $COMPOSE_FILE"
  compose_cmd ps
}

logs_server() {
  require_root
  [ -r "$COMPOSE_FILE" ] || die "Не найден $COMPOSE_FILE"
  compose_cmd logs --tail=200 -f
}

restart_server() {
  require_root
  [ -r "$COMPOSE_FILE" ] || die "Не найден $COMPOSE_FILE"
  compose_cmd restart
}

uninstall_server() {
  require_root
  [ -r "$COMPOSE_FILE" ] || die "Не найден $COMPOSE_FILE"
  compose_cmd down
  log "Контейнеры остановлены. Данные ключей оставлены в $RUSTDESK_DATA_DIR"
}

case "${1:-install}" in
  install) install_server ;;
  status) status_server ;;
  logs) logs_server ;;
  restart) restart_server ;;
  uninstall) uninstall_server ;;
  *)
    cat <<EOF
Использование:
  sudo bash install-rustdesk-server.sh [install|status|logs|restart|uninstall]
  curl -fsSL $RUSTDESK_INSTALL_URL | sudo bash -s -- [install|status|logs|restart|uninstall]

Переменные:
  RUSTDESK_PUBLIC_IP=$RUSTDESK_PUBLIC_IP
  RUSTDESK_PUBLIC_KEY=$RUSTDESK_PUBLIC_KEY
  RUSTDESK_PRIVATE_KEY_FILE=/root/id_ed25519
  RUSTDESK_REQUIRE_PRIVATE_KEY=$RUSTDESK_REQUIRE_PRIVATE_KEY
  RUSTDESK_INSTALL_URL=$RUSTDESK_INSTALL_URL
EOF
    exit 2
    ;;
esac
