#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="${WDTT_PANEL_REPOSITORY:-lebrit/wdtt-control-panel}"
BRANCH="${WDTT_PANEL_BRANCH:-main}"
ARCHIVE_URL="https://github.com/${REPOSITORY}/archive/refs/heads/${BRANCH}.tar.gz"
WORK_DIR=""
ACTION=""
INTERACTIVE=0

usage() {
  cat <<EOF
Usage: bootstrap.sh [install|update|uninstall|status|renew-cert] [options]

Without arguments an interactive management menu is shown.

Install options:
  --domain NAME       Domain pointing to this server
  --ip ADDRESS        Public IPv4 address (empty = auto-detect)
  --user NAME         Panel administrator login (default: admin)
  --password VALUE    Panel administrator password (12+ characters)
  --email ADDRESS     Email for Let's Encrypt notifications
  --https-port PORT   Public HTTPS port (default: 8443)
  --path VALUE        Secret URL path (empty = generate)
  --wdtt MODE         WDTT mode: auto or no
  --wdtt-password PWD Main WDTT password for a clean server
  --non-interactive   Do not ask questions; generate missing values
EOF
}

choose_action() {
  if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
    INTERACTIVE=0
    ACTION="install"
    return 0
  fi
  cat >/dev/tty <<'EOF'

WDTT Control Panel
1) Установить панель
2) Обновить панель
3) Показать статус и адрес
4) Проверить/обновить сертификат
5) Удалить панель
0) Выход
EOF
  printf 'Выберите действие [1]: ' >/dev/tty
  IFS= read -r choice </dev/tty || true
  case "${choice:-1}" in
    1) ACTION="install" ;;
    2) ACTION="update" ;;
    3) ACTION="status" ;;
    4) ACTION="renew-cert" ;;
    5)
      printf 'Удалить web-панель? WDTT и его пользователи останутся [y/N]: ' >/dev/tty
      IFS= read -r confirm </dev/tty || true
      case "$confirm" in y|Y|yes|YES|да|Да|ДА) ACTION="uninstall" ;; *) echo 'Отменено.' >/dev/tty; ACTION="" ;; esac
      ;;
    0) ACTION="exit" ;;
    *) echo 'Неизвестный пункт меню.' >/dev/tty; ACTION="" ;;
  esac
}

prompt_value() {
  local prompt="$1" default_value="${2:-}" result
  if [ -n "$default_value" ]; then
    printf '%s [%s]: ' "$prompt" "$default_value" >/dev/tty
  else
    printf '%s: ' "$prompt" >/dev/tty
  fi
  IFS= read -r result </dev/tty || true
  printf '%s' "${result:-$default_value}"
}

prompt_install_options() {
  [ "${NON_INTERACTIVE:-0}" = "1" ] && return 0
  [ -r /dev/tty ] && [ -w /dev/tty ] || return 0

  if [ -z "${PANEL_HOST:-}" ]; then
    cat >/dev/tty <<'EOF'

Адрес панели:
1) Домен
2) Указать публичный IPv4
3) Определить публичный IPv4 автоматически
EOF
    printf 'Выберите вариант [3]: ' >/dev/tty
    IFS= read -r host_mode </dev/tty || true
    case "${host_mode:-3}" in
      1) PANEL_HOST="$(prompt_value 'Введите домен')" ;;
      2) PANEL_HOST="$(prompt_value 'Введите публичный IPv4')" ;;
      3) PANEL_HOST="" ;;
      *) echo 'Неизвестный вариант адреса.' >/dev/tty; exit 2 ;;
    esac
  fi
  if [ -z "${PANEL_EMAIL:-}" ]; then
    PANEL_EMAIL="$(prompt_value "Email для Let's Encrypt, необязательно")"
  fi
  PANEL_USER="${PANEL_USER:-$(prompt_value 'Логин администратора' 'admin')}"
  PANEL_HTTPS_PORT="${PANEL_HTTPS_PORT:-$(prompt_value 'HTTPS-порт панели' '8443')}"
  if [ -z "${PANEL_PATH:-}" ]; then
    PANEL_PATH="$(prompt_value 'Секретный URL-путь (16-80 символов), Enter = сгенерировать')"
  fi
  if [ -z "${PANEL_PASSWORD:-}" ]; then
    printf 'Пароль панели, минимум 12 символов (Enter = сгенерировать): ' >/dev/tty
    IFS= read -r -s PANEL_PASSWORD </dev/tty || true
    printf '\n' >/dev/tty
  fi
  if [ -z "${INSTALL_WDTT:-}" ]; then
    cat >/dev/tty <<'EOF'

Установка WDTT:
1) Авто: использовать существующий WDTT или установить на пустой сервер
2) Установить только панель, WDTT уже развернут вручную
EOF
    printf 'Выберите вариант [1]: ' >/dev/tty
    IFS= read -r wdtt_mode </dev/tty || true
    case "${wdtt_mode:-1}" in 1) INSTALL_WDTT="auto" ;; 2) INSTALL_WDTT="no" ;; *) echo 'Неизвестный режим WDTT.' >/dev/tty; exit 2 ;; esac
  fi
  if [ "$INSTALL_WDTT" = "auto" ] && [ -z "${WDTT_MAIN_PASSWORD:-}" ]; then
    printf 'Главный пароль WDTT для пустого сервера (Enter = сгенерировать): ' >/dev/tty
    IFS= read -r -s WDTT_MAIN_PASSWORD </dev/tty || true
    printf '\n' >/dev/tty
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    install|update|uninstall|status|renew-cert) ACTION="$1"; shift ;;
    --domain|--host) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_HOST="$2"; shift 2 ;;
    --ip) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_HOST="$2"; shift 2 ;;
    --user) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_USER="$2"; shift 2 ;;
    --password) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_PASSWORD="$2"; shift 2 ;;
    --email) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_EMAIL="$2"; shift 2 ;;
    --https-port) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_HTTPS_PORT="$2"; shift 2 ;;
    --path) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_PATH="$2"; shift 2 ;;
    --wdtt) [ "$#" -ge 2 ] || { usage; exit 2; }; INSTALL_WDTT="$2"; shift 2 ;;
    --wdtt-password) [ "$#" -ge 2 ] || { usage; exit 2; }; WDTT_MAIN_PASSWORD="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[ -n "$ACTION" ] || { INTERACTIVE=1; choose_action; }

cleanup() {
  [ -z "$WORK_DIR" ] || rm -rf "$WORK_DIR"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/${BRANCH}/bootstrap.sh | sudo bash -s -- $ACTION" >&2
  exit 1
fi

command -v curl >/dev/null 2>&1 || {
  echo "curl is required" >&2
  exit 1
}
command -v tar >/dev/null 2>&1 || {
  echo "tar is required" >&2
  exit 1
}

run_action() {
  [ "$ACTION" != "exit" ] || return 10
  [ -n "$ACTION" ] || return 0
  if [ "$ACTION" = "install" ]; then
    prompt_install_options
  fi

  export PANEL_HOST="${PANEL_HOST:-}"
  export PANEL_USER="${PANEL_USER:-admin}"
  export PANEL_PASSWORD="${PANEL_PASSWORD:-}"
  export PANEL_EMAIL="${PANEL_EMAIL:-}"
  export PANEL_HTTPS_PORT="${PANEL_HTTPS_PORT:-8443}"
  export PANEL_PATH="${PANEL_PATH:-}"
  export INSTALL_WDTT="${INSTALL_WDTT:-auto}"
  export WDTT_MAIN_PASSWORD="${WDTT_MAIN_PASSWORD:-}"

  cleanup
  WORK_DIR="$(mktemp -d)"
  echo "[wdtt-panel] Downloading ${REPOSITORY}@${BRANCH}"
  curl -fsSL --retry 3 "$ARCHIVE_URL" | tar -xz -C "$WORK_DIR"
  SOURCE_DIR="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  [ -f "$SOURCE_DIR/install.sh" ] || {
    echo "Invalid project archive: install.sh not found" >&2
    return 1
  }
  bash "$SOURCE_DIR/install.sh" "$ACTION"
}

if [ "$INTERACTIVE" = "1" ]; then
  while true; do
    if run_action; then
      :
    else
      code=$?
      [ "$code" -eq 10 ] && exit 0
      echo "Действие завершилось с ошибкой ($code)." >/dev/tty
    fi
    ACTION=""
    choose_action
  done
fi

run_action
