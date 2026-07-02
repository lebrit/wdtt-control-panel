#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="${WDTT_PANEL_REPOSITORY:-lebrit/wdtt-control-panel}"
BRANCH="${WDTT_PANEL_BRANCH:-main}"
WORK_DIR=""
ACTION=""
INTERACTIVE=0
ROLLBACK_VERSION=""

usage() {
  cat <<EOF
Usage: bootstrap.sh [install|update|rollback|uninstall|status|renew-cert|change-password] [options]

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

Change-password options:
  --password VALUE    New panel administrator password (12+ characters)

Rollback options:
  --version TAG       Version tag from GitHub, for example v0.10.3
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
5) Сменить пароль входа в панель
6) Удалить панель
7) Откатить панель к прошлой версии
0) Выход
EOF
  printf 'Выберите действие [1]: ' >/dev/tty
  IFS= read -r choice </dev/tty || true
  case "${choice:-1}" in
    1) ACTION="install" ;;
    2) ACTION="update" ;;
    3) ACTION="status" ;;
    4) ACTION="renew-cert" ;;
    5) ACTION="change-password" ;;
    6)
      printf 'Удалить web-панель? WDTT и его пользователи останутся [y/N]: ' >/dev/tty
      IFS= read -r confirm </dev/tty || true
      case "$confirm" in y|Y|yes|YES|да|Да|ДА) ACTION="uninstall" ;; *) echo 'Отменено.' >/dev/tty; ACTION="" ;; esac
      ;;
    7) ACTION="rollback" ;;
    0) ACTION="exit" ;;
    *) echo 'Неизвестный пункт меню.' >/dev/tty; ACTION="" ;;
  esac
}

github_versions() {
  curl -fsSL --retry 3 "https://api.github.com/repos/${REPOSITORY}/tags?per_page=100" | python3 -c '
import json, sys
try:
    tags = json.load(sys.stdin)
except json.JSONDecodeError:
    tags = []
for item in tags:
    name = item.get("name") if isinstance(item, dict) else ""
    if isinstance(name, str) and name.startswith("v"):
        print(name)
'
}

prompt_rollback_version() {
  [ -n "$ROLLBACK_VERSION" ] && return 0
  [ "${NON_INTERACTIVE:-0}" != "1" ] || { echo "Для отката укажите --version vX.Y.Z" >&2; return 1; }
  [ -r /dev/tty ] && [ -w /dev/tty ] || { echo "Для отката укажите --version vX.Y.Z" >&2; return 1; }
  command -v python3 >/dev/null 2>&1 || { echo "Для списка версий нужен python3" >&2; return 1; }
  local -a versions=()
  mapfile -t versions < <(github_versions || true)
  [ "${#versions[@]}" -gt 0 ] || { echo "Не удалось получить список версий GitHub" >&2; return 1; }
  printf '\nДоступные версии:\n' >/dev/tty
  local index=1 version choice
  for version in "${versions[@]}"; do
    printf '%d) %s\n' "$index" "$version" >/dev/tty
    index=$((index + 1))
  done
  printf 'Выберите версию [1]: ' >/dev/tty
  IFS= read -r choice </dev/tty || true
  choice="${choice:-1}"
  [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#versions[@]}" ] || { echo "Некорректный номер версии" >&2; return 1; }
  ROLLBACK_VERSION="${versions[$((choice - 1))]}"
}

validate_rollback_version() {
  [[ "$ROLLBACK_VERSION" =~ ^v[0-9][0-9A-Za-z._-]*$ ]] || { echo "Некорректный тег версии: $ROLLBACK_VERSION" >&2; return 1; }
}

prompt_password_change() {
  [ "${NON_INTERACTIVE:-0}" = "1" ] && return 0
  [ -r /dev/tty ] && [ -w /dev/tty ] || return 0
  [ -n "${PANEL_PASSWORD:-}" ] && return 0
  printf 'Новый пароль панели, минимум 12 символов: ' >/dev/tty
  IFS= read -r -s PANEL_PASSWORD </dev/tty || true
  printf '\n' >/dev/tty
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

normalize_wdtt_main_password() {
  if [[ "${WDTT_MAIN_PASSWORD:-}" =~ ^[[:space:]]*$ ]]; then
    WDTT_MAIN_PASSWORD=""
  fi
}

wdtt_main_password_is_valid() {
  [ -z "${WDTT_MAIN_PASSWORD:-}" ] || [[ "$WDTT_MAIN_PASSWORD" =~ ^[A-Za-z0-9._~-]{12,64}$ ]]
}

prompt_wdtt_main_password() {
  while true; do
    printf 'Главный пароль WDTT для пустого сервера (Enter = сгенерировать): ' >/dev/tty
    IFS= read -r -s WDTT_MAIN_PASSWORD </dev/tty || true
    printf '\n' >/dev/tty
    normalize_wdtt_main_password
    if wdtt_main_password_is_valid; then
      return 0
    fi
    echo 'Пароль WDTT: 12-64 символа A-Z, a-z, 0-9, точка, _, ~ или -; без пробелов и двоеточия. Enter = сгенерировать.' >/dev/tty
  done
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
    prompt_wdtt_main_password
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    install|update|rollback|uninstall|status|renew-cert|change-password) ACTION="$1"; shift ;;
    --domain|--host) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_HOST="$2"; shift 2 ;;
    --ip) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_HOST="$2"; shift 2 ;;
    --user) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_USER="$2"; shift 2 ;;
    --password) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_PASSWORD="$2"; shift 2 ;;
    --email) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_EMAIL="$2"; shift 2 ;;
    --https-port) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_HTTPS_PORT="$2"; shift 2 ;;
    --path) [ "$#" -ge 2 ] || { usage; exit 2; }; PANEL_PATH="$2"; shift 2 ;;
    --wdtt) [ "$#" -ge 2 ] || { usage; exit 2; }; INSTALL_WDTT="$2"; shift 2 ;;
    --wdtt-password) [ "$#" -ge 2 ] || { usage; exit 2; }; WDTT_MAIN_PASSWORD="$2"; shift 2 ;;
    --version) [ "$#" -ge 2 ] || { usage; exit 2; }; ROLLBACK_VERSION="$2"; shift 2 ;;
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
    normalize_wdtt_main_password
    wdtt_main_password_is_valid || {
      echo 'WDTT_MAIN_PASSWORD: 12-64 символа A-Z, a-z, 0-9, точка, _, ~ или -; без пробелов и двоеточия' >&2
      return 2
    }
  elif [ "$ACTION" = "change-password" ]; then
    prompt_password_change
  elif [ "$ACTION" = "rollback" ]; then
    prompt_rollback_version
    validate_rollback_version
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
  local archive_url install_action source_ref
  if [ "$ACTION" = "rollback" ]; then
    source_ref="refs/tags/${ROLLBACK_VERSION}"
    install_action="update"
  else
    source_ref="refs/heads/${BRANCH}"
    install_action="$ACTION"
  fi
  archive_url="https://github.com/${REPOSITORY}/archive/${source_ref}.tar.gz"
  echo "[wdtt-panel] Downloading ${REPOSITORY}@${source_ref}"
  curl -fsSL --retry 3 "$archive_url" | tar -xz -C "$WORK_DIR"
  SOURCE_DIR="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  [ -f "$SOURCE_DIR/install.sh" ] || {
    echo "Invalid project archive: install.sh not found" >&2
    return 1
  }
  bash "$SOURCE_DIR/install.sh" "$install_action"
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
