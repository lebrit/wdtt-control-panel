#!/usr/bin/env bash
set -Eeuo pipefail

AGENT_SERVICE="wdtt-fleet-agent.service"
CONFIG_FILE="/var/lib/wdtt-panel/fleet-agent.json"
HELPER="/usr/local/sbin/wdtt-panel-admin"

[ "$(id -u)" -eq 0 ] || { echo "Запустите через sudo." >&2; exit 1; }

section() {
  printf '\n===== %s =====\n' "$1"
}

section "WDTT Fleet Agent: безопасная диагностика"
printf 'Время: %s\n' "$(date -Is)"
printf 'Сервер: %s\n' "$(hostname -f 2>/dev/null || hostname)"

section "Версия и служба"
if [ -d /opt/wdtt-panel ]; then
  (cd /opt/wdtt-panel && python3 -c 'from wdtt_panel import __version__; print("WDTT Control Panel:", __version__)') 2>&1 || true
fi
systemctl show "$AGENT_SERVICE" -p ActiveState -p SubState -p User -p NoNewPrivileges --no-pager 2>&1 || true
systemctl status "$AGENT_SERVICE" --no-pager -n 20 2>&1 || true

section "Конфигурация агента без секретов"
python3 - "$CONFIG_FILE" <<'PY'
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception as error:
    print(f"Конфигурация недоступна: {type(error).__name__}")
    raise SystemExit(0)

endpoint = str(data.get("endpoint") or "")
parsed = urlsplit(endpoint)
safe_endpoint = f"{parsed.scheme}://{parsed.netloc}/<скрыто>" if parsed.scheme and parsed.netloc else "не задан"
print("Адрес агента:", safe_endpoint)
print("Включён:", bool(data.get("enabled")))
print("Зарегистрирован:", bool(data.get("agent_token") and data.get("node_id")))
print("Грант сохранён:", bool(data.get("enrollment_grant")))
print("Токен сохранён:", bool(data.get("agent_token")))
print("Интервал:", data.get("poll_interval_seconds"))
print("Последний успех:", data.get("last_success_at") or "нет")
print("Последняя ошибка:", data.get("last_error_code") or "нет")
print("Завершённых команд:", len(data.get("completed_commands") or {}))
PY

section "Проверка локального helper-а без данных пользователей"
if [ ! -x "$HELPER" ]; then
  echo "Helper не найден: $HELPER"
else
  result_file="$(mktemp)"
  trap 'rm -f "$result_file"' EXIT
  if printf '%s' '{"action":"fleet.snapshot","payload":{}}' | sudo -n -u wdtt-panel /usr/bin/sudo -n "$HELPER" >"$result_file" 2>&1; then
    python3 - "$result_file" <<'PY'
import json
import sys

try:
    value = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("Helper вернул неразбираемый ответ")
    raise SystemExit(0)

if value.get("ok"):
    result = value.get("result") or {}
    print("Helper: успешно")
    print("Пользователей в снимке:", len(result.get("users") or []))
else:
    print("Helper: ошибка", str(value.get("error") or "неизвестна")[:240])
PY
  else
    echo "Helper: не выполнился (код $?)."
  fi
fi

section "HTTPS до центра"
endpoint="$(python3 - "$CONFIG_FILE" <<'PY'
import json
import sys
try:
    print(str(json.load(open(sys.argv[1], encoding="utf-8")).get("endpoint") or ""))
except Exception:
    pass
PY
)"
if [ -n "$endpoint" ]; then
  status="$(curl -sS --connect-timeout 10 --max-time 20 -o /dev/null -w '%{http_code}' "$endpoint/health" 2>/dev/null || true)"
  printf 'Ответ health без передачи секретов: %s\n' "${status:-нет ответа}"
else
  echo "Адрес центра не задан."
fi

section "Последние строки журнала агента"
journalctl -u "$AGENT_SERVICE" --no-pager -n 80 2>&1 || true

echo
echo "Готово. Этот отчёт не содержит токенов, грантов, паролей или списка пользователей."
