from __future__ import annotations

import base64
import binascii
import configparser
import errno
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlsplit

from .core import (
    MAX_USERS,
    ValidationError,
    generate_password,
    is_expired,
    normalize_hashes,
    normalize_user_label,
    parse_expiration,
    user_label_from_entry,
    user_view,
    validate_password,
    validate_ports,
)


DB_FILE = Path(os.environ.get("WDTT_DB_FILE", "/etc/wdtt/passwords.json"))
PANEL_LABELS_FILE = Path(os.environ.get("WDTT_PANEL_LABELS_FILE", "/var/lib/wdtt-panel-private/user-labels.json"))
WDTT_EXTENSION_STATE = Path(os.environ.get("WDTT_EXTENSION_STATE", "/var/lib/wdtt-panel-private/wdtt-extensions.json"))
WDTT_EXTENSION_MARKER = "wdtt-panel-extension-v5"
STATS_FILE = Path(os.environ.get("WDTT_STATS_FILE", "/etc/wdtt/server.log"))
BACKUP_DIR = Path(os.environ.get("WDTT_BACKUP_DIR", "/var/lib/wdtt-panel-private/backups"))
BACKUP_FORMAT = "wdtt-panel-backup-v1"
BACKUP_CONTENT_LIMIT = 3 * 1024 * 1024
BACKUP_SCHEDULE_FILE = Path(os.environ.get("WDTT_BACKUP_SCHEDULE_FILE", "/var/lib/wdtt-panel-private/backup-schedule.json"))
BACKUP_TIMER_NAME = "wdtt-panel-backup.timer"
BACKUP_SERVICE_NAME = "wdtt-panel-backup.service"
BACKUP_TIMER_FILE = Path(os.environ.get("WDTT_BACKUP_TIMER_FILE", f"/etc/systemd/system/{BACKUP_TIMER_NAME}"))
BACKUP_SERVICE_FILE = Path(os.environ.get("WDTT_BACKUP_SERVICE_FILE", f"/etc/systemd/system/{BACKUP_SERVICE_NAME}"))
BACKUP_RUNNER = Path(os.environ.get("WDTT_BACKUP_RUNNER", "/usr/local/sbin/wdtt-panel-backup"))
WDTT_UNIT_FILE = Path(os.environ.get("WDTT_UNIT_FILE", "/etc/systemd/system/wdtt.service"))
LOCK_FILE = Path(os.environ.get("WDTT_LOCK_FILE", "/var/lib/wdtt-panel-private/admin.lock"))
SERVICE = os.environ.get("WDTT_SERVICE", "wdtt.service")
SKIP_SYSTEMD = os.environ.get("WDTT_SKIP_SYSTEMD") == "1"
MAX_INPUT = 90 * 1024 * 1024
PANEL_UPDATE_COMMAND = Path(os.environ.get("WDTT_PANEL_UPDATE_COMMAND", "/usr/local/sbin/wdtt-panel-update"))
PANEL_RENEW_COMMAND = Path(os.environ.get("WDTT_PANEL_RENEW_COMMAND", "/opt/wdtt-panel/install.sh"))
PANEL_VERSION_URL = os.environ.get(
    "WDTT_PANEL_VERSION_URL",
    "https://raw.githubusercontent.com/lebrit/wdtt-control-panel/main/install.sh",
)
CASCADE_SETTINGS = Path(
    os.environ.get("WDTT_CASCADE_SETTINGS", "/var/lib/wdtt-panel-private/cascade.json")
)
CASCADE_CONFIG = Path(
    os.environ.get("WDTT_CASCADE_CONFIG", "/var/lib/wdtt-panel-private/sing-box.json")
)
WARP_DIR = Path(os.environ.get("WDTT_WARP_DIR", "/var/lib/wdtt-panel-private/warp"))
GEOFILES_DIR = Path(
    os.environ.get("WDTT_GEOFILES_DIR", "/var/lib/wdtt-panel-private/geofiles")
)
CASCADE_SERVICE = os.environ.get("WDTT_CASCADE_SERVICE", "wdtt-cascade.service")
CASCADE_INSTALL_COMMAND = Path(
    os.environ.get("WDTT_CASCADE_INSTALL_COMMAND", "/opt/wdtt-panel/install.sh")
)
XRAY_SETTINGS = Path(
    os.environ.get("WDTT_XRAY_SETTINGS", "/var/lib/wdtt-panel-private/xray-settings.json")
)
XRAY_CONFIG = Path(
    os.environ.get("WDTT_XRAY_CONFIG", "/var/lib/wdtt-panel-private/xray-config.json")
)
XRAY_ASSETS = Path(
    os.environ.get("WDTT_XRAY_ASSETS", "/var/lib/wdtt-panel-private/xray-assets")
)
XRAY_SERVICE = os.environ.get("WDTT_XRAY_SERVICE", "wdtt-xray.service")
XRAY_INSTALL_COMMAND = Path(
    os.environ.get("WDTT_XRAY_INSTALL_COMMAND", "/opt/wdtt-panel/install.sh")
)
WARP_INSTALL_COMMAND = Path(
    os.environ.get("WDTT_WARP_INSTALL_COMMAND", "/opt/wdtt-panel/install.sh")
)
XRAY_CASCADE_SETTINGS = Path(
    os.environ.get("WDTT_XRAY_CASCADE_SETTINGS", "/var/lib/wdtt-panel-private/xray-cascade.json")
)
XRAY_CASCADE_SERVICE = os.environ.get("WDTT_XRAY_CASCADE_SERVICE", "wdtt-xray-cascade.service")
XRAY_GATEWAY_SERVICE = os.environ.get("WDTT_XRAY_GATEWAY_SERVICE", "wdtt-xray-gateway.service")
IPTABLES_BINARY: str | None = None
XTABLES_LOCK_FILE = os.environ.get("WDTT_XTABLES_LOCK_FILE", "/var/lib/wdtt-panel-private/xtables.lock")
XRAY_ACCESS_LOG = Path(
    os.environ.get("WDTT_XRAY_ACCESS_LOG", "/var/lib/wdtt-panel-private/xray-access.log")
)
XRAY_ERROR_LOG = Path(
    os.environ.get("WDTT_XRAY_ERROR_LOG", "/var/lib/wdtt-panel-private/xray-error.log")
)
INSTALL_LOG_FILE = Path(os.environ.get("WDTT_INSTALL_LOG_FILE", "/var/log/wdtt-panel-install.log"))
NGINX_ACCESS_LOG = Path(os.environ.get("WDTT_NGINX_ACCESS_LOG", "/var/log/nginx/access.log"))
NGINX_ERROR_LOG = Path(os.environ.get("WDTT_NGINX_ERROR_LOG", "/var/log/nginx/error.log"))
XRAY_DEFAULT_GEOFILES = (
    {
        "tag": "geoip",
        "filename": "geoip.dat",
        "url": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat",
    },
    {
        "tag": "geosite",
        "filename": "geosite.dat",
        "url": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat",
    },
)
LEGACY_XRAY_GEOFILE_URLS = {
    "geoip": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
    "geosite": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
}
GOOGLE_AI_DOMAINS = (
    "gemini.google.com", "assistant.google.com", "bard.google.com", "robinfrontend-pa.googleapis.com", "generativelanguage.googleapis.com", "content-gemini.googleapis.com",
    "aistudio.google.com", "ai.google.dev", "accounts.google.com", "oauth2.googleapis.com", "google.com", "www.google.com",
    "googleapis.com", "www.googleapis.com", "ogs.google.com", "gstatic.com", "www.gstatic.com", "ssl.gstatic.com", "connectivitycheck.gstatic.com",
    "googleusercontent.com", "lh3.googleusercontent.com", "yt3.googleusercontent.com", "alkalicore-pa.clients6.google.com",
    "clients6.google.com", "signaler-pa.clients6.google.com", "waa-pa.clients6.google.com", "ogads-pa.clients6.google.com",
    "geller-pa.googleapis.com", "searchlabspartnerservice-pa.googleapis.com", "federatedcompute-pa.googleapis.com",
    "prod-lt-playstoregatewayadapter-pa.googleapis.com", "suggestqueries.google.com", "nearbysharing-pa.googleapis.com",
    "mobilemaps-pa-gz.googleapis.com", "geomobileservices-pa.googleapis.com", "firebaseinstallations.googleapis.com",
    "firebaselogging.googleapis.com", "play.googleapis.com", "play-fe.googleapis.com", "play.google.com", "android.apis.google.com",
    "mtalk.google.com", "cloudconfig.googleapis.com", "youtubei.googleapis.com", "app-measurement.com", "region1.app-measurement.com",
    "encrypted-tbn0.gstatic.com", "encrypted-tbn1.gstatic.com", "encrypted-tbn2.gstatic.com", "encrypted-tbn3.gstatic.com",
)
GOOGLE_AI_DOMAIN_MARKERS = frozenset(GOOGLE_AI_DOMAINS)
# These ranges cover Google Front End traffic that reaches Gemini over QUIC with no
# recoverable hostname. They are deliberately limited to the proven service ranges.
GOOGLE_AI_IPV4_CIDRS = (
    "64.233.160.0/19", "66.102.0.0/20", "66.249.80.0/20", "72.14.192.0/18", "74.125.0.0/16", "108.177.0.0/17",
    "142.250.0.0/15", "142.251.0.0/16", "172.217.0.0/16", "172.253.0.0/16", "173.194.0.0/16", "209.85.128.0/17",
    "216.58.192.0/19", "216.239.32.0/19",
)
RU_SITE_RULESET = (
    "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs"
)
RU_IP_RULESET = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs"
BUILTIN_RULESETS = {
    "ru-sites": RU_SITE_RULESET,
    "ru-ip": RU_IP_RULESET,
    "ru-blocked-sites": (
        "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/"
        "sing-box/rule-set-geosite/geosite-ru-blocked-all.srs"
    ),
    "ru-blocked-ip": (
        "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/"
        "sing-box/rule-set-geoip/geoip-ru-blocked.srs"
    ),
    "ai-services": (
        "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/"
        "geosite-category-ai-!cn.srs"
    ),
}
VK_HASH_LIBRARY_FORMAT = "wdtt-panel-vk-hash-library-v1"


class AdminError(RuntimeError):
    pass


def run(
    command: list[str], timeout: int = 20, check: bool = False, cwd: Path | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=check,
        cwd=cwd,
        env={**os.environ, **env} if env else None,
    )


def service_active() -> bool:
    if SKIP_SYSTEMD:
        return False
    result = run(["systemctl", "is-active", "--quiet", SERVICE])
    return result.returncode == 0


def service_exists() -> bool:
    if SKIP_SYSTEMD:
        return False
    result = run(["systemctl", "show", SERVICE, "--property=LoadState", "--value"])
    return result.returncode == 0 and result.stdout.strip() not in {"", "not-found"}


def service_action(action: str) -> dict[str, Any]:
    if action not in {"start", "stop", "restart"}:
        raise ValidationError("Недопустимое действие сервиса")
    if SKIP_SYSTEMD:
        return {"action": action, "state": "test"}
    result = run(["systemctl", action, SERVICE], timeout=45)
    if result.returncode != 0:
        raise AdminError(result.stderr.strip() or f"Не удалось выполнить systemctl {action}")
    return {"action": action, "active": service_active()}


def normalize_telegram_admin_id(value: str) -> str:
    value = (value or "").strip()
    if value and not re.fullmatch(r"-?[0-9]{1,20}", value):
        raise ValidationError("Telegram Admin ID должен быть числовым chat_id")
    return value


def normalize_telegram_bot_token(value: str) -> str:
    value = (value or "").strip()
    if value and not re.fullmatch(r"[0-9]{5,20}:[A-Za-z0-9_-]{20,200}", value):
        raise ValidationError("Telegram Bot Token должен быть в формате 123456:ABC...")
    return value


def mask_telegram_bot_token(value: str) -> str:
    value = str(value or "")
    if not value:
        return ""
    if len(value) <= 12:
        return "***"
    return f"{value[:6]}...{value[-4:]}"


def systemd_exec_token(value: str) -> str:
    if re.fullmatch(r"[^\s\"'\\]+", value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def set_wdtt_service_telegram(admin_id: str, bot_token: str) -> None:
    if SKIP_SYSTEMD:
        return
    if not WDTT_UNIT_FILE.is_file():
        raise AdminError(f"Не найден {WDTT_UNIT_FILE}; настройте Telegram в wdtt.service вручную")
    lines = WDTT_UNIT_FILE.read_text(encoding="utf-8").splitlines()
    changed = False
    found = False
    next_lines: list[str] = []
    for line in lines:
        if not line.startswith("ExecStart="):
            next_lines.append(line)
            continue
        found = True
        command = line.split("=", 1)[1]
        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            raise AdminError(f"Не удалось разобрать ExecStart в {WDTT_UNIT_FILE}: {exc}") from exc
        clean: list[str] = []
        skip_next = False
        for token in tokens:
            if skip_next:
                skip_next = False
                continue
            if token in {"-admin", "--admin", "-bot-token", "--bot-token"}:
                skip_next = True
                continue
            if token.startswith(("-admin=", "--admin=", "-bot-token=", "--bot-token=")):
                continue
            clean.append(token)
        if admin_id and bot_token:
            clean.extend(["-admin", admin_id, "-bot-token", bot_token])
        next_line = "ExecStart=" + " ".join(systemd_exec_token(token) for token in clean)
        changed = changed or next_line != line
        next_lines.append(next_line)
    if not found:
        raise AdminError(f"В {WDTT_UNIT_FILE} не найден ExecStart")
    if changed:
        write_systemd_unit(WDTT_UNIT_FILE, "\n".join(next_lines) + "\n")
        reloaded = run(["systemctl", "daemon-reload"], timeout=45)
        if reloaded.returncode != 0:
            raise AdminError(reloaded.stderr.strip() or "Не удалось обновить systemd после настройки Telegram")


def telegram_status(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = load_database()
    admin_id = str(data.get("admin_id") or "")
    bot_token = str(data.get("bot_token") or "")
    return {
        "enabled": bool(admin_id and bot_token),
        "admin_id": admin_id,
        "bot_token_set": bool(bot_token),
        "bot_token_hint": mask_telegram_bot_token(bot_token),
        "service_active": service_active(),
    }


def configure_telegram(payload: dict[str, Any]) -> dict[str, Any]:
    current = load_database()
    enabled = bool(payload.get("enabled"))
    admin_id = ""
    bot_token = ""
    if enabled:
        admin_id = normalize_telegram_admin_id(str(payload.get("admin_id") or ""))
        bot_token = normalize_telegram_bot_token(str(payload.get("bot_token") or current.get("bot_token") or ""))
        if not admin_id or not bot_token:
            raise ValidationError("Для включения Telegram укажите Admin ID и Bot Token")
    was_active = service_active()
    if was_active:
        service_action("stop")
    try:
        data = load_database()
        create_backup("telegram-settings")
        data["admin_id"] = admin_id
        data["bot_token"] = bot_token
        save_database(data)
        set_wdtt_service_telegram(admin_id, bot_token)
    except Exception:
        if was_active:
            service_action("start")
        raise
    if was_active:
        service_action("start")
    return telegram_status({})


def telegram_test(payload: dict[str, Any]) -> dict[str, Any]:
    data = load_database()
    admin_id = normalize_telegram_admin_id(str(data.get("admin_id") or ""))
    bot_token = normalize_telegram_bot_token(str(data.get("bot_token") or ""))
    if not admin_id or not bot_token:
        raise ValidationError("Сначала сохраните Telegram Bot Token и Admin ID")
    message = str(payload.get("message") or "WDTT Control Panel: Telegram bot connected").strip()[:500]
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        data=json.dumps({"chat_id": admin_id, "text": message}, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise AdminError(f"Не удалось отправить тестовое сообщение Telegram: {exc}") from exc
    if not isinstance(result, dict) or not result.get("ok"):
        description = result.get("description") if isinstance(result, dict) else ""
        raise AdminError(f"Telegram вернул ошибку: {description or 'unknown'}")
    return {"sent": True, "admin_id": admin_id}


def empty_database() -> dict[str, Any]:
    return {
        "main_password": "",
        "admin_id": "",
        "bot_token": "",
        "passwords": {},
        "devices": {},
    }


def load_database() -> dict[str, Any]:
    if not DB_FILE.exists():
        return empty_database()
    try:
        data = json.loads(DB_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdminError(f"Не удалось прочитать {DB_FILE}: {exc}") from exc
    if not isinstance(data, dict):
        raise AdminError("База WDTT имеет неверный формат")
    data.setdefault("passwords", {})
    data.setdefault("devices", {})
    if not isinstance(data["passwords"], dict) or not isinstance(data["devices"], dict):
        raise AdminError("Разделы passwords/devices имеют неверный формат")
    return data


def save_database(data: dict[str, Any]) -> None:
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    fd, temp_name = tempfile.mkstemp(prefix="passwords.", suffix=".tmp", dir=DB_FILE.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, DB_FILE)
        os.chmod(DB_FILE, 0o600)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def load_panel_labels() -> dict[str, str]:
    """Keep labels visible until an older WDTT binary is replaced."""
    try:
        raw = json.loads(PANEL_LABELS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        str(password): value.strip()
        for password, value in raw.items()
        if isinstance(value, str) and value.strip()
    }


def wdtt_extensions_are_verified() -> bool:
    try:
        state = json.loads(WDTT_EXTENSION_STATE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(state, dict) and state.get("marker") == WDTT_EXTENSION_MARKER


def save_panel_labels(labels: dict[str, str]) -> None:
    PANEL_LABELS_FILE.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(labels, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    fd, temp_name = tempfile.mkstemp(prefix="user-labels.", suffix=".tmp", dir=PANEL_LABELS_FILE.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, PANEL_LABELS_FILE)
        os.chmod(PANEL_LABELS_FILE, 0o600)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def update_panel_label(password: str, label: str, previous_password: str = "") -> None:
    if wdtt_extensions_are_verified():
        return
    labels = load_panel_labels()
    if previous_password and previous_password != password:
        labels.pop(previous_password, None)
    if label:
        labels[password] = label
    else:
        labels.pop(password, None)
    save_panel_labels(labels)


def remove_panel_label(password: str) -> None:
    if wdtt_extensions_are_verified():
        return
    labels = load_panel_labels()
    if password in labels:
        labels.pop(password, None)
        save_panel_labels(labels)


def create_backup(label: str = "auto") -> str:
    if not DB_FILE.exists():
        return ""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    safe_label = re.sub(r"[^A-Za-z0-9_-]", "-", label)[:32]
    stamp = f"{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 1_000_000:06d}"
    name = f"passwords-{stamp}-{safe_label}.json"
    destination = BACKUP_DIR / name
    shutil.copy2(DB_FILE, destination)
    os.chmod(destination, 0o600)
    prune_backups()
    return name


def prune_backups(keep: int = 50) -> None:
    if not BACKUP_DIR.exists():
        return
    files = sorted(BACKUP_DIR.glob("passwords-*.json"), key=lambda item: item.stat().st_mtime)
    for path in files[:-keep]:
        path.unlink(missing_ok=True)


def mutate_database(label: str, mutator: Callable[[dict[str, Any]], Any], backup: bool = True) -> Any:
    was_active = service_active()
    if was_active:
        service_action("stop")
    try:
        data = load_database()
        if backup:
            create_backup(label)
        result = mutator(data)
        save_database(data)
    except Exception:
        if was_active:
            service_action("start")
        raise
    if was_active:
        service_action("start")
    return result


def purge_expired(data: dict[str, Any]) -> int:
    removed = 0
    for password, entry in list(data["passwords"].items()):
        if not isinstance(entry, dict) or not is_expired(entry):
            continue
        device_id = str(entry.get("device_id") or "")
        if device_id:
            data["devices"].pop(device_id, None)
        del data["passwords"][password]
        removed += 1
    return removed


def entry_with_legacy_label(data: dict[str, Any], password: str, entry: dict[str, Any], panel_labels: dict[str, str] | None = None) -> dict[str, Any]:
    if user_label_from_entry(entry):
        return entry
    for field in ("labels", "remarks", "user_labels", "userLabels", "names", "comments", "tags", "marks"):
        labels = data.get(field)
        value = labels.get(password) if isinstance(labels, dict) else None
        if isinstance(value, str) and value.strip():
            return {**entry, "label": value.strip()}
    fallback = (panel_labels or {}).get(password)
    if fallback:
        return {**entry, "label": fallback}
    return entry


def list_users() -> dict[str, Any]:
    data = load_database()
    panel_labels = {} if wdtt_extensions_are_verified() else load_panel_labels()
    handshakes = wireguard_handshakes()
    users = [
        connected_user_view(
            user_view(
                password,
                entry_with_legacy_label(data, password, entry, panel_labels) if isinstance(entry, dict) else {},
                data["devices"],
            ).as_dict(),
            handshakes,
        )
        for password, entry in data["passwords"].items()
    ]
    users.sort(key=lambda item: (item["expired"], item["is_deactivated"], item["password"]))
    user_devices = {
        str(entry.get("device_id") or "")
        for entry in data["passwords"].values()
        if isinstance(entry, dict) and entry.get("device_id")
    }
    admins = []
    main_traffic_supported = "main_down_bytes" in data or "main_up_bytes" in data

    def main_admin_view(device_id: str = "", device: dict[str, Any] | None = None, last_handshake: int = 0) -> dict[str, Any]:
        return {
            "password": "Главный пароль",
            "role": "admin",
            "device_id": device_id,
            "device": device,
            "connected": handshake_is_active(last_handshake),
            "last_handshake": last_handshake,
            "down_bytes": int(data.get("main_down_bytes") or 0),
            "up_bytes": int(data.get("main_up_bytes") or 0),
            "last_upload_at": int(data.get("main_last_upload_at") or 0),
            "last_download_at": int(data.get("main_last_download_at") or 0),
            "traffic_supported": main_traffic_supported,
            "expires_at": 0,
            "label": "Администратор WDTT",
            "vk_hash": "Администратор WDTT",
            "ports": "",
            "is_deactivated": False,
            "expired": False,
        }

    for device_id, device in data["devices"].items():
        if device_id in user_devices or not isinstance(device, dict):
            continue
        public_key = str(device.get("pub_key") or device.get("PubKey") or "")
        last_handshake = int(handshakes.get(public_key) or 0)
        admins.append(main_admin_view(device_id, device, last_handshake))
    if data.get("main_password") and not admins:
        admins.append(main_admin_view())
    return {
        "users": users,
        "admins": admins,
        "main_password_present": bool(data.get("main_password")),
        "limit": MAX_USERS,
    }


def wireguard_handshakes() -> dict[str, int]:
    handshakes: dict[str, int] = {}
    if SKIP_SYSTEMD:
        return handshakes
    if shutil.which("wg"):
        result = run(["wg", "show", "wdtt0", "dump"], timeout=10)
        if result.returncode == 0:
            for index, line in enumerate(result.stdout.splitlines()):
                fields = line.split("\t")
                if index == 0 or len(fields) < 5:
                    continue
                try:
                    handshakes[fields[0]] = int(fields[4])
                except ValueError:
                    continue
    handshakes.update(userspace_wireguard_handshakes())
    return handshakes


def userspace_wireguard_handshakes() -> dict[str, int]:
    """Read handshakes directly from WDTT's embedded WireGuard UAPI socket.

    WDTT starts WireGuard in userspace.  On servers without wireguard-tools,
    `wg show` cannot query it even though the tunnel is healthy, which made
    connected administrator devices appear offline in the panel.
    """
    raw = ""
    for path in ("/var/run/wireguard/wdtt0.sock", "/run/wireguard/wdtt0.sock"):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(path)
                client.sendall(b"get=1\n\n")
                chunks: list[bytes] = []
                while True:
                    chunk = client.recv(16384)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if b"\n\n" in b"".join(chunks):
                        break
                raw = b"".join(chunks).decode("utf-8", "replace")
            break
        except OSError:
            continue
    if not raw:
        return {}

    handshakes: dict[str, int] = {}
    public_key = ""
    stamp = 0

    def save_peer() -> None:
        nonlocal public_key, stamp
        if not public_key:
            return
        try:
            key_bytes = bytes.fromhex(public_key)
            handshakes[base64.b64encode(key_bytes).decode("ascii")] = stamp
        except ValueError:
            pass

    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            continue
        if key == "public_key":
            save_peer()
            public_key, stamp = value, 0
        elif key == "last_handshake_time_sec":
            try:
                stamp = int(value)
            except ValueError:
                stamp = 0
    save_peer()
    return handshakes


def handshake_is_active(stamp: int, window: int = 75) -> bool:
    return stamp > 0 and time.time() - stamp <= window


def connected_user_view(user: dict[str, Any], handshakes: dict[str, int]) -> dict[str, Any]:
    device = user.get("device") or {}
    public_key = str(device.get("pub_key") or device.get("PubKey") or "")
    last_handshake = int(handshakes.get(public_key) or 0)
    user["connected"] = handshake_is_active(last_handshake)
    user["last_handshake"] = last_handshake
    user["role"] = "user"
    return user


def create_user(payload: dict[str, Any]) -> dict[str, Any]:
    requested = str(payload.get("password") or "").strip()
    password = validate_password(requested or generate_password())
    expires_at = parse_expiration(payload)
    vk_hash = normalize_hashes(str(payload.get("vk_hash") or ""))
    ports = validate_ports(str(payload.get("ports") or "56000,56001,9000"))
    label = normalize_user_label(str(payload.get("label") or ""))

    def apply(data: dict[str, Any]) -> dict[str, Any]:
        purge_expired(data)
        if password in data["passwords"] or password == data.get("main_password"):
            raise ValidationError("Такой пароль уже существует")
        if len(data["passwords"]) >= MAX_USERS:
            raise ValidationError(f"Лимит WDTT: не более {MAX_USERS} пользователей")
        entry = {
            "device_id": "",
            "expires_at": expires_at,
            "down_bytes": 0,
            "up_bytes": 0,
            "label": label,
            "vk_hash": vk_hash,
            "ports": ports,
            "is_deactivated": bool(payload.get("is_deactivated", False)),
        }
        data["passwords"][password] = entry
        return user_view(password, entry, data["devices"]).as_dict()

    result = mutate_database("create", apply)
    update_panel_label(password, label)
    return result


def create_users_bulk(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        count = int(payload.get("count", 1))
    except (TypeError, ValueError) as exc:
        raise ValidationError("Количество пользователей должно быть числом") from exc
    if not 1 <= count <= MAX_USERS:
        raise ValidationError(f"Можно создать от 1 до {MAX_USERS} пользователей")

    hashes = normalize_hashes(str(payload.get("vk_hash") or "")).split(",")
    hash_mode = str(payload.get("hash_mode") or "shared")
    if hash_mode not in {"shared", "rotate"}:
        raise ValidationError("Некорректный режим назначения VK-хешей")
    expires_at = parse_expiration(payload)
    ports = validate_ports(str(payload.get("ports") or "56000,56001,9000"))
    is_deactivated = bool(payload.get("is_deactivated", False))
    label_prefix = normalize_user_label(str(payload.get("label_prefix") or ""))

    def apply(data: dict[str, Any]) -> dict[str, Any]:
        purge_expired(data)
        available = MAX_USERS - len(data["passwords"])
        if count > available:
            raise ValidationError(f"Доступно мест: {available}; запрошено пользователей: {count}")

        created: list[dict[str, Any]] = []
        reserved = set(data["passwords"])
        reserved.add(str(data.get("main_password") or ""))
        for index in range(count):
            password = generate_password()
            while password in reserved:
                password = generate_password()
            reserved.add(password)
            assigned_hashes = hashes if hash_mode == "shared" else [hashes[index % len(hashes)]]
            label = ""
            if label_prefix:
                suffix = f" {index + 1}" if count > 1 else ""
                label = normalize_user_label(f"{label_prefix}{suffix}")
            entry = {
                "device_id": "",
                "expires_at": expires_at,
                "down_bytes": 0,
                "up_bytes": 0,
                "label": label,
                "vk_hash": ",".join(assigned_hashes),
                "ports": ports,
                "is_deactivated": is_deactivated,
            }
            data["passwords"][password] = entry
            created.append(user_view(password, entry, data["devices"]).as_dict())
        return {"users": created, "count": len(created)}

    result = mutate_database("bulk-create", apply)
    for user in result["users"]:
        update_panel_label(user["password"], str(user.get("label") or ""))
    return result


def update_user(payload: dict[str, Any]) -> dict[str, Any]:
    current = validate_password(str(payload.get("current_password") or ""))
    replacement_raw = str(payload.get("password") or current).strip()
    replacement = validate_password(replacement_raw)

    def apply(data: dict[str, Any]) -> dict[str, Any]:
        entry = data["passwords"].get(current)
        if not isinstance(entry, dict):
            raise ValidationError("Пользователь не найден")
        if replacement != current:
            if replacement in data["passwords"] or replacement == data.get("main_password"):
                raise ValidationError("Такой пароль уже существует")
            del data["passwords"][current]
            data["passwords"][replacement] = entry
        if "vk_hash" in payload:
            entry["vk_hash"] = normalize_hashes(str(payload["vk_hash"]))
        if "ports" in payload:
            entry["ports"] = validate_ports(str(payload["ports"]))
        if "label" in payload:
            entry["label"] = normalize_user_label(str(payload["label"] or ""))
        if any(key in payload for key in ("days", "expires_at", "unlimited")):
            entry["expires_at"] = parse_expiration(payload)
        if "is_deactivated" in payload:
            entry["is_deactivated"] = bool(payload["is_deactivated"])
        return user_view(replacement, entry, data["devices"]).as_dict()

    result = mutate_database("update", apply)
    if "label" in payload:
        update_panel_label(replacement, normalize_user_label(str(payload["label"] or "")), current)
    elif replacement != current:
        labels = load_panel_labels()
        if current in labels:
            labels[replacement] = labels.pop(current)
            save_panel_labels(labels)
    return result


def delete_user(payload: dict[str, Any]) -> dict[str, Any]:
    password = validate_password(str(payload.get("password") or ""))

    def apply(data: dict[str, Any]) -> dict[str, Any]:
        entry = data["passwords"].pop(password, None)
        if not isinstance(entry, dict):
            raise ValidationError("Пользователь не найден")
        device_id = str(entry.get("device_id") or "")
        if device_id:
            data["devices"].pop(device_id, None)
        return {"deleted": password}

    result = mutate_database("delete", apply)
    remove_panel_label(password)
    return result


def unbind_user(payload: dict[str, Any]) -> dict[str, Any]:
    password = validate_password(str(payload.get("password") or ""))

    def apply(data: dict[str, Any]) -> dict[str, Any]:
        entry = data["passwords"].get(password)
        if not isinstance(entry, dict):
            raise ValidationError("Пользователь не найден")
        device_id = str(entry.get("device_id") or "")
        if device_id:
            data["devices"].pop(device_id, None)
        entry["device_id"] = ""
        return user_view(password, entry, data["devices"]).as_dict()

    return mutate_database("unbind", apply)


def reset_traffic(payload: dict[str, Any]) -> dict[str, Any]:
    password = validate_password(str(payload.get("password") or ""))

    def apply(data: dict[str, Any]) -> dict[str, Any]:
        entry = data["passwords"].get(password)
        if not isinstance(entry, dict):
            raise ValidationError("Пользователь не найден")
        entry["down_bytes"] = 0
        entry["up_bytes"] = 0
        return user_view(password, entry, data["devices"]).as_dict()

    return mutate_database("traffic-reset", apply)


def bulk_user_action(payload: dict[str, Any]) -> dict[str, Any]:
    action = str(payload.get("action") or "")
    actions = {
        "activate": "Активация",
        "deactivate": "Деактивация",
        "set_expiration": "Изменение срока",
        "reset_traffic": "Сброс трафика",
        "unbind": "Отвязка устройств",
        "delete": "Удаление",
    }
    if action not in actions:
        raise ValidationError("Неизвестное массовое действие")
    raw_passwords = payload.get("passwords")
    if not isinstance(raw_passwords, list):
        raise ValidationError("Выберите хотя бы одного пользователя")
    passwords = list(dict.fromkeys(validate_password(str(item)) for item in raw_passwords))
    if not passwords or len(passwords) > MAX_USERS:
        raise ValidationError(f"Можно выбрать от 1 до {MAX_USERS} пользователей")
    expires_at = parse_expiration({"days": payload.get("days")}) if action == "set_expiration" else None

    def apply(data: dict[str, Any]) -> dict[str, Any]:
        missing = [password for password in passwords if not isinstance(data["passwords"].get(password), dict)]
        if missing:
            raise ValidationError("Часть выбранных пользователей уже не существует")
        for password in passwords:
            entry = data["passwords"][password]
            if action == "activate":
                entry["is_deactivated"] = False
            elif action == "deactivate":
                entry["is_deactivated"] = True
            elif action == "set_expiration":
                entry["expires_at"] = expires_at
            elif action == "reset_traffic":
                entry["down_bytes"] = 0
                entry["up_bytes"] = 0
            elif action == "unbind":
                device_id = str(entry.get("device_id") or "")
                if device_id:
                    data["devices"].pop(device_id, None)
                entry["device_id"] = ""
            elif action == "delete":
                device_id = str(entry.get("device_id") or "")
                if device_id:
                    data["devices"].pop(device_id, None)
                del data["passwords"][password]
        return {"action": action, "count": len(passwords)}

    return mutate_database(f"bulk-{action}", apply)


def backup_stamp() -> str:
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 1_000_000:06d}"


def backup_name(kind: str, label: str) -> str:
    safe_label = re.sub(r"[^A-Za-z0-9_-]", "-", label)[:32] or "manual"
    return f"{kind}-{backup_stamp()}-{safe_label}.json"


def read_private_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def read_private_text(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return value if len(value.encode("utf-8")) <= 512 * 1024 else None


def write_private_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def write_backup(name: str, data: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if len(encoded.encode("utf-8")) > BACKUP_CONTENT_LIMIT:
        raise ValidationError("Резервная копия превышает 3 МБ")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    destination = BACKUP_DIR / name
    write_private_text(destination, encoded)
    stat = destination.stat()
    return {"name": name, "size": stat.st_size, "created_at": int(stat.st_mtime)}


def backup_user_payload() -> dict[str, Any]:
    return {
        "format": BACKUP_FORMAT,
        "type": "users",
        "created_at": int(time.time()),
        "database": load_database(),
        "panel_labels": load_panel_labels(),
    }


def backup_full_payload() -> dict[str, Any]:
    return {
        **backup_user_payload(),
        "type": "full",
        "settings": {
            "xray": load_xray_settings(),
            "xray_cascade": load_xray_cascade_settings(),
            "legacy_cascade": {
                "settings": read_private_json(CASCADE_SETTINGS),
                "config": read_private_json(CASCADE_CONFIG),
            },
            "extension_state": read_private_json(WDTT_EXTENSION_STATE),
            "backup_schedule": load_backup_schedule_settings(),
        },
        "warp": {
            "account": read_private_text(WARP_DIR / "wgcf-account.toml"),
            "profile": read_private_text(WARP_DIR / "wgcf-profile.conf"),
        },
    }


def backup_type(data: Any) -> str:
    if isinstance(data, dict) and data.get("format") == BACKUP_FORMAT and data.get("type") in {"users", "full"}:
        return str(data["type"])
    return "users"


def backup_metadata(path: Path) -> dict[str, Any]:
    kind = "users"
    try:
        kind = backup_type(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        pass
    stat = path.stat()
    return {"name": path.name, "size": stat.st_size, "created_at": int(stat.st_mtime), "type": kind}


def list_backups() -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    if BACKUP_DIR.exists():
        paths = (path for path in BACKUP_DIR.glob("*.json") if re.fullmatch(r"(?:passwords|users|panel)-[A-Za-z0-9_-]+\.json", path.name))
        items = [backup_metadata(path) for path in sorted(paths, key=lambda item: item.stat().st_mtime, reverse=True)]
    return {"backups": items}


def create_manual_backup(payload: dict[str, Any]) -> dict[str, Any]:
    kind = str(payload.get("type") or "full")
    if kind not in {"full", "users"}:
        raise ValidationError("Выберите тип резервной копии")
    data = backup_full_payload() if kind == "full" else backup_user_payload()
    scheduled = bool(payload.get("scheduled", False))
    result = write_backup(backup_name("panel" if kind == "full" else "users", "scheduled" if scheduled else "manual"), data)
    if scheduled:
        prune_scheduled_backups(kind, load_backup_schedule_settings()["keep"])
    return {**result, "type": kind}


def default_backup_schedule() -> dict[str, Any]:
    return {"frequency": "disabled", "time": "03:30", "type": "full", "keep": 14}


def normalize_backup_schedule(payload: Any) -> dict[str, Any]:
    schedule = default_backup_schedule()
    if not isinstance(payload, dict):
        raise ValidationError("Некорректное расписание backup")
    frequency = str(payload.get("frequency") or schedule["frequency"])
    if frequency not in {"disabled", "daily", "weekly"}:
        raise ValidationError("Выберите период backup")
    schedule["frequency"] = frequency
    value = str(payload.get("time") or schedule["time"])
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
        raise ValidationError("Укажите время backup в формате ЧЧ:ММ")
    schedule["time"] = value
    kind = str(payload.get("type") or schedule["type"])
    if kind not in {"full", "users"}:
        raise ValidationError("Выберите тип автоматической копии")
    schedule["type"] = kind
    try:
        keep = int(payload.get("keep") or schedule["keep"])
    except (TypeError, ValueError) as exc:
        raise ValidationError("Укажите количество хранимых backup") from exc
    if not 1 <= keep <= 100:
        raise ValidationError("Можно хранить от 1 до 100 автоматических backup")
    schedule["keep"] = keep
    return schedule


def load_backup_schedule_settings() -> dict[str, Any]:
    saved = read_private_json(BACKUP_SCHEDULE_FILE)
    if not saved:
        return default_backup_schedule()
    try:
        return normalize_backup_schedule(saved)
    except ValidationError:
        return default_backup_schedule()


def write_systemd_unit(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def backup_schedule_units(schedule: dict[str, Any]) -> tuple[str, str]:
    hour, minute = schedule["time"].split(":")
    on_calendar = f"*-*-* {hour}:{minute}:00" if schedule["frequency"] == "daily" else f"Sun *-*-* {hour}:{minute}:00"
    service = f"""[Unit]
Description=WDTT panel automatic backup

[Service]
Type=oneshot
ExecStart={BACKUP_RUNNER} {schedule['type']}
"""
    timer = f"""[Unit]
Description=Schedule WDTT panel automatic backup

[Timer]
OnCalendar={on_calendar}
Persistent=true
Unit={BACKUP_SERVICE_NAME}

[Install]
WantedBy=timers.target
"""
    return service, timer


def prune_scheduled_backups(kind: str, keep: int) -> None:
    prefix = "panel" if kind == "full" else "users"
    paths = sorted(BACKUP_DIR.glob(f"{prefix}-*-scheduled.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    for path in paths[keep:]:
        path.unlink(missing_ok=True)


def backup_schedule_status(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    schedule = load_backup_schedule_settings()
    active = False
    if not SKIP_SYSTEMD:
        active = run(["systemctl", "is-enabled", "--quiet", BACKUP_TIMER_NAME], timeout=20).returncode == 0
    return {"settings": schedule, "active": active}


def save_backup_schedule(payload: dict[str, Any]) -> dict[str, Any]:
    schedule = normalize_backup_schedule(payload)
    save_private_json(BACKUP_SCHEDULE_FILE, schedule)
    if SKIP_SYSTEMD:
        return {"settings": schedule, "active": False, "state": "test"}
    if schedule["frequency"] == "disabled":
        run(["systemctl", "disable", "--now", BACKUP_TIMER_NAME], timeout=45)
        BACKUP_TIMER_FILE.unlink(missing_ok=True)
        BACKUP_SERVICE_FILE.unlink(missing_ok=True)
        reloaded = run(["systemctl", "daemon-reload"], timeout=45)
        if reloaded.returncode != 0:
            raise AdminError(reloaded.stderr.strip() or "Не удалось обновить systemd")
        return {"settings": schedule, "active": False}
    if not BACKUP_RUNNER.is_file():
        raise AdminError("Не найден модуль автоматических backup; обновите панель")
    service, timer = backup_schedule_units(schedule)
    write_systemd_unit(BACKUP_SERVICE_FILE, service)
    write_systemd_unit(BACKUP_TIMER_FILE, timer)
    reloaded = run(["systemctl", "daemon-reload"], timeout=45)
    if reloaded.returncode != 0:
        raise AdminError(reloaded.stderr.strip() or "Не удалось обновить systemd")
    enabled = run(["systemctl", "enable", "--now", BACKUP_TIMER_NAME], timeout=45)
    if enabled.returncode != 0:
        raise AdminError(enabled.stderr.strip() or "Не удалось включить таймер backup")
    return {"settings": schedule, "active": True}


def delete_backup(payload: dict[str, Any]) -> dict[str, Any]:
    name = validate_backup_name(str(payload.get("name") or ""))
    path = BACKUP_DIR / name
    if not path.is_file():
        raise ValidationError("Резервная копия не найдена")
    path.unlink()
    return {"deleted": name}


def validate_backup_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > 512 * 1024:
        raise ValidationError(f"В backup неверный {label}")
    return value


def validate_labels_payload(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValidationError("В backup отсутствуют корректные метки пользователей")
    return {
        str(password): label.strip()
        for password, label in value.items()
        if isinstance(label, str) and label.strip() and len(str(password)) <= 64 and len(label.strip()) <= 64
    }


def validate_full_backup(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or backup_type(data) != "full":
        raise ValidationError("В backup нет полного набора настроек")
    validate_database_payload(data.get("database"))
    settings = data.get("settings")
    warp = data.get("warp")
    if not isinstance(settings, dict) or not isinstance(warp, dict):
        raise ValidationError("В backup отсутствуют настройки панели")
    xray = settings.get("xray")
    xray_cascade = settings.get("xray_cascade")
    legacy_cascade = settings.get("legacy_cascade")
    extension_state = settings.get("extension_state")
    backup_schedule = settings.get("backup_schedule", default_backup_schedule())
    if not isinstance(xray, dict) or not isinstance(xray_cascade, dict) or not isinstance(legacy_cascade, dict):
        raise ValidationError("В backup неверные настройки Xray или каскада")
    for key in ("settings", "config"):
        if legacy_cascade.get(key) is not None and not isinstance(legacy_cascade.get(key), dict):
            raise ValidationError("В backup неверные настройки каскада")
    if extension_state is not None and not isinstance(extension_state, dict):
        raise ValidationError("В backup неверное состояние WDTT")
    normalized_xray = normalize_xray_settings(xray)
    normalized_cascade = normalize_xray_cascade_settings(xray_cascade)
    build_effective_xray_config(normalized_xray, normalized_cascade)
    return {
        "database": data["database"],
        "panel_labels": validate_labels_payload(data.get("panel_labels", {})),
        "xray": normalized_xray,
        "xray_cascade": normalized_cascade,
        "legacy_cascade": legacy_cascade,
        "extension_state": extension_state,
        "backup_schedule": normalize_backup_schedule(backup_schedule),
        "warp_account": validate_backup_text(warp.get("account"), "профиль WARP"),
        "warp_profile": validate_backup_text(warp.get("profile"), "профиль WARP"),
    }


def restore_optional_json(path: Path, value: dict[str, Any] | None) -> None:
    if value is None:
        path.unlink(missing_ok=True)
    else:
        save_private_json(path, value)


def restore_optional_text(path: Path, value: str | None) -> None:
    if value is None:
        path.unlink(missing_ok=True)
    else:
        write_private_text(path, value)


def apply_restored_services(xray: dict[str, Any], cascade: dict[str, Any]) -> list[str]:
    if SKIP_SYSTEMD:
        return []
    warnings: list[str] = []

    def apply(command: list[str], warning: str) -> bool:
        result = run(command, timeout=60)
        if result.returncode == 0:
            return True
        warnings.append(result.stderr.strip() or warning)
        return False

    if shutil.which("xray"):
        xray_action = "enable" if xray.get("enabled") else "disable"
        if apply(["systemctl", xray_action, XRAY_SERVICE], "Не удалось изменить состояние Xray"):
            apply(["systemctl", "restart" if xray.get("enabled") else "stop", XRAY_SERVICE], "Не удалось применить настройки Xray")
    elif xray.get("enabled"):
        warnings.append("Xray не установлен: настройки сохранены, но служба не запущена")

    if xray.get("gateway_enabled"):
        if apply(["systemctl", "enable", XRAY_GATEWAY_SERVICE], "Не удалось включить шлюз WDTT → Xray"):
            try:
                xray_gateway_apply_rules({})
            except AdminError as exc:
                warnings.append(str(exc))
    else:
        apply(["systemctl", "disable", XRAY_GATEWAY_SERVICE], "Не удалось выключить шлюз WDTT → Xray")
        try:
            xray_gateway_remove_rules({})
        except AdminError as exc:
            warnings.append(str(exc))

    if cascade.get("enabled"):
        if apply(["systemctl", "enable", "--now", XRAY_CASCADE_SERVICE], "Не удалось включить каскад RU → EU"):
            try:
                cascade_apply_rules({})
            except AdminError as exc:
                warnings.append(str(exc))
    else:
        apply(["systemctl", "disable", "--now", XRAY_CASCADE_SERVICE], "Не удалось выключить каскад RU → EU")
        try:
            cascade_remove_rules({})
        except AdminError as exc:
            warnings.append(str(exc))
    return warnings


def restore_backup(payload: dict[str, Any]) -> dict[str, Any]:
    name = validate_backup_name(str(payload.get("name") or ""))
    source = BACKUP_DIR / name
    if not source.is_file():
        raise ValidationError("Резервная копия не найдена")
    try:
        restored = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"Резервная копия повреждена: {exc}") from exc

    kind = backup_type(restored)
    if kind == "full":
        full = validate_full_backup(restored)
        database, labels = full["database"], full["panel_labels"]
    elif isinstance(restored, dict) and restored.get("format") == BACKUP_FORMAT:
        validate_database_payload(restored.get("database"))
        database, labels = restored["database"], validate_labels_payload(restored.get("panel_labels", {}))
    else:
        validate_database_payload(restored)
        database, labels = restored, load_panel_labels()

    safety_backup = create_manual_backup({"type": "full"})["name"]

    def apply(data: dict[str, Any]) -> None:
        data.clear()
        data.update(database)
        data.setdefault("devices", {})

    mutate_database("before-restore", apply, backup=False)
    save_panel_labels(labels)
    warnings: list[str] = []
    if kind == "full":
        restore_optional_json(XRAY_SETTINGS, full["xray"])
        restore_optional_json(XRAY_CONFIG, build_effective_xray_config(full["xray"], full["xray_cascade"]))
        restore_optional_json(XRAY_CASCADE_SETTINGS, full["xray_cascade"])
        restore_optional_json(CASCADE_SETTINGS, full["legacy_cascade"]["settings"])
        restore_optional_json(CASCADE_CONFIG, full["legacy_cascade"]["config"])
        restore_optional_json(WDTT_EXTENSION_STATE, full["extension_state"])
        WARP_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(WARP_DIR, 0o700)
        restore_optional_text(WARP_DIR / "wgcf-account.toml", full["warp_account"])
        restore_optional_text(WARP_DIR / "wgcf-profile.conf", full["warp_profile"])
        save_backup_schedule(full["backup_schedule"])
        warnings = apply_restored_services(full["xray"], full["xray_cascade"])
    return {"restored": name, "type": kind, "safety_backup": safety_backup, "warnings": warnings}


def export_backup(payload: dict[str, Any]) -> dict[str, Any]:
    name = validate_backup_name(str(payload.get("name") or ""))
    source = BACKUP_DIR / name
    if not source.is_file():
        raise ValidationError("Резервная копия не найдена")
    return {"name": name, "content": source.read_text(encoding="utf-8")}


def import_backup(payload: dict[str, Any]) -> dict[str, Any]:
    content = str(payload.get("content") or "")
    if not content or len(content.encode("utf-8")) > BACKUP_CONTENT_LIMIT:
        raise ValidationError("Файл backup пустой или превышает 3 МБ")
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Файл backup содержит неверный JSON: {exc}") from exc
    kind = backup_type(data)
    if kind == "full":
        validate_full_backup(data)
    elif isinstance(data, dict) and data.get("format") == BACKUP_FORMAT:
        validate_database_payload(data.get("database"))
        validate_labels_payload(data.get("panel_labels", {}))
    else:
        validate_database_payload(data)
    return {**write_backup(backup_name("panel" if kind == "full" else "users", "uploaded"), data), "type": kind}


def validate_backup_name(name: str) -> str:
    if not re.fullmatch(r"(?:passwords|users|panel)-[A-Za-z0-9_-]+\.json", name):
        raise ValidationError("Некорректное имя резервной копии")
    return name


def validate_database_payload(data: Any) -> None:
    if not isinstance(data, dict):
        raise ValidationError("Резервная копия должна содержать JSON-объект")
    if not isinstance(data.get("passwords"), dict) or not isinstance(data.get("devices", {}), dict):
        raise ValidationError("В backup отсутствуют корректные passwords/devices")


def version_parts(value: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+(?:\.\d+){1,3}", value):
        raise ValidationError(f"Некорректная версия панели: {value}")
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * (4 - len(parts))


def panel_version(payload: dict[str, Any]) -> dict[str, Any]:
    current = str(payload.get("current_version") or "0.0.0")
    version_parts(current)
    request = urllib.request.Request(PANEL_VERSION_URL, headers={"User-Agent": "wdtt-control-panel"})
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            source = response.read(128 * 1024).decode("utf-8", "replace")
        match = re.search(r'^PANEL_VERSION="([0-9.]+)"', source, re.MULTILINE)
        if not match:
            raise ValueError("PANEL_VERSION не найден")
        latest = match.group(1)
        return {
            "current": current,
            "latest": latest,
            "update_available": version_parts(latest) > version_parts(current),
        }
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return {"current": current, "latest": "", "update_available": False, "error": str(exc)}


def start_panel_update(payload: dict[str, Any]) -> dict[str, Any]:
    if not PANEL_UPDATE_COMMAND.exists():
        raise AdminError(f"Команда обновления не найдена: {PANEL_UPDATE_COMMAND}")
    if SKIP_SYSTEMD:
        return {"scheduled": True, "state": "test"}
    unit = f"wdtt-panel-self-update-{int(time.time())}"
    result = run(
        [
            "systemd-run",
            "--quiet",
            "--collect",
            f"--unit={unit}",
            "--on-active=3s",
            str(PANEL_UPDATE_COMMAND),
        ],
        timeout=20,
    )
    if result.returncode != 0:
        raise AdminError(result.stderr.strip() or "Не удалось запланировать обновление панели")
    return {"scheduled": True, "unit": unit}


def schedule_certificate_renew(payload: dict[str, Any]) -> dict[str, Any]:
    if SKIP_SYSTEMD:
        return {"scheduled": True, "state": "test"}
    unit = f"wdtt-panel-cert-refresh-{int(time.time())}"
    result = run(
        ["systemd-run", "--quiet", "--collect", f"--unit={unit}", "--on-active=2s", str(PANEL_RENEW_COMMAND), "renew-cert"],
        timeout=20,
    )
    if result.returncode != 0:
        raise AdminError(result.stderr.strip() or "Не удалось запланировать обновление сертификата")
    return {"scheduled": True, "unit": unit}


def export_certificate(payload: dict[str, Any]) -> dict[str, Any]:
    path = Path(str(payload.get("certificate_path") or ""))
    if not path.is_file():
        raise ValidationError("Файл сертификата не найден")
    return {"name": "wdtt-panel-certificate.pem", "content": path.read_text(encoding="utf-8")}


def read_stats() -> dict[str, Any]:
    try:
        data = json.loads(STATS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def journal_logs(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        limit = max(20, min(int(payload.get("limit", 1000)), 5000))
    except (TypeError, ValueError):
        limit = 1000
    source = str(payload.get("source") or "wdtt")
    sources = {
        "wdtt": ([SERVICE], "WDTT"),
        "xray": ([XRAY_SERVICE], "Xray / WARP"),
        "cascade": ([XRAY_CASCADE_SERVICE], "Каскад RU → EU"),
        "panel": (["wdtt-panel.service"], "Панель"),
        "nginx": (["nginx.service"], "Nginx"),
        "all": ([SERVICE, XRAY_SERVICE, XRAY_CASCADE_SERVICE, "wdtt-panel.service", "nginx.service"], "Все службы панели"),
    }
    if source == "installer":
        path = INSTALL_LOG_FILE
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
        except OSError as exc:
            raise AdminError(f"Не удалось прочитать журнал установщика: {exc}") from exc
        return {"lines": lines, "source": source, "title": "Установщик", "units": [], "limit": limit}
    if source == "xray-access":
        try:
            lines = XRAY_ACCESS_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:] if XRAY_ACCESS_LOG.is_file() else []
        except OSError as exc:
            raise AdminError(f"Не удалось прочитать журнал маршрутов Xray: {exc}") from exc
        return {
            "lines": lines,
            "source": source,
            "title": "Xray: домены и маршруты",
            "units": [] if SKIP_SYSTEMD else [{"unit": XRAY_SERVICE, "active": run(["systemctl", "is-active", "--quiet", XRAY_SERVICE], timeout=15).returncode == 0}],
            "limit": limit,
        }
    if source == "xray-errors":
        try:
            lines = XRAY_ERROR_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:] if XRAY_ERROR_LOG.is_file() else []
        except OSError as exc:
            raise AdminError(f"Не удалось прочитать журнал ошибок Xray: {exc}") from exc
        return {
            "lines": lines,
            "source": source,
            "title": "Xray: ошибки соединений",
            "units": [] if SKIP_SYSTEMD else [{"unit": XRAY_SERVICE, "active": run(["systemctl", "is-active", "--quiet", XRAY_SERVICE], timeout=15).returncode == 0}],
            "limit": limit,
        }
    if source not in sources:
        raise ValidationError("Неизвестный источник журнала")
    units, title = sources[source]
    if SKIP_SYSTEMD:
        return {"lines": [], "source": source, "title": title, "units": [], "limit": limit}
    command = ["journalctl"]
    for unit in units:
        command.extend(["-u", unit])
    command.extend(["-n", str(limit), "--no-pager", "--all", "-o", "short-iso"])
    result = run(command, timeout=45)
    if result.returncode != 0:
        raise AdminError(result.stderr.strip() or "Не удалось прочитать journalctl")
    states = [
        {"unit": unit, "active": run(["systemctl", "is-active", "--quiet", unit], timeout=15).returncode == 0}
        for unit in units
    ]
    return {"lines": result.stdout.splitlines(), "source": source, "title": title, "units": states, "limit": limit}


def directory_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    try:
        iterator = path.rglob("*")
    except OSError:
        return 0
    for item in iterator:
        try:
            if item.is_file() or item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def parse_size_text(value: str) -> int | None:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGTPE]?)(?:i?B)?", value, re.IGNORECASE)
    if not match:
        return None
    number = float(match.group(1))
    unit = match.group(2).upper()
    multipliers = {
        "": 1,
        "K": 1024,
        "M": 1024**2,
        "G": 1024**3,
        "T": 1024**4,
        "P": 1024**5,
        "E": 1024**6,
    }
    return int(number * multipliers.get(unit, 1))


def cleanup_os_error(exc: OSError) -> str:
    code = getattr(exc, "errno", None)
    if code == errno.EROFS:
        return "Файловая система только для чтения"
    if code in {errno.EACCES, errno.EPERM}:
        return "Нет прав на запись"
    return str(exc) or exc.__class__.__name__


def cleanup_target_error(target: str, exc: Exception) -> dict[str, Any]:
    if isinstance(exc, OSError):
        message = cleanup_os_error(exc)
    elif isinstance(exc, subprocess.TimeoutExpired):
        message = "Команда очистки не ответила вовремя"
    else:
        message = str(exc) or exc.__class__.__name__
    return {"target": target, "before_bytes": 0, "freed_bytes": 0, "remaining_bytes": 0, "available": False, "error": message}


def cleanup_log_files(apply: bool) -> dict[str, Any]:
    targets = {
        "installer": INSTALL_LOG_FILE,
        "xray_access": XRAY_ACCESS_LOG,
        "xray_errors": XRAY_ERROR_LOG,
        "nginx_access": NGINX_ACCESS_LOG,
        "nginx_error": NGINX_ERROR_LOG,
    }
    files = []
    freed = 0
    before_total = 0
    remaining = 0
    for name, path in targets.items():
        size = directory_size(path)
        before_total += size
        try:
            exists = path.is_file()
        except OSError as exc:
            exists = False
            file_info = {
                "name": name,
                "path": str(path),
                "bytes": size,
                "before_bytes": size,
                "after_bytes": size,
                "exists": False,
                "skipped": True,
                "error": cleanup_os_error(exc),
            }
            remaining += size
            files.append(file_info)
            continue
        file_info = {"name": name, "path": str(path), "bytes": size, "before_bytes": size, "exists": exists}
        if apply and exists:
            try:
                with path.open("w", encoding="utf-8"):
                    pass
                after_size = directory_size(path)
                try:
                    os.chmod(path, 0o640 if name.startswith("nginx") else 0o600)
                except OSError as exc:
                    file_info["warning"] = cleanup_os_error(exc)
                file_info["cleared"] = True
                file_info["after_bytes"] = after_size
                freed += max(0, size - after_size)
                remaining += after_size
            except OSError as exc:
                file_info["skipped"] = True
                file_info["error"] = cleanup_os_error(exc)
                file_info["after_bytes"] = size
                remaining += size
        else:
            freed += size
            file_info["after_bytes"] = size
            remaining += size
        files.append(file_info)
    return {"target": "service_logs", "before_bytes": before_total, "freed_bytes": freed, "remaining_bytes": remaining, "files": files}


def cleanup_package_cache(apply: bool) -> dict[str, Any]:
    cache_paths = [Path("/var/cache/apt/archives"), Path("/var/cache/dnf"), Path("/var/cache/yum"), Path("/var/cache/pacman/pkg")]
    before = sum(directory_size(path) for path in cache_paths)
    command: list[str] = []
    if shutil.which("apt-get"):
        command = ["apt-get", "clean"]
    elif shutil.which("dnf"):
        command = ["dnf", "clean", "all"]
    elif shutil.which("yum"):
        command = ["yum", "clean", "all"]
    elif shutil.which("paccache"):
        command = ["paccache", "-rk1"]
    if apply and command:
        result = run(command, timeout=120)
        if result.returncode != 0:
            raise AdminError(result.stderr.strip() or "Не удалось очистить кэш пакетного менеджера")
    remaining = sum(directory_size(path) for path in cache_paths) if apply else before
    freed = max(0, before - remaining) if apply else before
    return {
        "target": "package_cache",
        "before_bytes": before,
        "freed_bytes": freed,
        "remaining_bytes": remaining,
        "command": " ".join(command) if command else "",
    }


def cleanup_journal(apply: bool, keep_days: int) -> dict[str, Any]:
    if SKIP_SYSTEMD or not shutil.which("journalctl"):
        return {"target": "journal", "before_bytes": 0, "freed_bytes": 0, "remaining_bytes": 0, "available": False, "detail": "systemd journal недоступен"}
    usage = run(["journalctl", "--disk-usage"], timeout=20)
    before_detail = usage.stdout.strip() or usage.stderr.strip()
    before = parse_size_text(before_detail) or 0
    detail = before_detail
    remaining = before
    freed = before
    if apply:
        result = run(["journalctl", f"--vacuum-time={keep_days}d"], timeout=120)
        if result.returncode != 0:
            raise AdminError(result.stderr.strip() or "Не удалось очистить systemd journal")
        after_usage = run(["journalctl", "--disk-usage"], timeout=20)
        after_detail = after_usage.stdout.strip() or after_usage.stderr.strip()
        remaining = parse_size_text(after_detail) or 0
        freed = max(0, before - remaining)
        detail = after_detail or result.stdout.strip() or detail
    return {
        "target": "journal",
        "before_bytes": before,
        "freed_bytes": freed,
        "remaining_bytes": remaining,
        "available": True,
        "detail": detail,
    }


def cleanup_failed_units(apply: bool) -> dict[str, Any]:
    if SKIP_SYSTEMD or not shutil.which("systemctl"):
        return {"target": "failed_units", "before_bytes": 0, "freed_bytes": 0, "remaining_bytes": 0, "available": False}
    if apply:
        result = run(["systemctl", "reset-failed"], timeout=30)
        if result.returncode != 0:
            raise AdminError(result.stderr.strip() or "Не удалось сбросить failed-units")
    return {"target": "failed_units", "before_bytes": 0, "freed_bytes": 0, "remaining_bytes": 0, "available": True}


def cleanup_system(payload: dict[str, Any], apply: bool) -> dict[str, Any]:
    try:
        keep_days = max(1, min(int(payload.get("keep_days") or 14), 365))
    except (TypeError, ValueError):
        keep_days = 14
    raw_targets = payload.get("targets")
    allowed = {"service_logs", "journal", "package_cache", "failed_units"}
    targets = [str(item) for item in raw_targets] if isinstance(raw_targets, list) else ["service_logs", "journal", "package_cache"]
    targets = [target for target in dict.fromkeys(targets) if target in allowed]
    if not targets:
        raise ValidationError("Выберите хотя бы один безопасный раздел очистки")
    items = []
    for target in targets:
        try:
            if target == "service_logs":
                items.append(cleanup_log_files(apply))
            elif target == "journal":
                items.append(cleanup_journal(apply, keep_days))
            elif target == "package_cache":
                items.append(cleanup_package_cache(apply))
            elif target == "failed_units":
                items.append(cleanup_failed_units(apply))
        except (AdminError, OSError, subprocess.TimeoutExpired) as exc:
            items.append(cleanup_target_error(target, exc))
    return {
        "applied": apply,
        "keep_days": keep_days,
        "targets": targets,
        "items": items,
        "estimated_freed_bytes": sum(int(item.get("freed_bytes") or 0) for item in items),
    }


def certificate_info(path: str) -> dict[str, Any]:
    if not path:
        return {}
    cert_path = Path(path)
    if not cert_path.is_file():
        return {"path": path, "exists": False}
    try:
        decoded = ssl._ssl._test_decode_cert(str(cert_path))
        expires = decoded.get("notAfter", "")
        expires_at = int(ssl.cert_time_to_seconds(expires)) if expires else 0
        return {
            "path": path,
            "exists": True,
            "expires_at": expires_at,
            "days_left": round((expires_at - time.time()) / 86400, 1) if expires_at else None,
            "subject_alt_name": decoded.get("subjectAltName", []),
        }
    except (OSError, ValueError, ssl.SSLError) as exc:
        return {"path": path, "exists": True, "error": str(exc)}


def cpu_usage() -> float:
    def snapshot() -> tuple[int, int]:
        fields = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()[1:]
        values = [int(value) for value in fields]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        return sum(values), idle

    try:
        total_a, idle_a = snapshot()
        time.sleep(0.08)
        total_b, idle_b = snapshot()
        total = total_b - total_a
        return round(100 * (1 - (idle_b - idle_a) / total), 1) if total > 0 else 0.0
    except (OSError, ValueError, IndexError):
        return 0.0


def memory_usage() -> dict[str, Any]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, raw = line.split(":", 1)
            values[key] = int(raw.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        return {"total": 0, "used": 0, "available": 0, "percent": 0.0}
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    used = max(0, total - available)
    return {
        "total": total,
        "used": used,
        "available": available,
        "percent": round(used * 100 / total, 1) if total else 0.0,
    }


def local_tls_status(host: str, port: int) -> dict[str, Any]:
    result: dict[str, Any] = {"local_tls_ok": False, "listening": False, "error": ""}
    if SKIP_SYSTEMD or not host or not port:
        return result
    listener = run(["ss", "-ltn", f"sport = :{port}"], timeout=10)
    result["listening"] = listener.returncode == 0 and "LISTEN" in listener.stdout
    try:
        context = ssl._create_unverified_context()
        with socket.create_connection(("127.0.0.1", port), timeout=4) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                result["local_tls_ok"] = True
    except OSError as exc:
        result["error"] = str(exc)
    return result


def default_cascade_settings() -> dict[str, Any]:
    return {
        "enabled": False,
        "outbound": "vless",
        "vless_uri": "",
        "default_outbound": "direct",
        "rules": [],
        "geofiles": [],
    }


def load_cascade_settings() -> dict[str, Any]:
    settings = default_cascade_settings()
    if CASCADE_SETTINGS.is_file():
        try:
            saved = json.loads(CASCADE_SETTINGS.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                settings.update(saved)
        except (OSError, json.JSONDecodeError):
            pass
    settings["rules"] = settings.get("rules") if isinstance(settings.get("rules"), list) else []
    settings["geofiles"] = settings.get("geofiles") if isinstance(settings.get("geofiles"), list) else []
    return settings


def save_private_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def parse_vless_uri(uri: str) -> dict[str, Any]:
    parsed = urlsplit(uri.strip())
    if parsed.scheme.lower() != "vless" or not parsed.username or not parsed.hostname or not parsed.port:
        raise ValidationError("Нужна полная ссылка vless://UUID@host:port")
    try:
        user_id = str(uuid.UUID(unquote(parsed.username)))
    except (ValueError, binascii.Error) as exc:
        raise ValidationError("В VLESS-ссылке указан некорректный UUID") from exc
    query = {key: values[-1] for key, values in parse_qs(parsed.query).items() if values}
    outbound: dict[str, Any] = {
        "type": "vless",
        "tag": "cascade-vless",
        "server": parsed.hostname,
        "server_port": parsed.port,
        "uuid": user_id,
    }
    if query.get("flow"):
        outbound["flow"] = query["flow"]
    security = query.get("security", "none").lower()
    if security in {"tls", "reality"}:
        tls: dict[str, Any] = {
            "enabled": True,
            "server_name": query.get("sni") or parsed.hostname,
            "insecure": query.get("allowInsecure", "0") in {"1", "true"},
        }
        if query.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": query["fp"]}
        if security == "reality":
            public_key = query.get("pbk") or query.get("publicKey")
            if not public_key:
                raise ValidationError("Для VLESS Reality требуется параметр pbk")
            tls["reality"] = {
                "enabled": True,
                "public_key": public_key,
                "short_id": query.get("sid", ""),
            }
        outbound["tls"] = tls
    transport_type = query.get("type", "tcp").lower()
    if transport_type in {"ws", "http", "httpupgrade", "grpc"}:
        transport: dict[str, Any] = {"type": transport_type}
        if transport_type in {"ws", "http", "httpupgrade"} and query.get("path"):
            transport["path"] = unquote(query["path"])
        if transport_type == "grpc" and query.get("serviceName"):
            transport["service_name"] = query["serviceName"]
        host = query.get("host")
        if host and transport_type in {"ws", "http", "httpupgrade"}:
            transport["headers"] = {"Host": host}
        outbound["transport"] = transport
    return outbound


def warp_endpoint() -> dict[str, Any]:
    profile = WARP_DIR / "wgcf-profile.conf"
    if not profile.is_file():
        raise ValidationError("Профиль WARP еще не создан")
    parser = configparser.ConfigParser(strict=False)
    parser.read(profile, encoding="utf-8")
    interface = parser["Interface"]
    peer = parser["Peer"]
    endpoint = peer.get("Endpoint", "engage.cloudflareclient.com:2408")
    host, _, port = endpoint.rpartition(":")
    try:
        reserved = [int(item.strip()) for item in peer.get("Reserved", "0,0,0").split(",")]
    except ValueError:
        reserved = [0, 0, 0]
    return {
        "type": "wireguard",
        "tag": "warp",
        "system": False,
        "mtu": int(interface.get("MTU", "1280")),
        "address": [item.strip() for item in interface.get("Address", "").split(",") if item.strip()],
        "private_key": interface.get("PrivateKey", ""),
        "peers": [
            {
                "address": host,
                "port": int(port or 2408),
                "public_key": peer.get("PublicKey", ""),
                "allowed_ips": [item.strip() for item in peer.get("AllowedIPs", "0.0.0.0/0,::/0").split(",")],
                "reserved": reserved,
            }
        ],
    }


def split_rule_values(value: Any) -> list[str]:
    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"[\s,;]+", str(value or ""))
    return [str(item).strip() for item in items if str(item).strip()]


def normalize_route_rule(raw: Any, index: int) -> dict[str, Any] | None:
    if not isinstance(raw, dict) or raw.get("enabled", True) is False:
        return None
    target = str(raw.get("outbound") or "direct")
    if target not in {"direct", "vless", "warp", "block"}:
        raise ValidationError(f"Правило {index + 1}: неизвестный маршрут")
    rule: dict[str, Any] = {"action": "reject"} if target == "block" else {
        "action": "route",
        "outbound": {"direct": "direct", "vless": "cascade-vless", "warp": "warp"}[target],
    }
    match_type = str(raw.get("type") or "domain")
    values = split_rule_values(raw.get("values"))
    if match_type == "domain":
        rule["domain_suffix"] = [value.lstrip(".") for value in values]
    elif match_type == "ip":
        try:
            rule["ip_cidr"] = [str(ipaddress.ip_network(value, strict=False)) for value in values]
        except ValueError as exc:
            raise ValidationError(f"Правило {index + 1}: некорректный IP/CIDR") from exc
    elif match_type == "port":
        rule["port"] = [int(value) for value in values]
    elif match_type == "protocol":
        rule["protocol"] = values
    elif match_type == "source_user":
        data = load_database()
        source_ips = []
        for password in values:
            entry = data["passwords"].get(password) or {}
            device = data["devices"].get(str(entry.get("device_id") or "")) or {}
            if device.get("ip"):
                source_ips.append(f"{device['ip']}/32")
        if not source_ips:
            raise ValidationError(f"Правило {index + 1}: выбранные пользователи еще не имеют IP")
        rule["source_ip_cidr"] = source_ips
    elif match_type in {"builtin", "geofile"}:
        rule["rule_set"] = values
    else:
        raise ValidationError(f"Правило {index + 1}: неизвестный тип совпадения")
    if not values:
        raise ValidationError(f"Правило {index + 1}: не заданы значения")
    return rule


def geofile_rule_sets(settings: dict[str, Any]) -> list[dict[str, Any]]:
    result = [
        {
            "type": "remote",
            "tag": tag,
            "format": "binary",
            "url": url,
            "update_interval": "1d",
        }
        for tag, url in BUILTIN_RULESETS.items()
    ]
    for item in settings.get("geofiles", []):
        if not isinstance(item, dict) or not item.get("tag"):
            continue
        tag = re.sub(r"[^a-zA-Z0-9_-]", "-", str(item["tag"]))[:64]
        url = str(item.get("url") or "")
        if url and item.get("kind") == "srs" and not item.get("source_path"):
            result.append(
                {
                    "type": "remote",
                    "tag": tag,
                    "format": str(item.get("format") or "binary"),
                    "url": url,
                    "update_interval": str(item.get("update_interval") or "1d"),
                }
            )
        elif item.get("path"):
            result.append({"type": "local", "tag": tag, "format": "binary", "path": str(item["path"])})
    return result


def build_cascade_config(settings: dict[str, Any]) -> dict[str, Any]:
    outbounds: list[dict[str, Any]] = [{"type": "direct", "tag": "direct"}]
    endpoints: list[dict[str, Any]] = []
    if settings.get("vless_uri"):
        outbounds.append(parse_vless_uri(str(settings["vless_uri"])))
    if (WARP_DIR / "wgcf-profile.conf").is_file():
        endpoints.append(warp_endpoint())
    rules = [{"action": "sniff"}, {"ip_is_private": True, "action": "route", "outbound": "direct"}]
    for index, raw in enumerate(settings.get("rules", [])):
        rule = normalize_route_rule(raw, index)
        if rule:
            rules.append(rule)
    default = str(settings.get("default_outbound") or "direct")
    final = {"direct": "direct", "vless": "cascade-vless", "warp": "warp"}.get(default)
    if not final:
        raise ValidationError("Некорректный маршрут по умолчанию")
    tags = {item.get("tag") for item in outbounds + endpoints}
    for rule in rules:
        if rule.get("outbound") and rule["outbound"] not in tags:
            raise ValidationError(f"Для правила не настроен маршрут {rule['outbound']}")
    if final not in tags:
        raise ValidationError(f"Маршрут по умолчанию {final} не настроен")
    config: dict[str, Any] = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "tun",
                "tag": "wdtt-cascade-in",
                "interface_name": "wdtt-cascade0",
                "address": ["172.31.255.1/30"],
                "mtu": 1280,
                "auto_route": True,
                "auto_redirect": True,
                "strict_route": True,
                "include_interface": ["wdtt0"],
                "stack": "system",
            }
        ],
        "outbounds": outbounds,
        "route": {"auto_detect_interface": True, "rules": rules, "rule_set": geofile_rule_sets(settings), "final": final},
        "experimental": {"cache_file": {"enabled": True, "path": str(GEOFILES_DIR / "cache.db")}},
    }
    if endpoints:
        config["endpoints"] = endpoints
    return config


def cascade_status(payload: dict[str, Any]) -> dict[str, Any]:
    settings = load_cascade_settings()
    active = False
    logs: list[str] = []
    version = ""
    if not SKIP_SYSTEMD:
        active = run(["systemctl", "is-active", "--quiet", CASCADE_SERVICE]).returncode == 0
        version_result = run(["sing-box", "version"], timeout=10) if shutil.which("sing-box") else None
        if version_result and version_result.returncode == 0:
            version = version_result.stdout.splitlines()[0]
        journal = run(["journalctl", "-u", CASCADE_SERVICE, "-n", "30", "--no-pager", "-o", "cat"], timeout=15)
        if journal.returncode == 0:
            logs = journal.stdout.splitlines()
    public = dict(settings)
    if public.get("vless_uri"):
        parsed = urlsplit(str(public["vless_uri"]))
        public["vless_summary"] = f"{parsed.hostname}:{parsed.port}"
    return {
        "settings": public,
        "active": active,
        "installed": bool(shutil.which("sing-box")),
        "version": version,
        "warp_ready": (WARP_DIR / "wgcf-profile.conf").is_file(),
        "logs": logs,
        "builtin_rule_sets": list(BUILTIN_RULESETS),
    }


def cascade_save(payload: dict[str, Any]) -> dict[str, Any]:
    settings = default_cascade_settings()
    settings.update({key: payload[key] for key in settings if key in payload})
    settings["rules"] = payload.get("rules") if isinstance(payload.get("rules"), list) else []
    settings["geofiles"] = payload.get("geofiles") if isinstance(payload.get("geofiles"), list) else []
    settings["enabled"] = bool(payload.get("enabled", False))
    config = build_cascade_config(settings)
    save_private_json(CASCADE_SETTINGS, settings)
    save_private_json(CASCADE_CONFIG, config)
    if not SKIP_SYSTEMD and shutil.which("sing-box"):
        checked = run(["sing-box", "check", "-c", str(CASCADE_CONFIG)], timeout=30)
        if checked.returncode != 0:
            raise ValidationError(checked.stderr.strip() or "sing-box отклонил конфигурацию")
        action = "enable" if settings["enabled"] else "disable"
        run(["systemctl", action, CASCADE_SERVICE], timeout=30)
        run(["systemctl", "restart" if settings["enabled"] else "stop", CASCADE_SERVICE], timeout=45)
    return cascade_status({})


def schedule_cascade_runtime(payload: dict[str, Any]) -> dict[str, Any]:
    if SKIP_SYSTEMD:
        return {"scheduled": True, "state": "test"}
    unit = f"wdtt-cascade-install-{int(time.time())}"
    result = run(
        ["systemd-run", "--quiet", "--collect", f"--unit={unit}", "--on-active=2s", str(CASCADE_INSTALL_COMMAND), "install-cascade-runtime"],
        timeout=20,
    )
    if result.returncode != 0:
        raise AdminError(result.stderr.strip() or "Не удалось запланировать установку sing-box/WARP")
    return {"scheduled": True, "unit": unit}


def create_warp(payload: dict[str, Any]) -> dict[str, Any]:
    if not shutil.which("wgcf"):
        raise ValidationError("Сначала установите компоненты каскада")
    WARP_DIR.mkdir(parents=True, exist_ok=True)
    account = WARP_DIR / "wgcf-account.toml"
    if not account.is_file():
        registered = run(["wgcf", "register", "--accept-tos"], timeout=60, cwd=WARP_DIR)
        if registered.returncode != 0:
            raise AdminError(registered.stderr.strip() or "Не удалось зарегистрировать WARP")
        generated = WARP_DIR / "wgcf-account.toml"
        if generated.is_file():
            account = generated
    generated = run(["wgcf", "generate"], timeout=60, cwd=WARP_DIR)
    if generated.returncode != 0:
        raise AdminError(generated.stderr.strip() or "Не удалось создать профиль WARP")
    profile = WARP_DIR / "wgcf-profile.conf"
    os.chmod(account, 0o600)
    os.chmod(WARP_DIR / "wgcf-profile.conf", 0o600)
    return {"warp_ready": True}


def geofile_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    filename = Path(str(payload.get("name") or "geofile.srs")).name
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", filename):
        raise ValidationError("Некорректное имя GeoFile")
    tag = re.sub(r"[^A-Za-z0-9_-]", "-", str(payload.get("tag") or Path(filename).stem))[:64]
    if not tag:
        raise ValidationError("Укажите tag GeoFile")
    kind = str(payload.get("kind") or "srs").lower()
    if kind not in {"srs", "geoip", "geosite"}:
        raise ValidationError("Поддерживаются SRS, geoip.dat и geosite.dat")
    content = str(payload.get("content") or "")
    if not content:
        raise ValidationError("GeoFile пустой")
    try:
        raw = base64.b64decode(content, validate=True)
    except ValueError as exc:
        raise ValidationError("GeoFile передан в неверном формате") from exc
    if not raw or len(raw) > 64 * 1024 * 1024:
        raise ValidationError("GeoFile пустой или превышает 64 МБ")
    GEOFILES_DIR.mkdir(parents=True, exist_ok=True)
    source = GEOFILES_DIR / filename
    source.write_bytes(raw)
    os.chmod(source, 0o600)
    path = source
    category = str(payload.get("category") or "").strip()
    if kind in {"geoip", "geosite"}:
        if not category:
            raise ValidationError("Для .dat укажите категорию, например RU")
        converter = shutil.which("geodat2srs")
        if not converter:
            raise ValidationError("Конвертер GeoFiles не установлен; установите компоненты каскада")
        output_dir = GEOFILES_DIR / f"converted-{tag}"
        output_dir.mkdir(parents=True, exist_ok=True)
        prefix = f"{tag}-"
        converted = run(
            [converter, kind, "-i", str(source), "-o", str(output_dir), "--prefix", prefix],
            timeout=180,
        )
        if converted.returncode != 0:
            raise ValidationError(converted.stderr.strip() or "Не удалось преобразовать GeoFile")
        candidates = list(output_dir.glob(f"{prefix}{category.lower()}*.srs")) + list(
            output_dir.glob(f"{prefix}{category.upper()}*.srs")
        )
        if not candidates:
            raise ValidationError(f"Категория {category} не найдена в {filename}")
        path = candidates[0]
    return {
        "tag": tag,
        "kind": kind,
        "category": category,
        "source_path": str(source),
        "path": str(path),
        "url": str(payload.get("url") or ""),
        "auto_update": bool(payload.get("auto_update", False)),
        "update_interval": str(payload.get("update_interval") or "1d"),
        "updated_at": int(time.time()),
    }


def upload_geofile(payload: dict[str, Any]) -> dict[str, Any]:
    item = geofile_from_payload(payload)
    settings = load_cascade_settings()
    settings["geofiles"] = [entry for entry in settings["geofiles"] if entry.get("tag") != item["tag"]]
    settings["geofiles"].append(item)
    save_private_json(CASCADE_SETTINGS, settings)
    save_private_json(CASCADE_CONFIG, build_cascade_config(settings))
    return item


def refresh_geofile(payload: dict[str, Any]) -> dict[str, Any]:
    tag = str(payload.get("tag") or "")
    settings = load_cascade_settings()
    item = next((entry for entry in settings["geofiles"] if entry.get("tag") == tag), None)
    if not item or not item.get("url"):
        raise ValidationError("Для GeoFile не задан URL обновления")
    request = urllib.request.Request(str(item["url"]), headers={"User-Agent": "wdtt-control-panel"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(64 * 1024 * 1024 + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise AdminError(f"Не удалось загрузить GeoFile: {exc}") from exc
    if len(raw) > 64 * 1024 * 1024:
        raise ValidationError("Удаленный GeoFile превышает 64 МБ")
    updated = geofile_from_payload(
        {
            **item,
            "name": Path(str(item.get("source_path") or f"{tag}.srs")).name,
            "content": base64.b64encode(raw).decode("ascii"),
        }
    )
    settings["geofiles"] = [updated if entry.get("tag") == tag else entry for entry in settings["geofiles"]]
    save_private_json(CASCADE_SETTINGS, settings)
    save_private_json(CASCADE_CONFIG, build_cascade_config(settings))
    if not SKIP_SYSTEMD and run(["systemctl", "is-active", "--quiet", CASCADE_SERVICE]).returncode == 0:
        run(["systemctl", "restart", CASCADE_SERVICE], timeout=45)
    return updated


def interval_seconds(value: str) -> int:
    match = re.fullmatch(r"(\d+)([mhd])", value.strip().lower())
    if not match:
        return 86400
    multiplier = {"m": 60, "h": 3600, "d": 86400}[match.group(2)]
    return max(3600, int(match.group(1)) * multiplier)


def refresh_auto_geofiles(payload: dict[str, Any]) -> dict[str, Any]:
    settings = load_cascade_settings()
    refreshed = []
    errors = []
    now = int(time.time())
    for item in list(settings.get("geofiles", [])):
        if not item.get("auto_update") or not item.get("url"):
            continue
        due = int(item.get("updated_at") or 0) + interval_seconds(str(item.get("update_interval") or "1d"))
        if not payload.get("force") and due > now:
            continue
        try:
            refreshed.append(refresh_geofile({"tag": item.get("tag")}))
        except (ValidationError, AdminError) as exc:
            errors.append({"tag": item.get("tag"), "error": str(exc)})
    return {"refreshed": refreshed, "errors": errors}


def default_xray_settings() -> dict[str, Any]:
    return {
        "enabled": False,
        "mode": "managed",
        "log_level": "warning",
        "access_log": False,
        "gateway_enabled": False,
        "gateway_source_cidr": "10.66.66.0/24",
        "gateway_inbound_port": 12346,
        "inbounds": [],
        "outbounds": [],
        "routing_rules": [],
        "routes": [],
        "friendly_rules": [],
        "raw_config": "",
        "geofiles": [
            {
                **item,
                "enabled": True,
                "auto_update": True,
                "update_interval": "6h",
                "updated_at": 0,
            }
            for item in XRAY_DEFAULT_GEOFILES
        ],
    }


def xray_tag(value: Any, label: str = "tag") -> str:
    value = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
        raise ValidationError(f"Некорректный {label}")
    return value


def xray_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label} должен быть JSON-объектом")
    try:
        encoded = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{label} содержит неподдерживаемые значения") from exc
    if len(encoded.encode("utf-8")) > 256 * 1024:
        raise ValidationError(f"{label} превышает 256 КБ")
    return value


def load_xray_settings() -> dict[str, Any]:
    settings = default_xray_settings()
    if XRAY_SETTINGS.is_file():
        try:
            saved = json.loads(XRAY_SETTINGS.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                settings.update(saved)
        except (OSError, json.JSONDecodeError):
            pass
    settings["mode"] = settings.get("mode") if settings.get("mode") in {"managed", "raw"} else "managed"
    settings["log_level"] = str(settings.get("log_level") or "warning")
    settings["access_log"] = bool(settings.get("access_log", False))
    settings["gateway_enabled"] = bool(settings.get("gateway_enabled", False))
    try:
        gateway_network = ipaddress.ip_network(str(settings.get("gateway_source_cidr") or ""), strict=False)
        settings["gateway_source_cidr"] = str(gateway_network) if gateway_network.version == 4 and gateway_network.prefixlen <= 30 else "10.66.66.0/24"
    except ValueError:
        settings["gateway_source_cidr"] = "10.66.66.0/24"
    try:
        gateway_port = int(settings.get("gateway_inbound_port") or 12346)
        settings["gateway_inbound_port"] = gateway_port if 1024 <= gateway_port <= 65535 else 12346
    except (TypeError, ValueError):
        settings["gateway_inbound_port"] = 12346
    for key in ("inbounds", "outbounds", "routing_rules", "routes", "friendly_rules", "geofiles"):
        settings[key] = settings.get(key) if isinstance(settings.get(key), list) else []
    settings["raw_config"] = str(settings.get("raw_config") or "")

    defaults = {item["tag"]: item for item in default_xray_settings()["geofiles"]}
    saved_files = {
        str(item.get("tag")): item for item in settings["geofiles"] if isinstance(item, dict) and item.get("tag")
    }
    for tag, default in defaults.items():
        saved = saved_files.get(tag)
        if saved and str(saved.get("url") or "") == LEGACY_XRAY_GEOFILE_URLS.get(tag):
            saved_files[tag] = {**saved, "url": default["url"], "update_interval": "6h", "updated_at": 0}
    settings["geofiles"] = [
        {**item, **saved_files.pop(tag, {})} for tag, item in defaults.items()
    ] + list(saved_files.values())
    return settings


def normalize_xray_geofiles(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 32:
        raise ValidationError("Некорректный список GeoFiles")
    result: list[dict[str, Any]] = []
    tags: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValidationError(f"GeoFile {index + 1}: нужен объект")
        tag = xray_tag(raw.get("tag"), "tag GeoFile")
        if tag in tags:
            raise ValidationError(f"GeoFile с tag {tag} указан дважды")
        tags.add(tag)
        filename = Path(str(raw.get("filename") or f"{tag}.dat")).name
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", filename):
            raise ValidationError(f"GeoFile {tag}: некорректное имя файла")
        url = str(raw.get("url") or "").strip()
        if url:
            parsed = urlsplit(url)
            if parsed.scheme != "https" or not parsed.hostname:
                raise ValidationError(f"GeoFile {tag}: разрешены только HTTPS URL")
        result.append(
            {
                "tag": tag,
                "filename": filename,
                "url": url,
                "enabled": bool(raw.get("enabled", True)),
                "auto_update": bool(raw.get("auto_update", True)),
                "update_interval": str(raw.get("update_interval") or "1d"),
                "updated_at": int(raw.get("updated_at") or 0),
            }
        )
    return result


def normalize_xray_route_name(value: Any, fallback: str) -> str:
    name = str(value or fallback).strip()
    if not name or len(name) > 80 or any(ord(char) < 32 for char in name):
        raise ValidationError("Укажите понятное название маршрута длиной до 80 символов")
    return name


def normalize_xray_routes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 64:
        raise ValidationError("Некорректный список маршрутов Xray")
    result: list[dict[str, Any]] = []
    tags: set[str] = {"direct", "block", "warp", "eu-vless"}
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValidationError(f"Маршрут {index + 1}: нужен объект")
        route_type = str(raw.get("type") or "vless").lower()
        if route_type != "vless":
            raise ValidationError(f"Маршрут {index + 1}: пока поддерживается VLESS; для другого протокола используйте экспертный режим")
        tag = xray_tag(raw.get("tag"), "tag маршрута")
        if tag in tags:
            raise ValidationError(f"Маршрут с tag {tag} уже существует или зарезервирован")
        tags.add(tag)
        uri = str(raw.get("vless_uri") or "").strip()
        # Проверяем ссылку сразу: в рабочую конфигурацию попадает только разобранный VLESS.
        parse_xray_vless_uri(uri, tag)
        result.append(
            {
                "name": normalize_xray_route_name(raw.get("name"), tag),
                "tag": tag,
                "type": "vless",
                "vless_uri": uri,
                "enabled": bool(raw.get("enabled", True)),
            }
        )
    return result


def normalize_xray_domain(value: str, label: str) -> str:
    domain = value.strip().lower()
    for prefix in ("domain:", "full:", "*." ):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.lstrip(".")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", domain) or ".." in domain:
        raise ValidationError(f"Некорректный домен в правиле {label}: {value}")
    return domain


def normalize_xray_geo_categories(value: Any, prefix: str, label: str) -> list[str]:
    result: list[str] = []
    for raw in split_rule_values(value):
        category = raw.strip()
        if category.lower().startswith(prefix):
            category = category[len(prefix):]
        result.append(xray_tag(category, f"категория {label}"))
    return list(dict.fromkeys(result))


def normalize_xray_friendly_rules(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 128:
        raise ValidationError("Некорректный список простых правил маршрутизации")
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValidationError(f"Правило {index + 1}: нужен объект")
        name = normalize_xray_route_name(raw.get("name"), f"Правило {index + 1}")
        outbound = xray_tag(raw.get("outbound") or "direct", "исходящий правила")
        domains = [normalize_xray_domain(item, name) for item in split_rule_values(raw.get("domains"))]
        ip_values = split_rule_values(raw.get("ip_cidrs"))
        try:
            ip_cidrs = [str(ipaddress.ip_network(item, strict=False)) for item in ip_values]
        except ValueError as exc:
            raise ValidationError(f"Правило {name}: укажите корректный IP или CIDR") from exc
        geosite = normalize_xray_geo_categories(raw.get("geosite"), "geosite:", "GeoSite")
        geoip = normalize_xray_geo_categories(raw.get("geoip"), "geoip:", "GeoIP")
        if outbound == "warp" and set(domains).intersection(GOOGLE_AI_DOMAIN_MARKERS):
            domains = list(dict.fromkeys([*domains, *GOOGLE_AI_DOMAINS]))
            ip_cidrs = list(dict.fromkeys([*ip_cidrs, *GOOGLE_AI_IPV4_CIDRS]))
        if len(domains) + len(ip_cidrs) + len(geosite) + len(geoip) > 256:
            raise ValidationError(f"Правило {name}: не более 256 значений")
        if bool(raw.get("enabled", True)) and not (domains or ip_cidrs or geosite or geoip):
            raise ValidationError(f"Правило {name}: добавьте домен, IP/CIDR или Geo-категорию")
        result.append(
            {
                "name": name,
                "enabled": bool(raw.get("enabled", True)),
                "outbound": outbound,
                "domains": list(dict.fromkeys(domains)),
                "ip_cidrs": list(dict.fromkeys(ip_cidrs)),
                "geosite": geosite,
                "geoip": geoip,
            }
        )
    return result


def normalize_xray_settings(payload: dict[str, Any]) -> dict[str, Any]:
    settings = default_xray_settings()
    settings["enabled"] = bool(payload.get("enabled", False))
    settings["mode"] = str(payload.get("mode") or "managed")
    if settings["mode"] not in {"managed", "raw"}:
        raise ValidationError("Выберите режим Xray: managed или raw")
    settings["log_level"] = str(payload.get("log_level") or "warning")
    if settings["log_level"] not in {"debug", "info", "warning", "error", "none"}:
        raise ValidationError("Некорректный уровень журнала Xray")
    settings["access_log"] = bool(payload.get("access_log", False))
    settings["gateway_enabled"] = bool(payload.get("gateway_enabled", False))
    if settings["gateway_enabled"] and not settings["enabled"]:
        raise ValidationError("Сначала включите Xray, затем включайте шлюз WDTT → Xray")
    gateway_source = str(payload.get("gateway_source_cidr") or settings["gateway_source_cidr"]).strip()
    try:
        gateway_network = ipaddress.ip_network(gateway_source, strict=False)
    except ValueError as exc:
        raise ValidationError("Укажите корректную IPv4-подсеть пользователей WDTT для шлюза Xray") from exc
    if gateway_network.version != 4 or gateway_network.prefixlen > 30:
        raise ValidationError("Для шлюза Xray нужна IPv4-подсеть WDTT не менее двух адресов")
    settings["gateway_source_cidr"] = str(gateway_network)
    try:
        gateway_port = int(payload.get("gateway_inbound_port") or settings["gateway_inbound_port"])
    except (TypeError, ValueError) as exc:
        raise ValidationError("Укажите корректный локальный порт шлюза Xray") from exc
    if not 1024 <= gateway_port <= 65535:
        raise ValidationError("Порт шлюза Xray должен быть от 1024 до 65535")
    settings["gateway_inbound_port"] = gateway_port
    settings["geofiles"] = normalize_xray_geofiles(payload.get("geofiles", settings["geofiles"]))
    settings["routes"] = normalize_xray_routes(payload.get("routes", []))
    settings["friendly_rules"] = normalize_xray_friendly_rules(payload.get("friendly_rules", []))
    if settings["mode"] == "raw":
        if settings["gateway_enabled"]:
            raise ValidationError("Шлюз WDTT → Xray работает только в Managed-режиме")
        raw_config = str(payload.get("raw_config") or "").strip()
        if len(raw_config.encode("utf-8")) > 2 * 1024 * 1024:
            raise ValidationError("Raw Xray-конфигурация превышает 2 МБ")
        try:
            parsed = json.loads(raw_config)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Raw Xray-конфигурация содержит неверный JSON: {exc}") from exc
        xray_object(parsed, "Raw Xray-конфигурация")
        settings["raw_config"] = json.dumps(parsed, ensure_ascii=False, indent=2)
        return settings

    for key, label in (("inbounds", "Входящие"), ("outbounds", "Исходящие"), ("routing_rules", "Правила маршрутизации")):
        values = payload.get(key, [])
        if not isinstance(values, list) or len(values) > 100:
            raise ValidationError(f"{label}: некорректный список")
        settings[key] = [xray_object(item, f"{label} {index + 1}") for index, item in enumerate(values)]
    return settings


def build_xray_config(settings: dict[str, Any], extra_outbound_tags: set[str] | None = None) -> dict[str, Any]:
    if settings["mode"] == "raw":
        parsed = xray_object(json.loads(settings["raw_config"]), "Raw Xray-конфигурация")
        if settings.get("access_log"):
            raw_log = parsed.get("log") or {}
            if not isinstance(raw_log, dict):
                raise ValidationError("Raw Xray-конфигурация: log должен быть объектом")
            parsed["log"] = {**raw_log, "access": str(XRAY_ACCESS_LOG), "error": str(XRAY_ERROR_LOG)}
        return parsed

    inbounds: list[dict[str, Any]] = []
    for source in settings["inbounds"]:
        inbound = json.loads(json.dumps(source))
        if "sniffing" not in inbound:
            inbound["sniffing"] = {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": True,
            }
        inbounds.append(inbound)
    if settings.get("gateway_enabled"):
        if any(item.get("tag") == "wdtt-gateway-in" for item in inbounds):
            raise ValidationError("Tag wdtt-gateway-in зарезервирован для шлюза WDTT → Xray")
        if any(str(item.get("port") or "") == str(settings["gateway_inbound_port"]) for item in inbounds):
            raise ValidationError("Локальный порт шлюза WDTT → Xray уже занят входящим Xray")
        inbounds.append(
            {
                "tag": "wdtt-gateway-in",
                "listen": "0.0.0.0",
                "port": int(settings["gateway_inbound_port"]),
                "protocol": "dokodemo-door",
                "settings": {"network": "tcp,udp", "followRedirect": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
                "streamSettings": {"sockopt": {"tproxy": "tproxy"}},
            }
        )
    outbound_tags = {"direct", "block", *(extra_outbound_tags or set())}
    inbound_tags: set[str] = set()
    for item in inbounds:
        tag = xray_tag(item.get("tag"), "tag входящего")
        if tag in inbound_tags:
            raise ValidationError(f"Входящий с tag {tag} указан дважды")
        inbound_tags.add(tag)
        if not str(item.get("protocol") or "").strip():
            raise ValidationError(f"Входящий {tag}: не указан protocol")

    outbounds: list[dict[str, Any]] = [
        {"tag": "direct", "protocol": "freedom", "settings": {}},
        {"tag": "block", "protocol": "blackhole", "settings": {}},
    ]
    for item in settings["outbounds"]:
        tag = xray_tag(item.get("tag"), "tag исходящего")
        if tag in outbound_tags:
            raise ValidationError(f"Исходящий с tag {tag} указан дважды")
        if not str(item.get("protocol") or "").strip():
            raise ValidationError(f"Исходящий {tag}: не указан protocol")
        outbound_tags.add(tag)
        outbounds.append(item)

    for route in settings["routes"]:
        if not route["enabled"]:
            continue
        tag = route["tag"]
        if tag in outbound_tags:
            raise ValidationError(f"Маршрут {route['name']}: tag {tag} уже занят исходящим")
        outbound_tags.add(tag)
        outbounds.append(parse_xray_vless_uri(route["vless_uri"], tag))

    rules: list[dict[str, Any]] = []
    for rule in settings["friendly_rules"]:
        if not rule["enabled"]:
            continue
        target = rule["outbound"]
        if target not in outbound_tags:
            raise ValidationError(f"Правило {rule['name']}: маршрут {target} не настроен или выключен")
        domains = [*(f"domain:{item}" for item in rule["domains"]), *(f"geosite:{item}" for item in rule["geosite"])]
        ips = [*rule["ip_cidrs"], *(f"geoip:{item}" for item in rule["geoip"])]
        if domains:
            rules.append({"type": "field", "domain": domains, "outboundTag": target})
        if ips:
            rules.append({"type": "field", "ip": ips, "outboundTag": target})
    for index, rule in enumerate(settings["routing_rules"]):
        if not str(rule.get("type") or "").strip():
            rule = {"type": "field", **rule}
        target = str(rule.get("outboundTag") or "")
        if target and target not in outbound_tags:
            raise ValidationError(f"Правило {index + 1}: исходящий {target} не настроен")
        rules.append(rule)
    log = {"loglevel": settings["log_level"]}
    if settings.get("access_log"):
        log.update({"access": str(XRAY_ACCESS_LOG), "error": str(XRAY_ERROR_LOG)})
    config: dict[str, Any] = {
        "log": log,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    return config


def default_xray_cascade_settings() -> dict[str, Any]:
    return {
        "enabled": False,
        "source_cidr": "10.66.66.0/24",
        "inbound_port": 12345,
        "eu_vless_uri": "",
        "geosite_category": "ru-blocked",
        "geoip_category": "ru-blocked",
        "domains": [],
        "ip_cidrs": [],
    }


def load_xray_cascade_settings() -> dict[str, Any]:
    settings = default_xray_cascade_settings()
    if XRAY_CASCADE_SETTINGS.is_file():
        try:
            saved = json.loads(XRAY_CASCADE_SETTINGS.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                settings.update(saved)
        except (OSError, json.JSONDecodeError):
            pass
    return settings


def normalize_xray_cascade_settings(payload: dict[str, Any]) -> dict[str, Any]:
    settings = default_xray_cascade_settings()
    settings["enabled"] = bool(payload.get("enabled", False))
    source = str(payload.get("source_cidr") or settings["source_cidr"]).strip()
    try:
        network = ipaddress.ip_network(source, strict=False)
    except ValueError as exc:
        raise ValidationError("Укажите корректную IPv4-подсеть пользователей WDTT") from exc
    if network.version != 4 or network.prefixlen > 30:
        raise ValidationError("Для каскада нужна IPv4-подсеть не менее двух адресов")
    settings["source_cidr"] = str(network)
    try:
        port = int(payload.get("inbound_port") or settings["inbound_port"])
    except (TypeError, ValueError) as exc:
        raise ValidationError("Укажите корректный локальный порт каскада") from exc
    if not 1024 <= port <= 65535:
        raise ValidationError("Порт каскада должен быть от 1024 до 65535")
    settings["inbound_port"] = port
    settings["geosite_category"] = xray_tag(payload.get("geosite_category") or settings["geosite_category"], "категория GeoSite")
    settings["geoip_category"] = xray_tag(payload.get("geoip_category") or settings["geoip_category"], "категория GeoIP")
    domains = split_rule_values(payload.get("domains"))
    if len(domains) > 256:
        raise ValidationError("Можно указать не более 256 дополнительных доменов")
    normalized_domains: list[str] = []
    for domain in domains:
        value = domain.strip().lower().lstrip(".")
        if value.startswith("*."):
            value = value[2:]
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value) or ".." in value:
            raise ValidationError(f"Некорректный домен для каскада: {domain}")
        normalized_domains.append(value)
    settings["domains"] = list(dict.fromkeys(normalized_domains))
    networks = split_rule_values(payload.get("ip_cidrs"))
    if len(networks) > 256:
        raise ValidationError("Можно указать не более 256 IP/CIDR")
    try:
        settings["ip_cidrs"] = list(dict.fromkeys(str(ipaddress.ip_network(value, strict=False)) for value in networks))
    except ValueError as exc:
        raise ValidationError("Список IP каскада содержит некорректный IP/CIDR") from exc
    settings["eu_vless_uri"] = str(payload.get("eu_vless_uri") or "").strip()
    if settings["enabled"] and not settings["eu_vless_uri"]:
        raise ValidationError("Для каскада укажите VLESS-ссылку EU-сервера")
    return settings


def parse_xray_vless_uri(uri: str, tag: str = "eu-vless") -> dict[str, Any]:
    parsed = urlsplit(uri.strip())
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValidationError("В VLESS-ссылке указан некорректный порт") from exc
    if parsed.scheme.lower() != "vless" or not parsed.username or not parsed.hostname or not port:
        raise ValidationError("Нужна полная VLESS-ссылка: vless://UUID@host:port")
    try:
        user_id = str(uuid.UUID(unquote(parsed.username)))
    except (ValueError, binascii.Error) as exc:
        raise ValidationError("В VLESS-ссылке указан некорректный UUID") from exc
    query = {key: values[-1] for key, values in parse_qs(parsed.query).items() if values}
    user: dict[str, Any] = {"id": user_id, "encryption": query.get("encryption") or "none"}
    if query.get("flow"):
        user["flow"] = query["flow"]
    outbound: dict[str, Any] = {
        "tag": tag,
        "protocol": "vless",
        "settings": {"vnext": [{"address": parsed.hostname, "port": port, "users": [user]}]},
    }
    network = (query.get("type") or "tcp").lower()
    security = (query.get("security") or "none").lower()
    stream: dict[str, Any] = {"network": network, "security": security}
    if security == "tls":
        tls: dict[str, Any] = {"serverName": query.get("sni") or parsed.hostname}
        if query.get("fp"):
            tls["fingerprint"] = query["fp"]
        if query.get("alpn"):
            tls["alpn"] = [item.strip() for item in query["alpn"].split(",") if item.strip()]
        if query.get("allowInsecure", "0").lower() in {"1", "true"}:
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls
    elif security == "reality":
        public_key = query.get("pbk") or query.get("publicKey")
        if not public_key:
            raise ValidationError("Для VLESS Reality требуется параметр pbk")
        reality: dict[str, Any] = {
            "show": False,
            "fingerprint": query.get("fp") or "chrome",
            "serverName": query.get("sni") or parsed.hostname,
            "publicKey": public_key,
            "shortId": query.get("sid") or "",
        }
        if query.get("spx"):
            reality["spiderX"] = unquote(query["spx"])
        stream["realitySettings"] = reality
    elif security != "none":
        raise ValidationError("Поддерживаются VLESS security: none, tls или reality")
    if network == "ws":
        ws: dict[str, Any] = {"path": unquote(query.get("path") or "/")}
        if query.get("host"):
            ws["headers"] = {"Host": query["host"]}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": query.get("serviceName") or ""}
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": unquote(query.get("path") or "/"), "host": query.get("host") or ""}
    elif network not in {"tcp", "http", "h2"}:
        raise ValidationError(f"Транспорт VLESS {network} пока не поддерживается мастером; используйте Raw JSON")
    outbound["streamSettings"] = stream
    return outbound


def apply_xray_cascade(config: dict[str, Any], routing: dict[str, Any]) -> dict[str, Any]:
    if not routing.get("enabled"):
        return config
    inbounds = list(config.get("inbounds") or [])
    outbounds = list(config.get("outbounds") or [])
    if any(item.get("tag") == "wdtt-cascade-in" for item in inbounds if isinstance(item, dict)):
        raise ValidationError("Tag wdtt-cascade-in зарезервирован для каскада")
    if any(item.get("tag") == "eu-vless" for item in outbounds if isinstance(item, dict)):
        raise ValidationError("Tag eu-vless зарезервирован для каскада")
    inbound = {
        "tag": "wdtt-cascade-in",
        "listen": "0.0.0.0",
        "port": int(routing["inbound_port"]),
        "protocol": "dokodemo-door",
        "settings": {"network": "tcp,udp", "followRedirect": True},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        "streamSettings": {"sockopt": {"tproxy": "tproxy"}},
    }
    custom_rules: list[dict[str, Any]] = []
    if routing.get("domains"):
        custom_rules.append({"type": "field", "inboundTag": ["wdtt-cascade-in"], "domain": [f"domain:{value}" for value in routing["domains"]], "outboundTag": "eu-vless"})
    if routing.get("ip_cidrs"):
        custom_rules.append({"type": "field", "inboundTag": ["wdtt-cascade-in"], "ip": list(routing["ip_cidrs"]), "outboundTag": "eu-vless"})
    blocked_rules = [
        *custom_rules,
        {"type": "field", "inboundTag": ["wdtt-cascade-in"], "domain": [f"geosite:{routing['geosite_category']}"], "outboundTag": "eu-vless"},
        {"type": "field", "inboundTag": ["wdtt-cascade-in"], "ip": [f"geoip:{routing['geoip_category']}"], "outboundTag": "eu-vless"},
    ]
    result = json.loads(json.dumps(config))
    result["inbounds"] = [*inbounds, inbound]
    result["outbounds"] = [*outbounds, parse_xray_vless_uri(str(routing["eu_vless_uri"]))]
    routing_config = dict(result.get("routing") or {})
    routing_config["rules"] = [*blocked_rules, *(routing_config.get("rules") or [])]
    result["routing"] = routing_config
    return result


def build_effective_xray_config(settings: dict[str, Any], routing: dict[str, Any] | None = None) -> dict[str, Any]:
    routing = routing or load_xray_cascade_settings()
    if routing.get("enabled") and settings.get("mode") != "managed":
        raise ValidationError("Каскад RU→EU работает только в Managed-режиме Xray")
    if routing.get("enabled") and settings.get("gateway_enabled"):
        raise ValidationError("Каскад уже принимает трафик WDTT в Xray; отключите отдельный шлюз WDTT → Xray")
    extra_outbound_tags = {"eu-vless"} if routing.get("enabled") and settings.get("mode") == "managed" else set()
    return apply_xray_cascade(build_xray_config(settings, extra_outbound_tags), routing)


def persist_xray_configuration(settings: dict[str, Any], config: dict[str, Any]) -> None:
    xray_validate_config(config)
    save_private_json(XRAY_SETTINGS, settings)
    save_private_json(XRAY_CONFIG, config)
    if not SKIP_SYSTEMD and shutil.which("xray"):
        action = "enable" if settings["enabled"] else "disable"
        changed = run(["systemctl", action, XRAY_SERVICE], timeout=30)
        if changed.returncode != 0:
            raise AdminError(changed.stderr.strip() or "Не удалось изменить состояние службы Xray")
        changed = run(["systemctl", "restart" if settings["enabled"] else "stop", XRAY_SERVICE], timeout=60)
        if changed.returncode != 0:
            raise AdminError(changed.stderr.strip() or "Не удалось применить конфигурацию Xray")


def xray_validate_config(config: dict[str, Any]) -> None:
    if SKIP_SYSTEMD or not shutil.which("xray"):
        return
    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="xray-check.", suffix=".json", dir=XRAY_CONFIG.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False)
        checked = run(["xray", "run", "-test", "-c", name], timeout=45, env={"XRAY_LOCATION_ASSET": str(XRAY_ASSETS)})
        if checked.returncode != 0:
            raise ValidationError(checked.stderr.strip() or checked.stdout.strip() or "Xray отклонил конфигурацию")
    finally:
        Path(name).unlink(missing_ok=True)


def xray_status(payload: dict[str, Any]) -> dict[str, Any]:
    settings = load_xray_settings()
    active = False
    version = ""
    logs: list[str] = []
    if not SKIP_SYSTEMD:
        active = run(["systemctl", "is-active", "--quiet", XRAY_SERVICE]).returncode == 0
        if shutil.which("xray"):
            probe = run(["xray", "version"], timeout=15)
            if probe.returncode == 0:
                version = probe.stdout.splitlines()[0] if probe.stdout else "Xray"
        journal = run(["journalctl", "-u", XRAY_SERVICE, "-n", "50", "--no-pager", "-o", "cat"], timeout=20)
        if journal.returncode == 0:
            logs = journal.stdout.splitlines()
    files = []
    for item in settings["geofiles"]:
        path = XRAY_ASSETS / item["filename"]
        files.append({**item, "available": path.is_file(), "size": path.stat().st_size if path.is_file() else 0})
    return {
        "settings": settings,
        "active": active,
        "installed": bool(shutil.which("xray")),
        "version": version,
        "logs": logs,
        "config_exists": XRAY_CONFIG.is_file(),
        "geofiles": files,
        "gateway": xray_gateway_status({}),
    }


def xray_save(payload: dict[str, Any]) -> dict[str, Any]:
    settings = normalize_xray_settings(payload)
    cascade = load_xray_cascade_settings()
    persist_xray_configuration(settings, build_effective_xray_config(settings, cascade))
    if settings["gateway_enabled"]:
        if not SKIP_SYSTEMD:
            enabled = run(["systemctl", "enable", XRAY_GATEWAY_SERVICE], timeout=45)
            if enabled.returncode != 0:
                raise AdminError(enabled.stderr.strip() or "Не удалось включить шлюз WDTT → Xray")
        # The gateway unit invokes this very admin helper on boot. Restarting it
        # here while this request holds ADMIN_LOCK makes systemd wait for a second
        # helper process that is itself waiting for the same lock.
        xray_gateway_apply_rules({})
    else:
        if not SKIP_SYSTEMD:
            # Rules are removed directly below; stopping the oneshot unit would
            # run its ExecStop helper and recreate the same lock cycle.
            run(["systemctl", "disable", XRAY_GATEWAY_SERVICE], timeout=45)
        xray_gateway_remove_rules({})
    if cascade.get("enabled"):
        cascade_apply_rules({})
    return xray_status({})


def schedule_xray_runtime(payload: dict[str, Any]) -> dict[str, Any]:
    if SKIP_SYSTEMD:
        return {"scheduled": True, "state": "test"}
    unit = f"wdtt-xray-install-{int(time.time())}"
    result = run(
        ["systemd-run", "--quiet", "--collect", f"--unit={unit}", "--on-active=2s", str(XRAY_INSTALL_COMMAND), "install-xray-runtime"],
        timeout=20,
    )
    if result.returncode != 0:
        raise AdminError(result.stderr.strip() or "Не удалось запланировать установку Xray")
    return {"scheduled": True, "unit": unit}


def warp_profile_details() -> dict[str, Any]:
    profile = WARP_DIR / "wgcf-profile.conf"
    if not profile.is_file():
        raise ValidationError("Профиль Cloudflare WARP еще не создан")
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read(profile, encoding="utf-8")
        interface, peer = parser["Interface"], parser["Peer"]
    except (OSError, KeyError, configparser.Error) as exc:
        raise ValidationError("Не удалось прочитать профиль Cloudflare WARP") from exc
    secret_key, public_key = interface.get("PrivateKey", "").strip(), peer.get("PublicKey", "").strip()
    endpoint = peer.get("Endpoint", "engage.cloudflareclient.com:2408").strip()
    addresses = [item.strip() for item in interface.get("Address", "").split(",") if item.strip()]
    if not secret_key or not public_key or not endpoint or not addresses:
        raise ValidationError("Профиль Cloudflare WARP неполный")
    try:
        reserved = [int(item.strip()) for item in peer.get("Reserved", "0,0,0").split(",")]
        mtu = int(interface.get("MTU", "1280"))
    except ValueError as exc:
        raise ValidationError("Профиль Cloudflare WARP содержит некорректные параметры") from exc
    if len(reserved) != 3 or any(not 0 <= item <= 255 for item in reserved):
        raise ValidationError("Параметр Reserved в профиле Cloudflare WARP некорректен")
    return {
        "secret_key": secret_key,
        "public_key": public_key,
        "endpoint": endpoint,
        "addresses": addresses,
        "allowed_ips": [item.strip() for item in peer.get("AllowedIPs", "0.0.0.0/0,::/0").split(",") if item.strip()],
        "reserved": reserved,
        "mtu": max(576, min(mtu, 9000)),
    }


def warp_xray_outbound() -> dict[str, Any]:
    profile = warp_profile_details()
    return {
        "tag": "warp",
        "protocol": "wireguard",
        "settings": {
            "noKernelTun": True,
            "secretKey": profile["secret_key"],
            "address": profile["addresses"],
            "peers": [
                {
                    "publicKey": profile["public_key"],
                    "endpoint": profile["endpoint"],
                    "keepAlive": 25,
                    "allowedIPs": profile["allowed_ips"],
                }
            ],
            "mtu": profile["mtu"],
            "reserved": profile["reserved"],
            "domainStrategy": "ForceIPv4v6",
        },
    }


def sync_warp_outbound() -> None:
    settings = load_xray_settings()
    if settings.get("mode") != "managed":
        raise ValidationError("Для автоматического WARP переключите Xray в Managed-режим")
    settings["outbounds"] = [
        item for item in settings["outbounds"] if isinstance(item, dict) and item.get("tag") != "warp"
    ]
    settings["outbounds"].append(warp_xray_outbound())
    persist_xray_configuration(settings, build_effective_xray_config(settings))
    if load_xray_cascade_settings().get("enabled"):
        cascade_apply_rules({})


def warp_status(payload: dict[str, Any]) -> dict[str, Any]:
    profile = WARP_DIR / "wgcf-profile.conf"
    details: dict[str, Any] = {}
    if profile.is_file():
        try:
            raw = warp_profile_details()
            details = {"endpoint": raw["endpoint"], "addresses": raw["addresses"], "mtu": raw["mtu"]}
        except ValidationError as exc:
            details = {"error": str(exc)}
    settings = load_xray_settings()
    configured = any(isinstance(item, dict) and item.get("tag") == "warp" for item in settings["outbounds"])
    active = False
    if not SKIP_SYSTEMD:
        active = run(["systemctl", "is-active", "--quiet", XRAY_SERVICE]).returncode == 0 and configured
    return {
        "installed": bool(shutil.which("wgcf")),
        "account_exists": (WARP_DIR / "wgcf-account.toml").is_file(),
        "profile_exists": profile.is_file(),
        "configured": configured,
        "active": active,
        **details,
    }


def schedule_warp_runtime(payload: dict[str, Any]) -> dict[str, Any]:
    if SKIP_SYSTEMD:
        return {"scheduled": True, "state": "test"}
    unit = f"wdtt-warp-install-{int(time.time())}"
    result = run(
        ["systemd-run", "--quiet", "--collect", f"--unit={unit}", "--on-active=2s", str(WARP_INSTALL_COMMAND), "install-warp-runtime"],
        timeout=20,
    )
    if result.returncode != 0:
        raise AdminError(result.stderr.strip() or "Не удалось запланировать установку wgcf")
    return {"scheduled": True, "unit": unit}


def create_warp(payload: dict[str, Any]) -> dict[str, Any]:
    if SKIP_SYSTEMD:
        return {"created": True, "state": "test"}
    if not shutil.which("wgcf"):
        raise ValidationError("Сначала установите компонент WARP")
    WARP_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WARP_DIR, 0o700)
    account = WARP_DIR / "wgcf-account.toml"
    profile = WARP_DIR / "wgcf-profile.conf"
    if bool(payload.get("recreate")):
        account.unlink(missing_ok=True)
        profile.unlink(missing_ok=True)
    if not account.is_file():
        registered = run(["wgcf", "register", "--accept-tos"], timeout=90, cwd=WARP_DIR)
        if registered.returncode != 0:
            raise AdminError(registered.stderr.strip() or "Cloudflare WARP не принял регистрацию")
    generated = run(["wgcf", "generate"], timeout=90, cwd=WARP_DIR)
    if generated.returncode != 0 or not profile.is_file():
        raise AdminError(generated.stderr.strip() or "Не удалось создать профиль Cloudflare WARP")
    os.chmod(account, 0o600)
    os.chmod(profile, 0o600)
    sync_warp_outbound()
    return {"created": True, **warp_status({})}


def restart_warp(payload: dict[str, Any]) -> dict[str, Any]:
    if not (WARP_DIR / "wgcf-profile.conf").is_file():
        raise ValidationError("Сначала создайте профиль Cloudflare WARP")
    sync_warp_outbound()
    return {"restarted": True, **warp_status({})}


def warp_probe_config(port: int) -> dict[str, Any]:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "warp-probe-in",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [warp_xray_outbound()],
    }


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def parse_cloudflare_trace(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in content.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            result[key.strip()] = value.strip()
    return result


def ping_warp(payload: dict[str, Any]) -> dict[str, Any]:
    if SKIP_SYSTEMD:
        return {"ok": True, "state": "test", "latency_ms": 0}
    if not shutil.which("xray"):
        raise ValidationError("Сначала установите Xray для проверки WARP")
    if not shutil.which("curl"):
        raise ValidationError("Для проверки WARP требуется curl")
    config = warp_probe_config(free_loopback_port())
    port = int(config["inbounds"][0]["port"])
    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="warp-ping.", suffix=".json", dir=XRAY_CONFIG.parent)
    process: subprocess.Popen[str] | None = None
    started = time.monotonic()
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False)
        checked = run(["xray", "run", "-test", "-c", name], timeout=45, env={"XRAY_LOCATION_ASSET": str(XRAY_ASSETS)})
        if checked.returncode != 0:
            return {"ok": False, "error": checked.stderr.strip() or checked.stdout.strip() or "Xray отклонил WARP-профиль"}
        process = subprocess.Popen(
            ["xray", "run", "-c", name],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env={**os.environ, "XRAY_LOCATION_ASSET": str(XRAY_ASSETS)},
        )
        ready_at = time.monotonic() + 12
        while time.monotonic() < ready_at:
            if process.poll() is not None:
                stderr = process.stderr.read().strip() if process.stderr else ""
                return {"ok": False, "error": stderr or "Временный Xray для WARP завершился раньше проверки"}
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            return {"ok": False, "error": "Временный Xray не открыл локальный порт проверки"}
        environment = {
            **os.environ,
            "http_proxy": "", "https_proxy": "", "all_proxy": "", "no_proxy": "",
            "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "NO_PROXY": "",
        }
        failures: list[str] = []
        for trace_url in (
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://cloudflare.com/cdn-cgi/trace",
            "http://www.cloudflare.com/cdn-cgi/trace",
        ):
            curl = subprocess.run(
                [
                    "curl", "-fsS", "--socks5-hostname", f"127.0.0.1:{port}",
                    "--connect-timeout", "8", "--max-time", "30", trace_url,
                ],
                text=True,
                capture_output=True,
                timeout=40,
                env=environment,
            )
            latency = round((time.monotonic() - started) * 1000)
            if curl.returncode != 0:
                failures.append(curl.stderr.strip() or f"{trace_url}: недоступен")
                continue
            trace = parse_cloudflare_trace(curl.stdout)
            warp_state = trace.get("warp", "").lower()
            if warp_state == "on":
                return {"ok": True, "latency_ms": latency, "warp": warp_state, "ip": trace.get("ip", ""), "colo": trace.get("colo", ""), "trace_url": trace_url}
            failures.append(f"{trace_url}: Cloudflare вернул warp={warp_state or 'unknown'}")
        return {"ok": False, "latency_ms": round((time.monotonic() - started) * 1000), "error": "WARP не подтверждён. " + " | ".join(failures[-2:])}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": f"Проверка WARP не выполнена: {exc}"}
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        Path(name).unlink(missing_ok=True)


def xray_download_geofile(item: dict[str, Any]) -> dict[str, Any]:
    url = str(item.get("url") or "")
    if not url:
        raise ValidationError(f"Для GeoFile {item.get('tag', '')} не задан URL")
    request = urllib.request.Request(url, headers={"User-Agent": "wdtt-control-panel"})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read(64 * 1024 * 1024 + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise AdminError(f"Не удалось загрузить GeoFile {item.get('tag', '')}: {exc}") from exc
    if not raw or len(raw) > 64 * 1024 * 1024:
        raise ValidationError(f"GeoFile {item.get('tag', '')} пустой или превышает 64 МБ")
    XRAY_ASSETS.mkdir(parents=True, exist_ok=True)
    destination = XRAY_ASSETS / str(item["filename"])
    fd, name = tempfile.mkstemp(prefix=f"{destination.name}.", suffix=".tmp", dir=XRAY_ASSETS)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, 0o600)
        os.replace(name, destination)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return {**item, "updated_at": int(time.time())}


def xray_refresh_geofile(payload: dict[str, Any]) -> dict[str, Any]:
    tag = xray_tag(payload.get("tag"), "tag GeoFile")
    settings = load_xray_settings()
    found = next((item for item in settings["geofiles"] if item.get("tag") == tag), None)
    if not found:
        raise ValidationError("GeoFile не найден")
    updated = xray_download_geofile(found)
    settings["geofiles"] = [updated if item.get("tag") == tag else item for item in settings["geofiles"]]
    save_private_json(XRAY_SETTINGS, settings)
    if not SKIP_SYSTEMD and run(["systemctl", "is-active", "--quiet", XRAY_SERVICE]).returncode == 0:
        run(["systemctl", "restart", XRAY_SERVICE], timeout=60)
    return updated


def xray_refresh_auto_geofiles(payload: dict[str, Any]) -> dict[str, Any]:
    settings = load_xray_settings()
    now = int(time.time())
    refreshed: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for item in settings["geofiles"]:
        if not item.get("enabled", True) or not item.get("auto_update"):
            continue
        due = int(item.get("updated_at") or 0) + interval_seconds(str(item.get("update_interval") or "1d"))
        if not payload.get("force") and due > now:
            continue
        try:
            refreshed.append(xray_download_geofile(item))
        except (ValidationError, AdminError) as exc:
            errors.append({"tag": str(item.get("tag") or "unknown"), "error": str(exc)})
    if refreshed:
        changed = {item["tag"]: item for item in refreshed}
        settings["geofiles"] = [changed.get(item.get("tag"), item) for item in settings["geofiles"]]
        save_private_json(XRAY_SETTINGS, settings)
        if not SKIP_SYSTEMD and run(["systemctl", "is-active", "--quiet", XRAY_SERVICE]).returncode == 0:
            run(["systemctl", "restart", XRAY_SERVICE], timeout=60)
    return {"refreshed": refreshed, "errors": errors}


def iptables_available() -> bool:
    return bool(shutil.which("iptables") or shutil.which("iptables-legacy"))


def nftables_not_supported(result: subprocess.CompletedProcess[str]) -> bool:
    output = f"{result.stdout}\n{result.stderr}".lower()
    return "failed to initialize nft" in output


def cascade_iptables(arguments: list[str], table: str = "mangle") -> subprocess.CompletedProcess[str]:
    global IPTABLES_BINARY
    binary = IPTABLES_BINARY or shutil.which("iptables") or shutil.which("iptables-legacy")
    if not binary:
        return subprocess.CompletedProcess(["iptables", "-w", "-t", table, *arguments], 127, "", "iptables не установлен")
    environment = {"XTABLES_LOCKFILE": XTABLES_LOCK_FILE}
    result = run([binary, "-w", "-t", table, *arguments], timeout=30, env=environment)
    if not nftables_not_supported(result):
        return result
    legacy = shutil.which("iptables-legacy")
    if legacy and legacy != binary:
        IPTABLES_BINARY = legacy
        return run([legacy, "-w", "-t", table, *arguments], timeout=30, env=environment)
    result.stderr = f"{result.stderr.rstrip()}\nЯдро не поддерживает nftables; установите пакет iptables-legacy."
    return result


def cascade_run_or_raise(arguments: list[str], table: str = "mangle") -> None:
    result = cascade_iptables(arguments, table)
    if result.returncode != 0:
        raise AdminError(result.stderr.strip() or f"Не удалось применить iptables: {' '.join(arguments)}")


def xray_gateway_remove_rules(payload: dict[str, Any]) -> dict[str, Any]:
    if SKIP_SYSTEMD or not iptables_available():
        return {"removed": True, "state": "test" if SKIP_SYSTEMD else "not-installed"}
    for table, chain, parent, target in (
        ("mangle", "WDTT_XRAY_GATEWAY", "PREROUTING", "WDTT_XRAY_GATEWAY"),
        ("filter", "WDTT_XRAY_GATEWAY_IN", "INPUT", "WDTT_XRAY_GATEWAY_IN"),
    ):
        for _ in range(8):
            result = cascade_iptables(["-D", parent, "-j", target], table)
            if result.returncode != 0:
                break
        cascade_iptables(["-F", chain], table)
        cascade_iptables(["-X", chain], table)
    for _ in range(8):
        result = run(["ip", "rule", "del", "fwmark", "0x234/0xfff", "table", "234", "priority", "1234"], timeout=20)
        if result.returncode != 0:
            break
    run(["ip", "route", "flush", "table", "234"], timeout=20)
    return {"removed": True}


def xray_gateway_apply_rules(payload: dict[str, Any]) -> dict[str, Any]:
    settings = load_xray_settings()
    if not settings.get("gateway_enabled"):
        return xray_gateway_remove_rules({})
    if settings.get("mode") != "managed":
        raise ValidationError("Шлюз WDTT → Xray работает только в Managed-режиме")
    if load_xray_cascade_settings().get("enabled"):
        raise ValidationError("Каскад уже принимает трафик WDTT в Xray; отдельный шлюз включать не нужно")
    if SKIP_SYSTEMD:
        return {"applied": True, "state": "test", "source_cidr": settings["gateway_source_cidr"], "inbound_port": settings["gateway_inbound_port"]}
    if run(["systemctl", "is-active", "--quiet", XRAY_SERVICE], timeout=20).returncode != 0:
        raise AdminError("Xray не запущен; правила шлюза WDTT → Xray не были применены")
    if not iptables_available():
        raise AdminError("iptables не установлен; установите системные зависимости панели")
    for module in ("xt_TPROXY", "nf_tproxy_core"):
        if shutil.which("modprobe"):
            run(["modprobe", module], timeout=20)
    mangle_chain, input_chain = "WDTT_XRAY_GATEWAY", "WDTT_XRAY_GATEWAY_IN"
    for table, chain in (("mangle", mangle_chain), ("filter", input_chain)):
        created = cascade_iptables(["-N", chain], table)
        if created.returncode != 0 and "Chain already exists" not in created.stderr:
            raise AdminError(created.stderr.strip() or f"Не удалось создать цепочку {chain}")
        cascade_run_or_raise(["-F", chain], table)
    source, port = settings["gateway_source_cidr"], str(settings["gateway_inbound_port"])
    cascade_run_or_raise(["-A", mangle_chain, "-s", source, "-p", "tcp", "-j", "TPROXY", "--on-port", port, "--tproxy-mark", "0x234/0xfff"])
    cascade_run_or_raise(["-A", mangle_chain, "-s", source, "-p", "udp", "-j", "TPROXY", "--on-port", port, "--tproxy-mark", "0x234/0xfff"])
    for protocol in ("tcp", "udp"):
        cascade_run_or_raise(["-A", input_chain, "-s", source, "-p", protocol, "--dport", port, "-j", "ACCEPT"], "filter")
        cascade_run_or_raise(["-A", input_chain, "-p", protocol, "--dport", port, "-j", "DROP"], "filter")
        if cascade_iptables(["-C", "INPUT", "-p", protocol, "--dport", port, "-j", input_chain], "filter").returncode != 0:
            cascade_run_or_raise(["-I", "INPUT", "1", "-p", protocol, "--dport", port, "-j", input_chain], "filter")
    if cascade_iptables(["-C", "PREROUTING", "-j", mangle_chain]).returncode != 0:
        cascade_run_or_raise(["-I", "PREROUTING", "1", "-j", mangle_chain])
    rule = run(["ip", "rule", "add", "fwmark", "0x234/0xfff", "table", "234", "priority", "1234"], timeout=20)
    if rule.returncode != 0 and "File exists" not in rule.stderr:
        raise AdminError(rule.stderr.strip() or "Не удалось добавить policy routing для шлюза WDTT → Xray")
    route = run(["ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "234"], timeout=20)
    if route.returncode != 0:
        raise AdminError(route.stderr.strip() or "Не удалось добавить локальный маршрут шлюза WDTT → Xray")
    return {"applied": True, "source_cidr": source, "inbound_port": int(port)}


def xray_gateway_status(payload: dict[str, Any]) -> dict[str, Any]:
    settings = load_xray_settings()
    rules_active = False
    service_active = False
    if not SKIP_SYSTEMD:
        if iptables_available():
            rules_active = cascade_iptables(["-C", "PREROUTING", "-j", "WDTT_XRAY_GATEWAY"]).returncode == 0
        service_active = run(["systemctl", "is-active", "--quiet", XRAY_GATEWAY_SERVICE], timeout=20).returncode == 0
    return {
        "enabled": bool(settings.get("gateway_enabled")),
        "source_cidr": settings["gateway_source_cidr"],
        "inbound_port": settings["gateway_inbound_port"],
        "rules_active": rules_active,
        "service_active": service_active,
    }


def cascade_remove_rules(payload: dict[str, Any]) -> dict[str, Any]:
    if SKIP_SYSTEMD or not iptables_available():
        return {"removed": True, "state": "test" if SKIP_SYSTEMD else "not-installed"}
    for table, chain, parent, target in (
        ("mangle", "WDTT_XRAY_CASCADE", "PREROUTING", "WDTT_XRAY_CASCADE"),
        ("filter", "WDTT_XRAY_CASCADE_IN", "INPUT", "WDTT_XRAY_CASCADE_IN"),
    ):
        for _ in range(8):
            result = cascade_iptables(["-D", parent, "-j", target], table)
            if result.returncode != 0:
                break
        cascade_iptables(["-F", chain], table)
        cascade_iptables(["-X", chain], table)
    for _ in range(8):
        result = run(["ip", "rule", "del", "fwmark", "0x233/0xfff", "table", "233", "priority", "1233"], timeout=20)
        if result.returncode != 0:
            break
    run(["ip", "route", "flush", "table", "233"], timeout=20)
    return {"removed": True}


def cascade_apply_rules(payload: dict[str, Any]) -> dict[str, Any]:
    routing = load_xray_cascade_settings()
    if not routing.get("enabled"):
        return cascade_remove_rules({})
    routing = normalize_xray_cascade_settings(routing)
    if SKIP_SYSTEMD:
        return {"applied": True, "state": "test"}
    if run(["systemctl", "is-active", "--quiet", XRAY_SERVICE], timeout=20).returncode != 0:
        raise AdminError("Xray не запущен; правила каскада не были применены")
    if not iptables_available():
        raise AdminError("iptables не установлен; установите системные зависимости панели")
    for module in ("xt_TPROXY", "nf_tproxy_core"):
        if shutil.which("modprobe"):
            run(["modprobe", module], timeout=20)
    mangle_chain, input_chain = "WDTT_XRAY_CASCADE", "WDTT_XRAY_CASCADE_IN"
    for table, chain in (("mangle", mangle_chain), ("filter", input_chain)):
        created = cascade_iptables(["-N", chain], table)
        if created.returncode != 0 and "Chain already exists" not in created.stderr:
            raise AdminError(created.stderr.strip() or f"Не удалось создать цепочку {chain}")
        cascade_run_or_raise(["-F", chain], table)
    source, port = routing["source_cidr"], str(routing["inbound_port"])
    cascade_run_or_raise(["-A", mangle_chain, "-s", source, "-p", "tcp", "-j", "TPROXY", "--on-port", port, "--tproxy-mark", "0x233/0xfff"])
    cascade_run_or_raise(["-A", mangle_chain, "-s", source, "-p", "udp", "-j", "TPROXY", "--on-port", port, "--tproxy-mark", "0x233/0xfff"])
    for protocol in ("tcp", "udp"):
        cascade_run_or_raise(["-A", input_chain, "-s", source, "-p", protocol, "--dport", port, "-j", "ACCEPT"], "filter")
        cascade_run_or_raise(["-A", input_chain, "-p", protocol, "--dport", port, "-j", "DROP"], "filter")
        if cascade_iptables(["-C", "INPUT", "-p", protocol, "--dport", port, "-j", input_chain], "filter").returncode != 0:
            cascade_run_or_raise(["-I", "INPUT", "1", "-p", protocol, "--dport", port, "-j", input_chain], "filter")
    if cascade_iptables(["-C", "PREROUTING", "-j", mangle_chain]).returncode != 0:
        cascade_run_or_raise(["-I", "PREROUTING", "1", "-j", mangle_chain])
    rule = run(["ip", "rule", "add", "fwmark", "0x233/0xfff", "table", "233", "priority", "1233"], timeout=20)
    if rule.returncode != 0 and "File exists" not in rule.stderr:
        raise AdminError(rule.stderr.strip() or "Не удалось добавить policy routing для каскада")
    route = run(["ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "233"], timeout=20)
    if route.returncode != 0:
        raise AdminError(route.stderr.strip() or "Не удалось добавить локальный маршрут каскада")
    return {"applied": True, "source_cidr": source, "inbound_port": int(port)}


def cascade_status(payload: dict[str, Any]) -> dict[str, Any]:
    settings = load_xray_cascade_settings()
    summary = ""
    if settings.get("eu_vless_uri"):
        parsed = urlsplit(str(settings["eu_vless_uri"]))
        try:
            summary = f"{parsed.hostname}:{parsed.port}"
        except ValueError:
            summary = "некорректный порт"
    rules_active = False
    service_active = False
    if not SKIP_SYSTEMD:
        if iptables_available():
            rules_active = cascade_iptables(["-C", "PREROUTING", "-j", "WDTT_XRAY_CASCADE"]).returncode == 0
        service_active = run(["systemctl", "is-active", "--quiet", XRAY_CASCADE_SERVICE]).returncode == 0
    return {
        "settings": settings,
        "xray_active": (not SKIP_SYSTEMD and run(["systemctl", "is-active", "--quiet", XRAY_SERVICE]).returncode == 0),
        "service_active": service_active,
        "rules_active": rules_active,
        "eu_summary": summary,
    }


def cascade_save(payload: dict[str, Any]) -> dict[str, Any]:
    routing = normalize_xray_cascade_settings(payload)
    if routing["enabled"]:
        refreshed = xray_refresh_auto_geofiles({"force": True})
        if refreshed["errors"]:
            raise AdminError(f"Не удалось обновить GeoFiles: {refreshed['errors'][0]['tag']}")
    xray_settings = load_xray_settings()
    if routing["enabled"]:
        required_geofiles = {"geoip.dat", "geosite.dat"}
        available_geofiles = {
            str(item.get("filename"))
            for item in xray_settings["geofiles"]
            if item.get("enabled", True) and (XRAY_ASSETS / str(item.get("filename") or "")).is_file()
        }
        if not required_geofiles.issubset(available_geofiles):
            raise ValidationError("Для каскада включите и обновите GeoIP и GeoSite")
        if xray_settings.get("mode") != "managed":
            raise ValidationError("Каскад RU→EU требует Managed-режим Xray")
        if not xray_settings.get("enabled"):
            raise ValidationError("Сначала включите Xray и сохраните его конфигурацию")
        if not SKIP_SYSTEMD and not shutil.which("xray"):
            raise ValidationError("Сначала установите Xray")
    persist_xray_configuration(xray_settings, build_effective_xray_config(xray_settings, routing))
    save_private_json(XRAY_CASCADE_SETTINGS, routing)
    if not SKIP_SYSTEMD:
        if routing["enabled"]:
            enabled = run(["systemctl", "enable", "--now", XRAY_CASCADE_SERVICE], timeout=45)
            if enabled.returncode != 0:
                raise AdminError(enabled.stderr.strip() or "Не удалось включить правила каскада")
            cascade_apply_rules({})
        else:
            run(["systemctl", "disable", "--now", XRAY_CASCADE_SERVICE], timeout=45)
            cascade_remove_rules({})
    return cascade_status({})


def cascade_restart(payload: dict[str, Any]) -> dict[str, Any]:
    settings = load_xray_cascade_settings()
    if not settings.get("enabled"):
        raise ValidationError("Сначала включите каскад RU→EU")
    if SKIP_SYSTEMD:
        return {"restarted": True, "state": "test"}
    restarted = run(["systemctl", "restart", XRAY_SERVICE], timeout=60)
    if restarted.returncode != 0:
        raise AdminError(restarted.stderr.strip() or "Не удалось перезапустить Xray")
    cascade_apply_rules({})
    return {"restarted": True, **cascade_status({})}


def overview(payload: dict[str, Any]) -> dict[str, Any]:
    data = load_database()
    passwords = data.get("passwords", {})
    user_device_ids = {
        str(entry.get("device_id") or "")
        for entry in passwords.values()
        if isinstance(entry, dict) and entry.get("device_id")
    }
    admin_devices = sum(
        1
        for device_id, device in data.get("devices", {}).items()
        if device_id not in user_device_ids and isinstance(device, dict)
    )
    connection_state = list_users()
    online_user_devices = sum(1 for user in connection_state["users"] if user.get("connected") and user.get("device_id"))
    online_admin_devices = sum(1 for admin in connection_state["admins"] if admin.get("connected") and admin.get("device_id"))
    stats = read_stats()
    ip_forward = "unknown"
    if not SKIP_SYSTEMD:
        forward = run(["sysctl", "-n", "net.ipv4.ip_forward"])
        if forward.returncode == 0:
            ip_forward = forward.stdout.strip()
    disk = shutil.disk_usage("/")
    disk_percent = round(disk.used * 100 / disk.total, 1) if disk.total else 0.0
    certificate = certificate_info(str(payload.get("certificate_path") or ""))
    certificate.update(
        {
            "mode": str(payload.get("tls_mode") or "unknown"),
            "host": str(payload.get("public_host") or ""),
            "port": int(payload.get("https_port") or 443),
        }
    )
    certificate.update(local_tls_status(certificate["host"], certificate["port"]))
    return {
        "service": {
            "exists": service_exists(),
            "active": service_active(),
            "ip_forward": ip_forward,
            "binary": Path("/usr/local/bin/wdtt-server").is_file(),
        },
        "stats": stats,
        "users": len(passwords) + (1 if data.get("main_password") else 0),
        "managed_users": len(passwords),
        "devices": len(data.get("devices", {})),
        "admin_devices": admin_devices,
        "online_devices": online_user_devices + online_admin_devices,
        "online_admin_devices": online_admin_devices,
        "system": {
            "cpu_percent": cpu_usage(),
            "memory": memory_usage(),
            "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else [0, 0, 0],
        },
        "disk": {"total": disk.total, "used": disk.used, "free": disk.free, "percent": disk_percent},
        "certificate": certificate,
        "timestamp": int(time.time()),
    }


OPERATIONS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "overview": overview,
    "users.list": lambda payload: list_users(),
    "users.create": create_user,
    "users.create_bulk": create_users_bulk,
    "users.update": update_user,
    "users.delete": delete_user,
    "users.unbind": unbind_user,
    "users.reset_traffic": reset_traffic,
    "users.bulk_action": bulk_user_action,
    "service.action": lambda payload: service_action(str(payload.get("service_action") or "")),
    "logs": journal_logs,
    "cleanup.preview": lambda payload: cleanup_system(payload, False),
    "cleanup.apply": lambda payload: cleanup_system(payload, True),
    "backups.list": lambda payload: list_backups(),
    "backups.create": create_manual_backup,
    "backups.delete": delete_backup,
    "backups.restore": restore_backup,
    "backups.export": export_backup,
    "backups.import": import_backup,
    "backups.schedule": lambda payload: save_backup_schedule(payload) if payload else backup_schedule_status(),
    "panel.version": panel_version,
    "panel.update": start_panel_update,
    "certificate.export": export_certificate,
    "certificate.renew": schedule_certificate_renew,
    "telegram.status": lambda payload: telegram_status(payload),
    "telegram.save": configure_telegram,
    "telegram.test": telegram_test,
    "xray.status": xray_status,
    "xray.save": xray_save,
    "xray.install": schedule_xray_runtime,
    "xray.geofiles.refresh": xray_refresh_geofile,
    "xray.geofiles.refresh_auto": xray_refresh_auto_geofiles,
    "xray.gateway.apply": xray_gateway_apply_rules,
    "xray.gateway.remove": xray_gateway_remove_rules,
    "xray.gateway.status": xray_gateway_status,
    "warp.status": warp_status,
    "warp.install": schedule_warp_runtime,
    "warp.create": create_warp,
    "warp.restart": restart_warp,
    "warp.ping": ping_warp,
    "cascade.status": cascade_status,
    "cascade.save": cascade_save,
    "cascade.restart": cascade_restart,
    "cascade.apply": cascade_apply_rules,
    "cascade.remove": cascade_remove_rules,
}


def dispatch(request: dict[str, Any]) -> Any:
    action = str(request.get("action") or "")
    handler = OPERATIONS.get(action)
    if handler is None:
        raise ValidationError("Неизвестная административная операция")
    payload = request.get("payload") or {}
    if not isinstance(payload, dict):
        raise ValidationError("payload должен быть объектом")
    return handler(payload)


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        print(json.dumps({"ok": False, "error": "Запрос слишком большой"}))
        return 2
    try:
        request = json.loads(raw or b"{}")
        if not isinstance(request, dict):
            raise ValidationError("Запрос должен быть JSON-объектом")
        if os.name == "posix":
            import fcntl

            LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
            with LOCK_FILE.open("a", encoding="utf-8") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                result = dispatch(request)
        else:
            result = dispatch(request)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False))
        return 0
    except (ValidationError, AdminError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"Внутренняя ошибка: {exc}"}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
