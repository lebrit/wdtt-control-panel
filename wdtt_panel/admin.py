from __future__ import annotations

import base64
import binascii
import configparser
import ipaddress
import json
import os
import re
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
    parse_expiration,
    user_view,
    validate_password,
    validate_ports,
)


DB_FILE = Path(os.environ.get("WDTT_DB_FILE", "/etc/wdtt/passwords.json"))
STATS_FILE = Path(os.environ.get("WDTT_STATS_FILE", "/etc/wdtt/server.log"))
BACKUP_DIR = Path(os.environ.get("WDTT_BACKUP_DIR", "/var/lib/wdtt-panel-private/backups"))
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
XRAY_DEFAULT_GEOFILES = (
    {
        "tag": "geoip",
        "filename": "geoip.dat",
        "url": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
    },
    {
        "tag": "geosite",
        "filename": "geosite.dat",
        "url": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    },
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


class AdminError(RuntimeError):
    pass


def run(
    command: list[str], timeout: int = 20, check: bool = False, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=check,
        cwd=cwd,
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


def repair_wdtt_interface(payload: dict[str, Any]) -> dict[str, Any]:
    """Restart WDTT and wait for the interface it owns to appear."""
    if SKIP_SYSTEMD:
        return {"repaired": True, "interface": True, "state": "test"}
    if not service_exists():
        raise AdminError("Служба WDTT не установлена")
    run(["systemctl", "reset-failed", SERVICE], timeout=20)
    restarted = run(["systemctl", "restart", SERVICE], timeout=60)
    if restarted.returncode != 0:
        raise AdminError(restarted.stderr.strip() or "Не удалось перезапустить WDTT")
    for _ in range(20):
        if run(["ip", "link", "show", "wdtt0"], timeout=10).returncode == 0:
            return {"repaired": True, "interface": True, "active": service_active()}
        time.sleep(0.5)
    raise AdminError(f"WDTT перезапущен, но wdtt0 не появился: {service_error_hint()}")


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


def mutate_database(label: str, mutator: Callable[[dict[str, Any]], Any]) -> Any:
    was_active = service_active()
    if was_active:
        service_action("stop")
    try:
        data = load_database()
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


def list_users() -> dict[str, Any]:
    data = load_database()
    handshakes = wireguard_handshakes()
    active_ips = active_tunnel_ips()
    users = [
        connected_user_view(
            user_view(password, entry if isinstance(entry, dict) else {}, data["devices"]).as_dict(),
            handshakes,
            active_ips,
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
    for device_id, device in data["devices"].items():
        if device_id in user_devices or not isinstance(device, dict):
            continue
        public_key = str(device.get("pub_key") or device.get("PubKey") or "")
        last_handshake = int(handshakes.get(public_key) or 0)
        admins.append(
            {
                "password": "Главный пароль",
                "role": "admin",
                "device_id": device_id,
                "device": device,
                "connected": str(device.get("ip") or "") in active_ips or handshake_is_active(last_handshake),
                "last_handshake": last_handshake,
                "down_bytes": 0,
                "up_bytes": 0,
                "expires_at": 0,
                "vk_hash": "Администратор WDTT",
                "ports": "",
                "is_deactivated": False,
                "expired": False,
            }
        )
    return {
        "users": users,
        "admins": admins,
        "main_password_present": bool(data.get("main_password")),
        "limit": MAX_USERS,
    }


def wireguard_handshakes() -> dict[str, int]:
    if SKIP_SYSTEMD or not shutil.which("wg"):
        return {}
    result = run(["wg", "show", "wdtt0", "dump"], timeout=10)
    if result.returncode != 0:
        return {}
    handshakes: dict[str, int] = {}
    for index, line in enumerate(result.stdout.splitlines()):
        fields = line.split("\t")
        if index == 0 or len(fields) < 5:
            continue
        try:
            handshakes[fields[0]] = int(fields[4])
        except ValueError:
            continue
    return handshakes


def active_tunnel_ips() -> set[str]:
    if SKIP_SYSTEMD:
        return set()
    content = ""
    for path in (Path("/proc/net/nf_conntrack"), Path("/proc/net/ip_conntrack")):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            break
        except OSError:
            continue
    if not content and shutil.which("conntrack"):
        result = run(["conntrack", "-L"], timeout=15)
        if result.returncode in {0, 1}:
            content = result.stdout
    return set(re.findall(r"(?:src|dst)=(10\.66\.66\.\d+)", content))


def handshake_is_active(stamp: int, window: int = 180) -> bool:
    return stamp > 0 and time.time() - stamp <= window


def connected_user_view(
    user: dict[str, Any], handshakes: dict[str, int], active_ips: set[str]
) -> dict[str, Any]:
    device = user.get("device") or {}
    public_key = str(device.get("pub_key") or device.get("PubKey") or "")
    last_handshake = int(handshakes.get(public_key) or 0)
    user["connected"] = str(device.get("ip") or "") in active_ips or handshake_is_active(last_handshake)
    user["last_handshake"] = last_handshake
    user["role"] = "user"
    return user


def create_user(payload: dict[str, Any]) -> dict[str, Any]:
    requested = str(payload.get("password") or "").strip()
    password = validate_password(requested or generate_password())
    expires_at = parse_expiration(payload)
    vk_hash = normalize_hashes(str(payload.get("vk_hash") or ""))
    ports = validate_ports(str(payload.get("ports") or "56000,56001,9000"))

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
            "vk_hash": vk_hash,
            "ports": ports,
            "is_deactivated": bool(payload.get("is_deactivated", False)),
        }
        data["passwords"][password] = entry
        return user_view(password, entry, data["devices"]).as_dict()

    return mutate_database("create", apply)


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
            entry = {
                "device_id": "",
                "expires_at": expires_at,
                "down_bytes": 0,
                "up_bytes": 0,
                "vk_hash": ",".join(assigned_hashes),
                "ports": ports,
                "is_deactivated": is_deactivated,
            }
            data["passwords"][password] = entry
            created.append(user_view(password, entry, data["devices"]).as_dict())
        return {"users": created, "count": len(created)}

    return mutate_database("bulk-create", apply)


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
        if any(key in payload for key in ("days", "expires_at", "unlimited")):
            entry["expires_at"] = parse_expiration(payload)
        if "is_deactivated" in payload:
            entry["is_deactivated"] = bool(payload["is_deactivated"])
        return user_view(replacement, entry, data["devices"]).as_dict()

    return mutate_database("update", apply)


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

    return mutate_database("delete", apply)


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


def list_backups() -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    if BACKUP_DIR.exists():
        for path in sorted(BACKUP_DIR.glob("passwords-*.json"), reverse=True):
            stat = path.stat()
            items.append({"name": path.name, "size": stat.st_size, "created_at": int(stat.st_mtime)})
    return {"backups": items}


def create_manual_backup(payload: dict[str, Any]) -> dict[str, Any]:
    load_database()
    name = create_backup("manual")
    if not name:
        raise ValidationError("База WDTT еще не создана")
    path = BACKUP_DIR / name
    stat = path.stat()
    return {"name": name, "size": stat.st_size, "created_at": int(stat.st_mtime)}


def restore_backup(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "")
    if not re.fullmatch(r"passwords-[A-Za-z0-9_-]+\.json", name):
        raise ValidationError("Некорректное имя резервной копии")
    source = BACKUP_DIR / name
    if not source.is_file():
        raise ValidationError("Резервная копия не найдена")

    def apply(data: dict[str, Any]) -> dict[str, Any]:
        try:
            restored = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(f"Резервная копия повреждена: {exc}") from exc
        if not isinstance(restored, dict) or not isinstance(restored.get("passwords"), dict):
            raise ValidationError("Резервная копия имеет неверный формат")
        data.clear()
        data.update(restored)
        data.setdefault("devices", {})
        return {"restored": name}

    return mutate_database("before-restore", apply)


def export_backup(payload: dict[str, Any]) -> dict[str, Any]:
    name = validate_backup_name(str(payload.get("name") or ""))
    source = BACKUP_DIR / name
    if not source.is_file():
        raise ValidationError("Резервная копия не найдена")
    return {"name": name, "content": source.read_text(encoding="utf-8")}


def import_backup(payload: dict[str, Any]) -> dict[str, Any]:
    content = str(payload.get("content") or "")
    if not content or len(content.encode("utf-8")) > 3 * 1024 * 1024:
        raise ValidationError("Файл backup пустой или превышает 3 МБ")
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Файл backup содержит неверный JSON: {exc}") from exc
    validate_database_payload(data)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = f"{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 1_000_000:06d}"
    name = f"passwords-{stamp}-uploaded.json"
    destination = BACKUP_DIR / name
    destination.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(destination, 0o600)
    prune_backups()
    return {"name": name, "size": destination.stat().st_size, "created_at": int(time.time())}


def validate_backup_name(name: str) -> str:
    if not re.fullmatch(r"passwords-[A-Za-z0-9_-]+\.json", name):
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
        limit = max(20, min(int(payload.get("limit", 300)), 2000))
    except (TypeError, ValueError):
        limit = 300
    if SKIP_SYSTEMD:
        return {"lines": []}
    result = run(
        ["journalctl", "-u", SERVICE, "-n", str(limit), "--no-pager", "-o", "short-iso"],
        timeout=30,
    )
    if result.returncode != 0:
        raise AdminError(result.stderr.strip() or "Не удалось прочитать journalctl")
    return {"lines": result.stdout.splitlines()}


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


def service_error_hint() -> str:
    if SKIP_SYSTEMD:
        return ""
    result = run(["journalctl", "-u", SERVICE, "-n", "50", "--no-pager", "-o", "cat"], timeout=15)
    if result.returncode != 0:
        return result.stderr.strip()
    markers = ("fatal", "error", "failed", "cannot", "permission", "address already", "tun", "wdtt0")
    for line in reversed(result.stdout.splitlines()):
        if any(marker in line.lower() for marker in markers):
            return line.strip()[:500]
    return "Интерфейс создается самим WDTT; проверьте журнал сервиса"


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
        "inbounds": [],
        "outbounds": [],
        "routing_rules": [],
        "raw_config": "",
        "geofiles": [
            {
                **item,
                "enabled": True,
                "auto_update": True,
                "update_interval": "1d",
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
    for key in ("inbounds", "outbounds", "routing_rules", "geofiles"):
        settings[key] = settings.get(key) if isinstance(settings.get(key), list) else []
    settings["raw_config"] = str(settings.get("raw_config") or "")

    defaults = {item["tag"]: item for item in default_xray_settings()["geofiles"]}
    saved_files = {
        str(item.get("tag")): item for item in settings["geofiles"] if isinstance(item, dict) and item.get("tag")
    }
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


def normalize_xray_settings(payload: dict[str, Any]) -> dict[str, Any]:
    settings = default_xray_settings()
    settings["enabled"] = bool(payload.get("enabled", False))
    settings["mode"] = str(payload.get("mode") or "managed")
    if settings["mode"] not in {"managed", "raw"}:
        raise ValidationError("Выберите режим Xray: managed или raw")
    settings["log_level"] = str(payload.get("log_level") or "warning")
    if settings["log_level"] not in {"debug", "info", "warning", "error", "none"}:
        raise ValidationError("Некорректный уровень журнала Xray")
    settings["geofiles"] = normalize_xray_geofiles(payload.get("geofiles", settings["geofiles"]))
    if settings["mode"] == "raw":
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


def build_xray_config(settings: dict[str, Any]) -> dict[str, Any]:
    if settings["mode"] == "raw":
        parsed = json.loads(settings["raw_config"])
        return xray_object(parsed, "Raw Xray-конфигурация")

    inbounds = settings["inbounds"]
    outbound_tags = {"direct", "block"}
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

    rules: list[dict[str, Any]] = []
    for index, rule in enumerate(settings["routing_rules"]):
        if not str(rule.get("type") or "").strip():
            rule = {"type": "field", **rule}
        target = str(rule.get("outboundTag") or "")
        if target and target not in outbound_tags:
            raise ValidationError(f"Правило {index + 1}: исходящий {target} не настроен")
        rules.append(rule)
    config: dict[str, Any] = {
        "log": {"loglevel": settings["log_level"]},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    return config


def xray_validate_config(config: dict[str, Any]) -> None:
    if SKIP_SYSTEMD or not shutil.which("xray"):
        return
    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="xray-check.", suffix=".json", dir=XRAY_CONFIG.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False)
        checked = run(["xray", "run", "-test", "-c", name], timeout=45)
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
    }


def xray_save(payload: dict[str, Any]) -> dict[str, Any]:
    settings = normalize_xray_settings(payload)
    config = build_xray_config(settings)
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


def overview(payload: dict[str, Any]) -> dict[str, Any]:
    data = load_database()
    stats = read_stats()
    iface = False
    ip_forward = "unknown"
    if not SKIP_SYSTEMD:
        iface = run(["ip", "link", "show", "wdtt0"]).returncode == 0
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
            "interface": iface,
            "ip_forward": ip_forward,
            "binary": Path("/usr/local/bin/wdtt-server").is_file(),
            "interface_error": "" if iface else service_error_hint(),
        },
        "stats": stats,
        "users": len(data.get("passwords", {})),
        "devices": len(data.get("devices", {})),
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
    "service.action": lambda payload: service_action(str(payload.get("service_action") or "")),
    "service.repair": repair_wdtt_interface,
    "logs": journal_logs,
    "backups.list": lambda payload: list_backups(),
    "backups.create": create_manual_backup,
    "backups.restore": restore_backup,
    "backups.export": export_backup,
    "backups.import": import_backup,
    "panel.version": panel_version,
    "panel.update": start_panel_update,
    "certificate.export": export_certificate,
    "certificate.renew": schedule_certificate_renew,
    "xray.status": xray_status,
    "xray.save": xray_save,
    "xray.install": schedule_xray_runtime,
    "xray.geofiles.refresh": xray_refresh_geofile,
    "xray.geofiles.refresh_auto": xray_refresh_auto_geofiles,
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
