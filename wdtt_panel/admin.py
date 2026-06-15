from __future__ import annotations

import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

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
SERVICE = os.environ.get("WDTT_SERVICE", "wdtt.service")
SKIP_SYSTEMD = os.environ.get("WDTT_SKIP_SYSTEMD") == "1"
MAX_INPUT = 1024 * 1024


class AdminError(RuntimeError):
    pass


def run(command: list[str], timeout: int = 20, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=check,
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
    users = [
        user_view(password, entry if isinstance(entry, dict) else {}, data["devices"]).as_dict()
        for password, entry in data["passwords"].items()
    ]
    users.sort(key=lambda item: (item["expired"], item["is_deactivated"], item["password"]))
    return {
        "users": users,
        "main_password_present": bool(data.get("main_password")),
        "limit": MAX_USERS,
    }


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
    return {
        "service": {
            "exists": service_exists(),
            "active": service_active(),
            "interface": iface,
            "ip_forward": ip_forward,
            "binary": Path("/usr/local/bin/wdtt-server").is_file(),
        },
        "stats": stats,
        "users": len(data.get("passwords", {})),
        "devices": len(data.get("devices", {})),
        "disk": {"total": disk.total, "used": disk.used, "free": disk.free},
        "certificate": certificate_info(str(payload.get("certificate_path") or "")),
        "timestamp": int(time.time()),
    }


OPERATIONS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "overview": overview,
    "users.list": lambda payload: list_users(),
    "users.create": create_user,
    "users.update": update_user,
    "users.delete": delete_user,
    "users.unbind": unbind_user,
    "users.reset_traffic": reset_traffic,
    "service.action": lambda payload: service_action(str(payload.get("service_action") or "")),
    "logs": journal_logs,
    "backups.list": lambda payload: list_backups(),
    "backups.restore": restore_backup,
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

            lock_path = Path("/run/lock/wdtt-panel-admin.lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            with lock_path.open("a", encoding="utf-8") as lock:
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
