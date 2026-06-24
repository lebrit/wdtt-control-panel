from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


PROTOCOL_VERSION = "wdtt-fleet/v1"
FLEET_AGENT_CONFIG = Path(os.environ.get("WDTT_FLEET_AGENT_CONFIG", "/var/lib/wdtt-panel/fleet-agent.json"))
MAX_COMPLETED_COMMANDS = 1_000


class FleetValidationError(ValueError):
    pass


def normalize_endpoint(value: Any) -> str:
    endpoint = str(value or "").strip().rstrip("/")
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or len(endpoint) > 512
    ):
        raise FleetValidationError("Адрес Fleet Manager должен быть HTTPS URL без параметров")
    return endpoint


def normalize_enrollment_grant(value: Any) -> str:
    token = str(value or "").strip()
    if len(token) < 32 or len(token) > 256 or not all(char.isalnum() or char in "_-" for char in token):
        raise FleetValidationError("Некорректный одноразовый грант Fleet Manager")
    return token


def default_config() -> dict[str, Any]:
    return {
        "enabled": False,
        "endpoint": "",
        "enrollment_grant": "",
        "agent_token": "",
        "node_id": "",
        "identity_fingerprint": "",
        "completed_commands": {},
        "last_success_at": 0,
        "last_error_code": "",
        "agent_version": "",
        "poll_interval_seconds": 15,
    }


def load_config(path: Path = FLEET_AGENT_CONFIG) -> dict[str, Any]:
    config = default_config()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return config
    except (OSError, json.JSONDecodeError) as exc:
        raise FleetValidationError("Не удалось прочитать конфигурацию Fleet Agent") from exc
    if not isinstance(value, dict):
        raise FleetValidationError("Конфигурация Fleet Agent должна быть объектом")
    config.update({key: value[key] for key in config if key in value})
    if not isinstance(config["completed_commands"], dict):
        config["completed_commands"] = {}
    return config


def save_config(config: dict[str, Any], path: Path = FLEET_AGENT_CONFIG) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(config, ensure_ascii=False, separators=(",", ":")) + "\n"
    fd, temporary = tempfile.mkstemp(prefix="fleet-agent.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        try:
            import pwd

            account = pwd.getpwnam(os.environ.get("WDTT_FLEET_AGENT_USER", "wdtt-panel"))
            os.chown(path, account.pw_uid, account.pw_gid)
        except (ImportError, KeyError, PermissionError):
            pass
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def configure(payload: dict[str, Any], path: Path = FLEET_AGENT_CONFIG) -> dict[str, Any]:
    allowed = {"endpoint", "enrollment_grant", "enabled", "poll_interval_seconds"}
    unknown = set(payload) - allowed
    if unknown:
        raise FleetValidationError("Неизвестные поля настройки Fleet Agent")

    config = load_config(path)
    endpoint = normalize_endpoint(payload.get("endpoint")) if "endpoint" in payload else config["endpoint"]
    submitted_grant = str(payload.get("enrollment_grant") or "").strip()
    grant = normalize_enrollment_grant(submitted_grant) if submitted_grant else str(config["enrollment_grant"] or "")
    if not endpoint or (not grant and not config.get("agent_token")):
        raise FleetValidationError("Укажите HTTPS-адрес агента и одноразовый грант")
    if "enabled" in payload and not isinstance(payload["enabled"], bool):
        raise FleetValidationError("enabled должен быть логическим значением")
    if "poll_interval_seconds" in payload:
        try:
            interval = int(payload["poll_interval_seconds"])
        except (TypeError, ValueError) as exc:
            raise FleetValidationError("Некорректный интервал агента") from exc
        if not 5 <= interval <= 300:
            raise FleetValidationError("Интервал агента должен быть от 5 до 300 секунд")
        config["poll_interval_seconds"] = interval

    if endpoint != config["endpoint"] or (submitted_grant and grant != config["enrollment_grant"]):
        config.update({
            "endpoint": endpoint,
            "enrollment_grant": grant,
            "agent_token": "",
            "node_id": "",
            "completed_commands": {},
            "last_error_code": "",
        })
    config["enabled"] = bool(payload.get("enabled", True))
    if not config["identity_fingerprint"]:
        config["identity_fingerprint"] = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    save_config(config, path)
    return public_status(config)


def public_status(config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or load_config()
    return {
        "enabled": bool(config.get("enabled")),
        "configured": bool(config.get("endpoint") and (config.get("enrollment_grant") or config.get("agent_token"))),
        "enrolled": bool(config.get("agent_token") and config.get("node_id")),
        "endpoint": str(config.get("endpoint") or ""),
        "node_id": str(config.get("node_id") or ""),
        "last_success_at": int(config.get("last_success_at") or 0),
        "last_error_code": str(config.get("last_error_code") or ""),
        "poll_interval_seconds": int(config.get("poll_interval_seconds") or 15),
        "completed_commands": len(config.get("completed_commands") or {}),
        "protocol_version": PROTOCOL_VERSION,
    }


def remember_completion(config: dict[str, Any], command_id: str, status: str, error_code: str = "") -> None:
    completed = config.setdefault("completed_commands", {})
    completed[command_id] = {"status": status, "error_code": error_code, "completed_at": int(time.time())}
    if len(completed) > MAX_COMPLETED_COMMANDS:
        for command in sorted(completed, key=lambda item: int(completed[item].get("completed_at") or 0))[: len(completed) - MAX_COMPLETED_COMMANDS]:
            completed.pop(command, None)
