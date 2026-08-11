from __future__ import annotations

import calendar
import ipaddress
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


MAX_USERS = 10
PASSWORD_RE = re.compile(r"^[A-Za-z0-9._~-]{8,64}$")
HASH_RE = re.compile(r"^[A-Za-z0-9_-]{3,256}$")
MAX_USER_LABEL_LENGTH = 64
GIB = 1024**3
DEFAULT_TRAFFIC_GIB_PER_MONTH = 35


class ValidationError(ValueError):
    pass


def generate_password(length: int = 16) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def validate_password(value: str) -> str:
    value = (value or "").strip()
    if not PASSWORD_RE.fullmatch(value):
        raise ValidationError(
            "Пароль должен содержать 8-64 символа: латиница, цифры, . _ ~ -"
        )
    return value


def normalize_user_label(value: str) -> str:
    """Return a safe human-readable label shared with the WDTT Telegram bot."""
    label = (value or "").strip()
    if len(label) > MAX_USER_LABEL_LENGTH:
        raise ValidationError(f"Метка пользователя может содержать до {MAX_USER_LABEL_LENGTH} символов")
    if any(ord(char) < 32 or ord(char) == 127 for char in label):
        raise ValidationError("Метка пользователя не должна содержать служебные символы")
    return label


def user_label_from_entry(entry: dict[str, Any]) -> str:
    """Read labels written by both current and earlier WDTT Telegram bots."""
    for key in (
        "label",
        "remark",
        "name",
        "comment",
        "tag",
        "mark",
        "user_label",
        "userLabel",
        "user_name",
        "userName",
        "note",
        "description",
    ):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def normalize_hash(value: str) -> str:
    value = (value or "").strip()
    if "/" in value:
        value = value.rstrip("/").rsplit("/", 1)[-1]
    value = value.split("?", 1)[0].strip()
    if not HASH_RE.fullmatch(value):
        raise ValidationError(f"Некорректный VK-хеш: {value or '(пусто)'}")
    return value


def normalize_hashes(value: str) -> str:
    raw = re.split(r"[,\s]+", (value or "").strip())
    items = [normalize_hash(item) for item in raw if item]
    if not items:
        raise ValidationError("Укажите хотя бы один VK-хеш")
    if len(items) > 4:
        raise ValidationError("WDTT поддерживает не более четырех VK-хешей")
    return ",".join(dict.fromkeys(items))


def validate_ports(value: str) -> str:
    parts = [part.strip() for part in (value or "").split(",")]
    if len(parts) != 3:
        raise ValidationError("Порты задаются как DTLS,WG,TUN")
    ports: list[str] = []
    for part in parts:
        try:
            port = int(part)
        except ValueError as exc:
            raise ValidationError("Порт должен быть числом") from exc
        if not 1 <= port <= 65535:
            raise ValidationError("Порт должен быть в диапазоне 1-65535")
        ports.append(str(port))
    return ",".join(ports)


def add_calendar_months(timestamp: int, months: int) -> int:
    if not 1 <= months <= 36:
        raise ValidationError("Срок должен быть от 1 до 36 месяцев")
    value = datetime.fromtimestamp(timestamp, timezone.utc)
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return int(value.replace(year=year, month=month, day=day).timestamp())


def parse_expiration(payload: dict[str, Any], now: int | None = None) -> int:
    if payload.get("unlimited"):
        return 0
    now = int(now or time.time())
    if payload.get("months") not in (None, ""):
        try:
            months = int(payload["months"])
        except (TypeError, ValueError) as exc:
            raise ValidationError("Срок в месяцах должен быть числом") from exc
        return add_calendar_months(now, months)
    if payload.get("expires_at") not in (None, ""):
        try:
            expires_at = int(payload["expires_at"])
        except (TypeError, ValueError) as exc:
            raise ValidationError("Некорректная дата окончания") from exc
        if expires_at <= now:
            raise ValidationError("Дата окончания должна быть в будущем")
        return expires_at
    try:
        days = int(payload.get("days", 30))
    except (TypeError, ValueError) as exc:
        raise ValidationError("Срок должен быть числом дней") from exc
    if not 1 <= days <= 3650:
        raise ValidationError("Срок должен быть от 1 до 3650 дней")
    return now + days * 86400


def is_expired(entry: dict[str, Any], now: int | None = None) -> bool:
    expires_at = int(entry.get("expires_at") or 0)
    return expires_at > 0 and expires_at < int(now or time.time())


def traffic_quota(entry: dict[str, Any]) -> dict[str, Any]:
    current = max(0, int(entry.get("down_bytes") or 0) + int(entry.get("up_bytes") or 0))
    managed = bool(entry.get("traffic_managed", False))
    unlimited = not managed or bool(entry.get("traffic_unlimited", False))
    baseline = max(0, int(entry.get("traffic_baseline_bytes") or 0))
    primary = max(0, int(entry.get("traffic_primary_bytes") or 0))
    extra = max(0, int(entry.get("traffic_extra_bytes") or 0))
    used = max(0, current - baseline) if managed and not unlimited else current
    primary_remaining = max(0, primary - used) if not unlimited else 0
    extra_used = max(0, used - primary)
    extra_remaining = max(0, extra - extra_used) if not unlimited else 0
    remaining = primary_remaining + extra_remaining
    limit = primary + extra
    return {
        "traffic_managed": managed,
        "traffic_unlimited": unlimited,
        "traffic_baseline_bytes": baseline,
        "traffic_primary_bytes": primary,
        "traffic_extra_bytes": extra,
        "traffic_quota_used_bytes": used,
        "traffic_primary_remaining_bytes": primary_remaining,
        "traffic_extra_remaining_bytes": extra_remaining,
        "traffic_remaining_bytes": remaining,
        "traffic_limit_bytes": limit,
        "quota_exhausted": managed and not unlimited and remaining <= 0,
    }


def validate_public_host(value: str) -> str:
    value = (value or "").strip().strip("[]")
    if not value or len(value) > 253 or any(ch in value for ch in "/:@ "):
        raise ValidationError("Некорректный домен или IP")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    labels = value.rstrip(".").split(".")
    if len(labels) < 2:
        raise ValidationError("Укажите полный домен или IP")
    label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    if not all(label_re.fullmatch(label) for label in labels):
        raise ValidationError("Некорректный домен")
    return value.lower()


def quick_link(host: str, password: str, entry: dict[str, Any]) -> str:
    ports = validate_ports(str(entry.get("ports") or "56000,56001,9000")).split(",")
    hashes = str(entry.get("vk_hash") or "")
    return f"wdtt://{host}:{ports[0]}:{ports[1]}:{ports[2]}:{password}:{hashes}"


@dataclass(frozen=True)
class UserView:
    password: str
    label: str
    device_id: str
    expires_at: int
    down_bytes: int
    up_bytes: int
    last_upload_at: int
    last_download_at: int
    vk_hash: str
    ports: str
    is_deactivated: bool
    expired: bool
    device: dict[str, Any] | None
    traffic_managed: bool
    traffic_unlimited: bool
    traffic_baseline_bytes: int
    traffic_primary_bytes: int
    traffic_extra_bytes: int
    traffic_quota_used_bytes: int
    traffic_primary_remaining_bytes: int
    traffic_extra_remaining_bytes: int
    traffic_remaining_bytes: int
    traffic_limit_bytes: int
    quota_exhausted: bool
    traffic_operations: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def user_view(password: str, entry: dict[str, Any], devices: dict[str, Any]) -> UserView:
    device_id = str(entry.get("device_id") or "")
    quota = traffic_quota(entry)
    return UserView(
        password=password,
        label=user_label_from_entry(entry),
        device_id=device_id,
        expires_at=int(entry.get("expires_at") or 0),
        down_bytes=int(entry.get("down_bytes") or 0),
        up_bytes=int(entry.get("up_bytes") or 0),
        last_upload_at=int(entry.get("last_upload_at") or 0),
        last_download_at=int(entry.get("last_download_at") or 0),
        vk_hash=str(entry.get("vk_hash") or ""),
        ports=str(entry.get("ports") or "56000,56001,9000"),
        is_deactivated=bool(entry.get("is_deactivated", False)),
        expired=is_expired(entry),
        device=devices.get(device_id) if device_id else None,
        **quota,
        traffic_operations=[item for item in entry.get("traffic_operations", []) if isinstance(item, dict)][-50:],
    )
