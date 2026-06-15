from __future__ import annotations

import ipaddress
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any


MAX_USERS = 10
PASSWORD_RE = re.compile(r"^[A-Za-z0-9._~-]{8,64}$")
HASH_RE = re.compile(r"^[A-Za-z0-9_-]{3,256}$")


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


def parse_expiration(payload: dict[str, Any], now: int | None = None) -> int:
    if payload.get("unlimited"):
        return 0
    now = int(now or time.time())
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
    device_id: str
    expires_at: int
    down_bytes: int
    up_bytes: int
    vk_hash: str
    ports: str
    is_deactivated: bool
    expired: bool
    device: dict[str, Any] | None

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def user_view(password: str, entry: dict[str, Any], devices: dict[str, Any]) -> UserView:
    device_id = str(entry.get("device_id") or "")
    return UserView(
        password=password,
        device_id=device_id,
        expires_at=int(entry.get("expires_at") or 0),
        down_bytes=int(entry.get("down_bytes") or 0),
        up_bytes=int(entry.get("up_bytes") or 0),
        vk_hash=str(entry.get("vk_hash") or ""),
        ports=str(entry.get("ports") or "56000,56001,9000"),
        is_deactivated=bool(entry.get("is_deactivated", False)),
        expired=is_expired(entry),
        device=devices.get(device_id) if device_id else None,
    )
