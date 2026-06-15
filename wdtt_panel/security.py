from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any


PBKDF2_ITERATIONS = 600_000


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    if len(password) < 12:
        raise ValueError("Пароль панели должен содержать не менее 12 символов")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), _unb64(salt), int(rounds)
        )
        return hmac.compare_digest(digest, _unb64(expected))
    except (ValueError, TypeError):
        return False


def create_session(username: str, secret: str, ttl: int = 43_200) -> tuple[str, str]:
    now = int(time.time())
    payload = {
        "u": username,
        "iat": now,
        "exp": now + ttl,
        "n": secrets.token_urlsafe(18),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    body = _b64(raw)
    signature = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    token = f"{body}.{signature}"
    csrf = csrf_token(payload["n"], secret)
    return token, csrf


def read_session(token: str, secret: str) -> dict[str, Any] | None:
    try:
        body, signature = token.split(".", 1)
        expected = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(_unb64(body))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def csrf_token(nonce: str, secret: str) -> str:
    return _b64(hmac.new(secret.encode(), f"csrf:{nonce}".encode(), hashlib.sha256).digest())


def verify_csrf(value: str, session: dict[str, Any], secret: str) -> bool:
    expected = csrf_token(str(session.get("n", "")), secret)
    return hmac.compare_digest(value or "", expected)
