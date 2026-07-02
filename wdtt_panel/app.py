from __future__ import annotations

import hmac
import json
import mimetypes
import os
import secrets
import sqlite3
import subprocess
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from http import cookies
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Iterable
from urllib.parse import parse_qs
from wsgiref.simple_server import WSGIServer, make_server

from .core import ValidationError, normalize_hash, normalize_user_label
from .security import create_session, read_session, verify_csrf, verify_password


PACKAGE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = Path(os.environ.get("WDTT_PANEL_CONFIG", "/etc/wdtt-panel/config.json"))
STATE_DB = Path(os.environ.get("WDTT_PANEL_STATE", "/var/lib/wdtt-panel/panel.db"))
ADMIN_COMMAND = os.environ.get("WDTT_PANEL_ADMIN", "/usr/bin/sudo -n /usr/local/sbin/wdtt-panel-admin").split()
MAX_BODY = 90 * 1024 * 1024


class ThreadingServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class RateLimiter:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.failures: dict[str, list[float]] = {}

    def allowed(self, key: str) -> bool:
        cutoff = time.time() - 900
        with self.lock:
            recent = [stamp for stamp in self.failures.get(key, []) if stamp > cutoff]
            self.failures[key] = recent
            return len(recent) < 8

    def fail(self, key: str) -> None:
        with self.lock:
            self.failures.setdefault(key, []).append(time.time())

    def clear(self, key: str) -> None:
        with self.lock:
            self.failures.pop(key, None)


class Panel:
    def __init__(self) -> None:
        self.config = self.load_config()
        self.base = "/" + str(self.config["base_path"]).strip("/") + "/"
        self.rate_limiter = RateLimiter()
        self.init_state()

    @staticmethod
    def load_config() -> dict[str, Any]:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        required = {"username", "password_hash", "session_secret", "base_path", "public_host"}
        missing = required - data.keys()
        if missing:
            raise RuntimeError(f"В конфигурации панели отсутствует: {', '.join(sorted(missing))}")
        return data

    def init_state(self) -> None:
        STATE_DB.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(STATE_DB)) as db:
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    remote_addr TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    detail TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metrics (
                    captured_at INTEGER PRIMARY KEY,
                    active INTEGER NOT NULL,
                    total INTEGER NOT NULL,
                    up_gb REAL NOT NULL,
                    down_gb REAL NOT NULL,
                    users INTEGER NOT NULL,
                    devices INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vk_hash_library (
                    value TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL
                );
                """
            )
            db.commit()

    def audit(self, environ: dict[str, Any], action: str, status: str, detail: str = "") -> None:
        remote = self.remote_addr(environ)
        username = str(environ.get("wdtt.user") or self.config["username"])
        with closing(sqlite3.connect(STATE_DB)) as db:
            db.execute(
                "INSERT INTO audit(created_at, username, remote_addr, action, status, detail) VALUES(?,?,?,?,?,?)",
                (int(time.time()), username, remote, action, status, detail[:1000]),
            )
            db.commit()

    @staticmethod
    def remote_addr(environ: dict[str, Any]) -> str:
        forwarded = str(environ.get("HTTP_X_FORWARDED_FOR") or "").split(",", 1)[0].strip()
        return forwarded or str(environ.get("REMOTE_ADDR") or "unknown")

    def __call__(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        path = str(environ.get("PATH_INFO") or "/")
        if path == self.base.rstrip("/"):
            return self.redirect(start_response, self.base)
        if not path.startswith(self.base):
            return self.response(start_response, "404 Not Found", b"Not found", "text/plain")

        relative = path[len(self.base) :]
        if relative.startswith("static/"):
            return self.static(start_response, relative[7:])

        if relative == "api/v1/info" and environ["REQUEST_METHOD"] == "GET":
            return self.json_response(start_response, 200, {"ok": True, "result": self.api_v1_info_payload()})
        if relative == "api/v1/auth/login" and environ["REQUEST_METHOD"] == "POST":
            return self.api_v1_login(environ, start_response)
        if relative.startswith("api/v1/"):
            session = self.bearer_session(environ)
            if session is None:
                return self.json_response(start_response, 401, {"ok": False, "error": "Требуется bearer-токен"})
            environ["wdtt.user"] = session.get("u")
            return self.api_v1(environ, start_response, relative[7:], session)

        session = self.session(environ)
        if relative == "login" and environ["REQUEST_METHOD"] == "POST":
            return self.login(environ, start_response)
        if session is None:
            return self.login_page(start_response)
        environ["wdtt.user"] = session.get("u")

        if relative == "logout" and environ["REQUEST_METHOD"] == "POST":
            if not self.valid_csrf(environ, session):
                return self.json_response(start_response, 403, {"error": "CSRF-проверка не пройдена"})
            self.audit(environ, "logout", "ok")
            return self.redirect(start_response, self.base, clear_cookie=True)
        if relative == "" and environ["REQUEST_METHOD"] == "GET":
            return self.index_page(start_response, session)
        if relative.startswith("api/"):
            return self.api(environ, start_response, relative[4:], session)
        return self.response(start_response, "404 Not Found", b"Not found", "text/plain")

    def session(self, environ: dict[str, Any]) -> dict[str, Any] | None:
        jar = cookies.SimpleCookie(environ.get("HTTP_COOKIE", ""))
        item = jar.get("wdtt_session")
        if item is None:
            return None
        return read_session(item.value, str(self.config["session_secret"]))

    def bearer_session(self, environ: dict[str, Any]) -> dict[str, Any] | None:
        header = str(environ.get("HTTP_AUTHORIZATION") or "").strip()
        if not header.lower().startswith("bearer "):
            return None
        token = header[7:].strip()
        if not token:
            return None
        return read_session(token, str(self.config["session_secret"]))

    def login(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        remote = self.remote_addr(environ)
        if not self.rate_limiter.allowed(remote):
            self.audit(environ, "login", "blocked", "rate-limit")
            return self.login_page(start_response, "Слишком много попыток. Повторите позже.", 429)
        form = parse_qs(self.read_body(environ).decode("utf-8", "replace"))
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        expected_user = str(self.config["username"])
        user_ok = hmac.compare_digest(username, expected_user)
        password_ok = verify_password(password, str(self.config["password_hash"]))
        if not (user_ok and password_ok):
            self.rate_limiter.fail(remote)
            self.audit(environ, "login", "failed")
            return self.login_page(start_response, "Неверный логин или пароль", 401)
        self.rate_limiter.clear(remote)
        token, _ = create_session(expected_user, str(self.config["session_secret"]))
        self.audit(environ, "login", "ok")
        secure = (
            f"wdtt_session={token}; Path={self.base}; HttpOnly; Secure; "
            "SameSite=Strict; Max-Age=43200"
        )
        return self.redirect(start_response, self.base, set_cookie=secure)

    def api_v1_info_payload(self) -> dict[str, Any]:
        return {
            "name": "WDTT Control Panel",
            "api_version": 1,
            "panel_version": str(self.config.get("version") or "0.0.0"),
            "base_path": self.base,
            "public_host": str(self.config.get("public_host") or ""),
            "https_port": int(self.config.get("https_port") or 443),
            "auth": {"type": "password", "username_optional": True},
            "capabilities": [
                "overview",
                "users",
                "users.create",
                "users.update",
                "users.delete",
                "users.unbind",
                "users.reset_traffic",
                "users.bulk_action",
                "service",
                "logs",
                "backups",
                "panel.version",
            ],
        }

    def api_v1_login(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        remote = self.remote_addr(environ)
        if not self.rate_limiter.allowed(remote):
            self.audit(environ, "api.v1.login", "blocked", "rate-limit")
            return self.json_response(start_response, 429, {"ok": False, "error": "Слишком много попыток. Повторите позже."})
        payload = self.read_json(environ)
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        expected_user = str(self.config["username"])
        user_ok = not username or hmac.compare_digest(username, expected_user)
        password_ok = verify_password(password, str(self.config["password_hash"]))
        if not (user_ok and password_ok):
            self.rate_limiter.fail(remote)
            self.audit(environ, "api.v1.login", "failed")
            return self.json_response(start_response, 401, {"ok": False, "error": "Неверный пароль"})
        self.rate_limiter.clear(remote)
        token, _ = create_session(expected_user, str(self.config["session_secret"]))
        environ["wdtt.user"] = expected_user
        self.audit(environ, "api.v1.login", "ok")
        return self.json_response(
            start_response,
            200,
            {
                "ok": True,
                "result": {
                    "token": token,
                    "token_type": "Bearer",
                    "expires_in": 43200,
                    "username": expected_user,
                    "server": self.api_v1_info_payload(),
                },
            },
        )

    def valid_csrf(self, environ: dict[str, Any], session: dict[str, Any]) -> bool:
        value = str(environ.get("HTTP_X_CSRF_TOKEN") or "")
        return verify_csrf(value, session, str(self.config["session_secret"]))

    def api(
        self,
        environ: dict[str, Any],
        start_response: Any,
        route: str,
        session: dict[str, Any],
        require_csrf: bool = True,
    ) -> Iterable[bytes]:
        method = environ["REQUEST_METHOD"]
        if method not in {"GET", "POST"}:
            return self.json_response(start_response, 405, {"error": "Метод не поддерживается"})
        if method == "POST" and require_csrf and not self.valid_csrf(environ, session):
            return self.json_response(start_response, 403, {"error": "CSRF-проверка не пройдена"})
        payload = self.read_json(environ) if method == "POST" else {}
        if route == "vk-hashes":
            if method == "GET":
                return self.json_response(start_response, 200, {"ok": True, "result": self.list_vk_hashes()})
            try:
                result = self.add_vk_hashes(payload)
            except ValidationError as exc:
                self.audit(environ, "vk-hashes.add", "error", str(exc))
                return self.json_response(start_response, 400, {"ok": False, "error": str(exc)})
            self.audit(environ, "vk-hashes.add", "ok")
            return self.json_response(start_response, 200, {"ok": True, "result": result})
        if route == "vk-hashes/delete":
            if method != "POST":
                return self.json_response(start_response, 405, {"error": "Требуется POST"})
            try:
                result = self.delete_vk_hash(payload)
            except ValidationError as exc:
                self.audit(environ, "vk-hashes.delete", "error", str(exc))
                return self.json_response(start_response, 400, {"ok": False, "error": str(exc)})
            self.audit(environ, "vk-hashes.delete", "ok")
            return self.json_response(start_response, 200, {"ok": True, "result": result})
        if route == "users/create-auto":
            if method != "POST":
                return self.json_response(start_response, 405, {"error": "Требуется POST"})
            try:
                result = self.create_auto_user(payload)
            except ValidationError as exc:
                self.audit(environ, "users.create_auto", "error", str(exc))
                return self.json_response(start_response, 400, {"ok": False, "error": str(exc)})
            self.audit(environ, "users.create_auto", "ok" if result.get("ok") else "error", str(result.get("error") or ""))
            return self.json_response(start_response, 200 if result.get("ok") else 400, result)
        if route == "qwdtt/subscription":
            if method != "GET":
                return self.json_response(start_response, 405, {"error": "Требуется GET"})
            return self.json_response(start_response, 200, {"ok": True, "result": self.qwdtt_subscription()})
        mapping = {
            "overview": "overview",
            "users": "users.list",
            "users/create": "users.create",
            "users/create-bulk": "users.create_bulk",
            "users/update": "users.update",
            "users/delete": "users.delete",
            "users/unbind": "users.unbind",
            "users/reset-traffic": "users.reset_traffic",
            "users/bulk-action": "users.bulk_action",
            "service": "service.action",
            "logs": "logs",
            "backups": "backups.list",
            "backups/create": "backups.create",
            "backups/delete": "backups.delete",
            "backups/restore": "backups.restore",
            "backups/export": "backups.export",
            "backups/import": "backups.import",
            "backups/schedule": "backups.schedule",
            "panel/version": "panel.version",
            "panel/update": "panel.update",
            "certificate/export": "certificate.export",
            "certificate/renew": "certificate.renew",
            "xray": "xray.status",
            "xray/save": "xray.save",
            "xray/install": "xray.install",
            "xray/geofiles/refresh": "xray.geofiles.refresh",
            "xray/geofiles/refresh-all": "xray.geofiles.refresh_auto",
            "warp": "warp.status",
            "warp/install": "warp.install",
            "warp/create": "warp.create",
            "warp/recreate": "warp.create",
            "warp/restart": "warp.restart",
            "warp/ping": "warp.ping",
            "cascade": "cascade.status",
            "cascade/save": "cascade.save",
            "cascade/restart": "cascade.restart",
        }
        if route == "history" and method == "GET":
            return self.json_response(start_response, 200, self.history())
        if route == "audit" and method == "GET":
            return self.json_response(start_response, 200, self.audit_rows())
        action = mapping.get(route)
        if action is None:
            return self.json_response(start_response, 404, {"error": "API endpoint не найден"})
        if method == "GET" and action not in {"overview", "users.list", "logs", "backups.list", "backups.export", "backups.schedule", "panel.version", "certificate.export", "xray.status", "warp.status", "cascade.status"}:
            return self.json_response(start_response, 405, {"error": "Требуется POST"})
        if method == "POST" and action in {"overview", "users.list", "backups.list"}:
            return self.json_response(start_response, 405, {"error": "Требуется GET"})
        if action == "overview":
            payload["certificate_path"] = str(self.config.get("certificate_path") or "")
            payload["tls_mode"] = str(self.config.get("tls_mode") or "unknown")
            payload["public_host"] = str(self.config.get("public_host") or "")
            payload["https_port"] = int(self.config.get("https_port") or 443)
        if action == "logs":
            query = parse_qs(str(environ.get("QUERY_STRING") or ""))
            payload["limit"] = query.get("limit", [300])[0]
            payload["source"] = query.get("source", ["wdtt"])[0]
        if action == "panel.version":
            payload["current_version"] = str(self.config.get("version") or "0.0.0")
        if action == "backups.export":
            query = parse_qs(str(environ.get("QUERY_STRING") or ""))
            payload["name"] = query.get("name", [""])[0]
        if action == "certificate.export":
            payload["certificate_path"] = str(self.config.get("certificate_path") or "")
        if route == "xray/geofiles/refresh-all":
            payload["force"] = True
        result = self.admin(action, payload)
        status = 200 if result.get("ok") else 400
        if result.get("ok") and action == "overview":
            self.record_metrics(result.get("result") or {})
        if result.get("ok") and action in {"users.create", "users.create_bulk", "users.update"}:
            raw_hashes = str(payload.get("vk_hash") or "").strip()
            if raw_hashes:
                try:
                    self.add_vk_hashes({"hashes": raw_hashes})
                except ValidationError:
                    # A successful WDTT change should not be rolled back because the optional library is full.
                    pass
        if method == "POST":
            self.audit(environ, action, "ok" if result.get("ok") else "error", str(result.get("error") or ""))
        return self.json_response(start_response, status, result)

    def api_v1(
        self,
        environ: dict[str, Any],
        start_response: Any,
        route: str,
        session: dict[str, Any],
    ) -> Iterable[bytes]:
        route = route.strip("/")
        if route == "info" and environ["REQUEST_METHOD"] == "GET":
            return self.json_response(start_response, 200, {"ok": True, "result": self.api_v1_info_payload()})
        if route == "auth/session" and environ["REQUEST_METHOD"] == "GET":
            return self.json_response(
                start_response,
                200,
                {"ok": True, "result": {"username": session.get("u"), "server": self.api_v1_info_payload()}},
            )
        if route == "auth/logout" and environ["REQUEST_METHOD"] == "POST":
            self.audit(environ, "api.v1.logout", "ok")
            return self.json_response(start_response, 200, {"ok": True, "result": {"logged_out": True}})
        legacy_route = {
            "version": "panel/version",
            "users/bulk": "users/create-bulk",
            "users/auto": "users/create-auto",
        }.get(route, route)
        return self.api(environ, start_response, legacy_route, session, require_csrf=False)

    @staticmethod
    def admin(action: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = json.dumps({"action": action, "payload": payload}, ensure_ascii=False)
        try:
            completed = subprocess.run(
                ADMIN_COMMAND,
                input=request,
                text=True,
                capture_output=True,
                timeout=240 if action.startswith(("xray.", "warp.", "cascade.")) else 60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "error": f"Root-helper недоступен: {exc}"}
        try:
            response = json.loads(completed.stdout)
            if isinstance(response, dict):
                return response
        except json.JSONDecodeError:
            pass
        error = completed.stderr.strip() or completed.stdout.strip() or "Root-helper вернул неверный ответ"
        return {"ok": False, "error": error}

    def record_metrics(self, overview: dict[str, Any]) -> None:
        stats = overview.get("stats") or {}
        captured = int(time.time() // 10 * 10)
        try:
            values = (
                captured,
                int(stats.get("active") or 0),
                int(stats.get("total") or 0),
                float(stats.get("up_gb") or 0),
                float(stats.get("down_gb") or 0),
                int(overview.get("users") or 0),
                int(overview.get("devices") or 0),
            )
        except (TypeError, ValueError):
            return
        with closing(sqlite3.connect(STATE_DB)) as db:
            db.execute("INSERT OR REPLACE INTO metrics VALUES(?,?,?,?,?,?,?)", values)
            db.execute("DELETE FROM metrics WHERE captured_at < ?", (int(time.time()) - 7 * 86400,))
            db.commit()

    @staticmethod
    def list_vk_hashes() -> dict[str, Any]:
        with closing(sqlite3.connect(STATE_DB)) as db:
            rows = db.execute("SELECT value FROM vk_hash_library ORDER BY created_at, value").fetchall()
        return {"hashes": [row[0] for row in rows]}

    @staticmethod
    def add_vk_hashes(payload: dict[str, Any]) -> dict[str, Any]:
        raw = str(payload.get("hashes") or "")
        values = [normalize_hash(item) for item in raw.replace(",", " ").split()]
        values = list(dict.fromkeys(values))
        if not values:
            raise ValidationError("Укажите хотя бы один VK-хеш")
        if len(values) > 100:
            raise ValidationError("За один раз можно добавить не более 100 VK-хешей")
        with closing(sqlite3.connect(STATE_DB)) as db:
            existing = db.execute("SELECT COUNT(*) FROM vk_hash_library").fetchone()[0]
            new_values = [
                value for value in values
                if db.execute("SELECT 1 FROM vk_hash_library WHERE value = ?", (value,)).fetchone() is None
            ]
            if existing + len(new_values) > 500:
                raise ValidationError("В библиотеке может быть не более 500 VK-хешей")
            now = int(time.time())
            db.executemany(
                "INSERT OR IGNORE INTO vk_hash_library(value, created_at) VALUES(?, ?)",
                [(value, now) for value in values],
            )
            db.commit()
        return Panel.list_vk_hashes()

    @staticmethod
    def delete_vk_hash(payload: dict[str, Any]) -> dict[str, Any]:
        value = normalize_hash(str(payload.get("hash") or ""))
        with closing(sqlite3.connect(STATE_DB)) as db:
            db.execute("DELETE FROM vk_hash_library WHERE value = ?", (value,))
            db.commit()
        return Panel.list_vk_hashes()

    def create_auto_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        label = normalize_user_label(str(payload.get("label") or ""))
        if not label:
            raise ValidationError("Укажите метку пользователя")
        hashes = self.list_vk_hashes().get("hashes") or []
        if not hashes:
            raise ValidationError("Библиотека VK-хешей пуста")
        return self.admin(
            "users.create",
            {
                "label": label,
                "vk_hash": secrets.choice(hashes),
                "days": 30,
                "ports": "56000,56001,9000",
            },
        )

    def qwdtt_subscription(self) -> dict[str, Any]:
        users_result = self.admin("users.list", {})
        root = users_result.get("result") if users_result.get("ok") else {}
        users = root.get("users") if isinstance(root, dict) else []
        users = [user for user in users if isinstance(user, dict) and user.get("password")]
        used_bytes = sum(int(user.get("down_bytes") or 0) + int(user.get("up_bytes") or 0) for user in users)
        host = str(self.config.get("public_host") or "WDTT")
        return {
            "subscriptionName": f"WDTT {host}",
            "description": f"WDTT Control Panel {self.config.get('version') or '0.0.0'}",
            "trafficUsedMb": round(used_bytes / 1024 / 1024, 2),
            "updatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "version": 1,
            "profiles": [self.qwdtt_profile(user) for user in users],
        }

    def qwdtt_profile(self, user: dict[str, Any]) -> dict[str, Any]:
        ports = [item.strip() for item in str(user.get("ports") or "56000,56001,9000").split(",")]
        dtls_port = ports[0] if len(ports) > 0 and ports[0] else "56000"
        local_port = ports[2] if len(ports) > 2 and ports[2] else "9000"
        host = str(self.config.get("public_host") or "")
        peer = f"{host}:{dtls_port}" if host else f":{dtls_port}"
        return {
            "name": str(user.get("label") or user.get("password") or "WDTT"),
            "peer": peer,
            "hashes": str(user.get("vk_hash") or ""),
            "workers": 16,
            "port": int(local_port) if local_port.isdigit() else 9000,
            "password": str(user.get("password") or ""),
            "expiresAt": int(user.get("expires_at") or 0),
            "trafficUsedMb": round((int(user.get("down_bytes") or 0) + int(user.get("up_bytes") or 0)) / 1024 / 1024, 2),
        }

    @staticmethod
    def history() -> dict[str, Any]:
        cutoff = int(time.time()) - 24 * 3600
        with closing(sqlite3.connect(STATE_DB)) as db:
            rows = db.execute(
                "SELECT captured_at, active, total, up_gb, down_gb, users, devices "
                "FROM metrics WHERE captured_at >= ? ORDER BY captured_at",
                (cutoff,),
            ).fetchall()
        return {"points": [list(row) for row in rows]}

    @staticmethod
    def audit_rows() -> dict[str, Any]:
        with closing(sqlite3.connect(STATE_DB)) as db:
            rows = db.execute(
                "SELECT created_at, username, remote_addr, action, status, detail "
                "FROM audit ORDER BY id DESC LIMIT 200"
            ).fetchall()
        return {"items": [list(row) for row in rows]}

    def read_body(self, environ: dict[str, Any]) -> bytes:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            raise ValueError("Запрос слишком большой")
        return environ["wsgi.input"].read(length)

    def read_json(self, environ: dict[str, Any]) -> dict[str, Any]:
        try:
            body = self.read_body(environ)
            data = json.loads(body or b"{}")
            return data if isinstance(data, dict) else {}
        except (ValueError, json.JSONDecodeError):
            return {}

    def login_page(self, start_response: Any, error: str = "", status: int = 200) -> Iterable[bytes]:
        html = (PACKAGE_DIR / "templates" / "login.html").read_text(encoding="utf-8")
        html = html.replace("{{BASE}}", self.base).replace("{{ERROR}}", escape_html(error))
        return self.response(
            start_response,
            f"{status} {'OK' if status == 200 else 'Unauthorized'}",
            html.encode(),
            "text/html; charset=utf-8",
        )

    def index_page(self, start_response: Any, session: dict[str, Any]) -> Iterable[bytes]:
        html = (PACKAGE_DIR / "templates" / "index.html").read_text(encoding="utf-8")
        from .security import csrf_token

        csrf = csrf_token(str(session["n"]), str(self.config["session_secret"]))
        replacements = {
            "{{BASE}}": self.base,
            "{{CSRF}}": csrf,
            "{{USER}}": escape_html(str(session.get("u") or "")),
            "{{PUBLIC_HOST}}": escape_html(str(self.config["public_host"])),
            "{{HTTPS_PORT}}": str(self.config.get("https_port") or 443),
            "{{VERSION}}": escape_html(str(self.config.get("version") or "0.0.0")),
        }
        for source, target in replacements.items():
            html = html.replace(source, target)
        return self.response(start_response, "200 OK", html.encode(), "text/html; charset=utf-8")

    def static(self, start_response: Any, name: str) -> Iterable[bytes]:
        if name not in {"app.css", "app.js"}:
            return self.response(start_response, "404 Not Found", b"Not found", "text/plain")
        path = PACKAGE_DIR / "static" / name
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        return self.response(start_response, "200 OK", path.read_bytes(), content_type, cache=True)

    @staticmethod
    def response(
        start_response: Any,
        status: str,
        body: bytes,
        content_type: str,
        cache: bool = False,
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> Iterable[bytes]:
        headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
            ("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"),
            ("Cache-Control", "public, max-age=3600" if cache else "no-store"),
        ]
        if extra_headers:
            headers.extend(extra_headers)
        start_response(status, headers)
        return [body]

    @classmethod
    def json_response(cls, start_response: Any, status: int, data: dict[str, Any]) -> Iterable[bytes]:
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
        labels = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests"}
        return cls.response(start_response, f"{status} {labels.get(status, 'Error')}", body, "application/json; charset=utf-8")

    def redirect(
        self,
        start_response: Any,
        location: str,
        set_cookie: str = "",
        clear_cookie: bool = False,
    ) -> Iterable[bytes]:
        headers = [("Location", location)]
        if set_cookie:
            headers.append(("Set-Cookie", set_cookie))
        if clear_cookie:
            headers.append(("Set-Cookie", f"wdtt_session=; Path={self.base}; Max-Age=0; HttpOnly; Secure; SameSite=Strict"))
        return self.response(start_response, "303 See Other", b"", "text/plain", extra_headers=headers)


def escape_html(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def main() -> None:
    panel = Panel()
    host = str(panel.config.get("listen_host") or "127.0.0.1")
    port = int(panel.config.get("listen_port") or 8787)
    with make_server(host, port, panel, server_class=ThreadingServer) as server:
        print(f"WDTT Panel listening on {host}:{port}{panel.base}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
