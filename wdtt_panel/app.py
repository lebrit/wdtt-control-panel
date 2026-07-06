from __future__ import annotations

import base64
import hashlib
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

from .core import ValidationError, normalize_hash, normalize_user_label, quick_link
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
                CREATE TABLE IF NOT EXISTS user_traffic_state (
                    user_key TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    down_bytes INTEGER NOT NULL DEFAULT 0,
                    up_bytes INTEGER NOT NULL DEFAULT 0,
                    total_down_bytes INTEGER NOT NULL DEFAULT 0,
                    total_up_bytes INTEGER NOT NULL DEFAULT 0,
                    today_key TEXT NOT NULL DEFAULT '',
                    today_down_bytes INTEGER NOT NULL DEFAULT 0,
                    today_up_bytes INTEGER NOT NULL DEFAULT 0,
                    last_seen_at INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL
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
        if relative.startswith("sub/openwrt/"):
            return self.openwrt_subscription_response(environ, start_response, relative)

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
                "cleanup",
                "backups",
                "panel.version",
                "telegram",
                "telegram.save",
                "telegram.test",
                "openwrt.podkop_plus",
                "vk_hashes",
                "vk_hashes.import",
                "vk_hashes.export",
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
        if route == "vk-hashes/export":
            if method != "GET":
                return self.json_response(start_response, 405, {"error": "Требуется GET"})
            self.audit(environ, "vk-hashes.export", "ok")
            return self.json_response(start_response, 200, {"ok": True, "result": self.export_vk_hashes()})
        if route == "vk-hashes/import":
            if method != "POST":
                return self.json_response(start_response, 405, {"error": "Требуется POST"})
            try:
                result = self.import_vk_hashes(payload)
            except ValidationError as exc:
                self.audit(environ, "vk-hashes.import", "error", str(exc))
                return self.json_response(start_response, 400, {"ok": False, "error": str(exc)})
            self.audit(environ, "vk-hashes.import", "ok")
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
        if route == "openwrt/podkop-plus":
            if method != "POST":
                return self.json_response(start_response, 405, {"error": "Требуется POST"})
            try:
                result = self.openwrt_subscription_info(str(payload.get("password") or ""))
            except ValidationError as exc:
                self.audit(environ, "openwrt.podkop_plus", "error", str(exc))
                return self.json_response(start_response, 400, {"ok": False, "error": str(exc)})
            self.audit(environ, "openwrt.podkop_plus", "ok", "subscription-issued")
            return self.json_response(start_response, 200, {"ok": True, "result": result})
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
            "cleanup/preview": "cleanup.preview",
            "cleanup/apply": "cleanup.apply",
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
            "telegram": "telegram.status",
            "telegram/save": "telegram.save",
            "telegram/test": "telegram.test",
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
        if method == "GET" and action not in {"overview", "users.list", "logs", "backups.list", "backups.export", "backups.schedule", "panel.version", "certificate.export", "telegram.status", "xray.status", "warp.status", "cascade.status"}:
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
        if result.get("ok") and action == "users.list":
            result["result"] = self.enrich_user_statistics(result.get("result") or {})
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
    def _int_value(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    def enrich_user_statistics(self, root: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(root, dict):
            return root
        entries: list[dict[str, Any]] = []
        for role, key in (("user", "users"), ("admin", "admins")):
            values = root.get(key)
            if isinstance(values, list):
                for item in values:
                    if isinstance(item, dict):
                        item.setdefault("role", role)
                        entries.append(item)
        if not entries:
            return root

        now = int(time.time())
        today_key = datetime.fromtimestamp(now).strftime("%Y-%m-%d")
        with closing(sqlite3.connect(STATE_DB)) as db:
            for item in entries:
                password = str(item.get("password") or "")
                role = str(item.get("role") or "user")
                if not password:
                    continue
                user_key = f"{role}:{password}"
                down = self._int_value(item.get("down_bytes"))
                up = self._int_value(item.get("up_bytes"))
                activity_at = max(
                    self._int_value(item.get("last_handshake")),
                    self._int_value(item.get("last_upload_at")),
                    self._int_value(item.get("last_download_at")),
                )
                row = db.execute(
                    "SELECT down_bytes, up_bytes, total_down_bytes, total_up_bytes, today_key, "
                    "today_down_bytes, today_up_bytes, last_seen_at FROM user_traffic_state WHERE user_key = ?",
                    (user_key,),
                ).fetchone()
                if row is None:
                    total_down, total_up = down, up
                    today_down, today_up = 0, 0
                    last_seen_at = activity_at
                else:
                    previous_down, previous_up, total_down, total_up, previous_day, today_down, today_up, last_seen_at = row
                    delta_down = down - int(previous_down or 0) if down >= int(previous_down or 0) else down
                    delta_up = up - int(previous_up or 0) if up >= int(previous_up or 0) else up
                    total_down = max(int(total_down or 0) + delta_down, down)
                    total_up = max(int(total_up or 0) + delta_up, up)
                    if previous_day == today_key:
                        today_down = int(today_down or 0) + delta_down
                        today_up = int(today_up or 0) + delta_up
                    else:
                        today_down, today_up = delta_down, delta_up
                    if delta_down or delta_up:
                        last_seen_at = now
                    last_seen_at = max(int(last_seen_at or 0), activity_at)
                strict_connected = bool(item.get("connected"))
                recently_active = strict_connected or (last_seen_at > 0 and now - last_seen_at <= 300)
                connection_state = "online" if strict_connected else "active" if recently_active else "offline"
                item.update(
                    {
                        "strict_connected": strict_connected,
                        "recently_active": recently_active,
                        "connection_state": connection_state,
                        "last_seen_at": last_seen_at,
                        "traffic_current_down_bytes": down,
                        "traffic_current_up_bytes": up,
                        "traffic_current_bytes": down + up,
                        "traffic_total_down_bytes": total_down,
                        "traffic_total_up_bytes": total_up,
                        "traffic_total_bytes": total_down + total_up,
                        "traffic_today_down_bytes": today_down,
                        "traffic_today_up_bytes": today_up,
                        "traffic_today_bytes": today_down + today_up,
                    }
                )
                db.execute(
                    "INSERT INTO user_traffic_state(user_key, password, role, down_bytes, up_bytes, "
                    "total_down_bytes, total_up_bytes, today_key, today_down_bytes, today_up_bytes, "
                    "last_seen_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(user_key) DO UPDATE SET password=excluded.password, role=excluded.role, "
                    "down_bytes=excluded.down_bytes, up_bytes=excluded.up_bytes, "
                    "total_down_bytes=excluded.total_down_bytes, total_up_bytes=excluded.total_up_bytes, "
                    "today_key=excluded.today_key, today_down_bytes=excluded.today_down_bytes, "
                    "today_up_bytes=excluded.today_up_bytes, last_seen_at=excluded.last_seen_at, "
                    "updated_at=excluded.updated_at",
                    (
                        user_key,
                        password,
                        role,
                        down,
                        up,
                        total_down,
                        total_up,
                        today_key,
                        today_down,
                        today_up,
                        last_seen_at,
                        now,
                    ),
                )
            db.execute("DELETE FROM user_traffic_state WHERE updated_at < ?", (now - 90 * 86400,))
            db.commit()
        return root

    @staticmethod
    def list_vk_hashes() -> dict[str, Any]:
        with closing(sqlite3.connect(STATE_DB)) as db:
            rows = db.execute("SELECT value FROM vk_hash_library ORDER BY created_at, rowid").fetchall()
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

    @staticmethod
    def export_vk_hashes() -> dict[str, Any]:
        hashes = Panel.list_vk_hashes().get("hashes") or []
        created = int(time.time())
        content = json.dumps(
            {
                "format": "wdtt-panel-vk-hash-library-v1",
                "created_at": created,
                "hashes": hashes,
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n"
        return {"name": f"wdtt-vk-hashes-{created}.json", "content": content, "count": len(hashes)}

    @staticmethod
    def parse_vk_hash_import(content: str) -> list[str]:
        if not content or len(content.encode("utf-8")) > 1024 * 1024:
            raise ValidationError("Файл библиотеки VK-хешей пустой или больше 1 МБ")
        raw_values: list[Any]
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            raw = parsed.get("hashes") or parsed.get("vk_hashes") or parsed.get("values")
            raw_values = raw if isinstance(raw, list) else [raw]
        elif isinstance(parsed, list):
            raw_values = parsed
        else:
            raw_values = [content]
        values: list[str] = []
        for item in raw_values:
            if item is None:
                continue
            for part in str(item).replace(",", " ").split():
                values.append(normalize_hash(part))
        values = list(dict.fromkeys(values))
        if not values:
            raise ValidationError("В файле нет VK-хешей")
        if len(values) > 500:
            raise ValidationError("В библиотеке может быть не больше 500 VK-хешей")
        return values

    @staticmethod
    def import_vk_hashes(payload: dict[str, Any]) -> dict[str, Any]:
        values = Panel.parse_vk_hash_import(str(payload.get("content") or ""))
        with closing(sqlite3.connect(STATE_DB)) as db:
            existing = db.execute("SELECT COUNT(*) FROM vk_hash_library").fetchone()[0]
            new_values = [
                value for value in values
                if db.execute("SELECT 1 FROM vk_hash_library WHERE value = ?", (value,)).fetchone() is None
            ]
            if existing + len(new_values) > 500:
                raise ValidationError("В библиотеке может быть не больше 500 VK-хешей")
            now = int(time.time())
            db.executemany(
                "INSERT OR IGNORE INTO vk_hash_library(value, created_at) VALUES(?, ?)",
                [(value, now) for value in values],
            )
            db.commit()
        result = Panel.list_vk_hashes()
        result["imported"] = len(new_values)
        return result

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

    def external_base_url(self) -> str:
        host = str(self.config.get("public_host") or "").strip()
        if not host:
            raise ValidationError("Не указан public_host панели")
        https_port = int(self.config.get("https_port") or 443)
        port = "" if https_port == 443 else f":{https_port}"
        return f"https://{host}{port}{self.base.rstrip('/')}"

    def openwrt_token(self, password: str) -> str:
        secret = str(self.config.get("openwrt_subscription_secret") or self.config["session_secret"])
        digest = hmac.new(secret.encode(), f"openwrt-podkop-plus:{password}".encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def active_openwrt_users(self) -> list[dict[str, Any]]:
        users_result = self.admin("users.list", {})
        root = users_result.get("result") if users_result.get("ok") else {}
        users = root.get("users") if isinstance(root, dict) else []
        return [user for user in users if isinstance(user, dict) and user.get("password")]

    def find_openwrt_user_by_password(self, password: str) -> dict[str, Any] | None:
        for user in self.active_openwrt_users():
            if hmac.compare_digest(str(user.get("password") or ""), password):
                return user
        return None

    def find_openwrt_user_by_token(self, token: str) -> dict[str, Any] | None:
        if not token or len(token) < 32:
            return None
        for user in self.active_openwrt_users():
            password = str(user.get("password") or "")
            if hmac.compare_digest(self.openwrt_token(password), token):
                return user
        return None

    @staticmethod
    def openwrt_user_enabled(user: dict[str, Any]) -> bool:
        expires_at = int(user.get("expires_at") or 0)
        return not bool(user.get("is_deactivated")) and not bool(user.get("expired")) and not (expires_at > 0 and expires_at < int(time.time()))

    def openwrt_profile(self, user: dict[str, Any], token: str) -> dict[str, Any]:
        host = str(self.config.get("public_host") or "")
        password = str(user.get("password") or "")
        uri = quick_link(host, password, user)
        base = self.external_base_url()
        label = str(user.get("label") or password or "WDTT OpenWrt")
        ports = [item.strip() for item in str(user.get("ports") or "56000,56001,9000").split(",")]
        return {
            "version": 1,
            "type": "wdtt-openwrt-podkop-plus",
            "name": label,
            "panel": {
                "host": host,
                "base_url": base,
                "version": str(self.config.get("version") or "0.0.0"),
            },
            "user": {
                "label": label,
                "password": password,
                "expires_at": int(user.get("expires_at") or 0),
                "traffic_used_mb": round((int(user.get("down_bytes") or 0) + int(user.get("up_bytes") or 0)) / 1024 / 1024, 2),
                "active": self.openwrt_user_enabled(user),
            },
            "wdtt": {
                "uri": uri,
                "host": host,
                "ports": {
                    "dtls": ports[0] if len(ports) > 0 else "56000",
                    "wireguard": ports[1] if len(ports) > 1 else "56001",
                    "tun": ports[2] if len(ports) > 2 else "9000",
                },
                "vk_hash": str(user.get("vk_hash") or ""),
            },
            "podkop_plus": {
                "mode": "vpn-interface",
                "interface": "wdtt0",
                "section": "main",
                "uci": {
                    "connection_type": "vpn",
                    "interface": "wdtt0",
                },
                "reload_commands": [
                    "/etc/init.d/podkop-plus reload",
                    "/usr/bin/podkop-plus reload",
                    "/etc/init.d/podkop reload",
                ],
                "notes": [
                    "Podkop Plus routes traffic through an existing VPN interface.",
                    "WDTT must be started on the router by a compatible OpenWrt client that creates wdtt0.",
                    "This subscription is not a sing-box VLESS JSON and must not be imported as a generic proxy outbound.",
                ],
            },
            "links": {
                "metadata_json": f"{base}/sub/openwrt/{token}/podkop-plus.json",
                "wdtt_uri": f"{base}/sub/openwrt/{token}/wdtt.txt",
                "qwdtt_json": f"{base}/sub/openwrt/{token}/qwdtt.json",
                "install_script": f"{base}/sub/openwrt/{token}/install.sh",
            },
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def openwrt_subscription_info(self, password: str) -> dict[str, Any]:
        user = self.find_openwrt_user_by_password(password)
        if not user:
            raise ValidationError("Пользователь WDTT не найден")
        if not self.openwrt_user_enabled(user):
            raise ValidationError("Пользователь отключён или истёк")
        token = self.openwrt_token(password)
        profile = self.openwrt_profile(user, token)
        command = f"sh -c \"$(wget -qO- '{profile['links']['install_script']}')\""
        return {
            "profile": profile,
            "subscription_url": profile["links"]["metadata_json"],
            "wdtt_url": profile["links"]["wdtt_uri"],
            "qwdtt_url": profile["links"]["qwdtt_json"],
            "install_script_url": profile["links"]["install_script"],
            "install_command": command,
            "warning": "Для реального подключения на OpenWrt нужен совместимый WDTT-клиент/модуль Podkop Plus, который поднимает интерфейс wdtt0.",
        }

    def openwrt_install_script(self, profile: dict[str, Any]) -> str:
        metadata_url = shell_single_quote(profile["links"]["metadata_json"])
        wdtt_url = shell_single_quote(profile["links"]["wdtt_uri"])
        interface = shell_single_quote(str(profile["podkop_plus"]["interface"]))
        return f"""#!/bin/sh
set -eu

SUB_URL={metadata_url}
WDTT_URL={wdtt_url}
INTERFACE={interface}
STATE_DIR="/etc/wdtt-openwrt"

fetch_url() {{
  url="$1"
  output="$2"
  if command -v uclient-fetch >/dev/null 2>&1; then
    uclient-fetch -q -O "$output" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$output" "$url"
  else
    echo "wget/uclient-fetch not found" >&2
    exit 1
  fi
}}

mkdir -p "$STATE_DIR"
fetch_url "$SUB_URL" "$STATE_DIR/subscription.json"
fetch_url "$WDTT_URL" "$STATE_DIR/wdtt.txt"
chmod 600 "$STATE_DIR/subscription.json" "$STATE_DIR/wdtt.txt"

if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
  echo "WDTT interface $INTERFACE is not found."
  echo "Install or enable a compatible WDTT OpenWrt/Podkop Plus client first."
  echo "Saved subscription: $STATE_DIR/subscription.json"
  echo "Saved WDTT link: $STATE_DIR/wdtt.txt"
  exit 2
fi

if uci -q show podkop >/dev/null 2>&1; then
  uci set podkop.main.connection_type='vpn'
  uci set podkop.main.interface="$INTERFACE"
  uci commit podkop
fi

if [ -d /etc/crontabs ]; then
  touch /etc/crontabs/root
  sed -i '/WDTT_OPENWRT_SUBSCRIPTION/d' /etc/crontabs/root
  echo "17 */6 * * * wget -qO $STATE_DIR/subscription.json $SUB_URL && wget -qO $STATE_DIR/wdtt.txt $WDTT_URL # WDTT_OPENWRT_SUBSCRIPTION" >> /etc/crontabs/root
  /etc/init.d/cron restart >/dev/null 2>&1 || true
fi

if [ -x /etc/init.d/podkop-plus ]; then
  /etc/init.d/podkop-plus reload || /usr/bin/podkop-plus reload || /etc/init.d/podkop-plus restart
elif [ -x /etc/init.d/podkop ]; then
  /etc/init.d/podkop reload || /etc/init.d/podkop restart
elif command -v podkop-plus >/dev/null 2>&1; then
  podkop-plus reload || true
fi

echo "WDTT OpenWrt subscription installed for $INTERFACE."
"""

    def openwrt_subscription_response(
        self,
        environ: dict[str, Any],
        start_response: Any,
        relative: str,
    ) -> Iterable[bytes]:
        if environ["REQUEST_METHOD"] != "GET":
            return self.response(start_response, "405 Method Not Allowed", b"Method not allowed", "text/plain; charset=utf-8")
        parts = relative.strip("/").split("/")
        if len(parts) < 3:
            return self.response(start_response, "404 Not Found", b"Not found", "text/plain; charset=utf-8")
        token = parts[2]
        name = parts[3] if len(parts) > 3 and parts[3] else "podkop-plus.json"
        user = self.find_openwrt_user_by_token(token)
        if not user:
            return self.response(start_response, "404 Not Found", b"Subscription not found", "text/plain; charset=utf-8")
        if not self.openwrt_user_enabled(user):
            return self.response(start_response, "403 Forbidden", b"Subscription disabled", "text/plain; charset=utf-8")
        try:
            profile = self.openwrt_profile(user, token)
        except ValidationError as exc:
            return self.response(start_response, "400 Bad Request", str(exc).encode(), "text/plain; charset=utf-8")
        safe_name = "".join(char for char in name if char.isalnum() or char in "._-") or "subscription"
        headers = [("Content-Disposition", f'inline; filename="{safe_name}"')]
        if name in {"podkop-plus.json", "metadata.json", "subscription.json"}:
            body = json.dumps(profile, ensure_ascii=False, indent=2).encode()
            return self.response(start_response, "200 OK", body, "application/json; charset=utf-8", extra_headers=headers)
        if name == "qwdtt.json":
            payload = {
                "subscriptionName": f"WDTT OpenWrt {profile['name']}",
                "description": "Single-user WDTT profile for OpenWrt/Podkop Plus integration",
                "version": 1,
                "profiles": [self.qwdtt_profile(user)],
                "updatedAt": profile["updated_at"],
            }
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode()
            return self.response(start_response, "200 OK", body, "application/json; charset=utf-8", extra_headers=headers)
        if name in {"wdtt.txt", "links.txt"}:
            body = (profile["wdtt"]["uri"] + "\n").encode()
            return self.response(start_response, "200 OK", body, "text/plain; charset=utf-8", extra_headers=headers)
        if name in {"install.sh", "podkop-plus.sh"}:
            body = self.openwrt_install_script(profile).encode()
            return self.response(start_response, "200 OK", body, "text/x-shellscript; charset=utf-8", extra_headers=headers)
        return self.response(start_response, "404 Not Found", b"Format not found", "text/plain; charset=utf-8")

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


def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def main() -> None:
    panel = Panel()
    host = str(panel.config.get("listen_host") or "127.0.0.1")
    port = int(panel.config.get("listen_port") or 8787)
    with make_server(host, port, panel, server_class=ThreadingServer) as server:
        print(f"WDTT Panel listening on {host}:{port}{panel.base}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
