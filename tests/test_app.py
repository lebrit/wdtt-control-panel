import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlparse
from unittest import mock
from wsgiref.util import setup_testing_defaults

from wdtt_panel import app
from wdtt_panel.security import csrf_token, hash_password, read_session


class AppSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.config = root / "config.json"
        self.state = root / "panel.db"
        self.config.write_text(
            json.dumps(
                {
                    "username": "admin",
                    "password_hash": hash_password("Panel-password-12345"),
                    "session_secret": "test-session-secret",
                    "base_path": "/private-panel-path/",
                    "public_host": "panel.example.com",
                    "https_port": 8443,
                    "listen_host": "127.0.0.1",
                    "listen_port": 8787,
                    "certificate_path": "",
                }
            ),
            encoding="utf-8",
        )
        fake_admin = Path(__file__).with_name("fake_admin.py")
        self.patchers = [
            mock.patch.object(app, "CONFIG_FILE", self.config),
            mock.patch.object(app, "STATE_DB", self.state),
            mock.patch.object(app, "ADMIN_COMMAND", [sys.executable, str(fake_admin)]),
        ]
        for patcher in self.patchers:
            patcher.start()
        self.panel = app.Panel()

    def tearDown(self):
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temp.cleanup()

    def request(self, path, method="GET", body=b"", cookie="", csrf="", auth=""):
        environ = {}
        setup_testing_defaults(environ)
        environ.update(
            {
                "PATH_INFO": path,
                "REQUEST_METHOD": method,
                "CONTENT_LENGTH": str(len(body)),
                "CONTENT_TYPE": "application/x-www-form-urlencoded",
                "wsgi.input": io.BytesIO(body),
                "REMOTE_ADDR": "127.0.0.1",
                "HTTP_COOKIE": cookie,
                "HTTP_X_CSRF_TOKEN": csrf,
                "HTTP_AUTHORIZATION": auth,
            }
        )
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        response = b"".join(self.panel(environ, start_response))
        return captured, response

    def test_api_v1_password_login_and_bearer_requests(self):
        headers, body = self.request("/private-panel-path/api/v1/info")
        self.assertTrue(headers["status"].startswith("200"))
        parsed = json.loads(body)
        self.assertEqual(parsed["result"]["api_version"], 1)
        self.assertEqual(parsed["result"]["auth"]["type"], "password")

        headers, body = self.request("/private-panel-path/api/v1/overview")
        self.assertTrue(headers["status"].startswith("401"))
        self.assertFalse(json.loads(body)["ok"])

        payload = json.dumps({"password": "Panel-password-12345"}).encode()
        headers, body = self.request("/private-panel-path/api/v1/auth/login", "POST", payload)
        self.assertTrue(headers["status"].startswith("200"))
        token = json.loads(body)["result"]["token"]

        headers, body = self.request("/private-panel-path/api/v1/overview", auth=f"Bearer {token}")
        self.assertTrue(headers["status"].startswith("200"))
        self.assertTrue(json.loads(body)["ok"])

        headers, body = self.request("/private-panel-path/api/v1/qwdtt/subscription", auth=f"Bearer {token}")
        self.assertTrue(headers["status"].startswith("200"))
        subscription = json.loads(body)["result"]
        self.assertEqual(subscription["subscriptionName"], "WDTT panel.example.com")
        self.assertEqual(subscription["profiles"][0]["peer"], "panel.example.com:56000")
        self.assertEqual(subscription["profiles"][0]["workers"], 16)

        payload = json.dumps({"label": "Mobile client"}).encode()
        headers, body = self.request(
            "/private-panel-path/api/v1/users/create",
            "POST",
            payload,
            auth=f"Bearer {token}",
        )
        self.assertTrue(headers["status"].startswith("200"))
        self.assertEqual(json.loads(body)["result"]["label"], "Mobile client")

        payload = json.dumps({"keep_days": 14, "targets": ["service_logs", "package_cache"]}).encode()
        headers, body = self.request(
            "/private-panel-path/api/v1/cleanup/preview",
            "POST",
            payload,
            auth=f"Bearer {token}",
        )
        self.assertTrue(headers["status"].startswith("200"))
        self.assertEqual(json.loads(body)["result"]["estimated_freed_bytes"], 1024)

    def test_openwrt_podkop_plus_subscription_links(self):
        payload = json.dumps({"password": "Panel-password-12345"}).encode()
        headers, body = self.request("/private-panel-path/api/v1/auth/login", "POST", payload)
        self.assertTrue(headers["status"].startswith("200"))
        token = json.loads(body)["result"]["token"]

        payload = json.dumps({"password": "DemoUserA123"}).encode()
        headers, body = self.request(
            "/private-panel-path/api/v1/openwrt/podkop-plus",
            "POST",
            payload,
            auth=f"Bearer {token}",
        )
        self.assertTrue(headers["status"].startswith("200"))
        result = json.loads(body)["result"]
        self.assertIn("/sub/openwrt/", result["subscription_url"])
        self.assertIn("Podkop Plus", result["warning"])
        self.assertIn("/vless.txt", result["vless_url"])
        self.assertTrue(result["server"]["xray_installed"])

        subscription_path = urlparse(result["subscription_url"]).path
        headers, body = self.request(subscription_path)
        self.assertTrue(headers["status"].startswith("200"))
        subscription = json.loads(body)
        self.assertIn("outbounds", subscription)
        self.assertEqual(subscription["metadata"]["type"], "wdtt-podkop-plus-vless")
        self.assertEqual(subscription["outbounds"][0]["type"], "vless")
        self.assertEqual(subscription["outbounds"][0]["transport"]["type"], "ws")

        headers, body = self.request(urlparse(result["vless_url"]).path)
        self.assertTrue(headers["status"].startswith("200"))
        self.assertTrue(body.decode().strip().startswith("vless://"))

        headers, body = self.request(urlparse(result["install_script_url"]).path)
        self.assertTrue(headers["status"].startswith("200"))
        script = body.decode()
        self.assertIn("podkop-plus", script)
        self.assertIn("proxy_config_type='subscription'", script)

        payload = json.dumps({"password": "WaitingUser123"}).encode()
        headers, body = self.request(
            "/private-panel-path/api/v1/openwrt/podkop-plus",
            "POST",
            payload,
            auth=f"Bearer {token}",
        )
        self.assertTrue(headers["status"].startswith("400"))

    def test_user_statistics_accumulate_daily_and_total_traffic(self):
        first = {
            "users": [{"password": "TrafficUser123", "down_bytes": 100, "up_bytes": 50, "connected": False}],
            "admins": [],
        }
        with mock.patch.object(app.time, "time", return_value=1_800_000_000):
            enriched = self.panel.enrich_user_statistics(first)
        self.assertEqual(enriched["users"][0]["traffic_total_bytes"], 150)
        self.assertEqual(enriched["users"][0]["traffic_today_bytes"], 0)
        self.assertEqual(enriched["users"][0]["connection_state"], "offline")

        second = {
            "users": [
                {
                    "password": "TrafficUser123",
                    "down_bytes": 140,
                    "up_bytes": 70,
                    "connected": False,
                    "last_upload_at": 1_800_000_003,
                }
            ],
            "admins": [],
        }
        with mock.patch.object(app.time, "time", return_value=1_800_000_010):
            enriched = self.panel.enrich_user_statistics(second)
        self.assertEqual(enriched["users"][0]["traffic_today_bytes"], 60)
        self.assertEqual(enriched["users"][0]["traffic_total_bytes"], 210)
        self.assertTrue(enriched["users"][0]["recently_active"])
        self.assertEqual(enriched["users"][0]["connection_state"], "active")

        reset_counter = {
            "users": [{"password": "TrafficUser123", "down_bytes": 5, "up_bytes": 1, "connected": False}],
            "admins": [],
        }
        with mock.patch.object(app.time, "time", return_value=1_800_000_020):
            enriched = self.panel.enrich_user_statistics(reset_counter)
        self.assertEqual(enriched["users"][0]["traffic_today_bytes"], 66)
        self.assertEqual(enriched["users"][0]["traffic_total_bytes"], 216)

    def test_login_page_and_authenticated_overview(self):
        headers, body = self.request("/private-panel-path/")
        self.assertTrue(headers["status"].startswith("200"))
        self.assertIn(b"WDTT Control", body)

        form = b"username=admin&password=Panel-password-12345"
        headers, _ = self.request("/private-panel-path/login", "POST", form)
        self.assertTrue(headers["status"].startswith("303"))
        cookie = headers["headers"]["Set-Cookie"].split(";", 1)[0]

        headers, body = self.request("/private-panel-path/api/overview", cookie=cookie)
        self.assertTrue(headers["status"].startswith("200"))
        parsed = json.loads(body)
        self.assertTrue(parsed["ok"])

        headers, body = self.request("/private-panel-path/api/xray", cookie=cookie)
        self.assertTrue(headers["status"].startswith("200"))
        self.assertEqual(json.loads(body)["result"]["settings"]["mode"], "managed")
        headers, body = self.request("/private-panel-path/api/warp", cookie=cookie)
        self.assertTrue(headers["status"].startswith("200"))
        self.assertFalse(json.loads(body)["result"]["profile_exists"])
        headers, body = self.request("/private-panel-path/api/cascade", cookie=cookie)
        self.assertTrue(headers["status"].startswith("200"))
        self.assertFalse(json.loads(body)["result"]["settings"]["enabled"])
        headers, body = self.request("/private-panel-path/api/logs", cookie=cookie)
        self.assertTrue(headers["status"].startswith("200"))
        self.assertEqual(json.loads(body)["result"]["source"], "wdtt")
        self.assertEqual(parsed["result"]["stats"]["active"], 2)

    def test_vk_hash_library_is_managed_without_calling_root_helper(self):
        form = b"username=admin&password=Panel-password-12345"
        headers, _ = self.request("/private-panel-path/login", "POST", form)
        cookie = headers["headers"]["Set-Cookie"].split(";", 1)[0]
        token = cookie.split("=", 1)[1]
        session = read_session(token, "test-session-secret")
        csrf = csrf_token(session["n"], "test-session-secret")

        payload = json.dumps({"hashes": "https://vk.com/call/join/hash_one, hash_two"}).encode()
        headers, body = self.request("/private-panel-path/api/vk-hashes", "POST", payload, cookie, csrf)
        self.assertTrue(headers["status"].startswith("200"))
        self.assertEqual(json.loads(body)["result"]["hashes"], ["hash_one", "hash_two"])

        headers, body = self.request("/private-panel-path/api/vk-hashes", cookie=cookie)
        self.assertTrue(headers["status"].startswith("200"))
        self.assertEqual(json.loads(body)["result"]["hashes"], ["hash_one", "hash_two"])

        payload = json.dumps({"hash": "hash_one"}).encode()
        headers, body = self.request("/private-panel-path/api/vk-hashes/delete", "POST", payload, cookie, csrf)
        self.assertTrue(headers["status"].startswith("200"))
        self.assertEqual(json.loads(body)["result"]["hashes"], ["hash_two"])

        headers, body = self.request("/private-panel-path/api/vk-hashes/export", cookie=cookie)
        self.assertTrue(headers["status"].startswith("200"))
        exported = json.loads(body)["result"]
        self.assertEqual(exported["count"], 1)
        self.assertIn("wdtt-panel-vk-hash-library-v1", exported["content"])

        payload = json.dumps({"content": '{"format":"wdtt-panel-vk-hash-library-v1","hashes":["hash_two","hash_three"]}'}).encode()
        headers, body = self.request("/private-panel-path/api/vk-hashes/import", "POST", payload, cookie, csrf)
        self.assertTrue(headers["status"].startswith("200"))
        imported = json.loads(body)["result"]
        self.assertEqual(imported["imported"], 1)
        self.assertEqual(imported["hashes"], ["hash_two", "hash_three"])

        payload = json.dumps(
            {"count": 2, "vk_hash": "manual_one, manual_two", "ports": "56000,56001,9000"}
        ).encode()
        headers, _ = self.request("/private-panel-path/api/users/create-bulk", "POST", payload, cookie, csrf)
        self.assertTrue(headers["status"].startswith("200"))
        headers, body = self.request("/private-panel-path/api/vk-hashes", cookie=cookie)
        self.assertEqual(json.loads(body)["result"]["hashes"], ["hash_two", "hash_three", "manual_one", "manual_two"])

        payload = json.dumps({"label": "Авто клиент"}).encode()
        with mock.patch.object(app.secrets, "choice", return_value="manual_two"):
            headers, body = self.request("/private-panel-path/api/users/create-auto", "POST", payload, cookie, csrf)
        self.assertTrue(headers["status"].startswith("200"))
        created = json.loads(body)["result"]
        self.assertEqual(created["label"], "Авто клиент")
        self.assertEqual(created["vk_hash"], "manual_two")
        self.assertEqual(created["password"], "AutoDemoUser123")

    def test_telegram_settings_routes_call_root_helper(self):
        form = b"username=admin&password=Panel-password-12345"
        headers, _ = self.request("/private-panel-path/login", "POST", form)
        cookie = headers["headers"]["Set-Cookie"].split(";", 1)[0]
        token = cookie.split("=", 1)[1]
        session = read_session(token, "test-session-secret")
        csrf = csrf_token(session["n"], "test-session-secret")

        headers, body = self.request("/private-panel-path/api/telegram", cookie=cookie)
        self.assertTrue(headers["status"].startswith("200"))
        self.assertTrue(json.loads(body)["result"]["enabled"])

        payload = json.dumps({"enabled": True, "admin_id": "123456789", "bot_token": "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_test"}).encode()
        headers, body = self.request("/private-panel-path/api/telegram/save", "POST", payload, cookie, csrf)
        self.assertTrue(headers["status"].startswith("200"))
        self.assertEqual(json.loads(body)["result"]["admin_id"], "123456789")

        headers, body = self.request("/private-panel-path/api/telegram/test", "POST", b"{}", cookie, csrf)
        self.assertTrue(headers["status"].startswith("200"))
        self.assertTrue(json.loads(body)["result"]["sent"])


if __name__ == "__main__":
    unittest.main()
