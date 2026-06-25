import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
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

    def request(self, path, method="GET", body=b"", cookie="", csrf=""):
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
            }
        )
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        response = b"".join(self.panel(environ, start_response))
        return captured, response

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

        payload = json.dumps(
            {"count": 2, "vk_hash": "manual_one, manual_two", "ports": "56000,56001,9000"}
        ).encode()
        headers, _ = self.request("/private-panel-path/api/users/create-bulk", "POST", payload, cookie, csrf)
        self.assertTrue(headers["status"].startswith("200"))
        headers, body = self.request("/private-panel-path/api/vk-hashes", cookie=cookie)
        self.assertEqual(json.loads(body)["result"]["hashes"], ["hash_two", "manual_one", "manual_two"])

        payload = json.dumps({"label": "Авто клиент"}).encode()
        with mock.patch.object(app.secrets, "choice", return_value="manual_two"):
            headers, body = self.request("/private-panel-path/api/users/create-auto", "POST", payload, cookie, csrf)
        self.assertTrue(headers["status"].startswith("200"))
        created = json.loads(body)["result"]
        self.assertEqual(created["label"], "Авто клиент")
        self.assertEqual(created["vk_hash"], "manual_two")
        self.assertEqual(created["password"], "AutoDemoUser123")


if __name__ == "__main__":
    unittest.main()
