import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

from wdtt_panel import app


class AdminTransportTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
    def test_socket_sends_request_until_eof_and_receives_helper_result(self):
        with tempfile.TemporaryDirectory() as directory:
            address = str(Path(directory) / "admin.sock")
            requests = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(address)
                server.listen(1)

                def respond():
                    with server.accept()[0] as connection:
                        with connection.makefile("rb") as stream:
                            requests.append(json.loads(stream.read()))
                        connection.sendall(b'{"ok":true,"result":{"saved":true}}')

                worker = threading.Thread(target=respond)
                worker.start()
                with mock.patch.object(app, "ADMIN_COMMAND", []), mock.patch.object(app, "ADMIN_SOCKET", address):
                    result = app.Panel.admin("cleanup.settings", {"keep_days": 7})
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(requests, [{"action": "cleanup.settings", "payload": {"keep_days": 7}}])
                self.assertEqual(result, {"ok": True, "result": {"saved": True}})

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
    def test_unavailable_socket_reports_error_without_falling_back_to_sudo(self):
        with mock.patch.object(app, "ADMIN_COMMAND", []), mock.patch.object(app.socket, "socket", side_effect=OSError("unavailable")), mock.patch.object(app.subprocess, "run") as run:
            self.assertFalse(app.Panel.admin("users.list", {})["ok"])
            run.assert_not_called()
