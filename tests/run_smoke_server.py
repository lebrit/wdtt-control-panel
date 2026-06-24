"""Run the panel locally with a fake privileged helper for browser QA."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wdtt_panel import __version__, app
from wdtt_panel.security import hash_password


root = Path(tempfile.mkdtemp(prefix="wdtt-panel-smoke-"))
config = root / "config.json"
config.write_text(
    json.dumps(
        {
            "username": "admin",
            "password_hash": hash_password("Panel-password-12345"),
            "session_secret": "browser-smoke-session-secret",
            "base_path": "/private-panel-path/",
            "public_host": "panel.example.com",
            "https_port": 8443,
            "listen_host": "127.0.0.1",
            "listen_port": 8877,
            "certificate_path": "",
            "version": __version__,
        }
    ),
    encoding="utf-8",
)
app.CONFIG_FILE = config
app.STATE_DB = root / "panel.db"
app.ADMIN_COMMAND = [sys.executable, str(Path(__file__).with_name("fake_admin.py"))]
app.main()
