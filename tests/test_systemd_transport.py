import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid


@unittest.skipUnless(sys.platform == "linux" and os.environ.get("WDTT_SYSTEMD_TEST") == "1", "requires an isolated Linux systemd runner")
class SystemdTransportTests(unittest.TestCase):
    def test_helper_writes_outside_web_readonly_namespace(self):
        self.assertEqual(os.geteuid(), 0)
        repo = Path(__file__).resolve().parents[1]
        script = (repo / "install.sh").read_text()
        name = "wdtt-ci-" + uuid.uuid4().hex[:8]
        temporary = tempfile.TemporaryDirectory(prefix=name + "-")
        self.addCleanup(temporary.cleanup)
        fixture = Path(temporary.name)
        fixture.chmod(0o755)
        shutil.copytree(repo / "wdtt_panel", fixture / "wdtt_panel", ignore=shutil.ignore_patterns("__pycache__"))
        log = Path("/var/log") / (name + ".log")
        lock = Path("/run") / (name + ".lock")
        units = Path("/etc/systemd/system")
        files = []

        def run(*args):
            result = subprocess.run(args, text=True, capture_output=True, timeout=60)
            if result.returncode:
                journal = subprocess.run(["journalctl", "--no-pager", "-n", "30", "-u", name + "@*.service"], text=True, capture_output=True)
                self.fail(f"{args[0]} failed: {result.stdout}\n{result.stderr}\n{journal.stdout}")
            return result

        try:
            log.write_text("test log to truncate\n")
            log.chmod(0o666)
            for suffix in (".socket", "@.service"):
                pattern = r"cat > /etc/systemd/system/wdtt-panel-admin" + re.escape(suffix) + r" <<'?EOF'?\n(.*?)\nEOF"
                body = re.search(pattern, script, re.DOTALL).group(1)
                body = body.replace("wdtt-panel-admin", name).replace("SocketGroup=wdtt-panel", "SocketGroup=nogroup").replace("$INSTALL_DIR", str(fixture))
                if suffix == "@.service":
                    body += f"\nEnvironment=WDTT_SKIP_SYSTEMD=1 WDTT_LOCK_FILE={lock} WDTT_INSTALL_LOG_FILE={log}\n"
                    for variable in ("WDTT_XRAY_ACCESS_LOG", "WDTT_XRAY_ERROR_LOG", "WDTT_NGINX_ACCESS_LOG", "WDTT_NGINX_ERROR_LOG"):
                        body += f"Environment={variable}=/run/{name}-missing\n"
                path = units / (name + suffix)
                path.write_text(body + "\n")
                files.append(path)
            run("systemctl", "daemon-reload")
            run("systemctl", "start", name + ".socket")
            code = f"""from pathlib import Path
import errno
from wdtt_panel.app import Panel
assert 'NoNewPrivs:\\t1' in Path('/proc/self/status').read_text()
try:
    Path({str(log)!r}).write_text('must fail')
except OSError as error:
    assert error.errno == errno.EROFS, error
else:
    raise AssertionError('web namespace is writable')
result = Panel.admin('cleanup.apply', {{'targets':['service_logs']}})
assert result['ok'], result
assert Path({str(log)!r}).stat().st_size == 0
print('socket sandbox regression passed')
"""
            result = run("systemd-run", "--quiet", "--wait", "--pipe", "--unit=" + name + "-web", "--property=User=nobody", "--property=Group=nogroup", "--property=ProtectSystem=strict", "--property=NoNewPrivileges=yes", "--setenv=PYTHONPATH=" + str(fixture), "--setenv=WDTT_PANEL_ADMIN=", "--setenv=WDTT_PANEL_ADMIN_SOCKET=/run/" + name + ".sock", "/usr/bin/python3", "-c", code)
            self.assertIn("socket sandbox regression passed", result.stdout)
        finally:
            subprocess.run(["systemctl", "stop", name + ".socket", name + "@*.service", name + "-web.service"], capture_output=True)
            for path in files + [log, lock]:
                path.unlink(missing_ok=True)
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
