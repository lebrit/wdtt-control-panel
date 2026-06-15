from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InstallScriptTests(unittest.TestCase):
    def test_bootstrap_has_interactive_management_menu(self):
        script = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        for action in ("install", "update", "status", "renew-cert", "uninstall"):
            self.assertIn(action, script)
        self.assertIn("/dev/tty", script)
        self.assertIn("--domain", script)
        self.assertIn("--password", script)

    def test_installer_has_update_and_certificate_renewal(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("update_panel()", script)
        self.assertIn("renew_certificates()", script)
        self.assertIn("OnUnitActiveSec=12h", script)
        self.assertIn("write_maintenance_scripts", script)

    def test_panel_exposes_version_update_and_full_backup_controls(self):
        html = (ROOT / "wdtt_panel" / "templates" / "index.html").read_text(encoding="utf-8")
        script = (ROOT / "wdtt_panel" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="update-panel"', html)
        self.assertIn('id="create-backup"', html)
        self.assertIn('api("panel/update"', script)
        self.assertIn('api("backups/create"', script)

    def test_admin_lock_is_in_writable_private_state(self):
        script = (ROOT / "wdtt_panel" / "admin.py").read_text(encoding="utf-8")
        self.assertIn("/var/lib/wdtt-panel-private/admin.lock", script)
        self.assertNotIn("/run/lock/wdtt-panel-admin.lock", script)

    def test_dialog_cancel_buttons_skip_required_field_validation(self):
        html = (ROOT / "wdtt_panel" / "templates" / "index.html").read_text(encoding="utf-8")
        self.assertEqual(html.count('value="cancel" formnovalidate'), 4)


if __name__ == "__main__":
    unittest.main()
