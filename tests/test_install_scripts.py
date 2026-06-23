from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InstallScriptTests(unittest.TestCase):
    def test_version_is_consistent(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        package = (ROOT / "wdtt_panel" / "__init__.py").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn('PANEL_VERSION="0.9.5"', installer)
        self.assertIn('__version__ = "0.9.5"', package)
        self.assertIn("Текущая версия: 0.9.5", readme)

    def test_bootstrap_has_interactive_management_menu(self):
        script = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        for action in ("install", "update", "status", "renew-cert", "change-password", "uninstall"):
            self.assertIn(action, script)
        self.assertIn("/dev/tty", script)
        self.assertIn("--domain", script)
        self.assertIn("--password", script)
        self.assertIn("while true", script)

    def test_installer_has_update_and_certificate_renewal(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("update_panel()", script)
        self.assertIn("renew_certificates()", script)
        self.assertIn("OnUnitActiveSec=12h", script)
        self.assertIn("write_maintenance_scripts", script)
        self.assertIn("install_xray_runtime()", script)
        self.assertIn("install_warp_runtime()", script)
        self.assertIn("wdtt-xray-cascade.service", script)
        self.assertIn("wdtt-xray-gateway.service", script)
        self.assertIn("wdtt-panel-geofiles-update.timer", script)

    def test_installer_can_change_the_panel_login_password(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("change_panel_password()", script)
        self.assertIn('change-password|--change-password) change_panel_password ;;', script)
        self.assertIn('data["session_secret"] = session_secret', script)

    def test_acme_opens_port_80_before_certbot(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        request_start = script.index("request_certificate()")
        request_end = script.index("run_certbot_request()", request_start)
        request = script[request_start:request_end]
        self.assertIn("open_acme_firewall", request)
        self.assertIn("open_acme_firewall()", script)
        self.assertIn("--standalone --preferred-challenges http", script)
        self.assertIn("authenticator = standalone", script)

    def test_status_uses_the_saved_secret_path(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn(
            "status|--status|-s) require_root; load_panel_config; status_panel ;;",
            script,
        )
        self.assertIn("curl --noproxy '*' -kfsS", script)
        self.assertIn("for ((attempt = 1; attempt <= 10; attempt++))", script)

    def test_certificate_upgrade_reports_the_reason_for_a_failure(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("Публичный сертификат не запрошен: TCP 80 занят не Nginx", script)
        self.assertIn("Не удалось получить Let's Encrypt: проверьте DNS", script)

    def test_manager_wrapper_is_replaced_during_an_update(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('rm -f "$MANAGER_WRAPPER" /usr/local/sbin/wddt-panel /usr/local/sbin/wdtt-pane', script)
        self.assertIn('install -m 0755 "$INSTALL_DIR/bootstrap.sh" "$MANAGER_WRAPPER"', script)
        self.assertNotIn("MANAGER_ALIAS_ONE", script)
        self.assertNotIn("MANAGER_ALIAS_TWO", script)

    def test_hsts_is_only_enabled_for_a_public_certificate(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('if [ "$TLS_MODE" = "letsencrypt" ]; then', script)
        self.assertIn("HSTS_HEADER=", script)

    def test_panel_exposes_version_update_and_full_backup_controls(self):
        html = (ROOT / "wdtt_panel" / "templates" / "index.html").read_text(encoding="utf-8")
        script = (ROOT / "wdtt_panel" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="update-panel"', html)
        self.assertIn('id="create-backup"', html)
        self.assertIn('api("panel/update"', script)
        self.assertIn('api("backups/create"', script)
        self.assertIn('id="tab-xray"', html)
        self.assertIn('id="install-xray"', html)
        self.assertIn('api("xray/save"', script)
        self.assertIn('id="install-warp"', html)
        self.assertIn('id="ping-warp"', html)
        self.assertIn('id="save-cascade"', html)
        self.assertIn('api("cascade/save"', script)
        self.assertIn('id="add-xray-vless-route"', html)
        self.assertIn('id="add-xray-friendly-rule"', html)
        self.assertIn('id="xray-route-dialog"', html)
        self.assertIn('id="xray-rule-dialog"', html)
        self.assertIn('id="xray-rule-preset"', html)
        self.assertIn('id="xray-access-log"', html)
        self.assertIn('id="xray-gateway-enabled"', html)
        self.assertIn('<option value="xray-access">', html)
        self.assertIn('<option value="xray-errors">', html)
        self.assertIn('collectFriendlyRules()', script)
        self.assertIn('ROUTE_PRESETS', script)
        self.assertIn('eu-vless', script)
        self.assertIn('restoreSidebarState()', script)
        self.assertIn('id="log-source"', html)
        self.assertIn('id="sidebar-toggle"', html)
        self.assertIn('id="log-limit"', html)
        self.assertIn('id="download-logs"', html)
        self.assertIn('logs?source=', script)
        self.assertIn('static/app.js?v={{VERSION}}', html)
        self.assertNotIn('id="repair-wdtt"', html)
        self.assertNotIn('api("service/repair"', script)

    def test_admin_lock_is_in_writable_private_state(self):
        script = (ROOT / "wdtt_panel" / "admin.py").read_text(encoding="utf-8")
        self.assertIn("/var/lib/wdtt-panel-private/admin.lock", script)
        self.assertNotIn("/run/lock/wdtt-panel-admin.lock", script)

    def test_dialog_cancel_buttons_skip_required_field_validation(self):
        html = (ROOT / "wdtt_panel" / "templates" / "index.html").read_text(encoding="utf-8")
        self.assertEqual(html.count('value="cancel" formnovalidate'), 4)


if __name__ == "__main__":
    unittest.main()
