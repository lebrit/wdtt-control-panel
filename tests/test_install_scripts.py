import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class InstallScriptTests(unittest.TestCase):
    def test_version_is_consistent(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        package = (ROOT / "wdtt_panel" / "__init__.py").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn('PANEL_VERSION="0.11.0"', installer)
        self.assertIn('__version__ = "0.11.0"', package)
        self.assertIn("Текущая версия: 0.11.0", readme)

    def test_bootstrap_has_interactive_management_menu(self):
        script = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        for action in ("install", "update", "rollback", "status", "renew-cert", "change-password", "uninstall"):
            self.assertIn(action, script)
        self.assertIn("/dev/tty", script)
        self.assertIn("--domain", script)
        self.assertIn("--password", script)
        self.assertIn("while true", script)
        self.assertIn("github_versions()", script)
        self.assertIn("refs/tags/${ROLLBACK_VERSION}", script)

    def test_installer_has_update_and_certificate_renewal(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("update_panel()", script)
        self.assertIn("renew_certificates()", script)
        self.assertIn("OnUnitActiveSec=12h", script)
        self.assertIn("write_maintenance_scripts", script)
        self.assertIn("install_xray_runtime()", script)
        self.assertIn("install_warp_runtime()", script)
        self.assertIn("install_wdtt_extensions()", script)
        self.assertIn("schedule_wdtt_extensions", script)
        self.assertIn("write_wdtt_extensions_timer", script)
        self.assertIn("TimeoutStartSec=20min", script)
        self.assertIn("OnUnitActiveSec=10min", script)
        self.assertIn("OnUnitInactiveSec=10min", script)
        self.assertIn("Restart=on-failure", script)
        self.assertIn('systemctl restart --no-block "$WDTT_EXTENSIONS_SERVICE"', script)
        self.assertIn("WDTT_EXTENSION_MARKER", script)
        self.assertIn("wdtt_extensions_binary_is_current", script)
        self.assertIn("backup_wdtt_database_before_update", script)
        update_start = script.index("update_panel() {")
        update_block = script[update_start:script.index("install_panel() {", update_start)]
        self.assertLess(update_block.index("backup_wdtt_database_before_update"), update_block.index("schedule_wdtt_extensions"))
        self.assertIn('grep -aFq "$WDTT_EXTENSION_MARKER"', script)
        self.assertIn("awk 'NR == 1 { print $1; exit }'", script)
        self.assertIn("Некорректная контрольная сумма Go", script)
        self.assertIn('https://dl.google.com/go/${go_tarball}.sha256', script)
        self.assertIn("build -mod=mod", script)
        self.assertIn('GOMODCACHE="$work/gopath/pkg/mod"', script)
        self.assertIn('json:"label,omitempty"', script)
        self.assertIn('json:"main_down_bytes,omitempty"', script)
        self.assertIn('json:"last_upload_at,omitempty"', script)
        self.assertIn('"activity"', script)
        self.assertIn('"command":"settings"', script)
        self.assertIn("label prompt on Telegram creation", script)
        self.assertIn("label before password in Telegram list", script)
        self.assertIn("wdtt-xray-cascade.service", script)
        self.assertIn("wdtt-xray-gateway.service", script)
        self.assertIn("wdtt-panel-geofiles-update.timer", script)
        self.assertIn("wdtt-panel-backup.timer", script)
        self.assertIn("wdtt-panel-backup", script)

    def test_installer_recovers_legacy_labels_from_private_backups(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        start_marker = 'python3 - /etc/wdtt/passwords.json "$PRIVATE_STATE_DIR/user-labels.json" <<\'PY\'\n'
        start = installer.index(start_marker) + len(start_marker)
        end = installer.index('\nPY\n  fi\n  install -m 0755 "$work/wdtt-server"', start)
        migration = installer[start:end]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db_path = root / "etc" / "passwords.json"
            labels_path = root / "private" / "user-labels.json"
            backup_path = root / "private" / "backups" / "passwords-legacy.json"
            db_path.parent.mkdir(parents=True)
            backup_path.parent.mkdir(parents=True)
            db_path.write_text(json.dumps({"passwords": {"LegacyUser123": {}}, "devices": {}}), encoding="utf-8")
            labels_path.write_text("{}", encoding="utf-8")
            backup_path.write_text(json.dumps({"passwords": {"LegacyUser123": {"label": "Старое имя"}}}, ensure_ascii=False), encoding="utf-8")
            namespace = {"__name__": "__main__"}
            with mock.patch("sys.argv", ["migration.py", str(db_path), str(labels_path)]):
                exec(compile(migration, "label-migration.py", "exec"), namespace)
            restored = json.loads(db_path.read_text(encoding="utf-8"))
            self.assertEqual(restored["passwords"]["LegacyUser123"]["label"], "Старое имя")

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
        self.assertIn('id="create-full-backup"', html)
        self.assertIn('id="create-users-backup"', html)
        self.assertIn('id="save-backup-schedule"', html)
        self.assertIn('api("panel/update"', script)
        self.assertIn('api("backups/create"', script)
        self.assertIn('api("backups/delete"', script)
        self.assertIn('api("backups/schedule"', script)
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
        self.assertIn('ru_blocked', script)
        self.assertIn('Meta: Facebook, Instagram, Threads', html)
        self.assertIn('eu-vless', script)
        self.assertIn('restoreSidebarState()', script)
        self.assertIn('id="log-source"', html)
        self.assertIn('id="sidebar-toggle"', html)
        self.assertIn('id="theme-toggle"', html)
        self.assertNotIn('id="refresh"', html)
        self.assertIn('id="log-limit"', html)
        self.assertIn('id="download-logs"', html)
        self.assertIn('logs?source=', script)
        self.assertIn('static/app.js?v={{VERSION}}', html)
        self.assertNotIn('id="repair-wdtt"', html)
        self.assertNotIn('api("service/repair"', script)

    def test_user_labels_and_bulk_actions_are_exposed(self):
        html = (ROOT / "wdtt_panel" / "templates" / "index.html").read_text(encoding="utf-8")
        script = (ROOT / "wdtt_panel" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="edit-label"', html)
        self.assertIn('id="bulk-label-prefix"', html)
        self.assertIn('id="select-all-users"', html)
        self.assertIn('id="bulk-user-action"', html)
        self.assertIn('id="bulk-user-days"', html)
        self.assertIn('value="set_expiration"', html)
        self.assertIn('id="user-activity-dialog"', html)
        self.assertIn('id="user-auto-refresh-interval"', html)
        self.assertIn('data-user-sort="traffic"', html)
        self.assertIn('data-user-sort="label"', html)
        self.assertIn('api("users/bulk-action"', script)
        self.assertIn('openUserActivity', script)
        self.assertIn('restoreActiveTab()', script)
        self.assertIn('setUserAutoRefresh', script)
        self.assertIn('sortedUsers', script)
        self.assertNotIn('id="enable-wdtt-extensions"', html)
        self.assertNotIn('api("wdtt/extensions/enable"', script)

    def test_admin_lock_is_in_writable_private_state(self):
        script = (ROOT / "wdtt_panel" / "admin.py").read_text(encoding="utf-8")
        self.assertIn("/var/lib/wdtt-panel-private/admin.lock", script)
        self.assertNotIn("/run/lock/wdtt-panel-admin.lock", script)

    def test_panel_service_allows_netlink_for_tproxy_policy_routing(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", script)

    def test_installer_removes_obsolete_fleet_agent(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("remove_obsolete_fleet_agent()", script)
        self.assertIn("wdtt-fleet-agent.service", script)
        self.assertIn('$STATE_DIR/fleet-agent.json', script)
        self.assertNotIn("write_fleet_agent_service()", script)

    def test_dialog_cancel_buttons_skip_required_field_validation(self):
        html = (ROOT / "wdtt_panel" / "templates" / "index.html").read_text(encoding="utf-8")
        self.assertEqual(html.count('value="cancel" formnovalidate'), 4)


if __name__ == "__main__":
    unittest.main()
