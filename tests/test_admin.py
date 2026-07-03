import json
import base64
import errno
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from wdtt_panel import admin


class AdminDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_file = root / "etc" / "passwords.json"
        self.panel_labels = root / "user-labels.json"
        self.extension_state = root / "wdtt-extensions.json"
        self.backups = root / "backups"
        self.backup_schedule = root / "backup-schedule.json"
        self.lock_file = root / "admin.lock"
        self.cascade_settings = root / "cascade.json"
        self.cascade_config = root / "sing-box.json"
        self.warp_dir = root / "warp"
        self.geofiles_dir = root / "geofiles"
        self.xray_settings = root / "xray-settings.json"
        self.xray_config = root / "xray-config.json"
        self.xray_assets = root / "xray-assets"
        self.xray_cascade_settings = root / "xray-cascade.json"
        self.xray_access_log = root / "xray-access.log"
        self.xray_error_log = root / "xray-error.log"
        self.install_log = root / "install.log"
        self.nginx_access_log = root / "nginx-access.log"
        self.nginx_error_log = root / "nginx-error.log"
        self.patchers = [
            mock.patch.object(admin, "DB_FILE", self.db_file),
            mock.patch.object(admin, "PANEL_LABELS_FILE", self.panel_labels),
            mock.patch.object(admin, "WDTT_EXTENSION_STATE", self.extension_state),
            mock.patch.object(admin, "BACKUP_DIR", self.backups),
            mock.patch.object(admin, "BACKUP_SCHEDULE_FILE", self.backup_schedule),
            mock.patch.object(admin, "LOCK_FILE", self.lock_file),
            mock.patch.object(admin, "CASCADE_SETTINGS", self.cascade_settings),
            mock.patch.object(admin, "CASCADE_CONFIG", self.cascade_config),
            mock.patch.object(admin, "WARP_DIR", self.warp_dir),
            mock.patch.object(admin, "GEOFILES_DIR", self.geofiles_dir),
            mock.patch.object(admin, "XRAY_SETTINGS", self.xray_settings),
            mock.patch.object(admin, "XRAY_CONFIG", self.xray_config),
            mock.patch.object(admin, "XRAY_ASSETS", self.xray_assets),
            mock.patch.object(admin, "XRAY_CASCADE_SETTINGS", self.xray_cascade_settings),
            mock.patch.object(admin, "XRAY_ACCESS_LOG", self.xray_access_log),
            mock.patch.object(admin, "XRAY_ERROR_LOG", self.xray_error_log),
            mock.patch.object(admin, "INSTALL_LOG_FILE", self.install_log),
            mock.patch.object(admin, "NGINX_ACCESS_LOG", self.nginx_access_log),
            mock.patch.object(admin, "NGINX_ERROR_LOG", self.nginx_error_log),
            mock.patch.object(admin, "WDTT_UNIT_FILE", root / "wdtt.service"),
            mock.patch.object(admin, "SKIP_SYSTEMD", True),
        ]
        for patcher in self.patchers:
            patcher.start()
        admin.save_database(admin.empty_database())

    def tearDown(self):
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temp.cleanup()

    def test_create_update_unbind_delete(self):
        created = admin.create_user(
            {
                "password": "PanelUser123",
                "days": 30,
                "vk_hash": "https://vk.com/call/join/hash_123",
                "ports": "56000,56001,9000",
            }
        )
        self.assertEqual(created["password"], "PanelUser123")

        data = admin.load_database()
        data["passwords"]["PanelUser123"]["device_id"] = "android-device"
        data["devices"]["android-device"] = {
            "device_id": "android-device",
            "ip": "10.66.66.2",
            "priv_key": "private",
            "pub_key": "public",
        }
        admin.save_database(data)

        unbound = admin.unbind_user({"password": "PanelUser123"})
        self.assertEqual(unbound["device_id"], "")
        self.assertNotIn("android-device", admin.load_database()["devices"])

        updated = admin.update_user(
            {
                "current_password": "PanelUser123",
                "password": "RenamedUser123",
                "unlimited": True,
                "vk_hash": "hash_456",
                "ports": "56100,56101,9100",
                "is_deactivated": True,
            }
        )
        self.assertEqual(updated["password"], "RenamedUser123")
        self.assertTrue(updated["is_deactivated"])
        self.assertEqual(updated["expires_at"], 0)

        admin.delete_user({"password": "RenamedUser123"})
        self.assertEqual(admin.load_database()["passwords"], {})
        self.assertTrue(list(self.backups.glob("passwords-*.json")))

    def test_restore_backup(self):
        admin.create_user(
            {"password": "BackupUser123", "days": 7, "vk_hash": "hash_123", "ports": "56000,56001,9000"}
        )
        backup_name = admin.create_backup("manual")
        admin.delete_user({"password": "BackupUser123"})
        admin.restore_backup({"name": backup_name})
        self.assertIn("BackupUser123", admin.load_database()["passwords"])

    def test_full_backup_restores_users_statistics_devices_and_panel_settings(self):
        data = admin.load_database()
        data["custom_setting"] = "preserved"
        data["passwords"]["StatsUser123"] = {
            "device_id": "device-stats",
            "expires_at": 0,
            "down_bytes": 123456,
            "up_bytes": 654321,
            "vk_hash": "hash_stats",
            "ports": "56000,56001,9000",
            "is_deactivated": False,
        }
        data["devices"]["device-stats"] = {"device_id": "device-stats", "ip": "10.66.66.9"}
        admin.save_database(data)
        xray = admin.default_xray_settings()
        xray["access_log"] = True
        admin.save_private_json(self.xray_settings, xray)
        self.warp_dir.mkdir(parents=True)
        (self.warp_dir / "wgcf-profile.conf").write_text("[Interface]\nPrivateKey = restored\n", encoding="utf-8")

        backup = admin.create_manual_backup({"type": "full"})
        self.assertEqual(backup["type"], "full")
        changed = admin.load_database()
        changed["passwords"].clear()
        changed["devices"].clear()
        changed.pop("custom_setting")
        admin.save_database(changed)
        xray["access_log"] = False
        admin.save_private_json(self.xray_settings, xray)
        (self.warp_dir / "wgcf-profile.conf").write_text("[Interface]\nPrivateKey = changed\n", encoding="utf-8")

        admin.restore_backup({"name": backup["name"]})
        restored = admin.load_database()
        self.assertEqual(restored["passwords"]["StatsUser123"]["down_bytes"], 123456)
        self.assertEqual(restored["devices"]["device-stats"]["ip"], "10.66.66.9")
        self.assertEqual(restored["custom_setting"], "preserved")
        self.assertTrue(admin.load_xray_settings()["access_log"])
        self.assertIn("restored", (self.warp_dir / "wgcf-profile.conf").read_text(encoding="utf-8"))

    def test_users_backup_does_not_replace_panel_settings(self):
        admin.create_user(
            {"password": "UserOnly123", "label": "Отдельно", "days": 30, "vk_hash": "hash_one", "ports": "56000,56001,9000"}
        )
        xray = admin.default_xray_settings()
        xray["access_log"] = True
        admin.save_private_json(self.xray_settings, xray)
        backup = admin.create_manual_backup({"type": "users"})
        self.assertEqual(backup["type"], "users")

        admin.delete_user({"password": "UserOnly123"})
        xray["access_log"] = False
        admin.save_private_json(self.xray_settings, xray)

        admin.restore_backup({"name": backup["name"]})
        self.assertIn("UserOnly123", admin.load_database()["passwords"])
        self.assertFalse(admin.load_xray_settings()["access_log"])

    def test_backups_can_be_deleted_and_scheduled_with_retention(self):
        schedule = admin.save_backup_schedule({"frequency": "daily", "time": "04:20", "type": "users", "keep": 1})
        self.assertEqual(schedule["settings"], {"frequency": "daily", "time": "04:20", "type": "users", "keep": 1})
        self.assertFalse(schedule["active"])
        self.assertEqual(admin.backup_schedule_status()["settings"]["time"], "04:20")

        first = admin.create_manual_backup({"type": "users", "scheduled": True})
        second = admin.create_manual_backup({"type": "users", "scheduled": True})
        scheduled = list(self.backups.glob("users-*-scheduled.json"))
        self.assertEqual(len(scheduled), 1)
        self.assertEqual(scheduled[0].name, second["name"])
        self.assertFalse((self.backups / first["name"]).exists())

        manual = admin.create_manual_backup({"type": "full"})
        self.assertEqual(admin.delete_backup({"name": manual["name"]})["deleted"], manual["name"])
        self.assertFalse((self.backups / manual["name"]).exists())

    def test_bulk_create_assigns_shared_hashes(self):
        result = admin.create_users_bulk(
            {
                "count": 3,
                "days": 30,
                "vk_hash": "hash_one,hash_two",
                "hash_mode": "shared",
                "ports": "56000,56001,9000",
            }
        )
        self.assertEqual(result["count"], 3)
        self.assertEqual(len({item["password"] for item in result["users"]}), 3)
        self.assertTrue(all(item["vk_hash"] == "hash_one,hash_two" for item in result["users"]))

    def test_bulk_create_rotates_hashes(self):
        result = admin.create_users_bulk(
            {
                "count": 4,
                "unlimited": True,
                "vk_hash": "hash_one hash_two",
                "hash_mode": "rotate",
                "ports": "56000,56001,9000",
            }
        )
        self.assertEqual(
            [item["vk_hash"] for item in result["users"]],
            ["hash_one", "hash_two", "hash_one", "hash_two"],
        )
        self.assertTrue(all(item["expires_at"] == 0 for item in result["users"]))

    def test_labels_are_saved_for_single_and_bulk_users(self):
        created = admin.create_user(
            {
                "password": "NamedUser123",
                "label": "Иван — Pixel",
                "days": 30,
                "vk_hash": "hash_one",
                "ports": "56000,56001,9000",
            }
        )
        self.assertEqual(created["label"], "Иван — Pixel")
        updated = admin.update_user(
            {"current_password": "NamedUser123", "password": "NamedUser123", "label": "Иван дома"}
        )
        self.assertEqual(updated["label"], "Иван дома")
        result = admin.create_users_bulk(
            {
                "count": 2,
                "label_prefix": "Семья",
                "days": 30,
                "vk_hash": "hash_two",
                "ports": "56000,56001,9000",
            }
        )
        self.assertEqual([item["label"] for item in result["users"]], ["Семья 1", "Семья 2"])

    def test_legacy_telegram_label_is_shown_in_the_panel(self):
        data = admin.load_database()
        data["passwords"]["LegacyUser12"] = {
            "device_id": "",
            "expires_at": 0,
            "down_bytes": 0,
            "up_bytes": 0,
            "remark": "Старый бот — Ольга",
            "vk_hash": "hash_one",
            "ports": "56000,56001,9000",
        }
        admin.save_database(data)
        self.assertEqual(admin.list_users()["users"][0]["label"], "Старый бот — Ольга")

    def test_legacy_telegram_label_map_is_shown_in_the_panel(self):
        data = admin.load_database()
        data["passwords"]["MappedUser123"] = {
            "device_id": "",
            "expires_at": 0,
            "down_bytes": 0,
            "up_bytes": 0,
            "vk_hash": "hash_one",
            "ports": "56000,56001,9000",
        }
        data["labels"] = {"MappedUser123": "Telegram — Сергей"}
        admin.save_database(data)
        self.assertEqual(admin.list_users()["users"][0]["label"], "Telegram — Сергей")

    def test_panel_labels_survive_an_older_wdtt_rewriting_its_database(self):
        admin.create_user(
            {"password": "DurableUser12", "label": "Ноутбук Ольги", "days": 30, "vk_hash": "hash_one", "ports": "56000,56001,9000"}
        )
        data = admin.load_database()
        data["passwords"]["DurableUser12"].pop("label", None)
        admin.save_database(data)
        self.assertEqual(admin.list_users()["users"][0]["label"], "Ноутбук Ольги")

    def test_user_traffic_activity_is_returned_with_the_user(self):
        data = admin.load_database()
        data["passwords"]["ActiveUser123"] = {
            "device_id": "",
            "expires_at": 0,
            "down_bytes": 512,
            "up_bytes": 256,
            "last_upload_at": 1_700_000_001,
            "last_download_at": 1_700_000_002,
            "vk_hash": "hash_one",
            "ports": "56000,56001,9000",
        }
        admin.save_database(data)
        user = admin.list_users()["users"][0]
        self.assertEqual(user["last_upload_at"], 1_700_000_001)
        self.assertEqual(user["last_download_at"], 1_700_000_002)

    def test_telegram_settings_update_database_and_wdtt_unit(self):
        admin.WDTT_UNIT_FILE.write_text(
            "[Service]\nExecStart=/usr/local/bin/wdtt-server -listen 0.0.0.0:56000 -wg-port 56001 -config-dir /etc/wdtt -password MainPassword123\n",
            encoding="utf-8",
        )

        def fake_run(command, timeout=20, check=False, cwd=None, env=None):
            code = 1 if command[:3] == ["systemctl", "is-active", "--quiet"] else 0
            return subprocess.CompletedProcess(command, code, "", "")

        with mock.patch.object(admin, "SKIP_SYSTEMD", False), mock.patch.object(admin, "run", side_effect=fake_run):
            result = admin.configure_telegram(
                {
                    "enabled": True,
                    "admin_id": "123456789",
                    "bot_token": "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_test",
                }
            )

        data = admin.load_database()
        self.assertTrue(result["enabled"])
        self.assertEqual(data["admin_id"], "123456789")
        self.assertEqual(data["bot_token"], "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_test")
        unit = admin.WDTT_UNIT_FILE.read_text(encoding="utf-8")
        self.assertIn("-admin 123456789", unit)
        self.assertIn("-bot-token 123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_test", unit)

        with mock.patch.object(admin, "SKIP_SYSTEMD", False), mock.patch.object(admin, "run", side_effect=fake_run):
            disabled = admin.configure_telegram({"enabled": False})
        self.assertFalse(disabled["enabled"])
        self.assertNotIn("-bot-token", admin.WDTT_UNIT_FILE.read_text(encoding="utf-8"))

    def test_bulk_user_actions_apply_in_one_database_update(self):
        for password in ("FirstUser123", "SecondUser12"):
            admin.create_user(
                {"password": password, "days": 30, "vk_hash": "hash_one", "ports": "56000,56001,9000"}
            )
        data = admin.load_database()
        data["passwords"]["FirstUser123"].update({"device_id": "first-device", "down_bytes": 100, "up_bytes": 50})
        data["devices"]["first-device"] = {"device_id": "first-device", "ip": "10.66.66.2"}
        admin.save_database(data)

        result = admin.bulk_user_action(
            {"action": "deactivate", "passwords": ["FirstUser123", "SecondUser12"]}
        )
        self.assertEqual(result["count"], 2)
        self.assertTrue(all(entry["is_deactivated"] for entry in admin.load_database()["passwords"].values()))
        before_renewal = int(time.time())
        admin.bulk_user_action({"action": "set_expiration", "passwords": ["FirstUser123", "SecondUser12"], "days": 45})
        renewed = admin.load_database()["passwords"]
        self.assertTrue(all(entry["expires_at"] >= before_renewal + 44 * 86400 for entry in renewed.values()))
        admin.bulk_user_action({"action": "reset_traffic", "passwords": ["FirstUser123"]})
        self.assertEqual(admin.load_database()["passwords"]["FirstUser123"]["down_bytes"], 0)
        admin.bulk_user_action({"action": "unbind", "passwords": ["FirstUser123"]})
        self.assertEqual(admin.load_database()["passwords"]["FirstUser123"]["device_id"], "")
        self.assertNotIn("first-device", admin.load_database()["devices"])
        admin.bulk_user_action({"action": "delete", "passwords": ["SecondUser12"]})
        self.assertNotIn("SecondUser12", admin.load_database()["passwords"])

    def test_database_file_is_valid_json(self):
        parsed = json.loads(self.db_file.read_text(encoding="utf-8"))
        self.assertIn("passwords", parsed)
        self.assertIn("devices", parsed)

    def test_cleanup_preview_and_apply_only_known_safe_targets(self):
        self.install_log.write_text("install log\n", encoding="utf-8")
        self.xray_access_log.write_text("route log\n", encoding="utf-8")
        preview = admin.cleanup_system({"targets": ["service_logs"], "keep_days": 7}, False)
        self.assertFalse(preview["applied"])
        self.assertGreater(preview["estimated_freed_bytes"], 0)
        self.assertTrue(self.install_log.read_text(encoding="utf-8"))

        result = admin.cleanup_system({"targets": ["service_logs", "unknown"], "keep_days": 7}, True)
        self.assertTrue(result["applied"])
        self.assertEqual(self.install_log.read_text(encoding="utf-8"), "")
        self.assertEqual(self.xray_access_log.read_text(encoding="utf-8"), "")
        self.assertEqual(admin.load_database()["passwords"], {})

    def test_cleanup_apply_skips_read_only_log_without_failing(self):
        self.install_log.write_text("locked log\n", encoding="utf-8")
        self.xray_access_log.write_text("route log\n", encoding="utf-8")
        original_open = type(self.install_log).open

        def guarded_open(path, *args, **kwargs):
            mode = args[0] if args else kwargs.get("mode", "r")
            if path == self.install_log and "w" in mode:
                raise OSError(errno.EROFS, "Read-only file system", str(path))
            return original_open(path, *args, **kwargs)

        with mock.patch.object(type(self.install_log), "open", new=guarded_open):
            result = admin.cleanup_system({"targets": ["service_logs"], "keep_days": 14}, True)

        service_logs = result["items"][0]
        files = {item["name"]: item for item in service_logs["files"]}
        self.assertTrue(result["applied"])
        self.assertTrue(files["installer"]["skipped"])
        self.assertIn("только для чтения", files["installer"]["error"])
        self.assertTrue(files["xray_access"]["cleared"])
        self.assertEqual(self.install_log.read_text(encoding="utf-8"), "locked log\n")
        self.assertEqual(self.xray_access_log.read_text(encoding="utf-8"), "")

    def test_cleanup_target_error_is_reported_without_stopping_other_targets(self):
        self.install_log.write_text("install log\n", encoding="utf-8")
        with mock.patch.object(admin, "cleanup_package_cache", side_effect=admin.AdminError("cache locked")):
            result = admin.cleanup_system({"targets": ["package_cache", "service_logs"], "keep_days": 14}, True)

        items = {item["target"]: item for item in result["items"]}
        self.assertFalse(items["package_cache"]["available"])
        self.assertEqual(items["package_cache"]["error"], "cache locked")
        self.assertTrue(items["service_logs"]["files"][0]["cleared"])
        self.assertEqual(self.install_log.read_text(encoding="utf-8"), "")

    def test_version_comparison_normalizes_short_versions(self):
        self.assertEqual(admin.version_parts("1.2"), admin.version_parts("1.2.0"))
        self.assertGreater(admin.version_parts("1.2.1"), admin.version_parts("1.2"))

    def test_backup_can_be_exported_and_uploaded(self):
        backup = admin.create_manual_backup({})
        exported = admin.export_backup({"name": backup["name"]})
        uploaded = admin.import_backup({"name": "local.json", "content": exported["content"]})
        self.assertTrue((self.backups / uploaded["name"]).is_file())
        self.assertEqual(json.loads(exported["content"])["database"]["passwords"], {})
        self.assertEqual(uploaded["type"], "full")

    def test_admin_device_is_not_online_from_a_stale_conntrack_entry(self):
        data = admin.load_database()
        data["main_down_bytes"] = 200
        data["main_up_bytes"] = 100
        data["devices"]["admin-phone"] = {"device_id": "admin-phone", "ip": "10.66.66.2", "pub_key": "admin-public"}
        admin.save_database(data)
        with mock.patch.object(admin, "wireguard_handshakes", return_value={}):
            result = admin.list_users()
        self.assertEqual(result["admins"][0]["role"], "admin")
        self.assertFalse(result["admins"][0]["connected"])
        self.assertEqual(result["admins"][0]["down_bytes"], 200)
        self.assertTrue(result["admins"][0]["traffic_supported"])

    def test_admin_device_is_online_from_embedded_wireguard_handshake(self):
        data = admin.load_database()
        data["devices"]["admin-phone"] = {"device_id": "admin-phone", "ip": "10.66.66.2", "pub_key": "admin-public"}
        admin.save_database(data)
        with mock.patch.object(admin, "wireguard_handshakes", return_value={"admin-public": int(time.time())}):
            result = admin.list_users()
        self.assertTrue(result["admins"][0]["connected"])

    def test_main_administrator_is_listed_without_a_bound_device(self):
        data = admin.load_database()
        data["main_password"] = "admin"
        admin.save_database(data)
        result = admin.list_users()
        self.assertEqual(result["admins"][0]["label"], "Администратор WDTT")
        self.assertEqual(result["admins"][0]["device_id"], "")
        self.assertIsNone(result["admins"][0]["device"])
        self.assertFalse(result["admins"][0]["connected"])

    def test_stale_wireguard_handshake_is_not_online(self):
        self.assertFalse(admin.handshake_is_active(int(time.time()) - 76))

    def test_overview_counts_the_main_administrator_and_its_device(self):
        data = admin.load_database()
        data["main_password"] = "admin"
        data["devices"]["admin-phone"] = {"device_id": "admin-phone", "ip": "10.66.66.2"}
        admin.save_database(data)
        disk = mock.Mock(total=100, used=10, free=90)
        with mock.patch.object(admin, "read_stats", return_value={}), mock.patch.object(admin.shutil, "disk_usage", return_value=disk), mock.patch.object(admin, "cpu_usage", return_value=0), mock.patch.object(admin, "memory_usage", return_value={}), mock.patch.object(admin.os, "getloadavg", return_value=(0, 0, 0), create=True):
            result = admin.overview({})
        self.assertEqual(result["users"], 1)
        self.assertEqual(result["devices"], 1)
        self.assertEqual(result["admin_devices"], 1)
        self.assertEqual(result["online_devices"], 0)
        self.assertEqual(result["online_admin_devices"], 0)

    def test_userspace_wireguard_handshakes_are_used_when_wg_tools_are_missing(self):
        with mock.patch.object(admin, "SKIP_SYSTEMD", False), mock.patch.object(admin.shutil, "which", return_value=None), mock.patch.object(admin, "userspace_wireguard_handshakes", return_value={"public-key": 123}):
            self.assertEqual(admin.wireguard_handshakes(), {"public-key": 123})

    def test_full_diagnostics_log_sources_are_limited(self):
        result = admin.journal_logs({"source": "all", "limit": 9999})
        self.assertEqual(result["source"], "all")
        self.assertEqual(result["limit"], 5000)
        self.assertEqual(result["lines"], [])

    def test_xray_access_log_is_available_as_a_diagnostic_source(self):
        self.xray_access_log.write_text("accepted tcp:gemini.google.com:443 [eu-vless]", encoding="utf-8")
        result = admin.journal_logs({"source": "xray-access", "limit": 100})
        self.assertEqual(result["title"], "Xray: домены и маршруты")
        self.assertEqual(result["lines"], ["accepted tcp:gemini.google.com:443 [eu-vless]"])
        self.xray_error_log.write_text("connection failed: gemini.google.com", encoding="utf-8")
        errors = admin.journal_logs({"source": "xray-errors", "limit": 100})
        self.assertEqual(errors["title"], "Xray: ошибки соединений")
        self.assertEqual(errors["lines"], ["connection failed: gemini.google.com"])

    def test_xray_managed_config_has_safe_default_outbounds(self):
        settings = admin.normalize_xray_settings(
            {
                "enabled": True,
                "mode": "managed",
                "log_level": "warning",
                "inbounds": [],
                "outbounds": [
                    {"tag": "vless-out", "protocol": "vless", "settings": {"vnext": []}},
                ],
                "routing_rules": [{"type": "field", "outboundTag": "vless-out", "domain": ["geosite:ru"]}],
                "geofiles": admin.default_xray_settings()["geofiles"],
            }
        )
        config = admin.build_xray_config(settings)
        self.assertEqual([item["tag"] for item in config["outbounds"]], ["direct", "block", "vless-out"])
        self.assertEqual(config["routing"]["rules"][0]["outboundTag"], "vless-out")
        self.assertIn("runetfreedom", settings["geofiles"][0]["url"])
        self.assertTrue(config["inbounds"] == [] or config["inbounds"][0]["sniffing"]["enabled"])

    def test_xray_access_logging_writes_to_private_panel_state(self):
        settings = admin.normalize_xray_settings(
            {
                "enabled": True,
                "mode": "managed",
                "log_level": "info",
                "access_log": True,
                "inbounds": [],
                "outbounds": [],
                "routing_rules": [],
                "geofiles": admin.default_xray_settings()["geofiles"],
            }
        )
        config = admin.build_xray_config(settings)
        self.assertEqual(config["log"]["access"], str(self.xray_access_log))
        self.assertEqual(config["log"]["error"], str(self.xray_error_log))

    def test_xray_access_logging_also_applies_to_raw_config(self):
        settings = admin.normalize_xray_settings(
            {
                "enabled": True,
                "mode": "raw",
                "log_level": "warning",
                "access_log": True,
                "raw_config": '{"log": {"loglevel": "error"}, "inbounds": [], "outbounds": []}',
                "geofiles": admin.default_xray_settings()["geofiles"],
            }
        )
        config = admin.build_xray_config(settings)
        self.assertEqual(config["log"]["loglevel"], "error")
        self.assertEqual(config["log"]["access"], str(self.xray_access_log))

    def test_wdtt_gateway_adds_transparent_xray_inbound_without_cascade(self):
        settings = admin.normalize_xray_settings(
            {
                "enabled": True,
                "mode": "managed",
                "log_level": "info",
                "gateway_enabled": True,
                "gateway_source_cidr": "10.66.66.0/24",
                "gateway_inbound_port": 12346,
                "inbounds": [],
                "outbounds": [],
                "routing_rules": [],
                "friendly_rules": [{"name": "Google AI", "outbound": "warp", "domains": "gemini.google.com"}],
                "geofiles": admin.default_xray_settings()["geofiles"],
            }
        )
        settings["outbounds"] = [{"tag": "warp", "protocol": "freedom", "settings": {}}]
        config = admin.build_effective_xray_config(settings, {"enabled": False})
        inbound = next(item for item in config["inbounds"] if item["tag"] == "wdtt-gateway-in")
        self.assertEqual(inbound["port"], 12346)
        self.assertTrue(inbound["sniffing"]["enabled"])
        self.assertEqual(config["routing"]["rules"][0]["outboundTag"], "warp")

    def test_google_ai_warp_rule_covers_quic_google_frontends_by_ip(self):
        settings = admin.normalize_xray_settings(
            {
                "enabled": True,
                "mode": "managed",
                "log_level": "info",
                "inbounds": [],
                "outbounds": [{"tag": "warp", "protocol": "freedom", "settings": {}}],
                "routing_rules": [],
                "friendly_rules": [{"name": "Google AI", "outbound": "warp", "domains": "gemini.google.com"}],
                "geofiles": admin.default_xray_settings()["geofiles"],
            }
        )
        rule = settings["friendly_rules"][0]
        self.assertIn("robinfrontend-pa.googleapis.com", rule["domains"])
        self.assertIn("142.250.0.0/15", rule["ip_cidrs"])
        self.assertIn("216.239.32.0/19", rule["ip_cidrs"])
        config = admin.build_xray_config(settings)
        ip_rule = next(item for item in config["routing"]["rules"] if item.get("ip"))
        self.assertEqual(ip_rule["outboundTag"], "warp")
        self.assertIn("142.251.0.0/16", ip_rule["ip"])

    def test_gateway_and_cascade_cannot_capture_wdtt_traffic_together(self):
        settings = admin.normalize_xray_settings(
            {
                "enabled": True,
                "mode": "managed",
                "gateway_enabled": True,
                "gateway_source_cidr": "10.66.66.0/24",
                "gateway_inbound_port": 12346,
                "inbounds": [],
                "outbounds": [],
                "routing_rules": [],
                "geofiles": admin.default_xray_settings()["geofiles"],
            }
        )
        with self.assertRaises(admin.ValidationError):
            admin.build_effective_xray_config(settings, {"enabled": True})

    def test_xray_save_applies_gateway_without_restarting_its_oneshot_service(self):
        payload = {
            "enabled": True,
            "mode": "managed",
            "log_level": "warning",
            "gateway_enabled": True,
            "gateway_source_cidr": "10.66.66.0/24",
            "gateway_inbound_port": 12346,
            "inbounds": [],
            "outbounds": [],
            "routing_rules": [],
            "geofiles": admin.default_xray_settings()["geofiles"],
        }
        fake_run = mock.Mock(return_value=mock.Mock(returncode=0, stderr=""))
        with (
            mock.patch.object(admin, "SKIP_SYSTEMD", False),
            mock.patch.object(admin, "run", fake_run),
            mock.patch.object(admin, "persist_xray_configuration"),
            mock.patch.object(admin, "load_xray_cascade_settings", return_value={"enabled": False}),
            mock.patch.object(admin, "xray_gateway_apply_rules") as apply_rules,
            mock.patch.object(admin, "xray_status", return_value={"saved": True}),
        ):
            result = admin.xray_save(payload)

        self.assertEqual(result, {"saved": True})
        fake_run.assert_called_once_with(["systemctl", "enable", admin.XRAY_GATEWAY_SERVICE], timeout=45)
        apply_rules.assert_called_once_with({})

    def test_iptables_falls_back_to_legacy_when_nftables_is_unavailable(self):
        nft_error = mock.Mock(
            returncode=1,
            stdout="",
            stderr="iptables: Failed to initialize nft: Address family not supported by protocol",
        )
        legacy_result = mock.Mock(returncode=0, stdout="", stderr="")
        locations = {"iptables": "/usr/sbin/iptables", "iptables-legacy": "/usr/sbin/iptables-legacy"}
        fake_run = mock.Mock(side_effect=[nft_error, legacy_result])
        with (
            mock.patch.object(admin, "IPTABLES_BINARY", None),
            mock.patch.object(admin.shutil, "which", side_effect=locations.get),
            mock.patch.object(admin, "run", fake_run),
        ):
            result = admin.cascade_iptables(["-S", "PREROUTING"])

        self.assertIs(result, legacy_result)
        self.assertEqual(
            fake_run.call_args_list,
            [
                mock.call(
                    ["/usr/sbin/iptables", "-w", "-t", "mangle", "-S", "PREROUTING"],
                    timeout=30,
                    env={"XTABLES_LOCKFILE": admin.XTABLES_LOCK_FILE},
                ),
                mock.call(
                    ["/usr/sbin/iptables-legacy", "-w", "-t", "mangle", "-S", "PREROUTING"],
                    timeout=30,
                    env={"XTABLES_LOCKFILE": admin.XTABLES_LOCK_FILE},
                ),
            ],
        )

    def test_xray_friendly_routes_and_rules_build_without_json_editor(self):
        settings = admin.normalize_xray_settings(
            {
                "enabled": True,
                "mode": "managed",
                "log_level": "warning",
                "inbounds": [],
                "outbounds": [],
                "routing_rules": [],
                "routes": [
                    {
                        "name": "EU server",
                        "tag": "eu-main",
                        "type": "vless",
                        "vless_uri": "vless://00000000-0000-4000-8000-000000000000@eu.example.com:443?type=tcp&security=tls&sni=eu.example.com",
                    }
                ],
                "friendly_rules": [
                    {
                        "name": "Blocked resources",
                        "outbound": "eu-main",
                        "domains": "youtube.com\ngooglevideo.com",
                        "ip_cidrs": "203.0.113.10\n198.51.100.0/24",
                        "geosite": "ru-blocked",
                        "geoip": "ru-blocked",
                    }
                ],
                "geofiles": admin.default_xray_settings()["geofiles"],
            }
        )
        config = admin.build_xray_config(settings)
        self.assertEqual([item["tag"] for item in config["outbounds"]], ["direct", "block", "eu-main"])
        self.assertEqual(config["routing"]["rules"][0]["outboundTag"], "eu-main")
        self.assertEqual(config["routing"]["rules"][0]["domain"], ["domain:youtube.com", "domain:googlevideo.com", "geosite:ru-blocked"])
        self.assertEqual(config["routing"]["rules"][1]["ip"], ["203.0.113.10/32", "198.51.100.0/24", "geoip:ru-blocked"])

    def test_ru_to_eu_cascade_adds_transparent_inbound_and_blocked_routes(self):
        xray = admin.normalize_xray_settings(
            {
                "enabled": True,
                "mode": "managed",
                "log_level": "warning",
                "inbounds": [],
                "outbounds": [],
                "routing_rules": [],
                "geofiles": admin.default_xray_settings()["geofiles"],
            }
        )
        routing = admin.normalize_xray_cascade_settings(
            {
                "enabled": True,
                "source_cidr": "10.66.66.0/24",
                "inbound_port": 12345,
                "geosite_category": "ru-blocked",
                "geoip_category": "ru-blocked",
                "domains": "example.com\nblocked.example",
                "ip_cidrs": "203.0.113.10\n198.51.100.0/24",
                "eu_vless_uri": "vless://00000000-0000-4000-8000-000000000000@eu.example.com:443?type=tcp&security=tls&sni=eu.example.com",
            }
        )
        config = admin.build_effective_xray_config(xray, routing)
        self.assertIn("wdtt-cascade-in", [item["tag"] for item in config["inbounds"]])
        self.assertIn("eu-vless", [item["tag"] for item in config["outbounds"]])
        self.assertEqual(config["routing"]["rules"][0]["domain"], ["domain:example.com", "domain:blocked.example"])
        self.assertEqual(config["routing"]["rules"][1]["ip"], ["203.0.113.10/32", "198.51.100.0/24"])
        self.assertEqual(config["routing"]["rules"][2]["domain"], ["geosite:ru-blocked"])
        self.assertEqual(config["routing"]["rules"][3]["ip"], ["geoip:ru-blocked"])

    def test_friendly_rule_can_use_enabled_eu_vless_cascade(self):
        xray = admin.normalize_xray_settings(
            {
                "enabled": True,
                "mode": "managed",
                "log_level": "warning",
                "inbounds": [],
                "outbounds": [],
                "routing_rules": [],
                "friendly_rules": [{"name": "Google AI", "outbound": "eu-vless", "domains": "gemini.google.com"}],
                "geofiles": admin.default_xray_settings()["geofiles"],
            }
        )
        routing = admin.normalize_xray_cascade_settings(
            {
                "enabled": True,
                "source_cidr": "10.66.66.0/24",
                "inbound_port": 12345,
                "geosite_category": "ru-blocked",
                "geoip_category": "ru-blocked",
                "eu_vless_uri": "vless://00000000-0000-4000-8000-000000000000@eu.example.com:443?type=tcp&security=tls&sni=eu.example.com",
            }
        )
        config = admin.build_effective_xray_config(xray, routing)
        google_rule = next(rule for rule in config["routing"]["rules"] if rule.get("domain") == ["domain:gemini.google.com"])
        self.assertEqual(google_rule["outboundTag"], "eu-vless")

    def test_warp_profile_becomes_xray_wireguard_outbound(self):
        self.warp_dir.mkdir()
        (self.warp_dir / "wgcf-profile.conf").write_text(
            "[Interface]\nPrivateKey = private-key\nAddress = 172.16.0.2/32, 2606:4700:110:8a36::2/128\nMTU = 1280\n\n[Peer]\nPublicKey = public-key\nEndpoint = engage.cloudflareclient.com:2408\nAllowedIPs = 0.0.0.0/0, ::/0\nReserved = 1,2,3\n",
            encoding="utf-8",
        )
        outbound = admin.warp_xray_outbound()
        self.assertEqual(outbound["tag"], "warp")
        self.assertTrue(outbound["settings"]["noKernelTun"])
        self.assertEqual(outbound["settings"]["peers"][0]["endpoint"], "engage.cloudflareclient.com:2408")
        self.assertEqual(outbound["settings"]["reserved"], [1, 2, 3])
        self.assertEqual(outbound["settings"]["domainStrategy"], "ForceIPv4v6")
        probe = admin.warp_probe_config(1080)
        self.assertEqual(probe["inbounds"][0]["port"], 1080)
        self.assertEqual(probe["outbounds"][0]["tag"], "warp")
        self.assertEqual(admin.parse_cloudflare_trace("warp=on\nip=198.51.100.10\n")["warp"], "on")

    def test_xray_raw_config_and_geofile_sources_are_saved(self):
        result = admin.xray_save(
            {
                "enabled": False,
                "mode": "raw",
                "log_level": "warning",
                "raw_config": '{"inbounds": [], "outbounds": [{"tag": "direct", "protocol": "freedom"}]}',
                "geofiles": [
                    {
                        "tag": "custom",
                        "filename": "custom.dat",
                        "url": "https://example.com/custom.dat",
                        "enabled": True,
                        "auto_update": True,
                        "update_interval": "1d",
                    }
                ],
            }
        )
        self.assertTrue(self.xray_config.is_file())
        self.assertEqual(result["settings"]["mode"], "raw")
        with self.assertRaises(admin.ValidationError):
            admin.normalize_xray_geofiles([{"tag": "bad", "filename": "bad.dat", "url": "http://example.com/bad.dat"}])

if __name__ == "__main__":
    unittest.main()
