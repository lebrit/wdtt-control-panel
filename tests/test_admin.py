import json
import base64
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wdtt_panel import admin


class AdminDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_file = root / "etc" / "passwords.json"
        self.backups = root / "backups"
        self.lock_file = root / "admin.lock"
        self.cascade_settings = root / "cascade.json"
        self.cascade_config = root / "sing-box.json"
        self.warp_dir = root / "warp"
        self.geofiles_dir = root / "geofiles"
        self.xray_settings = root / "xray-settings.json"
        self.xray_config = root / "xray-config.json"
        self.xray_assets = root / "xray-assets"
        self.patchers = [
            mock.patch.object(admin, "DB_FILE", self.db_file),
            mock.patch.object(admin, "BACKUP_DIR", self.backups),
            mock.patch.object(admin, "LOCK_FILE", self.lock_file),
            mock.patch.object(admin, "CASCADE_SETTINGS", self.cascade_settings),
            mock.patch.object(admin, "CASCADE_CONFIG", self.cascade_config),
            mock.patch.object(admin, "WARP_DIR", self.warp_dir),
            mock.patch.object(admin, "GEOFILES_DIR", self.geofiles_dir),
            mock.patch.object(admin, "XRAY_SETTINGS", self.xray_settings),
            mock.patch.object(admin, "XRAY_CONFIG", self.xray_config),
            mock.patch.object(admin, "XRAY_ASSETS", self.xray_assets),
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

    def test_manual_backup_restores_users_statistics_devices_and_settings(self):
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

        backup = admin.create_manual_backup({})
        changed = admin.load_database()
        changed["passwords"].clear()
        changed["devices"].clear()
        changed.pop("custom_setting")
        admin.save_database(changed)

        admin.restore_backup({"name": backup["name"]})
        restored = admin.load_database()
        self.assertEqual(restored["passwords"]["StatsUser123"]["down_bytes"], 123456)
        self.assertEqual(restored["devices"]["device-stats"]["ip"], "10.66.66.9")
        self.assertEqual(restored["custom_setting"], "preserved")

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

    def test_database_file_is_valid_json(self):
        parsed = json.loads(self.db_file.read_text(encoding="utf-8"))
        self.assertIn("passwords", parsed)
        self.assertIn("devices", parsed)

    def test_version_comparison_normalizes_short_versions(self):
        self.assertEqual(admin.version_parts("1.2"), admin.version_parts("1.2.0"))
        self.assertGreater(admin.version_parts("1.2.1"), admin.version_parts("1.2"))

    def test_backup_can_be_exported_and_uploaded(self):
        backup = admin.create_manual_backup({})
        exported = admin.export_backup({"name": backup["name"]})
        uploaded = admin.import_backup({"name": "local.json", "content": exported["content"]})
        self.assertTrue((self.backups / uploaded["name"]).is_file())
        self.assertEqual(json.loads(exported["content"])["passwords"], {})

    def test_admin_device_is_listed_separately(self):
        data = admin.load_database()
        data["devices"]["admin-phone"] = {"device_id": "admin-phone", "ip": "10.66.66.2", "pub_key": "admin-public"}
        admin.save_database(data)
        with mock.patch.object(admin, "wireguard_handshakes", return_value={}), mock.patch.object(admin, "active_tunnel_ips", return_value={"10.66.66.2"}):
            result = admin.list_users()
        self.assertEqual(result["admins"][0]["role"], "admin")
        self.assertTrue(result["admins"][0]["connected"])

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

    def test_repair_wdtt_interface_is_available(self):
        result = admin.repair_wdtt_interface({})
        self.assertTrue(result["interface"])


if __name__ == "__main__":
    unittest.main()
