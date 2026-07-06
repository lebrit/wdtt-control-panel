import json
import sys


request = json.load(sys.stdin)
action = request.get("action")
if action == "overview":
    result = {
        "service": {"exists": True, "active": True, "ip_forward": "1", "binary": True},
        "stats": {"active": 2, "total": 5, "up_gb": "0.10", "down_gb": "0.20"},
        "users": 1,
        "devices": 1,
        "system": {"cpu_percent": 18.4, "memory": {"total": 2147483648, "used": 805306368, "percent": 37.5}, "load_average": [0.25, 0.2, 0.1]},
        "disk": {"total": 21474836480, "used": 5368709120, "free": 16106127360, "percent": 25.0},
        "certificate": {"exists": True, "expires_at": 1798761600, "days_left": 200.0, "mode": "self-signed", "local_tls_ok": True, "listening": True},
    }
elif action == "users.list":
    result = {
        "users": [
            {
                "password": "DemoUserA123",
                "label": "Демо — Pixel 8",
                "device_id": "pixel-8-demo",
                "expires_at": 1798761600,
                "down_bytes": 419430400,
                "up_bytes": 73400320,
                "last_upload_at": 1781510410,
                "last_download_at": 1781510420,
                "vk_hash": "vk_hash_demo",
                "ports": "56000,56001,9000",
                "is_deactivated": False,
                "expired": False,
                "device": {"device_id": "pixel-8-demo", "ip": "10.66.66.2"},
            },
            {
                "password": "WaitingUser123",
                "label": "Ожидает выдачи",
                "device_id": "",
                "expires_at": 0,
                "down_bytes": 0,
                "up_bytes": 0,
                "vk_hash": "second_hash",
                "ports": "56000,56001,9000",
                "is_deactivated": True,
                "expired": False,
                "device": None,
            },
        ],
        "main_password_present": True,
        "admins": [{"password": "Главный пароль", "label": "Администратор WDTT", "role": "admin", "device_id": "admin-device", "device": {"device_id": "admin-device", "ip": "10.66.66.1"}, "connected": True, "last_handshake": 1781510400, "expires_at": 0, "down_bytes": 0, "up_bytes": 0, "last_upload_at": 1781510430, "last_download_at": 1781510440, "traffic_supported": True, "vk_hash": "Администратор WDTT", "is_deactivated": False, "expired": False}],
        "limit": 10,
    }
elif action == "users.create_bulk":
    payload = request.get("payload") or {}
    count = int(payload.get("count") or 1)
    hashes = [item for item in str(payload.get("vk_hash") or "demo_hash").replace(",", " ").split() if item]
    shared = payload.get("hash_mode") != "rotate"
    result = {
        "count": count,
        "users": [
            {
                "password": f"BulkDemo{index + 1:02d}Pass",
                "vk_hash": ",".join(hashes) if shared else hashes[index % len(hashes)],
                "ports": str(payload.get("ports") or "56000,56001,9000"),
                "expires_at": 0,
                "is_deactivated": False,
                "device_id": "",
                "down_bytes": 0,
                "up_bytes": 0,
            }
            for index in range(count)
        ],
    }
elif action == "users.create":
    payload = request.get("payload") or {}
    result = {
        "password": str(payload.get("password") or "AutoDemoUser123"),
        "label": str(payload.get("label") or ""),
        "device_id": "",
        "expires_at": 1798761600,
        "down_bytes": 0,
        "up_bytes": 0,
        "last_upload_at": 0,
        "last_download_at": 0,
        "vk_hash": str(payload.get("vk_hash") or "demo_hash"),
        "ports": str(payload.get("ports") or "56000,56001,9000"),
        "is_deactivated": False,
        "expired": False,
        "device": None,
    }
elif action == "users.bulk_action":
    result = {"action": (request.get("payload") or {}).get("action"), "count": len((request.get("payload") or {}).get("passwords") or [])}
elif action == "logs":
    result = {
        "source": "wdtt",
        "title": "WDTT",
        "units": [{"unit": "wdtt.service", "active": True}],
        "limit": 1000,
        "lines": [
            "2026-06-15T08:00:00+00:00 wdtt-server[100]: [SERVER] Готов",
            "2026-06-15T08:00:10+00:00 wdtt-server[100]: [СТАТ] Активных: 2 | Всего: 5",
            "2026-06-15T08:00:12+00:00 wdtt-server[100]: [WG] Новое устройство pixel-8-demo",
        ]
    }
elif action in {"cleanup.preview", "cleanup.apply"}:
    payload = request.get("payload") or {}
    result = {
        "applied": action == "cleanup.apply",
        "keep_days": int(payload.get("keep_days") or 14),
        "targets": payload.get("targets") or ["service_logs"],
        "estimated_freed_bytes": 1024,
        "items": [{"target": "service_logs", "freed_bytes": 1024, "files": [{"name": "installer", "path": "/var/log/wdtt-panel-install.log", "bytes": 1024, "exists": True}]}],
    }
elif action == "backups.list":
    result = {"backups": [{"name": "panel-20260615-080000-manual.json", "size": 2048, "created_at": 1781510400, "type": "full"}]}
elif action == "backups.create":
    backup_type = request.get("payload", {}).get("type", "full")
    result = {"name": f"{'panel' if backup_type == 'full' else 'users'}-20260615-090000-manual.json", "size": 3072, "created_at": 1781514000, "type": backup_type}
elif action == "backups.delete":
    result = {"deleted": request.get("payload", {}).get("name", "")}
elif action == "backups.schedule":
    schedule = request.get("payload", {}) or {"frequency": "daily", "time": "03:30", "type": "full", "keep": 14}
    result = {"settings": schedule, "active": schedule.get("frequency") != "disabled"}
elif action == "panel.version":
    result = {"current": "0.5.0", "latest": "0.5.0", "update_available": False}
elif action == "panel.update":
    result = {"scheduled": True, "state": "test"}
elif action == "telegram.status":
    result = {"enabled": True, "admin_id": "123456789", "bot_token_set": True, "bot_token_hint": "123456...test", "service_active": True}
elif action == "telegram.save":
    payload = request.get("payload") or {}
    result = {"enabled": bool(payload.get("enabled")), "admin_id": str(payload.get("admin_id") or ""), "bot_token_set": bool(payload.get("bot_token")), "bot_token_hint": "123456...test", "service_active": True}
elif action == "telegram.test":
    result = {"sent": True, "admin_id": "123456789"}
elif action == "xray.status":
    result = {"settings": {"enabled": False, "mode": "managed", "log_level": "warning", "inbounds": [], "outbounds": [], "routing_rules": [], "geofiles": []}, "active": False, "installed": False, "version": "", "config_exists": False, "logs": [], "geofiles": []}
elif action == "xray.podkop.enable":
    result = {"settings": {"enabled": True, "mode": "managed", "podkop_native_enabled": True}, "active": True, "installed": True, "version": "Xray test", "config_exists": True, "logs": [], "geofiles": []}
elif action == "xray.podkop.refresh":
    result = {"enabled": True, "clients": 1}
elif action == "warp.status":
    result = {"installed": False, "account_exists": False, "profile_exists": False, "configured": False, "active": False}
elif action == "cascade.status":
    result = {"settings": {"enabled": False, "source_cidr": "10.66.66.0/24", "inbound_port": 12345, "eu_vless_uri": "", "geosite_category": "ru-blocked", "geoip_category": "ru-blocked", "domains": [], "ip_cidrs": []}, "xray_active": False, "service_active": False, "rules_active": False, "eu_summary": ""}
elif action == "warp.ping":
    result = {"ok": True, "latency_ms": 42, "warp": "on", "ip": "198.51.100.10", "colo": "FRA"}
elif action in {"xray.save", "xray.install", "xray.geofiles.refresh", "xray.geofiles.refresh_auto", "warp.install", "warp.create", "warp.restart", "cascade.save", "cascade.restart", "certificate.renew"}:
    result = {"scheduled": True, "state": "test"}
elif action == "certificate.export":
    result = {"name": "wdtt-panel-certificate.pem", "content": "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"}
elif action == "backups.export":
    result = {"name": "passwords-demo.json", "content": '{"passwords":{},"devices":{}}'}
elif action == "backups.import":
    result = {"name": "passwords-uploaded.json", "size": 32, "created_at": 1781514000}
else:
    result = {}
print(json.dumps({"ok": True, "result": result}))
