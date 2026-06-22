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
                "device_id": "pixel-8-demo",
                "expires_at": 1798761600,
                "down_bytes": 419430400,
                "up_bytes": 73400320,
                "vk_hash": "vk_hash_demo",
                "ports": "56000,56001,9000",
                "is_deactivated": False,
                "expired": False,
                "device": {"device_id": "pixel-8-demo", "ip": "10.66.66.2"},
            },
            {
                "password": "WaitingUser123",
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
        "admins": [{"password": "Главный пароль", "role": "admin", "device_id": "admin-device", "device": {"device_id": "admin-device", "ip": "10.66.66.1"}, "connected": True, "expires_at": 0, "down_bytes": 0, "up_bytes": 0, "vk_hash": "Администратор WDTT", "is_deactivated": False, "expired": False}],
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
elif action == "logs":
    result = {
        "lines": [
            "2026-06-15T08:00:00+00:00 wdtt-server[100]: [SERVER] Готов",
            "2026-06-15T08:00:10+00:00 wdtt-server[100]: [СТАТ] Активных: 2 | Всего: 5",
            "2026-06-15T08:00:12+00:00 wdtt-server[100]: [WG] Новое устройство pixel-8-demo",
        ]
    }
elif action == "backups.list":
    result = {"backups": [{"name": "passwords-20260615-080000-auto.json", "size": 2048, "created_at": 1781510400}]}
elif action == "backups.create":
    result = {"name": "passwords-20260615-090000-manual.json", "size": 3072, "created_at": 1781514000}
elif action == "panel.version":
    result = {"current": "0.5.0", "latest": "0.5.0", "update_available": False}
elif action == "panel.update":
    result = {"scheduled": True, "state": "test"}
elif action == "xray.status":
    result = {"settings": {"enabled": False, "mode": "managed", "log_level": "warning", "inbounds": [], "outbounds": [], "routing_rules": [], "geofiles": []}, "active": False, "installed": False, "version": "", "config_exists": False, "logs": [], "geofiles": []}
elif action in {"xray.save", "xray.install", "xray.geofiles.refresh", "xray.geofiles.refresh_auto", "certificate.renew"}:
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
