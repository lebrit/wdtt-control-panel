import json
import sys


request = json.load(sys.stdin)
action = request.get("action")
if action == "overview":
    result = {
        "service": {"exists": True, "active": True, "interface": True, "ip_forward": "1", "binary": True},
        "stats": {"active": 2, "total": 5, "up_gb": "0.10", "down_gb": "0.20"},
        "users": 1,
        "devices": 1,
        "certificate": {"exists": True, "expires_at": 1798761600, "days_left": 200.0},
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
        "limit": 10,
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
else:
    result = {}
print(json.dumps({"ok": True, "result": result}))
