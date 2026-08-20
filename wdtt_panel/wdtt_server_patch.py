from __future__ import annotations

import sys
from pathlib import Path


EXTENSION_MARKER = "wdtt-panel-extension-v8"
SUPPORTED_LAYOUT = "SpaceNeuroX qWDTT v1.4.2"


def _replace_once(source: str, old: str, new: str, title: str) -> str:
    if old not in source:
        raise ValueError(f"WDTT source changed: cannot apply {title}")
    return source.replace(old, new, 1)


def _replace_between(source: str, start: str, end: str, replacement: str, title: str) -> str:
    start_at = source.find(start)
    if start_at < 0:
        raise ValueError(f"WDTT source changed: cannot find start of {title}")
    end_at = source.find(end, start_at + len(start))
    if end_at < 0:
        raise ValueError(f"WDTT source changed: cannot find end of {title}")
    return source[:start_at] + replacement + source[end_at:]


def _read_sources(root: Path, names: tuple[str, ...]) -> dict[str, str]:
    sources: dict[str, str] = {}
    for name in names:
        path = root / "server" / name
        if not path.is_file():
            raise ValueError(f"WDTT source changed: missing server/{name} ({SUPPORTED_LAYOUT})")
        sources[name] = path.read_text(encoding="utf-8")
    return sources


def patch_spaceneurox_tree(root: Path) -> None:
    root = root.resolve()
    server_dir = root / "server"
    extension_path = server_dir / "panel_extension.go"
    if extension_path.is_file() and EXTENSION_MARKER in extension_path.read_text(encoding="utf-8"):
        return

    names = (
        "main.go", "database_bot.go", "statistics.go", "connections.go",
        "raw.go", "profile_api.go", "admin_api.go",
    )
    sources = _read_sources(root, names)

    sources["main.go"] = _replace_once(
        sources["main.go"],
        "\tlog.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)\n",
        "\tlog.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)\n"
        "\tlog.Printf(\"[WDTT Panel] extension %s enabled\", wdttPanelExtensionMarker)\n",
        "extension marker log",
    )

    database = sources["database_bot.go"]
    database = _replace_once(
        database,
        '\tIsDeactivated bool     `json:"is_deactivated,omitempty"`\n}',
        '\tIsDeactivated  bool  `json:"is_deactivated,omitempty"`\n'
        '\tLastUploadAt   int64 `json:"last_upload_at,omitempty"`\n'
        '\tLastDownloadAt int64 `json:"last_download_at,omitempty"`\n'
        '\tTrafficManaged       bool                     `json:"traffic_managed,omitempty"`\n'
        '\tTrafficUnlimited     bool                     `json:"traffic_unlimited,omitempty"`\n'
        '\tTrafficBaselineBytes int64                    `json:"traffic_baseline_bytes,omitempty"`\n'
        '\tTrafficPrimaryBytes  int64                    `json:"traffic_primary_bytes,omitempty"`\n'
        '\tTrafficExtraBytes    int64                    `json:"traffic_extra_bytes,omitempty"`\n'
        '\tTrafficOperations    []map[string]interface{} `json:"traffic_operations,omitempty"`\n}',
        "activity and quota fields",
    )
    database = _replace_once(
        database,
        '\tMainPassword string                    `json:"-"`\n'
        '\tAdminID      string                    `json:"-"`\n'
        '\tBotToken     string                    `json:"-"`\n',
        '\tMainPassword       string                    `json:"main_password"`\n'
        '\tAdminID            string                    `json:"admin_id,omitempty"`\n'
        '\tBotToken           string                    `json:"bot_token,omitempty"`\n'
        '\tMainDownBytes      int64                     `json:"main_down_bytes,omitempty"`\n'
        '\tMainUpBytes        int64                     `json:"main_up_bytes,omitempty"`\n'
        '\tMainLastUploadAt   int64                     `json:"main_last_upload_at,omitempty"`\n'
        '\tMainLastDownloadAt int64                     `json:"main_last_download_at,omitempty"`\n',
        "panel database fields",
    )
    database = _replace_once(
        database,
        "\t\tif !isPasswordExpired(entry) && !entry.IsDeactivated {\n",
        "\t\tif !isPasswordExpired(entry) && !entry.IsDeactivated && !trafficQuotaExhausted(entry) {\n",
        "quota-aware WRAP keys",
    )
    database = _replace_once(
        database,
        "\tfor _, dev := range db.Devices {\n\t\tupsertPeerInWG(wgDev, dev)\n\t}\n\n\t// Обновляем криптографические WRAP-ключи в памяти\n",
        "\tfor deviceID, dev := range db.Devices {\n"
        "\t\tif deviceAccessAllowedLocked(deviceID, dev) { upsertPeerInWG(wgDev, dev) }\n"
        "\t}\n\n\t// Обновляем криптографические WRAP-ключи в памяти\n",
        "reload access restrictions",
    )
    database = _replace_once(
        database,
        '\t\tcmds := `{"commands":[{"command":"new","description":"Создать временный пароль"},{"command":"list","description":"Управление доступами"}]}`\n',
        '\t\tcmds := `{"commands":[{"command":"start","description":"Главное меню"},{"command":"new","description":"Создать пользователя"},{"command":"list","description":"Управление доступами"},{"command":"settings","description":"Настройки сервера"}]}`\n',
        "Telegram commands",
    )
    database = _replace_once(
        database,
        "\tvar waitingForHash bool\n\tvar targetPassword string\n\n\tvar tempDays int\n",
        "\tvar waitingForHash bool\n\tvar waitingForLabel bool\n\tvar targetPassword string\n\n\tvar tempDays int\n\tvar tempLabel string\n",
        "Telegram label state",
    )
    database = _replace_once(
        database,
        '\t\t\t\t\tkb = append(kb, map[string]interface{}{\n'
        '\t\t\t\t\t\t"text":          "📂 Получить .conf файл",\n'
        '\t\t\t\t\t\t"callback_data": "getfile_" + pass,\n'
        '\t\t\t\t\t})\n',
        '\t\t\t\t\tkb = append(kb, map[string]interface{}{\n'
        '\t\t\t\t\t\t"text":          "📂 Получить .conf файл",\n'
        '\t\t\t\t\t\t"callback_data": "getfile_" + pass,\n'
        '\t\t\t\t\t})\n'
        '\t\t\t\t\tkb = append(kb, map[string]interface{}{\n'
        '\t\t\t\t\t\t"text":          "🏷 Изменить метку",\n'
        '\t\t\t\t\t\t"callback_data": "label_" + pass,\n'
        '\t\t\t\t\t})\n',
        "Telegram label button",
    )
    database = _replace_once(
        database,
        '\t\t\t\t} else if strings.HasPrefix(data, "deact_") {\n',
        '\t\t\t\t} else if strings.HasPrefix(data, "label_") {\n'
        '\t\t\t\t\tpass := strings.TrimPrefix(data, "label_")\n'
        '\t\t\t\t\tdbMutex.Lock()\n'
        '\t\t\t\t\t_, exists := db.Passwords[pass]\n'
        '\t\t\t\t\tdbMutex.Unlock()\n'
        '\t\t\t\t\tif !exists { sendTelegram(token, adminID, "❌ Пароль не найден", nil); continue }\n'
        '\t\t\t\t\ttargetPassword = pass\n'
        '\t\t\t\t\twaitingForLabel = true\n'
        '\t\t\t\t\tsendTelegram(token, adminID, "🏷 Отправьте метку до 64 символов. Отправьте - чтобы очистить.", nil)\n\n'
        '\t\t\t\t} else if strings.HasPrefix(data, "deact_") {\n',
        "Telegram label callback",
    )
    database = _replace_once(
        database,
        "\t\t\tcmd := strings.TrimSpace(msg.Text)\n\n\t\t\t// Обработка ввода количества дней\n",
        "\t\t\tcmd := strings.TrimSpace(msg.Text)\n\n"
        "\t\t\tif waitingForLabel {\n"
        "\t\t\t\twaitingForLabel = false\n"
        "\t\t\t\tlabel, labelErr := normalizeUserLabel(cmd)\n"
        "\t\t\t\tif labelErr != nil { sendTelegram(token, adminID, \"❌ Метка должна быть не длиннее 64 символов и без служебных символов.\", nil); continue }\n"
        "\t\t\t\tif targetPassword == \"__new_label__\" {\n"
        "\t\t\t\t\ttempLabel = label\n"
        "\t\t\t\t\ttargetPassword = \"\"\n"
        "\t\t\t\t\twaitingForDays = true\n"
        "\t\t\t\t\tsendTelegram(token, adminID, \"📅 Введите срок действия в днях (1–365) и, при необходимости, лимит устройств через пробел.\", nil)\n"
        "\t\t\t\t\tcontinue\n"
        "\t\t\t\t}\n"
        "\t\t\t\tdbMutex.Lock()\n"
        "\t\t\t\tentry, exists := db.Passwords[targetPassword]\n"
        "\t\t\t\tif exists && entry != nil { entry.Label = label; saveDB() }\n"
        "\t\t\t\tdbMutex.Unlock()\n"
        "\t\t\t\ttargetPassword = \"\"\n"
        "\t\t\t\tif !exists || entry == nil { sendTelegram(token, adminID, \"❌ Пароль не найден\", nil)\n"
        "\t\t\t\t} else if label == \"\" { sendTelegram(token, adminID, \"✅ Метка очищена\", nil)\n"
        "\t\t\t\t} else { sendTelegram(token, adminID, fmt.Sprintf(\"✅ Метка сохранена: %s\", telegramLabel(label)), nil) }\n"
        "\t\t\t\tcontinue\n"
        "\t\t\t}\n\n"
        "\t\t\t// Обработка ввода количества дней\n",
        "Telegram label input",
    )
    database = _replace_once(
        database,
        "\t\t\t\tnewLabel := nextPasswordLabel()\n\t\t\t\tdb.Passwords[newPass] = &PasswordEntry{\n",
        "\t\t\t\tnewLabel := tempLabel\n"
        "\t\t\t\tif newLabel == \"\" { newLabel = nextPasswordLabel() }\n"
        "\t\t\t\ttempLabel = \"\"\n"
        "\t\t\t\tdb.Passwords[newPass] = &PasswordEntry{\n"
        "\t\t\t\t\tTrafficManaged: true, TrafficPrimaryBytes: 35 * 1024 * 1024 * 1024,\n",
        "Telegram creation quota and label",
    )
    database = _replace_between(
        database,
        '\t\t\tif cmd == "/start" || cmd == "/help" {\n',
        '\n\t\t\t} else if cmd == "/list" {\n',
        '\t\t\tif cmd == "/start" || cmd == "/help" {\n'
        '\t\t\t\tsendTelegram(token, adminID, "🤖 *qWDTT VPN Manager*\\n\\n/new — Создать пользователя\\n/list — Список пользователей\\n/settings — Настройки сервера", nil)\n\n'
        '\t\t\t} else if cmd == "/settings" {\n'
        '\t\t\t\tsendTelegram(token, adminID, fmt.Sprintf("⚙️ *Настройки сервера*\\n\\n• DNS: `%s`\\n• MTU: `%d`\\n• Keepalive WireGuard: `%d сек.`\\n\\nНастройки маршрутизации и доступа меняются в WDTT Control Panel.", dns, wgMTU, keepalive), nil)\n\n'
        '\t\t\t} else if strings.HasPrefix(cmd, "/new ") || cmd == "/new" {\n'
        '\t\t\t\tdbMutex.Lock()\n'
        '\t\t\t\tif cleanupExpiredPasswordsLocked(wgDev) > 0 { saveDB() }\n'
        '\t\t\t\tif len(db.Passwords) >= maxGeneratedPasswords {\n'
        '\t\t\t\t\tdbMutex.Unlock()\n'
        '\t\t\t\t\tsendTelegram(token, adminID, fmt.Sprintf("❌ Лимит паролей: максимум %d. Удалите ненужного пользователя через /list.", maxGeneratedPasswords), nil)\n'
        '\t\t\t\t\tcontinue\n'
        '\t\t\t\t}\n'
        '\t\t\t\tdbMutex.Unlock()\n'
        '\t\t\t\ttargetPassword = "__new_label__"\n'
        '\t\t\t\twaitingForLabel = true\n'
        '\t\t\t\tsendTelegram(token, adminID, "🏷 Отправьте метку нового пользователя до 64 символов. Отправьте - без метки.", nil)\n',
        "Telegram creation flow",
    )
    database = _replace_once(
        database,
        '\t\t\ttxt += fmt.Sprintf("%s *%s* (%s)\\n", status, label, expiry)\n',
        '\t\t\ttxt += fmt.Sprintf("%s *%s* · `%s` (%s)\\n", status, telegramLabel(label), p, expiry)\n',
        "Telegram list label",
    )
    database = _replace_between(
        database,
        "func cleanupExpiredPasswordsLocked(wgDev *device.Device) int {\n",
        "\nfunc cleanupExpiredPasswords(wgDev *device.Device) int {\n",
        "func cleanupExpiredPasswordsLocked(wgDev *device.Device) int {\n"
        "\treturn applyPasswordRestrictionsLocked(wgDev)\n"
        "}\n",
        "retained restricted users",
    )
    database = _replace_once(
        database,
        "\tfor _, dev := range db.Devices {\n\t\tupsertPeerInWG(wgDev, dev)\n\t\tcount++\n\t}\n",
        "\tfor deviceID, dev := range db.Devices {\n"
        "\t\tif deviceAccessAllowedLocked(deviceID, dev) { upsertPeerInWG(wgDev, dev); count++ }\n"
        "\t}\n",
        "startup access restrictions",
    )
    sources["database_bot.go"] = database

    statistics = sources["statistics.go"]
    statistics = _replace_once(
        statistics,
        "\t\tif dev, ok := db.Devices[deviceID]; ok {\n"
        "\t\t\tdev.UpBytes += c.up\n\t\t\tdev.DownBytes += c.down\n"
        "\t\t\tif entry := generatedOwnerEntryLocked(dev, deviceID); entry != nil {\n"
        "\t\t\t\tentry.UpBytes += c.up\n\t\t\t\tentry.DownBytes += c.down\n\t\t\t}\n\t\t}\n",
        "\t\tif dev, ok := db.Devices[deviceID]; ok {\n"
        "\t\t\tdev.UpBytes += c.up\n\t\t\tdev.DownBytes += c.down\n"
        "\t\t\tif entry := generatedOwnerEntryLocked(dev, deviceID); entry != nil {\n"
        "\t\t\t\trecordPasswordTrafficLocked(entry, c.up, c.down)\n"
        "\t\t\t} else if deviceUsesMainPasswordLocked(dev) { recordMainTrafficLocked(c.up, c.down) }\n"
        "\t\t}\n",
        "raw activity and quotas",
    )
    statistics = _replace_once(
        statistics,
        "\t\tif entry != nil {\n\t\t\tentry.UpBytes += deltaRx\n\t\t\tentry.DownBytes += deltaTx\n\t\t}\n\n"
        "\t\tif entry == nil {\n\t\t\tatomic.AddInt64(&mainPassUp, deltaRx)\n\t\t\tatomic.AddInt64(&mainPassDown, deltaTx)\n\t\t}\n",
        "\t\tif entry != nil {\n\t\t\trecordPasswordTrafficLocked(entry, deltaRx, deltaTx)\n"
        "\t\t} else {\n\t\t\tatomic.AddInt64(&mainPassUp, deltaRx)\n\t\t\tatomic.AddInt64(&mainPassDown, deltaTx)\n"
        "\t\t\trecordMainTrafficLocked(deltaRx, deltaTx)\n\t\t}\n",
        "WireGuard activity and quotas",
    )
    sources["statistics.go"] = statistics

    connections = sources["connections.go"]
    connections = _replace_once(
        connections,
        "\t\t} else if valid && isGenPass && !entry.canConnectAndBind(deviceID) {\n",
        "\t\t} else if valid && isGenPass && trafficQuotaExhausted(entry) {\n"
        "\t\t\tclientConn.Write([]byte(\"DENIED:traffic_limit\"))\n"
        "\t\t\tlog.Printf(\"[WG] Отказ: лимит трафика исчерпан для %s\", maskPassword(password))\n"
        "\t\t\tdbMutex.Unlock()\n\t\t\treturn\n"
        "\t\t} else if valid && isGenPass && !entry.canConnectAndBind(deviceID) {\n",
        "WireGuard quota authentication",
    )
    connections = _replace_once(
        connections,
        "\t\townerAllowed := valid && authorizeDeviceOwnerLocked(deviceID, password, isMainPass, entry)\n"
        "\t\tif !valid || !bound || !ownerAllowed {\n",
        "\t\tif valid && isGenPass && trafficQuotaExhausted(entry) {\n"
        "\t\t\tdbMutex.Unlock()\n\t\t\tclientConn.Write([]byte(\"DENIED:traffic_limit\"))\n\t\t\treturn\n\t\t}\n"
        "\t\townerAllowed := valid && authorizeDeviceOwnerLocked(deviceID, password, isMainPass, entry)\n"
        "\t\tif !valid || !bound || !ownerAllowed {\n",
        "WireGuard worker quota authentication",
    )
    sources["connections.go"] = connections

    raw = sources["raw.go"]
    raw = _replace_once(
        raw,
        "\t\tif valid && !authorizeDeviceOwnerLocked(deviceID, password, isMainPass, entry) {\n",
        "\t\tif valid && isGenPass && trafficQuotaExhausted(entry) {\n"
        "\t\t\tdbMutex.Unlock()\n\t\t\tclientConn.Write([]byte(\"DENIED:traffic_limit\"))\n\t\t\treturn\n\t\t}\n"
        "\t\tif valid && !authorizeDeviceOwnerLocked(deviceID, password, isMainPass, entry) {\n",
        "raw quota authentication",
    )
    raw = _replace_once(
        raw,
        "\t\tif !valid || !bound || !authorizeDeviceOwnerLocked(deviceID, password, isMainPass, entry) {\n",
        "\t\tif valid && isGenPass && trafficQuotaExhausted(entry) {\n"
        "\t\t\tdbMutex.Unlock()\n\t\t\tclientConn.Write([]byte(\"DENIED:traffic_limit\"))\n\t\t\treturn\n\t\t}\n"
        "\t\tif !valid || !bound || !authorizeDeviceOwnerLocked(deviceID, password, isMainPass, entry) {\n",
        "raw worker quota authentication",
    )
    sources["raw.go"] = raw

    sources["profile_api.go"] = _replace_once(
        sources["profile_api.go"],
        '\t\t"expires_at":       entry.ExpiresAt,\n',
        '\t\t"expires_at":        entry.ExpiresAt,\n'
        '\t\t"traffic_managed":   entry.TrafficManaged,\n'
        '\t\t"traffic_unlimited": entry.TrafficUnlimited || !entry.TrafficManaged,\n'
        '\t\t"quota_exhausted":   trafficQuotaExhausted(entry),\n',
        "profile quota status",
    )

    admin = sources["admin_api.go"]
    admin = _replace_once(
        admin,
        '\tActiveDevices int      `json:"active_devices"`\n}',
        '\tActiveDevices int      `json:"active_devices"`\n'
        '\tLastUploadAt   int64    `json:"last_upload_at,omitempty"`\n'
        '\tLastDownloadAt int64    `json:"last_download_at,omitempty"`\n'
        '\tTrafficManaged bool     `json:"traffic_managed,omitempty"`\n'
        '\tTrafficUnlimited bool   `json:"traffic_unlimited,omitempty"`\n'
        '\tQuotaExhausted bool     `json:"quota_exhausted,omitempty"`\n}',
        "admin quota view fields",
    )
    admin = _replace_once(
        admin,
        "\t\tActiveDevices: active,\n\t}\n",
        "\t\tActiveDevices: active,\n"
        "\t\tLastUploadAt: entry.LastUploadAt,\n\t\tLastDownloadAt: entry.LastDownloadAt,\n"
        "\t\tTrafficManaged: entry.TrafficManaged,\n"
        "\t\tTrafficUnlimited: entry.TrafficUnlimited || !entry.TrafficManaged,\n"
        "\t\tQuotaExhausted: trafficQuotaExhausted(entry),\n\t}\n",
        "admin quota view",
    )
    admin = _replace_once(
        admin,
        "\tentry := &PasswordEntry{\n\t\tLabel:      label,\n",
        "\tentry := &PasswordEntry{\n"
        "\t\tTrafficManaged: true,\n\t\tTrafficPrimaryBytes: 35 * 1024 * 1024 * 1024,\n"
        "\t\tLabel:      label,\n",
        "admin default quota",
    )
    admin = _replace_once(
        admin,
        "\tif err := serverWrapKeys.AddPassword(pass); err != nil {\n",
        "\tif trafficQuotaExhausted(entry) {\n"
        "\t\tdbMutex.Unlock()\n\t\twriteAdminError(w, http.StatusConflict, \"traffic quota exhausted\")\n\t\treturn\n\t}\n"
        "\tif err := serverWrapKeys.AddPassword(pass); err != nil {\n",
        "admin activation quota guard",
    )
    sources["admin_api.go"] = admin

    extension_template = Path(__file__).with_name("wdtt_server_extension.go")
    extension = extension_template.read_text(encoding="utf-8")
    if EXTENSION_MARKER not in extension:
        raise ValueError("WDTT panel extension template has an unexpected marker")
    extension_test = Path(__file__).with_name("wdtt_server_extension_test.go").read_text(encoding="utf-8")

    for name, source in sources.items():
        (server_dir / name).write_text(source, encoding="utf-8")
    extension_path.write_text(extension, encoding="utf-8")
    (server_dir / "panel_extension_test.go").write_text(extension_test, encoding="utf-8")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} WDTT_SOURCE_ROOT", file=sys.stderr)
        return 2
    try:
        patch_spaceneurox_tree(Path(argv[1]))
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
