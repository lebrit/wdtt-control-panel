from __future__ import annotations

import sys
from pathlib import Path


EXTENSION_MARKER = "wdtt-panel-extension-v6"


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


def patch_spaceneurox_source(source: str) -> str:
    if EXTENSION_MARKER in source:
        return source

    source = _replace_once(
        source,
        "func main() {\n",
        f'const wdttPanelExtensionMarker = "{EXTENSION_MARKER}"\n\n'
        'func main() {\n\tlog.Printf("[WDTT Panel] extension %s enabled", wdttPanelExtensionMarker)\n',
        "extension marker",
    )
    source = _replace_once(
        source,
        '\tIsDeactivated bool     `json:"is_deactivated,omitempty"`\n}',
        '\tIsDeactivated  bool  `json:"is_deactivated,omitempty"`\n'
        '\tLastUploadAt   int64 `json:"last_upload_at,omitempty"`\n'
        '\tLastDownloadAt int64 `json:"last_download_at,omitempty"`\n}',
        "activity fields",
    )
    source = _replace_once(
        source,
        '\tMainPassword string                    `json:"main_password"`\n',
        '\tMainPassword       string                    `json:"main_password"`\n'
        '\tMainDownBytes      int64                     `json:"main_down_bytes,omitempty"`\n'
        '\tMainUpBytes        int64                     `json:"main_up_bytes,omitempty"`\n'
        '\tMainLastUploadAt   int64                     `json:"main_last_upload_at,omitempty"`\n'
        '\tMainLastDownloadAt int64                     `json:"main_last_download_at,omitempty"`\n',
        "main traffic fields",
    )
    source = _replace_once(
        source,
        '\t\tcmds := `{"commands":[{"command":"new","description":"Создать временный пароль"},{"command":"list","description":"Управление доступами"}]}`\n',
        '\t\tcmds := `{"commands":[{"command":"start","description":"Главное меню"},{"command":"new","description":"Создать пользователя"},{"command":"list","description":"Управление доступами"},{"command":"settings","description":"Настройки сервера"}]}`\n',
        "Telegram commands",
    )
    source = _replace_once(
        source,
        '\tvar waitingForHash bool\n\tvar targetPassword string\n\n\tvar tempDays int\n',
        '\tvar waitingForHash bool\n\tvar waitingForLabel bool\n\tvar targetPassword string\n\n\tvar tempDays int\n\tvar tempLabel string\n',
        "Telegram label state",
    )
    source = _replace_once(
        source,
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
    source = _replace_once(
        source,
        '\t\t\t\t} else if strings.HasPrefix(data, "deact_") {\n',
        '\t\t\t\t} else if strings.HasPrefix(data, "label_") {\n'
        '\t\t\t\t\tpass := strings.TrimPrefix(data, "label_")\n'
        '\t\t\t\t\tdbMutex.Lock()\n'
        '\t\t\t\t\t_, exists := db.Passwords[pass]\n'
        '\t\t\t\t\tdbMutex.Unlock()\n'
        '\t\t\t\t\tif !exists {\n'
        '\t\t\t\t\t\tsendTelegram(token, adminID, "❌ Пароль не найден", nil)\n'
        '\t\t\t\t\t\tcontinue\n'
        '\t\t\t\t\t}\n'
        '\t\t\t\t\ttargetPassword = pass\n'
        '\t\t\t\t\twaitingForLabel = true\n'
        '\t\t\t\t\tsendTelegram(token, adminID, "🏷 Отправьте метку до 64 символов. Отправьте - чтобы очистить.", nil)\n\n'
        '\t\t\t\t} else if strings.HasPrefix(data, "deact_") {\n',
        "Telegram label callback",
    )
    source = _replace_once(
        source,
        '\t\t\tcmd := strings.TrimSpace(msg.Text)\n\n\t\t\t// Обработка ввода количества дней\n',
        '\t\t\tcmd := strings.TrimSpace(msg.Text)\n\n'
        '\t\t\tif waitingForLabel {\n'
        '\t\t\t\twaitingForLabel = false\n'
        '\t\t\t\tlabel, labelErr := normalizeUserLabel(cmd)\n'
        '\t\t\t\tif labelErr != nil {\n'
        '\t\t\t\t\tsendTelegram(token, adminID, "❌ Метка должна быть не длиннее 64 символов и без служебных символов.", nil)\n'
        '\t\t\t\t\tcontinue\n'
        '\t\t\t\t}\n'
        '\t\t\t\tif targetPassword == "__new_label__" {\n'
        '\t\t\t\t\ttempLabel = label\n'
        '\t\t\t\t\ttargetPassword = ""\n'
        '\t\t\t\t\twaitingForDays = true\n'
        '\t\t\t\t\tsendTelegram(token, adminID, "📅 Введите срок действия в днях (1–365) и, при необходимости, лимит устройств через пробел.", nil)\n'
        '\t\t\t\t\tcontinue\n'
        '\t\t\t\t}\n'
        '\t\t\t\tdbMutex.Lock()\n'
        '\t\t\t\tentry, exists := db.Passwords[targetPassword]\n'
        '\t\t\t\tif exists && entry != nil {\n'
        '\t\t\t\t\tentry.Label = label\n'
        '\t\t\t\t\tsaveDB()\n'
        '\t\t\t\t}\n'
        '\t\t\t\tdbMutex.Unlock()\n'
        '\t\t\t\ttargetPassword = ""\n'
        '\t\t\t\tif !exists || entry == nil {\n'
        '\t\t\t\t\tsendTelegram(token, adminID, "❌ Пароль не найден", nil)\n'
        '\t\t\t\t} else if label == "" {\n'
        '\t\t\t\t\tsendTelegram(token, adminID, "✅ Метка очищена", nil)\n'
        '\t\t\t\t} else {\n'
        '\t\t\t\t\tsendTelegram(token, adminID, fmt.Sprintf("✅ Метка сохранена: %s", telegramLabel(label)), nil)\n'
        '\t\t\t\t}\n'
        '\t\t\t\tcontinue\n'
        '\t\t\t}\n\n'
        '\t\t\t// Обработка ввода количества дней\n',
        "Telegram label input",
    )
    source = _replace_once(
        source,
        '\t\t\t\tnewLabel := nextPasswordLabel()\n'
        '\t\t\t\tdb.Passwords[newPass] = &PasswordEntry{\n',
        '\t\t\t\tnewLabel := tempLabel\n'
        '\t\t\t\ttempLabel = ""\n'
        '\t\t\t\tdb.Passwords[newPass] = &PasswordEntry{\n',
        "Telegram creation label",
    )
    source = _replace_between(
        source,
        '\t\t\tif cmd == "/start" || cmd == "/help" {\n',
        '\n\t\t\t} else if cmd == "/list" {\n',
        '\t\t\tif cmd == "/start" || cmd == "/help" {\n'
        '\t\t\t\tsendTelegram(token, adminID, "🤖 *qWDTT VPN Manager*\\n\\n/new — Создать пользователя\\n/list — Список пользователей\\n/settings — Настройки сервера", nil)\n\n'
        '\t\t\t} else if cmd == "/settings" {\n'
        '\t\t\t\tsendTelegram(token, adminID, fmt.Sprintf("⚙️ *Настройки сервера*\\n\\n• DNS: `%s`\\n• MTU: `%d`\\n• Keepalive WireGuard: `%d сек.`\\n\\nНастройки маршрутизации и доступа меняются в WDTT Control Panel.", dns, wgMTU, keepalive), nil)\n\n'
        '\t\t\t} else if strings.HasPrefix(cmd, "/new ") || cmd == "/new" {\n'
        '\t\t\t\tdbMutex.Lock()\n'
        '\t\t\t\tif cleanupExpiredPasswordsLocked(wgDev) > 0 {\n'
        '\t\t\t\t\tsaveDB()\n'
        '\t\t\t\t}\n'
        '\t\t\t\tif len(db.Passwords) >= maxGeneratedPasswords {\n'
        '\t\t\t\t\tdbMutex.Unlock()\n'
        '\t\t\t\t\tsendTelegram(token, adminID, fmt.Sprintf("❌ Лимит паролей: максимум %d активных. Удалите ненужный пароль через /list.", maxGeneratedPasswords), nil)\n'
        '\t\t\t\t\tcontinue\n'
        '\t\t\t\t}\n'
        '\t\t\t\tdbMutex.Unlock()\n'
        '\t\t\t\ttargetPassword = "__new_label__"\n'
        '\t\t\t\twaitingForLabel = true\n'
        '\t\t\t\tsendTelegram(token, adminID, "🏷 Отправьте метку нового пользователя до 64 символов. Отправьте - без метки.", nil)\n',
        "Telegram commands",
    )
    source = _replace_once(
        source,
        '\t\t\ttxt += fmt.Sprintf("%s *%s* (%s)\\n", status, label, expiry)\n',
        '\t\t\ttxt += fmt.Sprintf("%s *%s* · `%s` (%s)\\n", status, telegramLabel(label), p, expiry)\n',
        "Telegram list label",
    )
    source = _replace_once(
        source,
        'func getNextIP() string {\n',
        'func normalizeUserLabel(value string) (string, error) {\n'
        '\tlabel := strings.TrimSpace(value)\n'
        '\tif label == "-" {\n'
        '\t\treturn "", nil\n'
        '\t}\n'
        '\tif len([]rune(label)) > 64 {\n'
        '\t\treturn "", errors.New("label is too long")\n'
        '\t}\n'
        '\tfor _, char := range label {\n'
        '\t\tif char < 32 || char == 127 {\n'
        '\t\t\treturn "", errors.New("label contains a control character")\n'
        '\t\t}\n'
        '\t}\n'
        '\treturn label, nil\n'
        '}\n\n'
        'func telegramLabel(value string) string {\n'
        '\treplacer := strings.NewReplacer("\\\\", "\\\\\\\\", "_", "\\\\_", "*", "\\\\*", "`", "\\\\`", "[", "\\\\[")\n'
        '\treturn replacer.Replace(value)\n'
        '}\n\n'
        'func getNextIP() string {\n',
        "label helpers",
    )
    source = _replace_once(
        source,
        '\t\tif deltaRx == 0 && deltaTx == 0 {\n\t\t\treturn\n\t\t}\n\n\t\tvar targetDevID string\n',
        '\t\tif deltaRx == 0 && deltaTx == 0 {\n\t\t\treturn\n\t\t}\n\n'
        '\t\tnow := time.Now().Unix()\n'
        '\t\tvar targetDevID string\n',
        "activity timestamp",
    )
    source = _replace_once(
        source,
        '\t\t\t\t\tentry.UpBytes += deltaRx\n\t\t\t\t\tentry.DownBytes += deltaTx\n\t\t\t\t\tfoundEntry = true\n',
        '\t\t\t\t\tentry.UpBytes += deltaRx\n\t\t\t\t\tentry.DownBytes += deltaTx\n'
        '\t\t\t\t\tif deltaRx > 0 { entry.LastUploadAt = now }\n'
        '\t\t\t\t\tif deltaTx > 0 { entry.LastDownloadAt = now }\n'
        '\t\t\t\t\tfoundEntry = true\n',
        "array device activity",
    )
    source = _replace_once(
        source,
        '\t\t\t\tentry.UpBytes += deltaRx\n\t\t\t\tentry.DownBytes += deltaTx\n\t\t\t\tfoundEntry = true\n',
        '\t\t\t\tentry.UpBytes += deltaRx\n\t\t\t\tentry.DownBytes += deltaTx\n'
        '\t\t\t\tif deltaRx > 0 { entry.LastUploadAt = now }\n'
        '\t\t\t\tif deltaTx > 0 { entry.LastDownloadAt = now }\n'
        '\t\t\t\tfoundEntry = true\n',
        "legacy device activity",
    )
    source = _replace_once(
        source,
        '\t\tif !foundEntry {\n\t\t\tatomic.AddInt64(&mainPassUp, deltaRx)\n\t\t\tatomic.AddInt64(&mainPassDown, deltaTx)\n\t\t}\n',
        '\t\tif !foundEntry {\n'
        '\t\t\tatomic.AddInt64(&mainPassUp, deltaRx)\n'
        '\t\t\tatomic.AddInt64(&mainPassDown, deltaTx)\n'
        '\t\t\tdb.MainUpBytes += deltaRx\n'
        '\t\t\tdb.MainDownBytes += deltaTx\n'
        '\t\t\tif deltaRx > 0 { db.MainLastUploadAt = now }\n'
        '\t\t\tif deltaTx > 0 { db.MainLastDownloadAt = now }\n'
        '\t\t}\n',
        "main traffic persistence",
    )
    return source


def patch_file(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    patched = patch_spaceneurox_source(source)
    path.write_text(patched, encoding="utf-8")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} SERVER_GO", file=sys.stderr)
        return 2
    try:
        patch_file(Path(argv[1]))
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
