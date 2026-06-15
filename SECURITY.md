# Security Notes

## Network exposure

Панель должна оставаться за Nginx. Не открывайте внутренний порт `8787` во внешнем firewall и не меняйте `listen_host` на `0.0.0.0`.

## Privileged helper

`wdtt-panel` не имеет общего `sudo`. Разрешен только root-owned helper без аргументов:

```text
wdtt-panel ALL=(root) NOPASSWD: /usr/local/sbin/wdtt-panel-admin
```

Все параметры передаются JSON-документом через stdin и валидируются до записи файлов или запуска `systemctl`.

## Backups

Резервные копии содержат рабочие WDTT-пароли и ключи устройств. Каталог `/var/lib/wdtt-panel-private/backups` доступен только root.

## Incident response

При компрометации панели:

1. Остановите `wdtt-panel.service` и закройте внешний TCP-порт панели.
2. Смените пароль панели повторной установкой с новым `PANEL_PASSWORD`.
3. Удалите или замените WDTT-пароли через проверенную локальную копию базы.
4. Проверьте audit log панели и `journalctl -u wdtt.service`.
5. При утечке главного пароля измените `-password` в unit-файле WDTT и перезапустите сервис.
