# WDTT Control Panel

Отдельная web-панель для [amurcanov/proxy-turn-vk-android](https://github.com/amurcanov/proxy-turn-vk-android). Исходники Android-приложения и `server.go` не изменяются.

## Возможности

- создание, изменение, деактивация и удаление до 10 WDTT-пользователей;
- массовое создание пользователей с автоматическими паролями и назначением VK-хешей всем или по кругу;
- срок действия, бессрочный доступ, до четырех VK-хешей и отдельные порты;
- просмотр привязанного устройства, WireGuard IP, отвязка и сброс счетчиков;
- генерация совместимых `wdtt://` ссылок;
- dashboard: соединения, NAT, uptime, трафик, пользователи и устройства;
- журнал `wdtt.service` с фильтрацией;
- start/stop/restart WDTT, диагностика `wdtt0`, IP forwarding и бинарника;
- автоматические резервные копии `passwords.json` перед каждым изменением;
- ручные полные backup и восстановление пользователей, устройств, статистики и настроек;
- восстановление резервной копии и журнал действий администратора;
- случайный URL панели вместо стандартного пути;
- автоматический HTTPS для домена и публичного IPv4;
- автоматическое продление Let's Encrypt и self-signed сертификатов;
- интерактивное меню установки, обновления, статуса, сертификатов и удаления;
- быстрые команды обновления и удаления из GitHub;
- отображение текущей и новой версии с обновлением прямо из web-панели;
- установка на пустой сервер или поверх уже развернутого WDTT.

## Совместимость

Панель работает с форматом базы актуального WDTT:

```text
/etc/wdtt/passwords.json
/etc/wdtt/server.log
systemd: wdtt.service
binary: /usr/local/bin/wdtt-server
```

WDTT не предоставляет административный API и не перечитывает `passwords.json` на лету. Поэтому панель применяет изменения безопасной транзакцией: останавливает `wdtt.service`, создает backup, атомарно заменяет JSON и запускает сервис обратно. Обычно это занимает несколько секунд и разрывает текущие туннели.

## Быстрая установка

```bash
curl -fsSL https://raw.githubusercontent.com/lebrit/wdtt-control-panel/main/bootstrap.sh | sudo bash
```

Откроется интерактивное меню. При установке можно выбрать домен, заданный IPv4 или автоматическое определение IPv4, а также указать логин, пароль, HTTPS-порт, секретный путь и режим установки WDTT.

Неинтерактивная установка с доменом и заданным паролем панели:

```bash
curl -fsSL https://raw.githubusercontent.com/lebrit/wdtt-control-panel/main/bootstrap.sh | \
  sudo bash -s -- install \
  --domain panel.example.com \
  --email admin@example.com \
  --password 'Long-Random-Panel-Password' \
  --non-interactive
```

Без домена публичный IPv4 определяется автоматически:

```bash
curl -fsSL https://raw.githubusercontent.com/lebrit/wdtt-control-panel/main/bootstrap.sh | \
  sudo bash -s -- install --password 'Long-Random-Panel-Password' --non-interactive
```

## Локальная установка

Скопируйте каталог проекта на сервер и выполните:

```bash
sudo bash install.sh
```

По умолчанию установщик:

1. Находит публичный IPv4.
2. Генерирует пароль администратора и случайный путь длиной не менее 16 символов.
3. Если WDTT уже установлен, не изменяет его бинарник и unit-файл.
4. Если сервер пустой, скачивает официальный репозиторий, собирает неизмененный `server.go` и запускает официальный `deploy.sh`.
5. Поднимает панель на `https://HOST:8443/СЛУЧАЙНЫЙ-ПУТЬ/`.

Явная конфигурация:

```bash
sudo env \
  PANEL_HOST=panel.example.com \
  PANEL_EMAIL=admin@example.com \
  PANEL_HTTPS_PORT=9443 \
  PANEL_USER=operator \
  PANEL_PASSWORD='Long-Random-Panel-Password' \
  bash install.sh
```

Установка панели без автоматической установки WDTT:

```bash
sudo env INSTALL_WDTT=no PANEL_HOST=203.0.113.10 bash install.sh
```

Команды обслуживания:

```bash
sudo wdtt-panel
sudo wdtt-panel-status
sudo wdtt-panel-update
sudo wdtt-panel-uninstall
sudo bash /opt/wdtt-panel/install.sh renew-cert
```

Те же операции доступны через главное интерактивное меню. Обновление скачивает свежую версию с GitHub и сохраняет адрес, логин, пароль, случайный путь, сертификаты, аудит и резервные копии.

Одноразовые команды без установленного локального wrapper:

```bash
curl -fsSL https://raw.githubusercontent.com/lebrit/wdtt-control-panel/main/update.sh | sudo bash
curl -fsSL https://raw.githubusercontent.com/lebrit/wdtt-control-panel/main/uninstall.sh | sudo bash
```

Удаление затрагивает только панель. WDTT, его пользователи и серверный бинарник не изменяются. Резервные копии остаются в `/var/lib/wdtt-panel-private/backups`.

## Сертификаты

- Для домена используется Certbot и HTTP-01; A/AAAA запись должна указывать на сервер, TCP 80 должен быть доступен.
- Для IPv4 используется Certbot 5.4+ и короткоживущий профиль Let's Encrypt.
- Проверка и продление сертификата выполняются systemd-таймером каждые 12 часов.
- Если публичный сертификат получить нельзя, установщик создает self-signed сертификат. Таймер повторно пытается получить доверенный сертификат, а self-signed автоматически заменяет до истечения срока.
- При self-signed сертификате браузер показывает предупреждение, пока сертификат не добавлен в доверенные.

Let's Encrypt объявил публичную доступность IP-сертификатов 15 января 2026 года и поддержку в Certbot 5.4+ 11 марта 2026 года:

- https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability
- https://letsencrypt.org/2026/03/11/shorter-certs-certbot

## Безопасность

- web-процесс запускается от отдельного пользователя `wdtt-panel` и слушает только `127.0.0.1:8787`;
- Nginx публикует только случайный путь, остальные URL возвращают `404`;
- пароли панели хранятся как PBKDF2-HMAC-SHA256 с 600 000 итераций;
- cookie имеет `Secure`, `HttpOnly`, `SameSite=Strict`; изменяющие запросы защищены CSRF;
- root-доступ отделен в `/usr/local/sbin/wdtt-panel-admin`; sudo разрешает только этот helper без аргументов;
- helper принимает JSON через stdin и поддерживает только фиксированный список операций;
- каждое изменение базы предваряется резервной копией.

Путь не заменяет аутентификацию, но уменьшает шум автоматических сканеров. Не публикуйте URL и пароль панели в открытых каналах.

## Проверка

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q wdtt_panel
bash -n bootstrap.sh install.sh update.sh uninstall.sh
```

## Ограничения исходного WDTT

- Максимум 10 сгенерированных паролей задан в `server.go`.
- Счетчики пользователя находятся в памяти и записываются в JSON только при некоторых операциях самого WDTT. Панель показывает сохраненные значения; незаписанная часть может потеряться при перезапуске.
- Изменение главного пароля не реализовано: WDTT получает его из `ExecStart -password`, а затем переписывает значение в JSON при каждом старте. Для ротации главного пароля нужен осознанный повторный деплой или изменение unit-файла.
- Панель не обновляет WDTT автоматически и не заменяет его бинарник на уже развернутом сервере.
