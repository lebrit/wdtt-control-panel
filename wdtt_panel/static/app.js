(() => {
  "use strict";

  const meta = (name) => document.querySelector(`meta[name="${name}"]`).content;
  const BASE = meta("base-path");
  const CSRF = meta("csrf-token");
  const PUBLIC_HOST = meta("public-host");
  const PANEL_VERSION = meta("panel-version");
  const state = { overview: null, users: [], logs: [], editing: null, cascade: null, routeRules: [], geofiles: [] };

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const formatBytes = (bytes) => {
    const value = Number(bytes || 0);
    if (value < 1024) return `${value} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let size = value;
    let unit = -1;
    do { size /= 1024; unit += 1; } while (size >= 1024 && unit < units.length - 1);
    return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[unit]}`;
  };
  const formatDate = (stamp) => stamp ? new Date(stamp * 1000).toLocaleString("ru-RU") : "Бессрочно";
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));

  async function api(route, options = {}) {
    const init = { method: options.method || "GET", headers: { "Accept": "application/json" } };
    if (init.method === "POST") {
      init.headers["Content-Type"] = "application/json";
      init.headers["X-CSRF-Token"] = CSRF;
      init.body = JSON.stringify(options.body || {});
    }
    const response = await fetch(`${BASE}api/${route}`, init);
    const data = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
    if (!response.ok || data.ok === false) throw new Error(data.error || "Ошибка запроса");
    return data.result ?? data;
  }

  function toast(message, error = false) {
    const node = $("#toast");
    node.textContent = message;
    node.classList.toggle("error", error);
    node.hidden = false;
    clearTimeout(node.timer);
    node.timer = setTimeout(() => { node.hidden = true; }, 4200);
  }

  function setBusy(button, busy) {
    if (!button) return;
    button.disabled = busy;
    if (busy) button.dataset.label = button.textContent;
    button.textContent = busy ? "Выполнение..." : (button.dataset.label || button.textContent);
  }

  function healthRow(label, ok, value) {
    return `<div class="health-item"><span><i class="status-dot ${ok ? "ok" : "bad"}"></i>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
  }

  async function loadOverview() {
    const overview = await api("overview");
    state.overview = overview;
    const service = overview.service || {};
    const stats = overview.stats || {};
    const active = Boolean(service.active);
    $("#service-label").textContent = active ? "Сервис работает" : "Сервис остановлен";
    $("#service-detail").textContent = active ? `NAT: ${stats.nat || "определяется"} · uptime ${stats.uptime || "0м"}` : "Активные туннели недоступны";
    $("#service-dot").className = `status-dot large ${active ? "ok" : "bad"}`;
    $("#sidebar-dot").className = `status-dot ${active ? "ok" : "bad"}`;
    $("#sidebar-status").textContent = active ? "WDTT активен" : "WDTT остановлен";
    $("#active-conns").textContent = stats.active ?? 0;
    $("#total-conns").textContent = `${stats.total ?? 0} всего`;
    $("#user-count").textContent = overview.users ?? 0;
    $("#device-count").textContent = `${overview.devices ?? 0} устройств`;
    const up = Number(stats.up_gb || 0), down = Number(stats.down_gb || 0);
    $("#traffic-total").textContent = `${(up + down).toFixed(2)} GB`;
    $("#traffic-split").textContent = `↑${up.toFixed(2)} / ↓${down.toFixed(2)}`;
    const system = overview.system || {}, memory = system.memory || {}, disk = overview.disk || {};
    $("#cpu-load").textContent = `${Number(system.cpu_percent || 0).toFixed(1)}%`;
    $("#system-load").textContent = `load ${Number((system.load_average || [0])[0]).toFixed(2)}`;
    $("#memory-load").textContent = `${Number(memory.percent || 0).toFixed(1)}%`;
    $("#memory-detail").textContent = `${formatBytes(memory.used)} / ${formatBytes(memory.total)}`;
    $("#disk-load").textContent = `${Number(disk.percent || 0).toFixed(1)}%`;
    $("#disk-detail").textContent = `${formatBytes(disk.used)} / ${formatBytes(disk.total)}`;
    $("#health-list").innerHTML = [
      healthRow("systemd unit", service.exists, service.exists ? "найден" : "не найден"),
      healthRow("wdtt-server", service.binary, service.binary ? "установлен" : "отсутствует"),
      healthRow("Интерфейс wdtt0", service.interface, service.interface ? "поднят" : "не активен"),
      healthRow("IPv4 forwarding", String(service.ip_forward) === "1", String(service.ip_forward) === "1" ? "включен" : "выключен"),
    ].join("");
    const interfaceError = $("#interface-error");
    interfaceError.textContent = service.interface_error || "";
    interfaceError.hidden = !service.interface_error;
    renderCertificate(overview.certificate || {});
    await loadHistory();
  }

  function renderCertificate(cert) {
    const rows = [];
    rows.push(`<div class="detail-row"><span>Режим</span><strong>${escapeHtml(cert.mode || "неизвестно")}</strong></div>`);
    rows.push(`<div class="detail-row"><span>Файл</span><strong>${cert.exists ? "найден" : "не найден"}</strong></div>`);
    rows.push(`<div class="detail-row"><span>HTTPS локально</span><strong>${cert.local_tls_ok ? "работает" : "не отвечает"}</strong></div>`);
    rows.push(`<div class="detail-row"><span>Порт</span><strong>${cert.listening ? "слушается" : "не слушается"}</strong></div>`);
    if (cert.expires_at) rows.push(`<div class="detail-row"><span>Истекает</span><strong>${escapeHtml(formatDate(cert.expires_at))}</strong></div>`);
    if (cert.days_left !== undefined && cert.days_left !== null) rows.push(`<div class="detail-row"><span>Осталось</span><strong>${escapeHtml(cert.days_left)} дней</strong></div>`);
    if (cert.error) rows.push(`<div class="detail-row"><span>Ошибка</span><strong>${escapeHtml(cert.error)}</strong></div>`);
    if (cert.mode === "self-signed") rows.push(`<p class="muted">Self-signed сертификат шифрует соединение, но браузер покажет предупреждение, пока сертификат не добавлен в доверенные.</p>`);
    $("#certificate-info").innerHTML = rows.join("") || `<p class="muted">Данные сертификата недоступны.</p>`;
  }

  async function loadHistory() {
    const history = await api("history");
    drawChart(history.points || []);
  }

  function drawChart(points) {
    const canvas = $("#activity-chart");
    const ratio = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = Math.max(600, rect.width * ratio);
    canvas.height = 280 * ratio;
    const ctx = canvas.getContext("2d");
    ctx.scale(ratio, ratio);
    const width = canvas.width / ratio, height = 280;
    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = "#1f2b3c"; ctx.lineWidth = 1;
    for (let y = 30; y < height; y += 52) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke(); }
    if (!points.length) {
      ctx.fillStyle = "#718198"; ctx.font = "12px sans-serif"; ctx.fillText("История появится после нескольких обновлений", 18, 34); return;
    }
    const values = points.map((item) => Number(item[1] || 0));
    const max = Math.max(4, ...values);
    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, "rgba(89,225,194,.3)"); gradient.addColorStop(1, "rgba(89,225,194,0)");
    ctx.beginPath();
    points.forEach((item, index) => {
      const x = points.length === 1 ? width / 2 : index * (width / (points.length - 1));
      const y = height - 28 - (Number(item[1] || 0) / max) * (height - 52);
      index ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.lineTo(width, height); ctx.lineTo(0, height); ctx.closePath(); ctx.fillStyle = gradient; ctx.fill();
    ctx.beginPath();
    points.forEach((item, index) => {
      const x = points.length === 1 ? width / 2 : index * (width / (points.length - 1));
      const y = height - 28 - (Number(item[1] || 0) / max) * (height - 52);
      index ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.strokeStyle = "#59e1c2"; ctx.lineWidth = 2; ctx.stroke();
  }

  async function loadUsers() {
    const result = await api("users");
    state.users = [...(result.admins || []), ...(result.users || [])];
    $("#user-limit").textContent = `${(result.users || []).length} / ${result.limit || 10}`;
    renderUsers();
  }

  function userStatus(user) {
    if (user.connected) return ["ok", "подключен"];
    if (user.expired) return ["bad", "истек"];
    if (user.is_deactivated) return ["warn", "выключен"];
    if (user.device_id) return ["warn", "не в сети"];
    return ["ok", "свободен"];
  }

  function renderUsers() {
    const query = $("#user-search").value.toLowerCase();
    const users = state.users.filter((user) => JSON.stringify(user).toLowerCase().includes(query));
    $("#users-body").innerHTML = users.map((user) => {
      const [statusClass, status] = userStatus(user);
      const traffic = `${formatBytes(user.down_bytes)} ↓ / ${formatBytes(user.up_bytes)} ↑`;
      const device = user.device ? `${escapeHtml(user.device.device_id || user.device_id)}<br><small>${escapeHtml(user.device.ip || "")}</small>` : "Не привязан";
      return `<tr>
        <td><strong class="mono">${escapeHtml(user.password)}</strong><br><small>${escapeHtml(user.vk_hash)}</small></td>
        <td><span class="badge ${statusClass}">${status}</span></td>
        <td>${escapeHtml(formatDate(user.expires_at))}</td>
        <td class="mono">${device}</td><td>${escapeHtml(traffic)}</td>
        <td><div class="row-actions">
          ${user.role === "admin" ? "" : `<button data-copy="${escapeHtml(user.password)}" title="Скопировать wdtt:// ссылку">Ссылка</button>`}
          ${user.role === "admin" ? "" : `
          <button data-edit="${escapeHtml(user.password)}">Изменить</button>
          ${user.device_id ? `<button data-unbind="${escapeHtml(user.password)}">Отвязать</button>` : ""}
          <button data-reset="${escapeHtml(user.password)}">Сброс трафика</button>
          <button data-delete="${escapeHtml(user.password)}">Удалить</button>`}
        </div></td></tr>`;
    }).join("") || `<tr><td colspan="6" class="muted">Пользователи не найдены.</td></tr>`;
  }

  function openUserDialog(user = null) {
    state.editing = user;
    $("#dialog-title").textContent = user ? "Изменить пользователя" : "Новый пользователь";
    $("#current-password").value = user?.password || "";
    $("#edit-password").value = user?.password || "";
    $("#edit-password").placeholder = user ? "Пароль доступа" : "Пусто = создать автоматически";
    $("#edit-hashes").value = user?.vk_hash || "";
    $("#edit-ports").value = user?.ports || "56000,56001,9000";
    $("#edit-unlimited").checked = Boolean(user && !user.expires_at);
    $("#edit-disabled").checked = Boolean(user?.is_deactivated);
    const days = user?.expires_at ? Math.max(1, Math.ceil((user.expires_at - Date.now() / 1000) / 86400)) : 30;
    $("#edit-days").value = days;
    $("#user-dialog").showModal();
  }

  async function saveUser(event) {
    event.preventDefault();
    if (event.submitter?.value === "cancel") { $("#user-dialog").close(); return; }
    const button = $("#save-user");
    setBusy(button, true);
    const payload = {
      password: $("#edit-password").value,
      vk_hash: $("#edit-hashes").value,
      ports: $("#edit-ports").value,
      days: Number($("#edit-days").value),
      unlimited: $("#edit-unlimited").checked,
      is_deactivated: $("#edit-disabled").checked,
    };
    if (state.editing) payload.current_password = state.editing.password;
    try {
      await api(state.editing ? "users/update" : "users/create", { method: "POST", body: payload });
      $("#user-dialog").close();
      toast(state.editing ? "Пользователь обновлен" : "Пользователь создан");
      await Promise.all([loadUsers(), loadOverview()]);
    } catch (error) { toast(error.message, true); }
    finally { setBusy(button, false); }
  }

  function openBulkUserDialog() {
    const remaining = Math.max(0, 10 - state.users.length);
    if (!remaining) { toast("Достигнут лимит 10 пользователей", true); return; }
    $("#bulk-count").max = remaining;
    $("#bulk-count").value = Math.min(2, remaining);
    $("#bulk-user-dialog").showModal();
  }

  async function saveBulkUsers(event) {
    event.preventDefault();
    if (event.submitter?.value === "cancel") { $("#bulk-user-dialog").close(); return; }
    const button = $("#save-bulk-users");
    setBusy(button, true);
    const payload = {
      count: Number($("#bulk-count").value),
      vk_hash: $("#bulk-hashes").value,
      hash_mode: $("#bulk-hash-mode").value,
      ports: $("#bulk-ports").value,
      days: Number($("#bulk-days").value),
      unlimited: $("#bulk-unlimited").checked,
      is_deactivated: $("#bulk-disabled").checked,
    };
    try {
      const result = await api("users/create-bulk", { method: "POST", body: payload });
      const users = result.users || [];
      $("#bulk-result-links").value = users.map(quickLink).join("\n");
      $("#bulk-user-dialog").close();
      $("#bulk-result-dialog").showModal();
      toast(`Создано пользователей: ${users.length}`);
      await Promise.all([loadUsers(), loadOverview()]);
    } catch (error) { toast(error.message, true); }
    finally { setBusy(button, false); }
  }

  async function copyBulkLinks() {
    try {
      await navigator.clipboard.writeText($("#bulk-result-links").value);
      toast("Все ссылки wdtt:// скопированы");
    } catch (error) { toast(`Не удалось скопировать: ${error.message}`, true); }
  }

  async function userAction(route, password, confirmText) {
    if (confirmText && !confirm(confirmText)) return;
    try {
      await api(route, { method: "POST", body: { password } });
      toast("Операция выполнена");
      await Promise.all([loadUsers(), loadOverview()]);
    } catch (error) { toast(error.message, true); }
  }

  function quickLink(user) {
    const ports = (user.ports || "56000,56001,9000").split(",");
    return `wdtt://${PUBLIC_HOST}:${ports[0]}:${ports[1]}:${ports[2]}:${user.password}:${user.vk_hash}`;
  }

  async function loadLogs() {
    try {
      const result = await api("logs?limit=700");
      state.logs = result.lines || [];
      renderLogs();
    } catch (error) { $("#logs-output").textContent = error.message; }
  }

  function renderLogs() {
    const filter = $("#log-filter").value;
    const lines = filter ? state.logs.filter((line) => line.includes(filter)) : state.logs;
    $("#logs-output").textContent = lines.join("\n") || "Нет строк для выбранного фильтра.";
  }

  async function serviceAction(action, button) {
    if (action === "stop" && !confirm("Остановить WDTT и разорвать активные туннели?")) return;
    setBusy(button, true);
    try {
      await api("service", { method: "POST", body: { service_action: action } });
      toast(`Сервис: ${action}`);
      setTimeout(loadOverview, 900);
    } catch (error) { toast(error.message, true); }
    finally { setBusy(button, false); }
  }

  async function loadBackups() {
    try {
      const result = await api("backups");
      $("#backups-list").innerHTML = (result.backups || []).map((item) => `<div class="backup-row"><span><strong>${escapeHtml(item.name)}</strong><br><small>${escapeHtml(formatDate(item.created_at))} · ${formatBytes(item.size)}</small></span><div class="row-actions"><button data-download-backup="${escapeHtml(item.name)}">Скачать</button><button data-restore="${escapeHtml(item.name)}">Восстановить</button></div></div>`).join("") || `<p class="muted">Резервные копии появятся перед первым изменением базы.</p>`;
    } catch (error) { toast(error.message, true); }
  }

  async function createBackup() {
    const button = $("#create-backup");
    setBusy(button, true);
    try {
      const result = await api("backups/create", { method: "POST" });
      toast(`Backup создан: ${result.name}`);
      await loadBackups();
    } catch (error) { toast(error.message, true); }
    finally { setBusy(button, false); }
  }

  async function loadPanelVersion() {
    const info = $("#panel-version-info");
    const updateButton = $("#update-panel");
    try {
      const result = await api("panel/version");
      const latest = result.latest || "недоступна";
      info.innerHTML = [
        `<div class="detail-row"><span>Установлена</span><strong>v${escapeHtml(result.current || PANEL_VERSION)}</strong></div>`,
        `<div class="detail-row"><span>На GitHub</span><strong>${result.latest ? `v${escapeHtml(latest)}` : escapeHtml(latest)}</strong></div>`,
        result.error ? `<div class="detail-row"><span>Проверка</span><strong>${escapeHtml(result.error)}</strong></div>` : "",
      ].join("");
      updateButton.hidden = !result.update_available;
      updateButton.textContent = result.update_available ? `Обновить до v${result.latest}` : "Обновить панель";
      $("#panel-version-pill").textContent = result.update_available
        ? `v${result.current} → v${result.latest}`
        : `v${result.current || PANEL_VERSION}`;
    } catch (error) {
      info.innerHTML = `<p class="muted">Не удалось проверить GitHub: ${escapeHtml(error.message)}</p>`;
      updateButton.hidden = true;
    }
  }

  async function updatePanel() {
    const button = $("#update-panel");
    if (!confirm("Обновить панель до новой версии? Web-панель перезапустится, WDTT продолжит работу.")) return;
    setBusy(button, true);
    try {
      await api("panel/update", { method: "POST" });
      toast("Обновление запущено. Панель перезагрузится автоматически.");
      setTimeout(() => location.reload(), 15000);
    } catch (error) {
      toast(error.message, true);
      setBusy(button, false);
    }
  }

  async function loadAudit() {
    const result = await api("audit");
    $("#audit-body").innerHTML = (result.items || []).map((item) => `<tr><td>${escapeHtml(formatDate(item[0]))}</td><td>${escapeHtml(item[1])}</td><td class="mono">${escapeHtml(item[2])}</td><td>${escapeHtml(item[3])}</td><td><span class="badge ${item[4] === "ok" ? "ok" : "bad"}">${escapeHtml(item[4])}</span></td></tr>`).join("");
  }

  async function restoreBackup(name) {
    if (!confirm(`Восстановить ${name}? Текущая база будет сохранена отдельно.`)) return;
    try {
      await api("backups/restore", { method: "POST", body: { name } });
      toast("Резервная копия восстановлена");
      await Promise.all([loadUsers(), loadOverview(), loadBackups()]);
    } catch (error) { toast(error.message, true); }
  }

  function downloadText(name, content, type = "application/json") {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const link = document.createElement("a");
    link.href = url; link.download = name; document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function downloadBackup(name) {
    try {
      const result = await api(`backups/export?name=${encodeURIComponent(name)}`);
      downloadText(result.name, result.content);
    } catch (error) { toast(error.message, true); }
  }

  async function uploadBackup(file) {
    if (!file) return;
    try {
      const result = await api("backups/import", { method: "POST", body: { name: file.name, content: await file.text() } });
      toast(`Backup загружен: ${result.name}`);
      await loadBackups();
    } catch (error) { toast(error.message, true); }
  }

  async function renewCertificate() {
    const button = $("#renew-certificate"); setBusy(button, true);
    try { await api("certificate/renew", { method: "POST" }); toast("Проверка сертификата запущена"); setTimeout(loadOverview, 7000); }
    catch (error) { toast(error.message, true); }
    finally { setBusy(button, false); }
  }

  async function downloadCertificate() {
    try {
      const result = await api("certificate/export");
      downloadText(result.name, result.content, "application/x-pem-file");
    } catch (error) { toast(error.message, true); }
  }

  const routeTypeOptions = [
    ["domain", "Домены"], ["ip", "IP/CIDR"], ["port", "Порты"], ["protocol", "Протокол"],
    ["source_user", "Пользователи"], ["builtin", "Готовый набор"], ["geofile", "GeoFile"],
  ];
  const routeTargetOptions = [["direct", "Напрямую"], ["vless", "VLESS"], ["warp", "WARP"], ["block", "Блокировать"]];

  function optionList(options, current) {
    return options.map(([value, label]) => `<option value="${value}" ${value === current ? "selected" : ""}>${label}</option>`).join("");
  }

  function renderRouteRules() {
    $("#route-rules").innerHTML = state.routeRules.map((rule, index) => `<div class="route-rule" data-rule-index="${index}">
      <div class="route-order"><button data-rule-up="${index}" ${index === 0 ? "disabled" : ""}>↑</button><button data-rule-down="${index}" ${index === state.routeRules.length - 1 ? "disabled" : ""}>↓</button></div>
      <select data-rule-field="type">${optionList(routeTypeOptions, rule.type || "domain")}</select>
      <textarea data-rule-field="values" placeholder="Значения через запятую или с новой строки">${escapeHtml(Array.isArray(rule.values) ? rule.values.join("\n") : (rule.values || ""))}</textarea>
      <select class="route-target" data-rule-field="outbound">${optionList(routeTargetOptions, rule.outbound || "direct")}</select>
      <div class="row-actions"><label class="checkbox"><input data-rule-field="enabled" type="checkbox" ${rule.enabled === false ? "" : "checked"}> Вкл.</label><button data-rule-remove="${index}">Удалить</button></div>
    </div>`).join("") || `<p class="muted">Правил нет. Весь трафик идет по маршруту по умолчанию.</p>`;
  }

  function renderGeofiles() {
    $("#geofiles-list").innerHTML = state.geofiles.map((item) => `<div class="backup-row"><span><strong>${escapeHtml(item.tag)}</strong><br><small>${escapeHtml(item.kind || "srs")} · ${item.auto_update ? `авто ${escapeHtml(item.update_interval || "1d")}` : "вручную"} · ${escapeHtml(formatDate(item.updated_at))}</small></span><button data-refresh-geofile="${escapeHtml(item.tag)}" ${item.url ? "" : "disabled"}>Обновить</button></div>`).join("") || `<p class="muted">Пользовательские GeoFiles не загружены.</p>`;
  }

  async function loadCascade() {
    try {
      const result = await api("cascade");
      state.cascade = result;
      const settings = result.settings || {};
      state.routeRules = settings.rules || [];
      state.geofiles = settings.geofiles || [];
      $("#cascade-vless").value = settings.vless_uri || "";
      $("#cascade-default").value = settings.default_outbound || "direct";
      $("#cascade-enabled").checked = Boolean(settings.enabled);
      $("#cascade-status").className = `badge ${result.active ? "ok" : (settings.enabled ? "bad" : "warn")}`;
      $("#cascade-status").textContent = result.active ? "работает" : (settings.enabled ? "ошибка" : "выключен");
      $("#warp-status").textContent = result.warp_ready ? "WARP готов" : "WARP не настроен";
      $("#install-cascade").textContent = result.installed ? (result.version || "Компоненты установлены") : "Установить компоненты";
      $("#cascade-log").textContent = (result.logs || []).join("\n") || "Нет записей.";
      renderRouteRules(); renderGeofiles();
    } catch (error) { toast(error.message, true); }
  }

  async function saveCascade() {
    const button = $("#save-cascade"); setBusy(button, true);
    try {
      await api("cascade/save", { method: "POST", body: {
        enabled: $("#cascade-enabled").checked,
        vless_uri: $("#cascade-vless").value.trim(),
        default_outbound: $("#cascade-default").value,
        rules: state.routeRules,
        geofiles: state.geofiles,
      }});
      toast("Маршрутизация сохранена и применена"); await loadCascade();
    } catch (error) { toast(error.message, true); }
    finally { setBusy(button, false); }
  }

  function addRouteRule(type = "domain", values = "", outbound = "vless") {
    state.routeRules.push({ enabled: true, type, values, outbound }); renderRouteRules();
  }

  async function installCascade() {
    const button = $("#install-cascade"); setBusy(button, true);
    try { await api("cascade/install", { method: "POST" }); toast("Установка sing-box, WARP и GeoFile-конвертера запущена"); setTimeout(loadCascade, 15000); }
    catch (error) { toast(error.message, true); setBusy(button, false); }
  }

  async function createWarp() {
    const button = $("#create-warp"); setBusy(button, true);
    try { await api("cascade/warp", { method: "POST" }); toast("Профиль WARP создан"); await loadCascade(); }
    catch (error) { toast(error.message, true); }
    finally { setBusy(button, false); }
  }

  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer); let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 32768) binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
    return btoa(binary);
  }

  async function uploadGeofile() {
    const file = $("#geofile-file").files[0];
    if (!file) { toast("Выберите GeoFile", true); return; }
    const button = $("#upload-geofile"); setBusy(button, true);
    try {
      const item = await api("geofiles/upload", { method: "POST", body: {
        name: file.name, content: arrayBufferToBase64(await file.arrayBuffer()), kind: $("#geofile-kind").value,
        tag: $("#geofile-tag").value.trim(), category: $("#geofile-category").value.trim(),
        url: $("#geofile-url").value.trim(), auto_update: $("#geofile-auto").checked,
        update_interval: $("#geofile-interval").value,
      }});
      state.geofiles = state.geofiles.filter((entry) => entry.tag !== item.tag); state.geofiles.push(item);
      renderGeofiles(); toast(`GeoFile ${item.tag} загружен`);
    } catch (error) { toast(error.message, true); }
    finally { setBusy(button, false); }
  }

  async function refreshGeofile(tag) {
    try { await api("geofiles/refresh", { method: "POST", body: { tag } }); toast(`GeoFile ${tag} обновлен`); await loadCascade(); }
    catch (error) { toast(error.message, true); }
  }

  function bindEvents() {
    $$(".nav-item").forEach((button) => button.addEventListener("click", () => {
      $$(".nav-item").forEach((item) => item.classList.toggle("active", item === button));
      $$(".tab").forEach((tab) => tab.classList.toggle("active", tab.id === `tab-${button.dataset.tab}`));
      $("#page-title").textContent = button.textContent;
      if (button.dataset.tab === "logs") loadLogs();
      if (button.dataset.tab === "cascade") loadCascade();
      if (button.dataset.tab === "system") { loadBackups(); loadAudit(); loadPanelVersion(); }
    }));
    $("#refresh").addEventListener("click", () => Promise.all([loadOverview(), loadUsers()]).catch((error) => toast(error.message, true)));
    $("#new-user").addEventListener("click", () => openUserDialog());
    $("#bulk-users").addEventListener("click", openBulkUserDialog);
    $("#user-form").addEventListener("submit", saveUser);
    $("#bulk-user-form").addEventListener("submit", saveBulkUsers);
    $("#copy-bulk-links").addEventListener("click", copyBulkLinks);
    $("#user-search").addEventListener("input", renderUsers);
    $("#users-body").addEventListener("click", async (event) => {
      const button = event.target.closest("button"); if (!button) return;
      const find = (password) => state.users.find((item) => item.password === password);
      if (button.dataset.edit) openUserDialog(find(button.dataset.edit));
      if (button.dataset.unbind) userAction("users/unbind", button.dataset.unbind, "Отвязать устройство? Следующее подключение создаст новую привязку.");
      if (button.dataset.reset) userAction("users/reset-traffic", button.dataset.reset, "Сбросить счетчики трафика пользователя?");
      if (button.dataset.delete) userAction("users/delete", button.dataset.delete, "Удалить пользователя и его устройство без возможности отмены?");
      if (button.dataset.copy) {
        const user = find(button.dataset.copy);
        await navigator.clipboard.writeText(quickLink(user));
        toast("Ссылка wdtt:// скопирована");
      }
    });
    $("#load-logs").addEventListener("click", loadLogs);
    $("#log-filter").addEventListener("change", renderLogs);
    $$('[data-service]').forEach((button) => button.addEventListener("click", () => serviceAction(button.dataset.service, button)));
    $("#load-backups").addEventListener("click", loadBackups);
    $("#create-backup").addEventListener("click", createBackup);
    $("#update-panel").addEventListener("click", updatePanel);
    $("#renew-certificate").addEventListener("click", renewCertificate);
    $("#download-certificate").addEventListener("click", downloadCertificate);
    $("#upload-backup").addEventListener("click", () => $("#backup-upload").click());
    $("#backup-upload").addEventListener("change", (event) => uploadBackup(event.target.files[0]));
    $("#backups-list").addEventListener("click", (event) => {
      const restore = event.target.closest("[data-restore]"); if (restore) restoreBackup(restore.dataset.restore);
      const download = event.target.closest("[data-download-backup]"); if (download) downloadBackup(download.dataset.downloadBackup);
    });
    $("#save-cascade").addEventListener("click", saveCascade);
    $("#install-cascade").addEventListener("click", installCascade);
    $("#create-warp").addEventListener("click", createWarp);
    $("#add-route-rule").addEventListener("click", () => addRouteRule());
    $("#upload-geofile").addEventListener("click", uploadGeofile);
    $("#refresh-all-geofiles").addEventListener("click", async () => {
      try { const result = await api("geofiles/refresh-all", { method: "POST" }); toast(`Обновлено GeoFiles: ${(result.refreshed || []).length}`); await loadCascade(); }
      catch (error) { toast(error.message, true); }
    });
    $("#geofiles-list").addEventListener("click", (event) => { const button = event.target.closest("[data-refresh-geofile]"); if (button) refreshGeofile(button.dataset.refreshGeofile); });
    $$("[data-preset]").forEach((button) => button.addEventListener("click", () => {
      const target = ["ru-sites", "ru-ip"].includes(button.dataset.preset) ? "direct" : "vless";
      addRouteRule("builtin", button.dataset.preset, target);
    }));
    $("#route-rules").addEventListener("input", (event) => {
      const row = event.target.closest("[data-rule-index]"); const field = event.target.dataset.ruleField;
      if (!row || !field) return;
      const rule = state.routeRules[Number(row.dataset.ruleIndex)]; rule[field] = event.target.type === "checkbox" ? event.target.checked : event.target.value;
    });
    $("#route-rules").addEventListener("click", (event) => {
      const up = event.target.closest("[data-rule-up]"), down = event.target.closest("[data-rule-down]"), remove = event.target.closest("[data-rule-remove]");
      if (up) { const i = Number(up.dataset.ruleUp); [state.routeRules[i - 1], state.routeRules[i]] = [state.routeRules[i], state.routeRules[i - 1]]; renderRouteRules(); }
      if (down) { const i = Number(down.dataset.ruleDown); [state.routeRules[i + 1], state.routeRules[i]] = [state.routeRules[i], state.routeRules[i + 1]]; renderRouteRules(); }
      if (remove) { state.routeRules.splice(Number(remove.dataset.ruleRemove), 1); renderRouteRules(); }
    });
    $$("dialog button[value='cancel']").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
    $("#logout-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      await fetch(`${BASE}logout`, { method: "POST", headers: { "X-CSRF-Token": CSRF } });
      location.reload();
    });
    window.addEventListener("resize", () => { if (state.overview) loadHistory().catch(() => {}); });
  }

  bindEvents();
  Promise.all([loadOverview(), loadUsers(), loadPanelVersion()]).catch((error) => toast(error.message, true));
  setInterval(() => loadOverview().catch(() => {}), 10000);
})();
