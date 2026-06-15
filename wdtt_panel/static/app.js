(() => {
  "use strict";

  const meta = (name) => document.querySelector(`meta[name="${name}"]`).content;
  const BASE = meta("base-path");
  const CSRF = meta("csrf-token");
  const PUBLIC_HOST = meta("public-host");
  const state = { overview: null, users: [], logs: [], editing: null };

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
    $("#health-list").innerHTML = [
      healthRow("systemd unit", service.exists, service.exists ? "найден" : "не найден"),
      healthRow("wdtt-server", service.binary, service.binary ? "установлен" : "отсутствует"),
      healthRow("Интерфейс wdtt0", service.interface, service.interface ? "поднят" : "не активен"),
      healthRow("IPv4 forwarding", String(service.ip_forward) === "1", String(service.ip_forward) === "1" ? "включен" : "выключен"),
    ].join("");
    renderCertificate(overview.certificate || {});
    await loadHistory();
  }

  function renderCertificate(cert) {
    const rows = [];
    rows.push(`<div class="detail-row"><span>Файл</span><strong>${cert.exists ? "найден" : "не найден"}</strong></div>`);
    if (cert.expires_at) rows.push(`<div class="detail-row"><span>Истекает</span><strong>${escapeHtml(formatDate(cert.expires_at))}</strong></div>`);
    if (cert.days_left !== undefined && cert.days_left !== null) rows.push(`<div class="detail-row"><span>Осталось</span><strong>${escapeHtml(cert.days_left)} дней</strong></div>`);
    if (cert.error) rows.push(`<div class="detail-row"><span>Ошибка</span><strong>${escapeHtml(cert.error)}</strong></div>`);
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
    state.users = result.users || [];
    $("#user-limit").textContent = `${state.users.length} / ${result.limit || 10}`;
    renderUsers();
  }

  function userStatus(user) {
    if (user.expired) return ["bad", "истек"];
    if (user.is_deactivated) return ["warn", "выключен"];
    if (user.device_id) return ["ok", "привязан"];
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
          <button data-copy="${escapeHtml(user.password)}" title="Скопировать wdtt:// ссылку">Ссылка</button>
          <button data-edit="${escapeHtml(user.password)}">Изменить</button>
          ${user.device_id ? `<button data-unbind="${escapeHtml(user.password)}">Отвязать</button>` : ""}
          <button data-reset="${escapeHtml(user.password)}">Сброс трафика</button>
          <button data-delete="${escapeHtml(user.password)}">Удалить</button>
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
      $("#backups-list").innerHTML = (result.backups || []).map((item) => `<div class="backup-row"><span><strong>${escapeHtml(item.name)}</strong><br><small>${escapeHtml(formatDate(item.created_at))} · ${formatBytes(item.size)}</small></span><button class="secondary" data-restore="${escapeHtml(item.name)}">Восстановить</button></div>`).join("") || `<p class="muted">Резервные копии появятся перед первым изменением базы.</p>`;
    } catch (error) { toast(error.message, true); }
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

  function bindEvents() {
    $$(".nav-item").forEach((button) => button.addEventListener("click", () => {
      $$(".nav-item").forEach((item) => item.classList.toggle("active", item === button));
      $$(".tab").forEach((tab) => tab.classList.toggle("active", tab.id === `tab-${button.dataset.tab}`));
      $("#page-title").textContent = button.textContent;
      if (button.dataset.tab === "logs") loadLogs();
      if (button.dataset.tab === "system") { loadBackups(); loadAudit(); }
    }));
    $("#refresh").addEventListener("click", () => Promise.all([loadOverview(), loadUsers()]).catch((error) => toast(error.message, true)));
    $("#new-user").addEventListener("click", () => openUserDialog());
    $("#user-form").addEventListener("submit", saveUser);
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
    $("#backups-list").addEventListener("click", (event) => { const button = event.target.closest("[data-restore]"); if (button) restoreBackup(button.dataset.restore); });
    $("#logout-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      await fetch(`${BASE}logout`, { method: "POST", headers: { "X-CSRF-Token": CSRF } });
      location.reload();
    });
    window.addEventListener("resize", () => { if (state.overview) loadHistory().catch(() => {}); });
  }

  bindEvents();
  Promise.all([loadOverview(), loadUsers()]).catch((error) => toast(error.message, true));
  setInterval(() => loadOverview().catch(() => {}), 10000);
})();
