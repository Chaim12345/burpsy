// src/common.ts
function $(sel, root = document) {
  return root.querySelector(sel);
}
function $all(sel, root = document) {
  return Array.from(root.querySelectorAll(sel));
}
var ESCAPE_MAP = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
};
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ESCAPE_MAP[c] ?? c);
}
function statusBadge(status) {
  if (status === null || status === undefined)
    return "-";
  return `<span class="s${String(status)[0]}">${status}</span>`;
}
class ApiError extends Error {
  status;
  body;
  constructor(message, status, body) {
    super(message);
    this.status = status;
    this.body = body;
    this.name = "ApiError";
  }
}
function isErrorBody(v) {
  return typeof v === "object" && v !== null && "error" in v;
}
async function request(method, url, body) {
  const init = { method };
  if (body !== undefined) {
    init.headers = { "content-type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const r = await fetch(url, init);
  const text = await r.text();
  let json = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  if (!r.ok) {
    const message = isErrorBody(json) && json.error ? json.error : text || `${r.status} ${r.statusText}`;
    throw new ApiError(message, r.status, json ?? text);
  }
  return json;
}
var getJSON = (url) => request("GET", url);
var postJSON = (url, body = {}) => request("POST", url, body);
var putJSON = (url, body = {}) => request("PUT", url, body);
var delJSON = (url) => request("DELETE", url);
function switchTab(id) {
  $all("nav button[data-t]").forEach((b) => b.classList.toggle("on", b.dataset["t"] === id));
  $all("main > section").forEach((s) => s.classList.toggle("on", s.id === id));
}
function initTabs() {
  $all("nav button[data-t]").forEach((b) => {
    b.onclick = () => switchTab(b.dataset["t"]);
  });
}
var toastTimer;
function toast(message, kind = "info") {
  let el = document.getElementById("toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "toast";
    document.body.appendChild(el);
  }
  el.textContent = message;
  el.className = kind;
  el.offsetWidth;
  el.classList.add("show");
  if (toastTimer)
    clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el?.classList.remove("show"), 3000);
}
var bus = new EventTarget;
function on(event, handler) {
  bus.addEventListener(event, (e) => handler(e.detail));
}
function emit(event, detail) {
  bus.dispatchEvent(new CustomEvent(event, { detail }));
}

// src/liveaudit.ts
var mounts = [];
var last = null;
var inFlight = null;
function liveAuditCardHtml(prefix) {
  return `
    <div class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:4px">
        <div class="card-title" style="margin:0">Live active audit</div>
        <label class="switch" title="audit new in-scope traffic as it is captured"><input type="checkbox" id="${prefix}-audit-toggle" /><span class="slider"></span></label>
      </div>
      <p class="hint">Auditing new in-scope traffic. Active checks are never sent automatically
        while this is off.</p>
      <div id="${prefix}-audit-hint" class="hint"></div>
      <div class="row">
        <div class="stat-tile grow"><div class="label">Exchanges swept</div><div class="value" id="${prefix}-audit-swept">0</div></div>
        <div class="stat-tile grow"><div class="label">Findings</div><div class="value" id="${prefix}-audit-findings">0</div></div>
      </div>
      <div class="row" id="${prefix}-audit-chips"></div>
      <div id="${prefix}-audit-verdict"></div>
    </div>`;
}
function mountLiveAudit(prefix) {
  const toggle = $(`#${prefix}-audit-toggle`);
  if (!toggle)
    return;
  if (!mounts.includes(prefix))
    mounts.push(prefix);
  toggle.addEventListener("change", (e) => void setLiveAudit(e.target.checked));
  if (last)
    applyTo(prefix, last);
  refreshLiveAudit();
}
function refreshLiveAudit() {
  if (mounts.length === 0)
    return Promise.resolve();
  if (inFlight)
    return inFlight;
  inFlight = (async () => {
    try {
      const r = await getJSON("/api/scanner/live");
      last = r;
      for (const prefix of mounts)
        applyTo(prefix, r);
    } catch {} finally {
      inFlight = null;
    }
  })();
  return inFlight;
}
async function setLiveAudit(enabled) {
  try {
    last = await postJSON("/api/scanner/live", { enabled });
    for (const prefix of mounts)
      applyTo(prefix, last);
  } catch (e) {
    toast(e.message, "error");
    await refreshLiveAudit();
  }
}
function applyTo(prefix, r) {
  const toggle = $(`#${prefix}-audit-toggle`);
  const hint = $(`#${prefix}-audit-hint`);
  const chips = $(`#${prefix}-audit-chips`);
  const verdict = $(`#${prefix}-audit-verdict`);
  if (!toggle || !hint)
    return;
  toggle.disabled = !r.wired;
  if (!r.wired) {
    toggle.checked = false;
    hint.textContent = r.hint ?? "not available";
    if (chips)
      chips.innerHTML = "";
    if (verdict)
      verdict.innerHTML = "";
    return;
  }
  toggle.checked = r.enabled;
  const state = r.enabled ? "sweeping new in-scope traffic" : "off — no active checks are being sent";
  hint.textContent = r.query ? `${state} · filtered to ${r.query}` : state;
  $(`#${prefix}-audit-swept`).textContent = (r.swept ?? 0).toLocaleString();
  $(`#${prefix}-audit-findings`).textContent = (r.findings ?? 0).toLocaleString();
  if (chips)
    chips.innerHTML = chipsHtml(r);
  if (verdict)
    verdict.innerHTML = verdictHtml(r);
}
function chipsHtml(r) {
  const chips = [];
  if (r.behind > 0) {
    chips.push(chip(`${r.behind.toLocaleString()} not swept yet`, "sev-medium", "captured but not yet reached by the sweep cursor"));
  }
  if (r.skipped) {
    chips.push(chip(`${r.skipped.toLocaleString()} given up on`, "sev-low", "the sweep stopped waiting for a response; these were not audited and are not counted as clean"));
  }
  if (r.stalled_at !== undefined) {
    chips.push(chip(`waiting on #${r.stalled_at}`, "sev-medium", "the cursor is blocked on this exchange"));
  }
  if (r.collapsed) {
    chips.push(chip(`${r.collapsed.toLocaleString()} already covered`, "", "checks the shared ledger refused because an identical one had already run — this work ran, it is not a gap"));
  }
  if (r.ledger_resets) {
    chips.push(chip(`${r.ledger_resets.toLocaleString()} ledger reset(s)`, "sev-low", "the dedup ledger was dropped at its cap; checks it had collapsed will re-dispatch once more"));
  }
  return chips.join(" ");
}
function chip(text, cls, title) {
  return `<span class="pill pill-outline ${cls}" title="${esc(title)}">${esc(text)}</span>`;
}
function verdictHtml(r) {
  const gaps = [];
  if (r.behind > 0)
    gaps.push(`${r.behind.toLocaleString()} exchange(s) not reached yet`);
  if (r.skipped)
    gaps.push(`${r.skipped.toLocaleString()} given up on with no response`);
  if (r.stalled_at !== undefined)
    gaps.push(`the cursor is waiting on exchange ${r.stalled_at}`);
  if (gaps.length === 0) {
    return `<div class="hint ok">complete — the sweep is caught up, nothing skipped and nothing waiting</div>`;
  }
  return `<div class="hint err">a floor, not a total: ${esc(gaps.join("; "))}</div>`;
}

// src/live.ts
var DEFAULT_FALLBACK_MS = 4000;
var DEFAULT_MIN_GAP_MS = 300;
var FALLBACK_TICK_MS = 500;
var SILENCE_LIMIT_MS = 60000;
var WATCHDOG_TICK_MS = 15000;
var panes = [];
var stream = null;
var delivering = false;
var connects = 0;
var lastFrameAt = 0;
var fallbackTimer;
var indicator = null;
function live(spec) {
  panes.push({
    kinds: spec.kinds,
    section: spec.section,
    refresh: spec.refresh,
    fallbackMs: spec.fallbackMs ?? DEFAULT_FALLBACK_MS,
    minGapMs: spec.minGapMs ?? DEFAULT_MIN_GAP_MS,
    stale: false,
    owed: 0,
    lastRun: Date.now()
  });
}
function initLive() {
  ensureIndicator();
  watchTabSwitches();
  connect();
  startFallback();
  setInterval(() => {
    if (delivering && Date.now() - lastFrameAt > SILENCE_LIMIT_MS) {
      reconnect();
    }
  }, WATCHDOG_TICK_MS);
}
function connect() {
  if (typeof EventSource === "undefined") {
    markDown();
    return;
  }
  try {
    stream = new EventSource("/api/events");
  } catch {
    markDown();
    return;
  }
  stream.onmessage = (e) => onFrame(e.data);
  stream.onerror = () => {
    markDown();
  };
}
function reconnect() {
  stream?.close();
  stream = null;
  markDown();
  connect();
}
function onFrame(data) {
  lastFrameAt = Date.now();
  let frame;
  try {
    frame = JSON.parse(data);
  } catch {
    return;
  }
  if (!frame.kind)
    return;
  if (frame.kind === "hello") {
    markUp();
    if (connects++ > 0)
      panes.forEach((pane) => markStale(pane, 0));
    return;
  }
  if (frame.kind === "ping") {
    markUp();
    return;
  }
  markUp();
  for (const pane of panes) {
    if (pane.kinds.includes(frame.kind))
      markStale(pane, frame.changes ?? 0);
  }
}
function markStale(pane, changes) {
  pane.stale = true;
  pane.owed += changes;
  schedule(pane);
}
function schedule(pane) {
  if (!pane.stale || pane.timer !== undefined || !visible(pane))
    return;
  const wait = Math.max(0, pane.minGapMs - (Date.now() - pane.lastRun));
  pane.timer = setTimeout(() => {
    pane.timer = undefined;
    if (!pane.stale || !visible(pane))
      return;
    pane.stale = false;
    pane.lastRun = Date.now();
    const owed = pane.owed;
    pane.owed = 0;
    pane.refresh(owed);
  }, wait);
}
function visible(pane) {
  if (pane.section === "")
    return true;
  return document.getElementById(pane.section)?.classList.contains("on") === true;
}
function watchTabSwitches() {
  const sections = Array.from(document.querySelectorAll("main > section"));
  if (sections.length === 0)
    return;
  const observer = new MutationObserver(() => {
    for (const pane of panes) {
      if (pane.stale)
        schedule(pane);
    }
  });
  sections.forEach((s) => observer.observe(s, { attributes: true, attributeFilter: ["class"] }));
}
function startFallback() {
  if (fallbackTimer !== undefined)
    return;
  fallbackTimer = setInterval(() => {
    if (delivering)
      return;
    const now = Date.now();
    for (const pane of panes) {
      if (!visible(pane) || now - pane.lastRun < pane.fallbackMs)
        continue;
      pane.stale = false;
      pane.owed = 0;
      pane.lastRun = now;
      pane.refresh(0);
    }
  }, FALLBACK_TICK_MS);
}
function stopFallback() {
  if (fallbackTimer === undefined)
    return;
  clearInterval(fallbackTimer);
  fallbackTimer = undefined;
}
function markUp() {
  lastFrameAt = Date.now();
  if (delivering)
    return;
  delivering = true;
  stopFallback();
  renderIndicator();
}
function markDown() {
  if (!delivering && fallbackTimer !== undefined)
    return;
  delivering = false;
  startFallback();
  renderIndicator();
}
function ensureIndicator() {
  const stats = $("#stats");
  if (!stats || indicator)
    return;
  indicator = document.createElement("span");
  indicator.id = "live-state";
  indicator.className = "hint";
  stats.insertAdjacentElement("afterend", indicator);
  renderIndicator();
}
function renderIndicator() {
  if (!indicator)
    return;
  indicator.textContent = delivering ? "live" : "polling";
  indicator.title = delivering ? "changes are pushed from the server as they happen (/api/events)" : "the event stream is not delivering, so panes are polled on an interval instead — this is the fallback, not a live view";
}

// src/dashboard.ts
function initDashboard() {
  const section = $("#dashboard");
  if (!section)
    return;
  section.innerHTML = `
    <div class="four">
      <div class="stat-tile"><div class="label">Exchanges captured</div><div class="value" id="dash-exchanges">–</div></div>
      <div class="stat-tile"><div class="label">Storage used</div><div class="value" id="dash-storage">–</div></div>
      <div class="stat-tile"><div class="label">Scope rules</div><div class="value" id="dash-scope">–</div></div>
      <div class="stat-tile"><div class="label">Tasks running</div><div class="value" id="dash-running">–</div></div>
    </div>
    <div class="card">
      <div class="card-title">Counts, and what they do not account for</div>
      <p class="hint">A count with a caveat is a floor, not a total. Nothing here reports a number
        without reporting the work that produced no verdict.</p>
      <div class="four" id="dash-summaries"></div>
    </div>
    <div class="card">
      <div class="card-title">Tasks</div>
      <table>
        <thead><tr><th>Kind</th><th>Target</th><th>State</th><th>Progress</th><th>Result</th><th>Elapsed</th></tr></thead>
        <tbody id="dash-tasks"></tbody>
      </table>
      <div id="dash-tasks-meta" class="hint"></div>
    </div>
    <div class="two">
      <div class="card">
        <div class="card-title">Requests sent</div>
        <p class="hint">Every request burpsy's own tools sent. Proxy traffic lives in History.</p>
        <table>
          <thead><tr><th>Time</th><th>Tool</th><th>Request</th></tr></thead>
          <tbody id="dash-activity"></tbody>
        </table>
        <div id="dash-activity-meta" class="hint"></div>
      </div>
      <div class="card">
        <div class="card-title">What the tool did</div>
        <p class="hint">Tasks starting and finishing, scope edits, bounds hit — the things that are not
          requests, so they are not in the list beside this one.</p>
        <table>
          <thead><tr><th>Time</th><th>Kind</th><th>Detail</th></tr></thead>
          <tbody id="dash-events"></tbody>
        </table>
        <div id="dash-events-meta" class="hint"></div>
      </div>
    </div>
    <div class="two">
      ${liveAuditCardHtml("dash")}
    </div>
  `;
  mountLiveAudit("dash");
  live({
    kinds: ["history", "issues", "toollog", "dashboard"],
    section: "dashboard",
    refresh: () => void refresh(),
    minGapMs: 1000,
    fallbackMs: 4000
  });
  refresh();
}
async function refresh() {
  await Promise.all([refreshDashboard(), refreshScope()]);
}
async function refreshDashboard() {
  try {
    const d = await getJSON("/api/dashboard");
    $("#dash-exchanges").textContent = d.exchanges.toLocaleString();
    $("#dash-storage").textContent = `${(d.stored_bytes / 1048576).toFixed(1)} MB`;
    $("#dash-running").textContent = String(d.tasks_running);
    $("#dash-summaries").innerHTML = d.summaries.map(renderSummary).join("");
    renderTasks(d);
    renderActivity(d);
    renderEvents(d);
  } catch (e) {
    $("#dash-summaries").innerHTML = `<div class="err">${esc(e.message)}</div>`;
  }
}
function renderSummary(s) {
  const b = s.breakdown;
  const chips = [
    b.skipped > 0 ? `<span class="pill pill-outline sev-low">${b.skipped} skipped</span>` : "",
    b.errored > 0 ? `<span class="pill pill-outline sev-high">${b.errored} errored</span>` : "",
    b.gated > 0 ? `<span class="pill pill-outline sev-medium">${b.gated} gated</span>` : ""
  ].filter(Boolean).join(" ");
  const verdict = b.complete ? `<div class="hint ok">complete — nothing skipped, errored or gated</div>` : `<div class="hint err">a floor, not a total: ${b.unaccounted} ${esc(s.work_unit)} produced no verdict</div>`;
  const reasons = b.complete ? "" : `<ul class="hint">${s.reasons.map((r) => `<li>${r.count} — ${esc(r.detail)}</li>`).join("")}</ul>`;
  return `<div class="stat-tile">
    <div class="label">${esc(s.label)}</div>
    <div class="value">${b.found.toLocaleString()}</div>
    <div class="hint">${esc(s.unit)}</div>
    <div class="row">${chips}</div>
    ${verdict}
    ${reasons}
  </div>`;
}
function renderTasks(d) {
  const body = $("#dash-tasks");
  body.innerHTML = d.tasks.length ? d.tasks.map((t) => `<tr>
        <td><span class="tag">${esc(t.kind)}</span></td>
        <td>${esc(t.target)}</td>
        <td>${stateBadge(t)}</td>
        <td>${progressCell(t)}</td>
        <td>${resultCell(t)}</td>
        <td>${(t.elapsed_ms / 1000).toFixed(1)}s</td>
      </tr>`).join("") : `<tr><td colspan="6" class="hint">nothing has run yet — start an audit, an attack or a crawl</td></tr>`;
  $("#dash-tasks-meta").textContent = `${d.tasks.length} shown, ${d.tasks_running} running` + (d.tasks_dropped ? ` · ${d.tasks_dropped} older finished tasks dropped at the capacity bound` : "");
}
function stateBadge(t) {
  const cls = t.state === "failed" ? "sev-high" : t.state === "stopped" ? "sev-medium" : t.state === "done" ? "ok" : "";
  return `<span class="pill pill-outline ${cls}">${esc(t.state)}</span>`;
}
function progressCell(t) {
  if (!t.fraction_known) {
    return `<span class="hint">${esc(t.progress)}</span>`;
  }
  return `<div class="seq-bar-track" title="${esc(t.progress)}">
      <span class="seq-bar-fill" style="width:${(t.fraction * 100).toFixed(1)}%"></span>
    </div><span class="hint">${esc(t.progress)}</span>`;
}
function resultCell(t) {
  if (t.state === "running")
    return `<span class="hint">pending</span>`;
  const cls = t.complete ? "ok" : "err";
  const note = t.note ? `<div class="hint">${esc(t.note)}</div>` : "";
  return `<span class="${cls}">${esc(t.result.summary)}</span>${note}`;
}
function renderActivity(d) {
  const body = $("#dash-activity");
  body.innerHTML = d.activity.length ? d.activity.map((e) => `<tr>
          <td>${relTime(e.started_ms)}</td>
          <td><span class="tag tag-${esc(e.tool)}">${esc(e.tool)}</span></td>
          <td>${esc(e.method)} ${esc(e.path)} ${e.error ? `<span class="err">${esc(e.error)}</span>` : e.status !== null ? `→ ${e.status}` : ""}</td>
        </tr>`).join("") : `<tr><td colspan="3" class="hint">nothing yet — use Repeater to see activity here</td></tr>`;
  $("#dash-activity-meta").textContent = `newest ${d.activity_shown} of ${d.activity_total}` + (d.activity_dropped ? ` · ${d.activity_dropped} dropped at the log's capacity bound` : "");
}
function renderEvents(d) {
  const body = $("#dash-events");
  body.innerHTML = d.events.length ? d.events.map((e) => `<tr>
          <td>${relTime(e.at_ms)}</td>
          <td><span class="pill pill-outline ${severityClass(e.severity)}">${esc(e.kind)}</span></td>
          <td class="${severityClass(e.severity)}">${esc(e.detail)}</td>
        </tr>`).join("") : `<tr><td colspan="3" class="hint">nothing yet — start an audit, a crawl or an attack</td></tr>`;
  $("#dash-events-meta").textContent = `newest ${d.events_shown} of ${d.events_total}` + (d.events_dropped ? ` · ${d.events_dropped} dropped at the log's capacity bound` : "");
}
function severityClass(sev) {
  return sev === "error" ? "err" : sev === "warn" ? "sev-medium" : "";
}
async function refreshScope() {
  try {
    const s = await getJSON("/api/scope");
    $("#dash-scope").textContent = s.allow_all ? "everything" : `${s.rules.length}`;
  } catch {}
}
function relTime(startedMs) {
  const diffS = Math.max(0, Math.round((Date.now() - startedMs) / 1000));
  if (diffS < 60)
    return `${diffS}s ago`;
  if (diffS < 3600)
    return `${Math.round(diffS / 60)}m ago`;
  return `${Math.round(diffS / 3600)}h ago`;
}

// src/types.ts
var EVT_SEND_TO_REPEATER = "send-to-repeater";
var EVT_SEND_TO_INTRUDER = "send-to-intruder";
var EVT_SEND_TO_COMPARER = "send-to-comparer";
var EVT_SHOW_EXCHANGE = "show-exchange";
var EVT_FILTER_HISTORY = "filter-history";

// src/contextmenu.ts
var MENU_ID = "ctx-menu";
var EDGE_MARGIN = 4;
var openMenu = null;
function isContextMenuOpen() {
  return openMenu !== null;
}
function closeContextMenu() {
  if (!openMenu)
    return;
  openMenu.remove();
  openMenu = null;
  document.removeEventListener("pointerdown", onOutsidePointer, true);
  document.removeEventListener("keydown", onMenuKey, true);
  window.removeEventListener("scroll", closeContextMenu, true);
  window.removeEventListener("resize", closeContextMenu);
  window.removeEventListener("blur", closeContextMenu);
}
function showContextMenu(x, y, items, heading) {
  closeContextMenu();
  const drawable = items.filter((i) => i.separator || i.label);
  if (drawable.length === 0)
    return;
  const el = document.createElement("div");
  el.id = MENU_ID;
  el.setAttribute("role", "menu");
  el.tabIndex = -1;
  if (heading) {
    const h = document.createElement("div");
    h.className = "ctx-head";
    h.textContent = heading;
    el.appendChild(h);
  }
  for (const item of drawable) {
    if (item.separator) {
      const sep = document.createElement("div");
      sep.className = "ctx-sep";
      el.appendChild(sep);
      continue;
    }
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ctx-item";
    btn.setAttribute("role", "menuitem");
    btn.disabled = item.disabled === true;
    btn.tabIndex = -1;
    const label = document.createElement("span");
    label.textContent = item.label ?? "";
    btn.appendChild(label);
    if (item.hint) {
      const hint = document.createElement("span");
      hint.className = "ctx-hint";
      hint.textContent = item.hint;
      btn.appendChild(hint);
    }
    btn.addEventListener("mouseenter", () => btn.focus());
    btn.addEventListener("click", () => {
      const run = item.run;
      closeContextMenu();
      if (run)
        run();
    });
    el.appendChild(btn);
  }
  el.addEventListener("contextmenu", (e) => e.preventDefault());
  el.style.left = "-9999px";
  el.style.top = "0";
  document.body.appendChild(el);
  position(el, x, y);
  openMenu = el;
  document.addEventListener("pointerdown", onOutsidePointer, true);
  document.addEventListener("keydown", onMenuKey, true);
  window.addEventListener("scroll", closeContextMenu, true);
  window.addEventListener("resize", closeContextMenu);
  window.addEventListener("blur", closeContextMenu);
  el.focus({ preventScroll: true });
}
function position(el, x, y) {
  const r = el.getBoundingClientRect();
  const maxX = window.innerWidth - EDGE_MARGIN;
  const maxY = window.innerHeight - EDGE_MARGIN;
  let left = x;
  let top = y;
  if (left + r.width > maxX)
    left = x - r.width;
  if (top + r.height > maxY)
    top = y - r.height;
  el.style.left = `${Math.max(EDGE_MARGIN, left)}px`;
  el.style.top = `${Math.max(EDGE_MARGIN, top)}px`;
}
function itemsOf(menu) {
  return Array.from(menu.querySelectorAll(".ctx-item:not(:disabled)"));
}
function onOutsidePointer(e) {
  if (openMenu && !openMenu.contains(e.target))
    closeContextMenu();
}
function onMenuKey(e) {
  const menu = openMenu;
  if (!menu)
    return;
  if (e.key === "Escape") {
    e.preventDefault();
    e.stopPropagation();
    closeContextMenu();
    return;
  }
  if (e.key === "Tab") {
    e.preventDefault();
    e.stopPropagation();
    closeContextMenu();
    return;
  }
  const keys = ["ArrowDown", "ArrowUp", "Home", "End"];
  if (!keys.includes(e.key))
    return;
  const entries = itemsOf(menu);
  if (entries.length === 0)
    return;
  e.preventDefault();
  e.stopPropagation();
  const current = entries.findIndex((b) => b === document.activeElement);
  let next;
  switch (e.key) {
    case "Home":
      next = 0;
      break;
    case "End":
      next = entries.length - 1;
      break;
    case "ArrowUp":
      next = current <= 0 ? entries.length - 1 : current - 1;
      break;
    default:
      next = current === -1 || current === entries.length - 1 ? 0 : current + 1;
  }
  entries[next]?.focus();
}
function attachRowContextMenu(opts) {
  const container = typeof opts.container === "string" ? document.querySelector(opts.container) : opts.container;
  if (!container)
    return;
  container.addEventListener("contextmenu", (e) => {
    const row = e.target?.closest(opts.rowSelector);
    if (!row || !container.contains(row))
      return;
    const model = opts.resolve(row);
    if (model === null)
      return;
    const items = opts.items(model, row);
    if (items.length === 0)
      return;
    e.preventDefault();
    opts.select?.(model, row);
    showContextMenu(e.clientX, e.clientY, items, opts.heading?.(model, row));
  });
}

// src/sendto.ts
function targetOf(ex) {
  return `${ex.tls ? "https" : "http"}://${ex.host}:${ex.port}`;
}
function urlOf(ex) {
  const scheme = ex.tls ? "https" : "http";
  const defaultPort = ex.tls ? 443 : 80;
  const authority = ex.port === defaultPort ? ex.host : `${ex.host}:${ex.port}`;
  return `${scheme}://${authority}${ex.path}`;
}
async function sendToRepeater(ex) {
  try {
    const req = await getJSON(`/api/message/${ex.request}`);
    emit(EVT_SEND_TO_REPEATER, { target: targetOf(ex), raw: req.text, protocol: ex.protocol });
    switchTab("repeater");
  } catch (e) {
    toast(e.message, "error");
  }
}
function sendToIntruder(ex) {
  emit(EVT_SEND_TO_INTRUDER, { msgId: ex.request, target: targetOf(ex) });
  switchTab("intruder");
}
function sendToComparer(ex, side) {
  emit(EVT_SEND_TO_COMPARER, { side, msgId: ex.request, label: `${ex.method} ${ex.path}` });
  switchTab("comparer");
  toast(`sent request #${ex.request} to Comparer ${side.toUpperCase()}`);
}
function showInHistory(ex) {
  emit(EVT_SHOW_EXCHANGE, { exchangeId: ex.id });
  switchTab("history");
}
async function saveToOrganizer(ex) {
  try {
    await postJSON("/api/tools/organizer", { exchange: ex.id });
    toast(`saved ${ex.method} ${ex.path} to Organizer`);
  } catch (e) {
    toast(e.message, "error");
  }
}
function openUrl(ex) {
  window.open(urlOf(ex), "_blank", "noopener,noreferrer");
}
async function copyText(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`copied ${what}`);
    return;
  } catch {}
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("aria-hidden", "true");
  ta.style.position = "fixed";
  ta.style.top = "-1000px";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  ta.remove();
  toast(ok ? `copied ${what}` : `could not copy ${what} — the clipboard is blocked`, ok ? "info" : "error");
}
function shellQuote(s) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
function asCurl(ex, raw) {
  const split = raw.search(/\r?\n\r?\n/);
  const head = split === -1 ? raw : raw.slice(0, split);
  const body = split === -1 ? "" : raw.slice(split).replace(/^\r?\n\r?\n/, "");
  const lines = head.split(/\r?\n/);
  const method = (lines[0] ?? "").split(" ")[0] || ex.method || "GET";
  const parts = [`curl -i -sS -X ${method} ${shellQuote(urlOf(ex))}`];
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(":");
    if (colon <= 0)
      continue;
    if (/^content-length$/i.test(line.slice(0, colon).trim()))
      continue;
    parts.push(`-H ${shellQuote(line.trim())}`);
  }
  if (body.length > 0)
    parts.push(`--data-raw ${shellQuote(body)}`);
  return parts.join(" \\\n  ");
}
async function copyAsCurl(ex) {
  try {
    const req = await getJSON(`/api/message/${ex.request}`);
    await copyText(asCurl(ex, req.text), `#${ex.id} as curl`);
  } catch (e) {
    toast(e.message, "error");
  }
}
function exchangeActions(showHistory) {
  const actions = [
    { label: "Send to Repeater", hint: "Ctrl+R", act: (ex) => sendToRepeater(ex) },
    { label: "Send to Intruder", hint: "Ctrl+I", act: (ex) => sendToIntruder(ex) },
    { label: "Send to Comparer (A)", act: (ex) => sendToComparer(ex, "a") },
    { label: "Send to Comparer (B)", act: (ex) => sendToComparer(ex, "b") },
    { label: "Save to Organizer", before: true, act: (ex) => saveToOrganizer(ex) },
    { label: "Copy URL", before: true, act: (ex) => copyText(urlOf(ex), `#${ex.id} URL`) },
    { label: "Copy as curl", act: (ex) => copyAsCurl(ex) },
    { label: "Open URL in a new tab", act: (ex) => openUrl(ex) }
  ];
  if (showHistory) {
    actions.push({ label: "Show in History", before: true, act: (ex) => showInHistory(ex) });
  }
  return actions;
}
function toMenuItems(actions, run) {
  const items = [];
  for (const a of actions) {
    if (a.before)
      items.push({ separator: true });
    const item = { label: a.label, run: run(a) };
    if (a.hint !== undefined)
      item.hint = a.hint;
    items.push(item);
  }
  return items;
}
function exchangeMenuItems(ex, opts) {
  return toMenuItems(exchangeActions(opts?.showInHistory === true), (a) => () => void a.act(ex));
}
function exchangeIdMenuItems(id, absent = "no captured request here — nothing to send", opts) {
  if (id === null || id === undefined)
    return [{ label: absent, disabled: true }];
  return toMenuItems(exchangeActions(opts?.showInHistory === true), (a) => () => void withExchange(id, (ex) => a.act(ex)));
}
async function withExchange(id, fn) {
  try {
    const ex = await getJSON(`/api/exchange/${id}`);
    await fn(ex);
  } catch (e) {
    toast(e.message, "error");
  }
}
async function fetchExchange(id) {
  try {
    return await getJSON(`/api/exchange/${id}`);
  } catch (e) {
    toast(e.message, "error");
    return null;
  }
}

// src/shortcuts.ts
var rowSources = new Map;
function registerRowTarget(tabId, get) {
  rowSources.set(tabId, get);
}
function activeTabId() {
  return $("main > section.on")?.id ?? null;
}
function tabLabel(tabId) {
  const btn = $all("nav button[data-t]").find((b) => b.dataset["t"] === tabId);
  return btn?.textContent?.trim() ?? tabId;
}
function activeRowSource() {
  const id = activeTabId();
  return id === null ? undefined : rowSources.get(id);
}
function hasRowSource() {
  return activeRowSource() !== undefined;
}
async function resolveTarget(t) {
  if (t.exchange)
    return t.exchange;
  if (t.exchangeId !== undefined)
    return await fetchExchange(t.exchangeId);
  toast(t.note ?? `${t.label} has no captured request to send`, "error");
  return null;
}
function sendSelected(where, keys) {
  const get = activeRowSource();
  if (!get)
    return;
  const target = get();
  if (!target) {
    const id = activeTabId();
    toast(`nothing selected — click a row in ${id ? tabLabel(id) : "this tab"} first, then press ${keys}`);
    return;
  }
  resolveTarget(target).then((ex) => {
    if (!ex)
      return;
    if (where === "repeater")
      sendToRepeater(ex);
    else
      sendToIntruder(ex);
  });
}
function moveTab(delta) {
  const buttons = $all("nav button[data-t]");
  if (buttons.length === 0)
    return;
  const current = buttons.findIndex((b) => b.classList.contains("on"));
  const from = current === -1 ? 0 : current;
  const next = buttons[((from + delta) % buttons.length + buttons.length) % buttons.length];
  const id = next?.dataset["t"];
  if (id)
    switchTab(id);
}
function mod(e) {
  return (e.ctrlKey || e.metaKey) && !e.altKey;
}
var ROW_PANES = "History, Site map, WS History, Scanner";
var BINDINGS = [
  {
    keys: "Ctrl+R",
    what: "Send the selected row to Repeater",
    where: ROW_PANES,
    when: (e) => mod(e) && !e.shiftKey && e.key.toLowerCase() === "r",
    claim: hasRowSource,
    run: () => sendSelected("repeater", "Ctrl+R")
  },
  {
    keys: "Ctrl+I",
    what: "Send the selected row to Intruder",
    where: ROW_PANES,
    when: (e) => mod(e) && !e.shiftKey && e.key.toLowerCase() === "i",
    claim: hasRowSource,
    run: () => sendSelected("intruder", "Ctrl+I")
  },
  {
    keys: "Ctrl+Enter",
    what: "Send the request being edited",
    where: "Repeater — works inside the editor",
    when: (e) => mod(e) && !e.shiftKey && e.key === "Enter",
    claim: () => activeTabId() === "repeater" && $("#rep-send") !== null,
    run: () => $("#rep-send")?.click(),
    inEditable: true
  },
  {
    keys: "Ctrl+Shift+→",
    what: "Next tab",
    where: "anywhere",
    when: (e) => mod(e) && e.shiftKey && e.key === "ArrowRight",
    run: () => moveTab(1)
  },
  {
    keys: "Ctrl+Shift+←",
    what: "Previous tab",
    where: "anywhere",
    when: (e) => mod(e) && e.shiftKey && e.key === "ArrowLeft",
    run: () => moveTab(-1)
  },
  {
    keys: "?",
    what: "Show or hide this list",
    where: "anywhere",
    when: (e) => !e.ctrlKey && !e.metaKey && !e.altKey && e.key === "?",
    run: () => toggleSheet()
  }
];
var SHEET_ID = "shortcut-sheet";
var MENU_PANES = [
  ["History", "send to Repeater / Intruder / Comparer, save to Organizer, copy URL or curl"],
  ["Site map", "the node's most recent exchange: send to any tool, copy its URL, open it in History"],
  ["WS History", "the upgrade exchange, and copy the message payload"],
  ["Scanner", "the finding's first occurrence: open it in History or send it to any tool"],
  ["Logger", "copy the host or path, or filter History by that host"]
];
function sheetHtml() {
  const rows = BINDINGS.map((b) => `<tr><td><kbd>${esc(b.keys)}</kbd></td><td>${esc(b.what)}</td><td class="hint">${esc(b.where)}</td></tr>`).join("");
  const menus = MENU_PANES.map(([pane, what]) => `<tr><td><b>${esc(pane)}</b></td><td colspan="2" class="hint">${esc(what)}</td></tr>`).join("");
  return `
    <div class="sheet">
      <div class="row">
        <b class="card-title" style="margin:0">Keyboard shortcuts</b>
        <span class="grow"></span>
        <button class="ghost small" id="sheet-close">Close</button>
      </div>
      <table>
        <thead><tr><th>Key</th><th>Does</th><th>Where</th></tr></thead>
        <tbody>
          ${rows}
          <tr><td><kbd>Esc</kbd></td><td>Close this list, or an open right-click menu</td><td class="hint">anywhere</td></tr>
        </tbody>
      </table>
      <p class="hint">On macOS press <kbd>⌘</kbd> wherever this says <kbd>Ctrl</kbd>. Tab switching
        avoids <kbd>Ctrl</kbd>+<kbd>1</kbd>..<kbd>9</kbd> because the browser reserves those for its own
        tabs and a page cannot override them. <kbd>Ctrl</kbd>+<kbd>R</kbd> stays the browser's reload on
        any tab without selectable rows.</p>
      <div class="card-title" style="margin-top:12px">Right-click a row</div>
      <table><tbody>${menus}</tbody></table>
      <p class="hint">Right-click also selects the row, so <kbd>Ctrl</kbd>+<kbd>R</kbd> afterwards acts
        on the same one.</p>
    </div>`;
}
function sheetEl() {
  return document.getElementById(SHEET_ID);
}
function closeSheet() {
  const el = sheetEl();
  if (!el)
    return;
  el.remove();
  document.removeEventListener("keydown", onSheetKey, true);
}
function openSheet() {
  if (sheetEl())
    return;
  const el = document.createElement("div");
  el.id = SHEET_ID;
  el.className = "sheet-backdrop";
  el.innerHTML = sheetHtml();
  document.body.appendChild(el);
  el.addEventListener("click", (e) => {
    if (e.target === el || e.target.id === "sheet-close")
      closeSheet();
  });
  document.addEventListener("keydown", onSheetKey, true);
}
function toggleSheet() {
  if (sheetEl())
    closeSheet();
  else
    openSheet();
}
function onSheetKey(e) {
  if (e.key === "Escape" || e.key === "?") {
    e.preventDefault();
    e.stopPropagation();
    closeSheet();
  }
}
function inEditable(target) {
  if (!(target instanceof HTMLElement))
    return false;
  if (target.isContentEditable)
    return true;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}
function onKey(e) {
  if (isContextMenuOpen())
    return;
  if (e.isComposing)
    return;
  const editable = inEditable(e.target);
  for (const b of BINDINGS) {
    if (!b.when(e))
      continue;
    if (editable && b.inEditable !== true)
      return;
    if (b.claim && !b.claim())
      return;
    e.preventDefault();
    b.run();
    return;
  }
}
function addHelpButton() {
  const header = $("header");
  if (!header || document.getElementById("shortcut-help"))
    return;
  const btn = document.createElement("button");
  btn.id = "shortcut-help";
  btn.className = "ghost small";
  btn.type = "button";
  btn.textContent = "? shortcuts";
  btn.title = "keyboard shortcuts and right-click actions (press ?)";
  btn.addEventListener("click", () => toggleSheet());
  const caLink = document.getElementById("ca-link");
  if (caLink)
    header.insertBefore(btn, caLink);
  else
    header.appendChild(btn);
}
function initShortcuts() {
  addHelpButton();
  document.addEventListener("keydown", onKey);
}

// src/history.ts
var allRows = [];
var cachedScope = null;
var queryTimer;
var selected = null;
var rendered = new Map;
function initHistory() {
  const section = $("#history");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">right-click a row for send-to actions · Ctrl+R Repeater · Ctrl+I Intruder · ? for all shortcuts</span>
      <span id="hist-note" class="hint"></span>
    </div>
    <div class="row">
      <label><input type="checkbox" class="hist-status" value="2" checked /> 2xx</label>
      <label><input type="checkbox" class="hist-status" value="3" checked /> 3xx</label>
      <label><input type="checkbox" class="hist-status" value="4" checked /> 4xx</label>
      <label><input type="checkbox" class="hist-status" value="5" checked /> 5xx</label>
      <label><input type="checkbox" id="hist-scope-only" /> in scope only</label>
      <input id="hist-search" placeholder="filter method/host/path" style="width:220px" />
      <label><input type="checkbox" id="hist-regex" /> regex</label>
    </div>
    <div class="row">
      <input id="hist-query" placeholder='query: status == 200 and host ~ "api." and not method == "OPTIONS"' style="width:100%" />
    </div>
    <table>
      <thead>
        <tr><th>#</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th>
            <th>Len</th><th>ms</th><th>TLS</th><th>Actions</th></tr>
      </thead>
      <tbody id="hist-body"></tbody>
    </table>
    <div class="two" style="margin-top:10px">
      <div><b class="muted">Request</b><pre id="hist-req">select a row</pre></div>
      <div><b class="muted">Response</b><pre id="hist-res"></pre></div>
    </div>
  `;
  $all(".hist-status").forEach((c) => c.addEventListener("change", () => applyFilter()));
  $("#hist-search").addEventListener("input", () => applyFilter());
  $("#hist-regex").addEventListener("change", () => applyFilter());
  $("#hist-query").addEventListener("input", () => {
    if (queryTimer)
      clearTimeout(queryTimer);
    queryTimer = setTimeout(() => void load(), 300);
  });
  const scopeOnly = $("#hist-scope-only");
  scopeOnly.addEventListener("change", () => {
    if (scopeOnly.checked) {
      ensureScopeLoaded().then(() => applyFilter());
    } else {
      applyFilter();
    }
  });
  on(EVT_SHOW_EXCHANGE, (d) => void loadExchangeById(d.exchangeId));
  on(EVT_FILTER_HISTORY, (d) => {
    $("#hist-search").value = d.search;
    applyFilter();
  });
  attachRowContextMenu({
    container: "#hist-body",
    rowSelector: "tr[data-id]",
    resolve: (row) => rendered.get(Number(row.dataset["id"])) ?? null,
    heading: (ex) => `#${ex.id} ${ex.method} ${ex.path}`,
    select: (ex) => markSelected(ex),
    items: (ex) => exchangeMenuItems(ex)
  });
  registerRowTarget("history", () => selected ? { label: `exchange #${selected.id}`, exchange: selected } : null);
  live({ kinds: ["history"], section: "history", refresh: () => void load() });
  load();
}
function markSelected(ex) {
  selected = ex;
  $all("#hist-body tr").forEach((tr) => tr.classList.toggle("on", Number(tr.dataset["id"]) === ex.id));
}
async function loadExchangeById(id) {
  try {
    const ex = await getJSON(`/api/exchange/${id}`);
    await openExchange(ex);
  } catch (e) {
    toast(e.message, "error");
  }
}
async function load() {
  const body = $("#hist-body");
  const q = $("#hist-query").value.trim();
  const qs = q ? `?limit=300&q=${encodeURIComponent(q)}` : "?limit=300";
  try {
    allRows = await getJSON(`/api/history${qs}`);
  } catch (e) {
    allRows = [];
    body.innerHTML = `<tr><td colspan="9" class="err"><pre style="white-space:pre;margin:0">${esc(e.message)}</pre></td></tr>`;
    return;
  }
  applyFilter();
}
async function ensureScopeLoaded() {
  if (cachedScope)
    return;
  try {
    cachedScope = await getJSON("/api/scope");
  } catch (e) {
    toast(e.message, "error");
  }
}
function applyFilter() {
  const body = $("#hist-body");
  const note = $("#hist-note");
  if (allRows.length === 0) {
    body.innerHTML = "";
    const activeQuery = $("#hist-query")?.value.trim();
    note.textContent = activeQuery ? "no history rows match the query" : "no traffic yet — set your browser proxy to this host:8080";
    return;
  }
  const checkedClasses = new Set($all(".hist-status").filter((c) => c.checked).map((c) => c.value));
  const query = $("#hist-search").value.trim();
  const useRegex = $("#hist-regex").checked;
  const scopeOnly = $("#hist-scope-only").checked;
  let re = null;
  let regexInvalid = false;
  if (useRegex && query) {
    try {
      re = new RegExp(query, "i");
    } catch {
      regexInvalid = true;
    }
  }
  const rows = allRows.filter((ex) => {
    if (!matchesStatusClass(ex, checkedClasses))
      return false;
    if (!regexInvalid && !matchesSearch(ex, query, re))
      return false;
    if (scopeOnly && cachedScope && !isInScope(ex, cachedScope))
      return false;
    return true;
  });
  body.innerHTML = rows.length ? rows.map(rowHtml).join("") : `<tr><td colspan="9" class="hint">no rows match the current filter</td></tr>`;
  wireRows(rows);
  note.textContent = regexInvalid ? "invalid regex — search ignored" : "";
}
function matchesStatusClass(ex, checkedClasses) {
  if (ex.status === null || ex.status === undefined)
    return true;
  const cls = String(ex.status)[0] ?? "";
  if (!["2", "3", "4", "5"].includes(cls))
    return true;
  return checkedClasses.has(cls);
}
function matchesSearch(ex, query, re) {
  if (!query)
    return true;
  const haystack = `${ex.method} ${ex.host} ${ex.path}`;
  if (re)
    return re.test(haystack);
  return haystack.toLowerCase().includes(query.toLowerCase());
}
function isInScope(ex, scope) {
  if (scope.allow_all)
    return true;
  let inScope = false;
  for (const rule of scope.rules) {
    if (rule.host && ex.host.includes(rule.host)) {
      inScope = rule.kind === "Include";
    }
  }
  return inScope;
}
function rowHtml(r) {
  return `<tr class="clickable" data-id="${r.id}">
    <td>${r.id}</td><td>${esc(r.method)}</td><td>${esc(r.host)}:${r.port}</td>
    <td>${esc(r.path)}</td><td>${statusBadge(r.status)}</td><td>${r.response_len}</td>
    <td>${r.duration_ms}</td><td>${r.tls ? "yes" : ""}</td>
    <td class="actions">
      <button class="ghost small" data-act="repeater">Repeater</button>
      <button class="ghost small" data-act="intruder">Intruder</button>
      <button class="ghost small" data-act="cmp-a">Cmp A</button>
      <button class="ghost small" data-act="cmp-b">Cmp B</button>
      <button class="ghost small" data-act="organize">Save</button>
    </td>
  </tr>`;
}
function wireRows(rows) {
  rendered = new Map(rows.map((r) => [r.id, r]));
  const byId = rendered;
  $all("#hist-body tr").forEach((tr) => {
    const id = Number(tr.dataset["id"]);
    const ex = byId.get(id);
    if (!ex)
      return;
    if (selected && selected.id === id)
      tr.classList.add("on");
    tr.addEventListener("click", (e) => {
      if (e.target.closest("button"))
        return;
      openExchange(ex);
    });
    $all("button", tr).forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        handleAction(btn.dataset["act"] ?? "", ex);
      });
    });
  });
}
async function openExchange(ex) {
  markSelected(ex);
  const reqEl = $("#hist-req");
  const resEl = $("#hist-res");
  reqEl.textContent = "loading…";
  resEl.textContent = "";
  try {
    const req = await getJSON(`/api/message/${ex.request}`);
    reqEl.textContent = req.text;
  } catch (e) {
    reqEl.textContent = e.message;
  }
  if (ex.response !== null) {
    try {
      const res = await getJSON(`/api/message/${ex.response}`);
      resEl.textContent = res.text;
    } catch (e) {
      resEl.textContent = e.message;
    }
  }
}
async function handleAction(act, ex) {
  markSelected(ex);
  switch (act) {
    case "repeater":
      await sendToRepeater(ex);
      break;
    case "intruder":
      sendToIntruder(ex);
      break;
    case "cmp-a":
      sendToComparer(ex, "a");
      break;
    case "cmp-b":
      sendToComparer(ex, "b");
      break;
    case "organize":
      await saveToOrganizer(ex);
      break;
    default:
      break;
  }
}

// src/wshistory.ts
var connectionsByExchange = new Map;
var currentRows = [];
var selected2 = null;
function initWshistory() {
  const section = $("#wshistory");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <label>connection
        <select id="ws-conn"><option value="">all connections</option></select>
      </label>
      <span class="hint">right-click a row for the upgrade exchange's send-to actions · ? for shortcuts</span>
      <span id="ws-meta" class="hint"></span>
    </div>
    <table>
      <thead>
        <tr><th>#</th><th>Dir</th><th>Opcode</th><th>Host</th><th>Path</th>
            <th>Len</th><th>Frames</th><th>Time</th></tr>
      </thead>
      <tbody id="ws-body"></tbody>
    </table>
    <div id="ws-detail" style="margin-top:10px">
      <b class="muted">Payload</b>
      <pre id="ws-payload">select a row</pre>
    </div>
  `;
  $("#ws-conn").addEventListener("change", () => void load2());
  attachRowContextMenu({
    container: "#ws-body",
    rowSelector: "tr[data-id]",
    resolve: (tr) => currentRows.find((r) => r.id === Number(tr.dataset["id"])) ?? null,
    heading: (row) => `message #${row.id} on exchange #${row.exchange}`,
    select: (row) => markSelected2(row),
    items: (row) => rowMenuItems(row)
  });
  registerRowTarget("wshistory", () => selected2 ? { label: `WS message #${selected2.id}`, exchangeId: selected2.exchange } : null);
  live({ kinds: ["ws"], section: "wshistory", refresh: () => void loadAll() });
  loadAll();
}
function markSelected2(row) {
  selected2 = row;
  $all("#ws-body tr").forEach((tr) => tr.classList.toggle("on", Number(tr.dataset["id"]) === row.id));
}
function rowMenuItems(row) {
  return [
    { label: "Copy this message's payload", run: () => void copyPayload(row) },
    { separator: true },
    ...exchangeIdMenuItems(row.exchange, "this message has no upgrade exchange recorded", { showInHistory: true })
  ];
}
async function copyPayload(row) {
  try {
    const msg = await getJSON(`/api/ws/message/${row.id}`);
    await copyText(msg.opcode === "text" ? msg.text : msg.hex, `message #${row.id} payload`);
  } catch (e) {
    toast(e.message, "error");
  }
}
async function loadAll() {
  try {
    const conns = await getJSON("/api/ws/connections");
    connectionsByExchange = new Map(conns.map((c) => [c.exchange, c]));
    renderConnectionOptions(conns);
  } catch (e) {
    $("#ws-meta").innerHTML = `<span class="err">${esc(e.message)}</span>`;
    return;
  }
  await load2();
}
function renderConnectionOptions(conns) {
  const sel = $("#ws-conn");
  const prev = sel.value;
  sel.innerHTML = `<option value="">all connections</option>` + conns.map((c) => `<option value="${c.exchange}">${esc(c.host)}:${c.port}${esc(c.path)} (${c.messages} messages)</option>`).join("");
  if (conns.some((c) => String(c.exchange) === prev))
    sel.value = prev;
}
async function load2() {
  const body = $("#ws-body");
  const meta = $("#ws-meta");
  const exchange = $("#ws-conn").value;
  const qs = exchange ? `?exchange=${encodeURIComponent(exchange)}&limit=300` : "?limit=300";
  try {
    const resp = await getJSON(`/api/ws/history${qs}`);
    currentRows = resp.rows;
    meta.textContent = `${resp.rows.length} of ${resp.total} message(s)`;
    body.innerHTML = resp.rows.map(rowHtml2).join("") || `<tr><td colspan="8" class="hint">no WebSocket traffic captured yet</td></tr>`;
    wireRows2();
  } catch (e) {
    body.innerHTML = `<tr><td colspan="8" class="err">${esc(e.message)}</td></tr>`;
  }
}
function directionLabel(d) {
  return d === "client_to_server" ? "→ server" : "← client";
}
function rowHtml2(r) {
  const conn = connectionsByExchange.get(r.exchange);
  const host = conn ? `${conn.host}:${conn.port}` : "";
  const path = conn ? conn.path : "";
  const time = new Date(r.at_ms).toLocaleTimeString();
  return `<tr class="clickable" data-id="${r.id}">
    <td>${r.id}</td><td>${esc(directionLabel(r.direction))}</td><td>${esc(r.opcode)}</td>
    <td>${esc(host)}</td><td>${esc(path)}</td>
    <td>${r.len}${r.truncated ? ` <span class="err" title="${r.dropped} byte(s) dropped">(truncated)</span>` : ""}</td>
    <td>${r.fragments}</td><td>${esc(time)}</td>
  </tr>`;
}
function wireRows2() {
  const byId = new Map(currentRows.map((r) => [r.id, r]));
  $all("#ws-body tr").forEach((tr) => {
    const id = Number(tr.dataset["id"]);
    const row = byId.get(id);
    if (!row)
      return;
    if (selected2 && selected2.id === id)
      tr.classList.add("on");
    tr.addEventListener("click", () => void openMessage(row));
  });
}
async function openMessage(row) {
  markSelected2(row);
  const el = $("#ws-payload");
  el.textContent = "loading…";
  let msg;
  try {
    msg = await getJSON(`/api/ws/message/${row.id}`);
  } catch (e) {
    el.textContent = e.message;
    return;
  }
  const warning = row.truncated ? `<div class="hint err">truncated: ${row.dropped} byte(s) dropped, showing only what was kept</div>` : "";
  const closeLine = msg.close ? `close ${msg.close.code}: ${msg.close.reason}

` : "";
  const body = msg.opcode === "text" ? msg.text : msg.hex;
  el.innerHTML = "";
  $("#ws-detail").querySelector(".hint.err")?.remove();
  if (warning)
    el.insertAdjacentHTML("beforebegin", warning);
  el.textContent = closeLine + body;
}

// src/sitemap.ts
var selected3 = null;
var selectedExchange = null;
var searchDebounce;
function initSitemap() {
  const section = $("#sitemap");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <button class="go" id="site-refresh">Refresh</button>
      <input id="site-q" placeholder="filter by segment or path…" style="width:220px" />
      <label><input type="checkbox" id="site-scope-only" /> in scope only</label>
      <span class="hint">right-click a node to send its latest exchange to a tool · ? for shortcuts</span>
      <span id="site-note" class="hint"></span>
      <span id="site-stale" class="hint"></span>
    </div>
    <div id="site-tree" class="tree"></div>
    <div id="site-detail"></div>
  `;
  $("#site-refresh").addEventListener("click", () => void load3());
  live({ kinds: ["history"], section: "sitemap", refresh: markTreeStale, minGapMs: 1000 });
  $("#site-q").addEventListener("input", () => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => void load3(), 300);
  });
  $("#site-scope-only").addEventListener("change", () => void load3());
  $("#site-tree").addEventListener("click", (e) => {
    const target = e.target;
    const twisty = target.closest(".twisty");
    const node = target.closest(".node");
    if (!node)
      return;
    if (twisty) {
      toggle(node);
    } else {
      select(node);
    }
  });
  attachRowContextMenu({
    container: "#site-tree",
    rowSelector: ".node",
    resolve: (node) => node,
    heading: (node) => `${node.dataset["host"] ?? ""}${node.dataset["path"] ?? ""}`,
    select: (node) => {
      if (selected3?.host !== node.dataset["host"] || selected3?.path !== node.dataset["path"])
        select(node);
    },
    items: (node) => nodeMenuItems(node)
  });
  registerRowTarget("sitemap", () => selected3 ? {
    label: `${selected3.host}${selected3.path}`,
    ...selectedExchange !== null ? { exchangeId: selectedExchange } : {},
    note: `nothing has been captured at ${selected3.host}${selected3.path} yet — there is no request to send`
  } : null);
  load3();
}
function nodeExchangeId(node) {
  const raw = node.dataset["lastExchange"];
  if (raw === undefined || raw === "")
    return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}
function nodeMenuItems(node) {
  const items = [];
  if (node.dataset["haschildren"] === "1") {
    const open = node.dataset["loaded"] === "1" && node.nextElementSibling?.style.display !== "none";
    items.push({ label: open ? "Collapse" : "Expand", run: () => void toggle(node) }, { separator: true });
  }
  items.push(...exchangeIdMenuItems(nodeExchangeId(node), "no exchange captured at this node yet", { showInHistory: true }));
  return items;
}
function query() {
  const q = $("#site-q").value.trim();
  const scopeOnly = $("#site-scope-only").checked;
  const params = new URLSearchParams;
  if (q)
    params.set("q", q);
  if (scopeOnly)
    params.set("in_scope_only", "true");
  const s = params.toString();
  return s ? `?${s}` : "";
}
var staleSince = 0;
function markTreeStale(changes) {
  if (changes <= 0)
    return;
  staleSince += changes;
  const marker = $("#site-stale");
  if (marker)
    marker.textContent = `· ${staleSince} captured since this tree was drawn — Refresh`;
}
async function load3() {
  const note = $("#site-note");
  const container = $("#site-tree");
  staleSince = 0;
  const marker = $("#site-stale");
  if (marker)
    marker.textContent = "";
  try {
    const resp = await getJSON(`/api/sitemap${query()}`);
    const matched = resp.matched != null ? ` · ${resp.matched} of ${resp.nodes} match` : "";
    note.textContent = `${resp.exchanges} exchanges · ${resp.nodes} nodes` + (resp.in_flight ? ` · ${resp.in_flight} in flight` : "") + matched;
    container.innerHTML = resp.tree.length ? `<ul>${resp.tree.map((n) => nodeLi(n, n.segment)).join("")}</ul>` : `<p class="hint">no traffic yet${resp.matched != null ? " matches the filter" : ""}</p>`;
  } catch (e) {
    container.innerHTML = `<p class="err">${esc(e.message)}</p>`;
  }
}
function nodeLi(n, rootHost) {
  const hasChildren = n.child_count > 0;
  const loaded = (n.children?.length ?? 0) > 0;
  const meta = [
    `${n.exchanges}/${n.subtree_exchanges}`,
    n.methods.length ? n.methods.join(",") : "",
    n.statuses.length ? n.statuses.join(",") : "",
    n.params.length ? `params: ${n.params.join(",")}` : ""
  ].filter(Boolean).join(" · ");
  const childrenHtml = loaded ? `<ul>${n.children.map((c) => nodeLi(c, rootHost)).join("")}</ul>` : "";
  const isSelected = selected3 && selected3.host === rootHost && selected3.path === n.path;
  return `<li>
    <div class="node${n.requested ? "" : " unrequested"}${isSelected ? " on" : ""}" data-host="${esc(rootHost)}" data-path="${esc(n.path)}"
         data-haschildren="${hasChildren ? 1 : 0}" data-loaded="${loaded ? 1 : 0}"
         data-last-exchange="${n.last_exchange ?? ""}">
      <span class="twisty">${hasChildren ? loaded ? "▾" : "▸" : "·"}</span>
      <span class="seg">${esc(n.segment)}</span>
      <span class="count">${esc(meta)}</span>
    </div>
    <div class="children"${hasChildren ? "" : ' style="display:none"'}>${childrenHtml}</div>
  </li>`;
}
async function toggle(node) {
  if (node.dataset["haschildren"] !== "1")
    return;
  const childrenDiv = node.nextElementSibling;
  if (!childrenDiv)
    return;
  const twisty = node.querySelector(".twisty");
  if (node.dataset["loaded"] === "1") {
    const open = childrenDiv.style.display !== "none";
    childrenDiv.style.display = open ? "none" : "";
    twisty.textContent = open ? "▸" : "▾";
    return;
  }
  const host = node.dataset["host"] ?? "";
  const path = node.dataset["path"] ?? "/";
  twisty.textContent = "…";
  try {
    const resp = await getJSON(`/api/sitemap?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}&depth=1${query() ? "&" + query().slice(1) : ""}`);
    const n = resp.tree[0];
    childrenDiv.innerHTML = n && (n.children?.length ?? 0) > 0 ? `<ul>${n.children.map((c) => nodeLi(c, host)).join("")}</ul>` : `<span class="hint">no children</span>`;
    node.dataset["loaded"] = "1";
    twisty.textContent = "▾";
  } catch (e) {
    childrenDiv.innerHTML = `<span class="err">${esc(e.message)}</span>`;
    twisty.textContent = "▸";
  }
}
async function select(node) {
  const host = node.dataset["host"] ?? "";
  const path = node.dataset["path"] ?? "/";
  if (selected3 && selected3.host === host && selected3.path === path) {
    selected3 = null;
    selectedExchange = null;
    $("#site-detail").innerHTML = "";
    node.classList.remove("on");
    return;
  }
  selected3 = { host, path };
  selectedExchange = nodeExchangeId(node);
  $("#site-tree").querySelectorAll(".node.on").forEach((n) => n.classList.remove("on"));
  node.classList.add("on");
  const out = $("#site-detail");
  out.innerHTML = `<p class="hint">loading…</p>`;
  try {
    const resp = await getJSON(`/api/sitemap?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}&depth=0`);
    const n = resp.tree[0];
    if (!n) {
      out.innerHTML = `<p class="err">node not found</p>`;
      return;
    }
    if (selected3?.host === host && selected3?.path === path)
      selectedExchange = n.last_exchange;
    await renderDetail(n, host);
  } catch (e) {
    out.innerHTML = `<p class="err">${esc(e.message)}</p>`;
  }
}
var DETAIL_EXCHANGE_LIMIT = 25;
async function renderDetail(n, rootHost) {
  const out = $("#site-detail");
  const ids = (n.recent_exchanges ?? []).slice(0, DETAIL_EXCHANGE_LIMIT);
  const [exchanges, findings] = await Promise.all([loadExchanges(ids), loadFindingsFor(n.path)]);
  const exRows = exchanges.length ? exchanges.map((e) => `<tr class="clickable" data-exchange-id="${e.id}">` + `<td>${e.id}</td><td>${esc(e.method)}</td><td>${e.status ?? ""}</td>` + `<td>${e.response_len}</td><td>${e.duration_ms} ms</td></tr>`).join("") : `<tr><td colspan="5" class="hint">no captured exchanges at this exact node</td></tr>`;
  const total = n.exchanges;
  const shownNote = total > ids.length ? `showing newest ${ids.length} of ${total}` : `${total} exchange${total === 1 ? "" : "s"}`;
  const findingRows = findings.length ? findings.map((f) => `<div class="row">` + `<span class="sev-${esc(f.severity.toLowerCase())}">${esc(f.severity)}</span>` + `<b>${esc(f.issue_name ?? f.check_name)}</b>` + `<span class="grow"></span>` + `<button class="ghost small" data-jump-finding="${f.id}">view in Scanner</button>` + `</div>`).join("") : `<span class="hint">no findings recorded at this exact path</span>`;
  out.innerHTML = `
    <div class="card">
      <div class="row">
        <b class="card-title">${esc(rootHost)}${esc(n.path)}</b>
        <span class="hint">${shownNote}</span>
      </div>
      <table>
        <thead><tr><th>id</th><th>method</th><th>status</th><th>len</th><th>duration</th></tr></thead>
        <tbody>${exRows}</tbody>
      </table>
      <div class="stack" style="margin-top:8px">
        <b class="muted">Findings</b>
        ${findingRows}
      </div>
    </div>
  `;
  out.querySelectorAll("tr[data-exchange-id]").forEach((row) => {
    row.addEventListener("click", () => {
      emit(EVT_SHOW_EXCHANGE, { exchangeId: Number(row.dataset["exchangeId"]) });
      switchTab("history");
    });
  });
  out.querySelectorAll("button[data-jump-finding]").forEach((btn) => {
    btn.addEventListener("click", () => switchTab("scanner"));
  });
}
async function loadExchanges(ids) {
  const results = await Promise.all(ids.map((id) => getJSON(`/api/exchange/${id}`).catch(() => null)));
  return results.filter((e) => e !== null);
}
async function loadFindingsFor(path) {
  try {
    const resp = await getJSON("/api/issues");
    return resp.findings.filter((f) => f.occurrences.some((o) => o.path === path));
  } catch {
    return [];
  }
}

// src/repeater.ts
var DEFAULT_RAW = `GET / HTTP/1.1\r
Host: example.com\r
User-Agent: burpsy\r
Connection: close\r
\r
`;
var tabs = [];
var activeId = 0;
var nextId = 1;
function initRepeater() {
  const section = $("#repeater");
  if (!section)
    return;
  section.innerHTML = `
    <div class="tabstrip" id="rep-tabs"></div>
    <div class="row">
      <input id="rep-target" placeholder="http://host:port or https://host" style="width:340px" />
      <select id="rep-protocol" title="protocol to send this request over (H2-01)">
        <option value="Http1">HTTP/1.1</option>
        <option value="Http2">HTTP/2</option>
      </select>
      <button class="go" id="rep-send">Send</button>
      <span id="rep-meta" class="hint"></span>
    </div>
    <div class="two">
      <textarea id="rep-raw" spellcheck="false"></textarea>
      <pre id="rep-res"></pre>
    </div>
  `;
  $("#rep-send").addEventListener("click", () => void send());
  $("#rep-tabs").addEventListener("click", (e) => onTabStripClick(e));
  addTab();
  on(EVT_SEND_TO_REPEATER, (d) => {
    addTab({ target: d.target, raw: d.raw, protocol: d.protocol });
    toast(`loaded into Repeater (tab ${activeId})`);
  });
}
function onTabStripClick(e) {
  const target = e.target;
  if (target.id === "rep-tab-add") {
    addTab();
    return;
  }
  const closeId = target.dataset["close"];
  if (closeId) {
    closeTab(Number(closeId));
    return;
  }
  const item = target.closest(".tab-item");
  if (item?.dataset["id"])
    selectTab(Number(item.dataset["id"]));
}
function renderTabs() {
  const el = $("#rep-tabs");
  if (!el)
    return;
  el.innerHTML = tabs.map((t) => `<div class="tab-item${t.id === activeId ? " on" : ""}" data-id="${t.id}">${t.id}` + `<span class="tab-close" data-close="${t.id}" title="close tab">&times;</span></div>`).join("") + `<button class="tab-add" id="rep-tab-add" title="new tab">+</button>`;
}
function saveEditorIntoActiveTab() {
  const tab = tabs.find((t) => t.id === activeId);
  if (!tab)
    return;
  tab.target = $("#rep-target").value;
  tab.raw = $("#rep-raw").value;
  tab.protocol = $("#rep-protocol").value;
}
function loadActiveIntoEditor() {
  const tab = tabs.find((t) => t.id === activeId);
  if (!tab)
    return;
  $("#rep-target").value = tab.target;
  $("#rep-raw").value = tab.raw;
  $("#rep-protocol").value = tab.protocol;
  $("#rep-meta").innerHTML = tab.request_msg_id ? `${statusBadge(tab.status)} · ${tab.duration_ms} ms · req msg ${tab.request_msg_id}` : "";
  $("#rep-res").textContent = tab.response;
}
function addTab(opts) {
  if (tabs.length > 0)
    saveEditorIntoActiveTab();
  const tab = {
    id: nextId++,
    target: opts?.target ?? "",
    raw: opts?.raw ?? DEFAULT_RAW,
    protocol: opts?.protocol ?? "Http1",
    status: null,
    duration_ms: null,
    request_msg_id: null,
    response: ""
  };
  tabs.push(tab);
  activeId = tab.id;
  renderTabs();
  loadActiveIntoEditor();
}
function selectTab(id) {
  if (id === activeId)
    return;
  saveEditorIntoActiveTab();
  activeId = id;
  renderTabs();
  loadActiveIntoEditor();
}
function closeTab(id) {
  const idx = tabs.findIndex((t) => t.id === id);
  if (idx === -1)
    return;
  if (tabs.length === 1) {
    tabs[0] = { id: tabs[0].id, target: "", raw: DEFAULT_RAW, protocol: "Http1", status: null, duration_ms: null, request_msg_id: null, response: "" };
    activeId = tabs[0].id;
  } else {
    tabs.splice(idx, 1);
    if (activeId === id)
      activeId = tabs[Math.min(idx, tabs.length - 1)].id;
  }
  renderTabs();
  loadActiveIntoEditor();
}
async function send() {
  saveEditorIntoActiveTab();
  const tab = tabs.find((t) => t.id === activeId);
  if (!tab)
    return;
  const sendingId = tab.id;
  $("#rep-res").textContent = "sending…";
  try {
    const d = await postJSON("/api/repeater/send", {
      target: tab.target,
      raw: tab.raw,
      protocol: tab.protocol
    });
    tab.status = d.status;
    tab.duration_ms = d.duration_ms;
    tab.request_msg_id = d.request_msg_id;
    tab.response = d.response;
    if (activeId === sendingId) {
      $("#rep-meta").innerHTML = `${statusBadge(d.status)} · ${d.duration_ms} ms · req msg ${d.request_msg_id}`;
      $("#rep-res").textContent = d.response;
    }
  } catch (e) {
    if (activeId === sendingId) {
      $("#rep-res").innerHTML = `<span class="err">${esc(e.message)}</span>`;
    }
  }
}

// src/intruder.ts
var DEFAULT_PAYLOADS = [`'
`, '"', "../../etc/passwd", "{{7*7}}", "<script>"].join(",");
var SINGLE = -1;
var points = [];
var selected4 = new Set;
var mode = "sniper";
var sources = new Map;
function sourceFor(idx) {
  let s = sources.get(idx);
  if (!s) {
    s = {
      kind: "list",
      list: DEFAULT_PAYLOADS,
      numbers: { from: 1, to: 100, step: 1, order: "sequential", count: 0, base: "decimal", pad_to: 0 },
      dates: { from: "2024-01-01", to: "2024-01-31", step: 1, format: "yyyy-MM-dd" },
      bruteForce: { charset: "abc123", min_len: 1, max_len: 3 },
      customIter: { text: `adm,usr
1,2,3`, separator: "-" },
      nullCount: "10"
    };
    sources.set(idx, s);
  }
  return s;
}
var ruleChain = [];
function defaultRuleRow(rule = "add_prefix") {
  return { rule, text: "", pattern: "", replace: "", all: false, layer: "url", algorithm: "md5" };
}
function initIntruder() {
  const section = $("#intruder");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <input id="int-msg" placeholder="request msg id" style="width:130px" />
      <input id="int-target" placeholder="http://host:port" style="width:280px" />
      <label><input type="checkbox" id="int-all" /> all point types</label>
      <button class="go" id="int-find">Find points</button>
    </div>
    <table>
      <thead><tr><th></th><th>#</th><th>Kind</th><th>Label</th><th>Offset</th><th>Len</th><th>Current value</th></tr></thead>
      <tbody id="int-points"></tbody>
    </table>
    <div class="row" style="margin-top:10px">
      <label>mode
        <select id="int-mode">
          <option value="sniper">sniper</option>
          <option value="battering_ram">battering ram</option>
          <option value="pitchfork">pitchfork</option>
          <option value="cluster_bomb">cluster bomb</option>
        </select>
      </label>
      <button class="go" id="int-run">Attack</button>
      <span id="int-meta" class="hint"></span>
    </div>
    <div id="int-payloads" class="stack"></div>
    <div id="int-rules" class="stack" style="margin-top:10px"></div>
    <div class="row" style="margin-top:10px">
      <label>max payloads <input id="int-maxpayloads" placeholder="default" style="width:90px" /></label>
      <label>grep match <input id="int-grep-match" placeholder="regex" style="width:160px" /></label>
      <label>grep extract <input id="int-grep-extract" placeholder="regex" style="width:160px" /></label>
    </div>
    <div class="row" style="margin-top:6px">
      <label>pool name <input id="int-pool" placeholder="optional" style="width:140px" /></label>
      <label><input type="checkbox" id="int-throttle-enable" /> auto-throttle</label>
      <label>statuses <input id="int-throttle-statuses" value="429,503" style="width:90px" /></label>
      <label>after <input id="int-throttle-after" value="3" style="width:50px" /></label>
      <label>factor <input id="int-throttle-factor" value="2" style="width:50px" /></label>
      <label>recover after <input id="int-throttle-recover" value="50" style="width:60px" /></label>
    </div>
    <div id="int-report" class="hint"></div>
    <div id="int-results"></div>
  `;
  $("#int-find").addEventListener("click", () => void findPoints());
  $("#int-run").addEventListener("click", () => void runAttack());
  $("#int-mode").addEventListener("change", (e) => {
    captureSourceValues();
    mode = e.target.value;
    renderPayloadArea();
  });
  on(EVT_SEND_TO_INTRUDER, (d) => {
    $("#int-msg").value = String(d.msgId);
    $("#int-target").value = d.target;
  });
  renderPayloadArea();
  renderRulesArea();
}
async function findPoints() {
  const body = $("#int-points");
  const msgId = Number($("#int-msg").value);
  const all = $("#int-all").checked;
  selected4.clear();
  for (const idx of [...sources.keys()]) {
    if (idx !== SINGLE)
      sources.delete(idx);
  }
  try {
    points = await postJSON("/api/intruder/points", { msg_id: msgId, all });
  } catch (e) {
    points = [];
    body.innerHTML = `<tr><td colspan="7" class="err">${esc(e.message)}</td></tr>`;
    renderPayloadArea();
    return;
  }
  renderPointsTable();
  renderPayloadArea();
}
function renderPointsTable() {
  const body = $("#int-points");
  body.innerHTML = points.map((p) => `<tr><td><input type="checkbox" class="int-pt" data-idx="${p.index}" ${selected4.has(p.index) ? "checked" : ""} /></td>
           <td>${p.index}</td><td>${esc(p.kind)}</td><td>${esc(p.label)}</td><td>${p.offset}</td><td>${p.len}</td><td>${esc(p.current)}</td></tr>`).join("") || `<tr><td colspan="7" class="hint">no insertion points found</td></tr>`;
  $all("#int-points .int-pt").forEach((cb) => {
    cb.addEventListener("change", () => {
      captureSourceValues();
      const idx = Number(cb.dataset["idx"]);
      if (cb.checked)
        selected4.add(idx);
      else
        selected4.delete(idx);
      renderPayloadArea();
    });
  });
}
function pointLabel(p) {
  return `#${p.index} ${p.kind}${p.label ? ` (${p.label})` : ""}`;
}
function captureSourceValues() {
  $all(".int-src-list").forEach((el) => {
    sourceFor(Number(el.dataset["idx"])).list = el.value;
  });
  $all(".int-source-body").forEach((el) => {
    const bodyEl = el;
    const idx = Number(bodyEl.dataset["idx"]);
    const s = sourceFor(idx);
    const str = (f) => bodyEl.querySelector(`[data-f="${f}"]`)?.value ?? "";
    const num = (f) => Number(str(f)) || 0;
    switch (s.kind) {
      case "numbers": {
        const seedRaw = str("seed").trim();
        s.numbers = {
          from: num("from"),
          to: num("to"),
          step: num("step"),
          order: bodyEl.querySelector(`[data-f="order"]`)?.value || "sequential",
          count: num("count"),
          base: bodyEl.querySelector(`[data-f="base"]`)?.value || "decimal",
          pad_to: num("pad_to"),
          seed: seedRaw === "" ? undefined : Number(seedRaw)
        };
        break;
      }
      case "dates":
        s.dates = { from: str("from"), to: str("to"), step: num("step"), format: str("format") };
        break;
      case "brute_force":
        s.bruteForce = { charset: str("charset"), min_len: num("min_len"), max_len: num("max_len") };
        break;
      case "custom_iterator":
        s.customIter = { text: str("positions"), separator: str("separator") };
        break;
      case "null":
        s.nullCount = str("count");
        break;
      case "list":
        break;
    }
  });
}
function renderPayloadArea() {
  const area = $("#int-payloads");
  const sel = [...selected4].sort((a, b) => a - b);
  if (mode === "sniper" || mode === "battering_ram") {
    area.innerHTML = renderSourceBlock(SINGLE, "");
    wireSourceControls();
    return;
  }
  if (sel.length === 0) {
    area.innerHTML = `<div class="hint">select 2-20 insertion points above for ${esc(mode)}</div>`;
    return;
  }
  area.innerHTML = sel.map((idx) => {
    const p = points[idx];
    const label = p ? pointLabel(p) : `#${idx}`;
    return renderSourceBlock(idx, `<label style="width:220px">${esc(label)}</label>`);
  }).join("");
  wireSourceControls();
}
function renderSourceBlock(idx, labelHtml) {
  const s = sourceFor(idx);
  const options = [
    ["list", "list"],
    ["numbers", "numbers"],
    ["dates", "dates"],
    ["brute_force", "brute forcer"],
    ["custom_iterator", "custom iterator"],
    ["null", "null payloads"]
  ];
  return `<div class="row int-source-row">
      ${labelHtml}
      <select class="int-src-kind" data-idx="${idx}">
        ${options.map(([v, label]) => `<option value="${v}" ${s.kind === v ? "selected" : ""}>${label}</option>`).join("")}
      </select>
    </div>
    <div class="int-source-body" data-idx="${idx}">${sourceBodyHtml(idx, s)}</div>`;
}
function sourceBodyHtml(idx, s) {
  switch (s.kind) {
    case "list":
      return `<div class="row">
        <textarea class="int-src-list" data-idx="${idx}" placeholder="payloads, comma separated"
                  style="width:400px;min-height:60px">${esc(s.list)}</textarea>
        <label class="hint">load from file <input type="file" class="int-src-file" data-idx="${idx}" /></label>
      </div>`;
    case "numbers":
      return `<div class="row">
        <label>from <input class="int-src-f" data-f="from" data-idx="${idx}" style="width:80px" value="${s.numbers.from}" /></label>
        <label>to <input class="int-src-f" data-f="to" data-idx="${idx}" style="width:80px" value="${s.numbers.to}" /></label>
        <label>step <input class="int-src-f" data-f="step" data-idx="${idx}" style="width:60px" value="${s.numbers.step}" /></label>
        <label>order
          <select class="int-src-f" data-f="order" data-idx="${idx}">
            <option value="sequential" ${s.numbers.order === "sequential" ? "selected" : ""}>sequential</option>
            <option value="random" ${s.numbers.order === "random" ? "selected" : ""}>random</option>
          </select>
        </label>
        <label>count (random) <input class="int-src-f" data-f="count" data-idx="${idx}" style="width:70px" value="${s.numbers.count}" /></label>
        <label>base
          <select class="int-src-f" data-f="base" data-idx="${idx}">
            <option value="decimal" ${s.numbers.base === "decimal" ? "selected" : ""}>decimal</option>
            <option value="hex" ${s.numbers.base === "hex" ? "selected" : ""}>hex</option>
          </select>
        </label>
        <label>pad to <input class="int-src-f" data-f="pad_to" data-idx="${idx}" style="width:50px" value="${s.numbers.pad_to}" /></label>
        <label>seed <input class="int-src-f" data-f="seed" data-idx="${idx}" style="width:80px" value="${s.numbers.seed ?? ""}" /></label>
      </div>`;
    case "dates":
      return `<div class="row">
        <label>from <input class="int-src-f" data-f="from" data-idx="${idx}" style="width:110px" placeholder="YYYY-MM-DD" value="${esc(s.dates.from)}" /></label>
        <label>to <input class="int-src-f" data-f="to" data-idx="${idx}" style="width:110px" placeholder="YYYY-MM-DD" value="${esc(s.dates.to)}" /></label>
        <label>step (days) <input class="int-src-f" data-f="step" data-idx="${idx}" style="width:60px" value="${s.dates.step}" /></label>
        <label>format <input class="int-src-f" data-f="format" data-idx="${idx}" style="width:120px" value="${esc(s.dates.format)}" /></label>
      </div>`;
    case "brute_force":
      return `<div class="row">
        <label>charset <input class="int-src-f" data-f="charset" data-idx="${idx}" style="width:180px" value="${esc(s.bruteForce.charset)}" /></label>
        <label>min len <input class="int-src-f" data-f="min_len" data-idx="${idx}" style="width:60px" value="${s.bruteForce.min_len}" /></label>
        <label>max len <input class="int-src-f" data-f="max_len" data-idx="${idx}" style="width:60px" value="${s.bruteForce.max_len}" /></label>
      </div>`;
    case "custom_iterator":
      return `<div class="row">
        <textarea class="int-src-f" data-f="positions" data-idx="${idx}" placeholder="one slot per line, comma-separated items"
                  style="width:300px;min-height:60px">${esc(s.customIter.text)}</textarea>
        <label>separator <input class="int-src-f" data-f="separator" data-idx="${idx}" style="width:60px" value="${esc(s.customIter.separator)}" /></label>
      </div>`;
    case "null":
      return `<div class="row">
        <label>count <input class="int-src-f" data-f="count" data-idx="${idx}" style="width:70px" value="${esc(s.nullCount)}" /></label>
      </div>`;
  }
}
function wireSourceControls() {
  $all(".int-src-kind").forEach((sel) => {
    sel.addEventListener("change", () => {
      captureSourceValues();
      const idx = Number(sel.dataset["idx"]);
      sourceFor(idx).kind = sel.value;
      renderPayloadArea();
    });
  });
  $all(".int-src-file").forEach((input) => {
    input.addEventListener("change", () => {
      const idx = Number(input.dataset["idx"]);
      const file = input.files?.[0];
      if (!file)
        return;
      const reader = new FileReader;
      reader.onload = () => {
        const text = typeof reader.result === "string" ? reader.result : "";
        const lines = text.split(`
`).map((l) => l.replace(/\r$/, ""));
        if (lines.length > 0 && lines[lines.length - 1] === "")
          lines.pop();
        sourceFor(idx).list = lines.join(",");
        renderPayloadArea();
      };
      reader.readAsText(file);
    });
  });
}
function buildPayloadSource(idx) {
  const s = sourceFor(idx);
  switch (s.kind) {
    case "list":
      return { type: "list", items: s.list.split(",") };
    case "numbers":
      return { type: "numbers", ...s.numbers };
    case "dates":
      return { type: "dates", ...s.dates };
    case "brute_force":
      return { type: "brute_force", ...s.bruteForce };
    case "custom_iterator":
      return {
        type: "custom_iterator",
        positions: s.customIter.text.split(`
`).map((line) => line.split(",")).filter((slot) => slot.some((v) => v !== "")),
        separator: s.customIter.separator
      };
    case "null":
      return { type: "null", count: Number(s.nullCount) || 0 };
  }
}
function renderRulesArea() {
  const el = $("#int-rules");
  el.innerHTML = `
    <div class="row"><b>Processing rules</b><button class="ghost small" id="int-rule-add">+ add rule</button></div>
    ${ruleChain.map((r, i) => ruleRowHtml(r, i)).join("") || `<div class="hint">no processing rules</div>`}
  `;
  $("#int-rule-add").addEventListener("click", () => {
    captureRuleChain();
    ruleChain.push(defaultRuleRow());
    renderRulesArea();
  });
  wireRuleRows();
}
var RULE_OPTIONS = [
  ["add_prefix", "add prefix"],
  ["add_suffix", "add suffix"],
  ["replace", "regex replace"],
  ["uppercase", "uppercase"],
  ["lowercase", "lowercase"],
  ["encode", "encode"],
  ["decode", "decode"],
  ["hash", "hash"],
  ["skip_if_matches", "skip if matches"]
];
var ENCODE_LAYERS = ["url", "html", "base64", "base64url", "hex", "gzip", "deflate"];
function ruleRowHtml(r, i) {
  return `<div class="row int-rule-row" data-i="${i}">
    <select class="int-rule-kind" data-i="${i}">
      ${RULE_OPTIONS.map(([v, label]) => `<option value="${v}" ${r.rule === v ? "selected" : ""}>${label}</option>`).join("")}
    </select>
    ${ruleFieldsHtml(r, i)}
    <button class="ghost small" data-act="up" data-i="${i}">up</button>
    <button class="ghost small" data-act="down" data-i="${i}">down</button>
    <button class="ghost small" data-act="del" data-i="${i}">remove</button>
  </div>`;
}
function ruleFieldsHtml(r, i) {
  switch (r.rule) {
    case "add_prefix":
    case "add_suffix":
      return `<input class="int-rule-f" data-f="text" data-i="${i}" placeholder="text" style="width:160px" value="${esc(r.text)}" />`;
    case "replace":
      return `<input class="int-rule-f" data-f="pattern" data-i="${i}" placeholder="pattern" style="width:140px" value="${esc(r.pattern)}" />
        <input class="int-rule-f" data-f="replace" data-i="${i}" placeholder="replace" style="width:140px" value="${esc(r.replace)}" />
        <label><input type="checkbox" class="int-rule-f" data-f="all" data-i="${i}" ${r.all ? "checked" : ""} /> all</label>`;
    case "uppercase":
    case "lowercase":
      return "";
    case "encode":
    case "decode":
      return `<select class="int-rule-f" data-f="layer" data-i="${i}">
        ${ENCODE_LAYERS.map((l) => `<option value="${l}" ${r.layer === l ? "selected" : ""}>${l}</option>`).join("")}
      </select>`;
    case "hash":
      return `<select class="int-rule-f" data-f="algorithm" data-i="${i}">
        <option value="md5" ${r.algorithm === "md5" ? "selected" : ""}>md5</option>
        <option value="sha256" ${r.algorithm === "sha256" ? "selected" : ""}>sha256</option>
      </select>`;
    case "skip_if_matches":
      return `<input class="int-rule-f" data-f="pattern" data-i="${i}" placeholder="pattern" style="width:200px" value="${esc(r.pattern)}" />`;
  }
}
function captureRuleChain() {
  $all(".int-rule-row").forEach((row) => {
    const i = Number(row.dataset["i"]);
    const r = ruleChain[i];
    if (!r)
      return;
    const text = row.querySelector(`[data-f="text"]`);
    if (text)
      r.text = text.value;
    const pattern = row.querySelector(`[data-f="pattern"]`);
    if (pattern)
      r.pattern = pattern.value;
    const replace = row.querySelector(`[data-f="replace"]`);
    if (replace)
      r.replace = replace.value;
    const all = row.querySelector(`[data-f="all"]`);
    if (all)
      r.all = all.checked;
    const layer = row.querySelector(`[data-f="layer"]`);
    if (layer)
      r.layer = layer.value;
    const algorithm = row.querySelector(`[data-f="algorithm"]`);
    if (algorithm)
      r.algorithm = algorithm.value;
  });
}
function wireRuleRows() {
  $all(".int-rule-kind").forEach((sel) => {
    sel.addEventListener("change", () => {
      captureRuleChain();
      const i = Number(sel.dataset["i"]);
      ruleChain[i] = defaultRuleRow(sel.value);
      renderRulesArea();
    });
  });
  $all(".int-rule-row button").forEach((btn) => {
    btn.addEventListener("click", () => {
      captureRuleChain();
      const i = Number(btn.dataset["i"]);
      const act = btn.dataset["act"];
      if (act === "del") {
        ruleChain.splice(i, 1);
      } else if (act === "up" && i > 0) {
        [ruleChain[i - 1], ruleChain[i]] = [ruleChain[i], ruleChain[i - 1]];
      } else if (act === "down" && i < ruleChain.length - 1) {
        [ruleChain[i], ruleChain[i + 1]] = [ruleChain[i + 1], ruleChain[i]];
      }
      renderRulesArea();
    });
  });
}
function buildRuleSpecs() {
  return ruleChain.map((r) => {
    switch (r.rule) {
      case "add_prefix":
        return { rule: "add_prefix", text: r.text };
      case "add_suffix":
        return { rule: "add_suffix", text: r.text };
      case "replace":
        return { rule: "replace", pattern: r.pattern, replace: r.replace, all: r.all };
      case "uppercase":
        return { rule: "uppercase" };
      case "lowercase":
        return { rule: "lowercase" };
      case "encode":
        return { rule: "encode", layer: r.layer };
      case "decode":
        return { rule: "decode", layer: r.layer };
      case "hash":
        return { rule: "hash", algorithm: r.algorithm };
      case "skip_if_matches":
        return { rule: "skip_if_matches", pattern: r.pattern };
    }
  });
}
async function runAttack() {
  const meta = $("#int-meta");
  const report = $("#int-report");
  const results = $("#int-results");
  const sel = [...selected4].sort((a, b) => a - b);
  if (sel.length === 0) {
    meta.innerHTML = `<span class="err">select at least one insertion point</span>`;
    return;
  }
  if ((mode === "pitchfork" || mode === "cluster_bomb") && (sel.length < 2 || sel.length > 20)) {
    meta.innerHTML = `<span class="err">${esc(mode)} needs between 2 and 20 selected points</span>`;
    return;
  }
  captureSourceValues();
  captureRuleChain();
  const idxs = mode === "sniper" || mode === "battering_ram" ? [SINGLE] : sel;
  const anyGenerator = idxs.some((i) => sourceFor(i).kind !== "list");
  meta.textContent = "running…";
  report.innerHTML = "";
  results.innerHTML = "";
  const body = {
    msg_id: Number($("#int-msg").value),
    target: $("#int-target").value,
    all: $("#int-all").checked,
    mode,
    points: sel
  };
  if (anyGenerator) {
    body["payload_sources"] = idxs.map((i) => buildPayloadSource(i));
  } else {
    body["payload_sets"] = idxs.map((i) => sourceFor(i).list.split(","));
  }
  const rules = buildRuleSpecs();
  if (rules.length > 0)
    body["payload_rules"] = rules;
  const maxPayloadsRaw = $("#int-maxpayloads").value.trim();
  if (maxPayloadsRaw)
    body["max_payloads"] = Number(maxPayloadsRaw);
  const grepMatchRaw = $("#int-grep-match").value.trim();
  if (grepMatchRaw)
    body["grep_match"] = grepMatchRaw;
  const grepExtractRaw = $("#int-grep-extract").value.trim();
  if (grepExtractRaw)
    body["grep_extract"] = grepExtractRaw;
  const poolRaw = $("#int-pool").value.trim();
  if (poolRaw)
    body["pool"] = poolRaw;
  if ($("#int-throttle-enable").checked) {
    body["auto_throttle"] = {
      statuses: $("#int-throttle-statuses").value.split(",").map((v) => Number(v.trim())).filter((n) => Number.isFinite(n)),
      after: Number($("#int-throttle-after").value) || 0,
      factor: Number($("#int-throttle-factor").value) || 1,
      recover_after: Number($("#int-throttle-recover").value) || 0
    };
  }
  let out;
  try {
    out = await postJSON("/api/intruder/run", body);
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc(e.message)}</span>`;
    return;
  }
  if (Array.isArray(out)) {
    renderLegacyResults(out);
    return;
  }
  renderReport(out);
}
function renderLegacyResults(rows) {
  const meta = $("#int-meta");
  const results = $("#int-results");
  meta.textContent = `${rows.length} attempts`;
  results.innerHTML = `
    <table>
      <thead><tr><th>Payload</th><th>Status</th><th>Len</th><th>ms</th><th>Error</th></tr></thead>
      <tbody>
        ${rows.map((a) => `<tr><td>${esc(a.payload)}</td><td>${statusBadge(a.status)}</td><td>${a.len}</td>
               <td>${a.duration_ms}</td><td class="err">${esc(a.error ?? "")}</td></tr>`).join("")}
      </tbody>
    </table>
  `;
}
function renderReport(out) {
  const meta = $("#int-meta");
  const report = $("#int-report");
  const results = $("#int-results");
  const r = out.report;
  meta.textContent = `${r.sent} sent`;
  report.innerHTML = `
    <div class="row">
      <span>${esc(r.kind)}</span>
      <span>combinations: ${r.combinations}${r.combinations_exact ? "" : "+"}</span>
      <span>sent: ${r.sent}</span>
      <span>failed: ${r.failed}</span>
      <span>${r.elapsed_ms} ms</span>
      ${r.truncated ? `<span class="err">truncated at ${r.max_requests}</span>` : ""}
      ${r.grep_matched > 0 ? `<span>grep matched: ${r.grep_matched}</span>` : ""}
      ${r.pool ? `<span>pool: ${esc(r.pool)}</span>` : ""}
      ${r.auto_throttle_engaged > 0 ? `<span class="err">throttled ${r.auto_throttle_engaged}×</span>` : ""}
    </div>
    ${payloadSetsHtml(out.payload_sets)}
  `;
  const examplesByOrdinal = new Map(out.examples.map((e) => [e.first_ordinal, e.payloads]));
  results.innerHTML = `
    <table>
      <thead><tr><th>First #</th><th>Status</th><th>Len</th><th>Reflected</th><th>Count</th><th>Grep</th><th>Extract</th><th>Payloads</th></tr></thead>
      <tbody>
        ${r.buckets.map((b) => {
    const payloads = examplesByOrdinal.get(b.first_ordinal) ?? [];
    return `<tr><td>${b.first_ordinal}</td><td>${statusBadge(b.status)}</td><td>${b.response_len}</td>
                <td>${b.reflected ? "yes" : ""}</td><td>${b.count}</td>
                <td>${b.grep_matches > 0 ? `${b.grep_matches}/${b.count}` : ""}</td>
                <td>${esc(b.grep_extract ?? "")}</td>
                <td>${esc(payloads.join(" + "))}</td></tr>`;
  }).join("") || `<tr><td colspan="8" class="hint">no buckets</td></tr>`}
      </tbody>
    </table>
    ${r.buckets_truncated ? `<div class="hint">bucket list truncated; ${r.unbucketed} unbucketed responses</div>` : ""}
    ${r.errors.length ? `<div class="hint err">${esc(r.errors.map((e) => `${e.error} ×${e.count}`).join(", "))}</div>` : ""}
  `;
}
function payloadSetsHtml(sets) {
  if (sets.length === 0)
    return "";
  return `<div class="stack">
    ${sets.map((s, i) => {
    const total = `${s.count}/${s.total}${s.total_exact ? "" : "+"}`;
    const dropped = s.dropped.map((d) => `${esc(d.reason)} ×${d.count}`).join(", ");
    return `<div class="row">
          <span>set ${i} (${esc(s.kind)}): ${total}</span>
          ${s.truncated ? `<span class="err">truncated at ${s.max_count}</span>` : ""}
          ${s.skipped > 0 ? `<span class="err">${s.skipped} skipped${dropped ? `: ${dropped}` : ""}</span>` : ""}
        </div>`;
  }).join("")}
  </div>`;
}

// src/intercept.ts
var FIELDS = [
  { value: "host", label: "Host" },
  { value: "path", label: "Path" },
  { value: "extension", label: "File extension" },
  { value: "method", label: "Method" },
  { value: "url", label: "URL" },
  { value: "status_code", label: "Status code" },
  { value: "content_type", label: "Content type" }
];
var CATEGORIES = [
  { value: "regex", label: "Regex" },
  { value: "literal", label: "Literal" }
];
var lists = {
  request: { active: true, rules: [] },
  response: { active: false, rules: [] }
};
var selectedId = null;
var heldClock;
function initIntercept() {
  const section = $("#intercept");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <label class="switch"><input type="checkbox" id="ic-enabled" /><span class="slider"></span></label>
      <span>Intercept is on</span>
      <span id="ic-status" class="hint"></span>
      <span class="grow"></span>
    </div>
    ${rulesSectionHtml("request")}
    ${rulesSectionHtml("response")}
    <div class="row"><b>Held queue</b><span id="ic-queue-hint" class="hint"></span></div>
    <table>
      <thead><tr><th>#</th><th>Dir</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Held</th><th>Len</th></tr></thead>
      <tbody id="ic-body"></tbody>
    </table>
    <div id="ic-editor"></div>
  `;
  $("#ic-enabled").addEventListener("change", (e) => void setEnabled(e.target.checked));
  ["request", "response"].forEach(wireRulesSection);
  load4();
  loadRules("request");
  loadRules("response");
  live({ kinds: ["intercept"], section: "intercept", refresh: () => void load4(), minGapMs: 0, fallbackMs: 1500 });
}
async function setEnabled(enabled) {
  try {
    await postJSON("/api/intercept/enable", { enabled });
  } catch (e) {
    $("#ic-status").innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
  load4();
}
async function load4() {
  const body = $("#ic-body");
  const status = $("#ic-status");
  const checkbox = $("#ic-enabled");
  let resp;
  try {
    resp = await getJSON("/api/intercept");
  } catch (e) {
    status.innerHTML = `<span class="err">${esc(e.message)}</span>`;
    return;
  }
  checkbox.checked = resp.enabled;
  status.innerHTML = !resp.wired ? esc(resp.hint ?? "interception is not wired up") : `<span class="status-pill ${resp.pending ? "bad" : "off"}">${resp.pending} pending</span>`;
  $("#ic-queue-hint").textContent = queueHint(resp);
  body.innerHTML = resp.held.map((h) => `<tr class="clickable" data-id="${h.id}">
      <td>${h.id}</td><td>${esc(h.direction)}</td><td>${esc(h.method)}</td>
      <td>${esc(h.host)}:${h.port}${h.tls ? " (tls)" : ""}</td>
      <td>${esc(h.path)}</td><td>${h.status === null ? "-" : h.status}</td>
      <td class="ic-held" data-base="${h.held_ms}">${h.held_ms} ms</td><td>${h.len}</td>
    </tr>`).join("") || `<tr><td colspan="8" class="hint">nothing held</td></tr>`;
  startHeldClock(Date.now());
  $all("#ic-body tr[data-id]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const id = Number(tr.dataset["id"]);
      const h = resp.held.find((x) => x.id === id);
      if (h)
        openEditor(h);
    });
  });
  if (selectedId !== null && !resp.held.some((h) => h.id === selectedId)) {
    selectedId = null;
    $("#ic-editor").innerHTML = "";
  }
}
function startHeldClock(fetchedAt) {
  if (heldClock !== undefined) {
    clearInterval(heldClock);
    heldClock = undefined;
  }
  if ($all(".ic-held").length === 0)
    return;
  heldClock = setInterval(() => {
    const cells = $all(".ic-held");
    if (cells.length === 0) {
      if (heldClock !== undefined)
        clearInterval(heldClock);
      heldClock = undefined;
      return;
    }
    const since = Date.now() - fetchedAt;
    cells.forEach((cell) => {
      cell.textContent = `${Number(cell.dataset["base"] ?? 0) + since} ms`;
    });
  }, 1000);
}
function queueHint(resp) {
  if (!resp.wired)
    return "";
  if (!resp.enabled)
    return "the master switch is off, so nothing is held";
  const holding = [
    resp.holds_every_request ? "every request" : lists.request.active ? "matching requests" : null,
    resp.holds_every_response ? "every response" : lists.response.active ? "matching responses" : null
  ].filter((s) => s !== null);
  return holding.length ? `holding ${holding.join(" and ")}` : "interception is on, but both rule lists are switched off — nothing will be held";
}
function rulesSectionHtml(dir) {
  const noun = dir === "request" ? "requests" : "responses";
  return `<div class="card">
    <div class="row">
      <b>${dir === "request" ? "Request" : "Response"} interception rules</b>
      <label><input type="checkbox" id="ic-${dir}-active" /> hold ${noun} matching these rules</label>
      <span class="grow"></span>
      <button class="go small" id="ic-${dir}-save">Save</button>
      <span id="ic-${dir}-meta" class="hint"></span>
    </div>
    <table>
      <thead><tr>
        <th style="width:40px">On</th><th style="width:150px">Field</th><th>Match</th>
        <th style="width:110px">Kind</th><th style="width:140px">Comment</th><th style="width:80px"></th>
      </tr></thead>
      <tbody id="ic-${dir}-body"></tbody>
    </table>
    <button class="dashed" id="ic-${dir}-add">+ add rule</button>
  </div>`;
}
function wireRulesSection(dir) {
  $(`#ic-${dir}-active`).addEventListener("change", (e) => {
    lists[dir].active = e.target.checked;
    note(dir, "unsaved");
  });
  $(`#ic-${dir}-save`).addEventListener("click", () => void saveRules(dir));
  $(`#ic-${dir}-add`).addEventListener("click", () => {
    lists[dir].rules.push(defaultRule(dir));
    renderRules(dir);
    note(dir, "unsaved");
  });
}
function defaultRule(dir) {
  return {
    field: dir === "request" ? "host" : "status_code",
    enabled: true,
    string_match: "",
    category: "regex",
    comment: ""
  };
}
function note(dir, text, isError = false) {
  const el = $(`#ic-${dir}-meta`);
  if (isError)
    el.innerHTML = `<span class="err">${esc(text)}</span>`;
  else
    el.textContent = text;
}
function optionsHtml(opts, selected5) {
  return opts.map((o) => `<option value="${o.value}"${o.value === selected5 ? " selected" : ""}>${o.label}</option>`).join("");
}
function renderRules(dir) {
  const body = $(`#ic-${dir}-body`);
  const { rules } = lists[dir];
  $(`#ic-${dir}-active`).checked = lists[dir].active;
  body.innerHTML = rules.length ? rules.map((r, i) => `<tr data-idx="${i}">
      <td><input type="checkbox" class="ic-r-on"${r.enabled ? " checked" : ""} /></td>
      <td><select class="ic-r-field">${optionsHtml(FIELDS, r.field)}</select></td>
      <td><input class="ic-r-match" style="width:100%" value="${esc(r.string_match)}" placeholder="pattern to match" /></td>
      <td><select class="ic-r-cat">${optionsHtml(CATEGORIES, r.category)}</select></td>
      <td><input class="ic-r-comment" style="width:100%" value="${esc(r.comment)}" placeholder="label" /></td>
      <td><button class="ghost small ic-r-del">Remove</button></td>
    </tr>`).join("") : `<tr><td colspan="6" class="hint">no rules — every ${dir} is held while this list is on</td></tr>`;
  $all(`#ic-${dir}-body tr[data-idx]`).forEach((tr) => {
    const idx = Number(tr.dataset["idx"]);
    const rule = lists[dir].rules[idx];
    if (!rule)
      return;
    const bind = (sel, event, apply) => {
      tr.querySelector(sel).addEventListener(event, (e) => {
        apply(e.target);
        note(dir, "unsaved");
      });
    };
    bind(".ic-r-on", "change", (el) => {
      rule.enabled = el.checked;
    });
    bind(".ic-r-field", "change", (el) => {
      rule.field = el.value;
    });
    bind(".ic-r-match", "input", (el) => {
      rule.string_match = el.value;
    });
    bind(".ic-r-cat", "change", (el) => {
      rule.category = el.value;
    });
    bind(".ic-r-comment", "input", (el) => {
      rule.comment = el.value;
    });
    tr.querySelector(".ic-r-del").addEventListener("click", () => {
      lists[dir].rules = lists[dir].rules.filter((_, i) => i !== idx);
      renderRules(dir);
      note(dir, "unsaved");
    });
  });
}
function endpoint(dir) {
  return `/api/intercept/rules/${dir === "request" ? "requests" : "responses"}`;
}
async function loadRules(dir) {
  let resp;
  try {
    resp = await getJSON(endpoint(dir));
  } catch (e) {
    note(dir, e.message, true);
    return;
  }
  if (resp.wired === false) {
    note(dir, "interception is not wired up");
    return;
  }
  lists[dir] = { active: resp.active ?? false, rules: resp.rules ?? [] };
  renderRules(dir);
  note(dir, describe(dir, resp));
}
async function saveRules(dir) {
  note(dir, "saving…");
  let resp;
  try {
    resp = await putJSON(endpoint(dir), lists[dir]);
  } catch (e) {
    note(dir, e.message, true);
    return;
  }
  renderRules(dir);
  note(dir, describe(dir, resp));
  load4();
}
function describe(dir, resp) {
  if (resp.active === false)
    return `off — no ${dir} is held`;
  if (resp.unconditional)
    return `on with no conditions — every ${dir} is held`;
  if (!(resp.rules ?? []).some((r) => r.enabled)) {
    return `on, but every condition is unchecked — no ${dir} is held`;
  }
  return `on with ${resp.count ?? 0} condition(s)`;
}
function openEditor(h) {
  selectedId = h.id;
  const editor = $("#ic-editor");
  const title = h.direction === "response" ? `#${h.id} response ${h.status ?? "?"} to ${esc(h.method)} ${esc(h.host)}:${h.port}${esc(h.path)}` : `#${h.id} ${esc(h.method)} ${esc(h.host)}:${h.port}${esc(h.path)}`;
  editor.innerHTML = `
    <div class="card">
      <div class="row"><b>${title}</b></div>
      <textarea id="ic-raw" spellcheck="false">${esc(h.raw)}</textarea>
      <div class="row">
        <label><input type="checkbox" id="ic-fixlen" checked /> fix Content-Length</label>
        <button class="go" id="ic-forward">Forward</button>
        <input id="ic-reason" placeholder="drop reason (optional)" style="width:220px" />
        <button class="ghost" id="ic-drop">Drop</button>
        <span id="ic-editor-meta" class="hint"></span>
      </div>
    </div>
  `;
  $("#ic-forward").addEventListener("click", () => void forward(h.id));
  $("#ic-drop").addEventListener("click", () => void dropHeld(h.id));
}
async function forward(id) {
  const raw = $("#ic-raw").value;
  const fix = $("#ic-fixlen").checked;
  try {
    await postJSON(`/api/intercept/${id}/forward`, { raw, fix_content_length: fix });
  } catch (e) {
    $("#ic-editor-meta").innerHTML = `<span class="err">${esc(e.message)}</span>`;
    return;
  }
  selectedId = null;
  $("#ic-editor").innerHTML = "";
  load4();
}
async function dropHeld(id) {
  const reason = $("#ic-reason").value;
  try {
    await postJSON(`/api/intercept/${id}/drop`, reason ? { reason } : {});
  } catch (e) {
    $("#ic-editor-meta").innerHTML = `<span class="err">${esc(e.message)}</span>`;
    return;
  }
  selectedId = null;
  $("#ic-editor").innerHTML = "";
  load4();
}

// src/scanner.ts
var openFindingId = null;
var rendered2 = [];
var selected5 = null;
function initScanner() {
  const section = $("#scanner");
  if (!section)
    return;
  section.innerHTML = `
    ${liveAuditCardHtml("scan")}
    <div class="row">
      <span id="scan-counts"></span>
      <span class="hint">right-click a finding to open or send its first occurrence · ? for shortcuts</span>
      <span class="grow"></span>
      <span class="hint">Audit exchange:</span>
      <input id="scan-audit-id" placeholder="exchange id" style="width:110px" />
      <button class="ghost" id="scan-audit-run">Audit</button>
    </div>
    <div class="row">
      <span class="hint">Download report:</span>
      <a class="ghost" href="/api/report/html" download>HTML</a>
      <a class="ghost" href="/api/report/json" download>JSON</a>
      <a class="ghost" href="/api/report/sarif" download>SARIF</a>
    </div>
    <div id="scan-hint" class="hint"></div>
    <div id="scan-audit-out"></div>
    <table>
      <thead><tr><th>Sev</th><th>Conf</th><th>Check</th><th>Issue</th><th>Host</th><th>Seen</th><th>Detail</th></tr></thead>
      <tbody id="scan-body"></tbody>
    </table>
    <div id="scan-detail"></div>
  `;
  $("#scan-audit-run").addEventListener("click", () => void runAudit());
  mountLiveAudit("scan");
  attachRowContextMenu({
    container: "#scan-body",
    rowSelector: "tr[data-id]",
    resolve: (tr) => rendered2.find((f) => f.id === Number(tr.dataset["id"])) ?? null,
    heading: (f) => f.issue_name ?? f.check_name,
    select: (f) => markSelected3(f),
    items: (f) => findingMenuItems(f)
  });
  registerRowTarget("scanner", () => {
    if (!selected5)
      return null;
    const first = selected5.occurrences[0];
    return {
      label: `finding "${selected5.issue_name ?? selected5.check_name}"`,
      ...first ? { exchangeId: first.exchange_id } : {},
      note: "this finding has no recorded occurrence, so there is no request to send"
    };
  });
  live({ kinds: ["issues"], section: "scanner", refresh: () => void load5() });
  load5();
}
function markSelected3(f) {
  selected5 = f;
  $all("#scan-body tr").forEach((tr) => tr.classList.toggle("on", Number(tr.dataset["id"]) === f.id));
}
function findingMenuItems(f) {
  const first = f.occurrences[0];
  const items = [
    { label: "Copy finding as text", run: () => void copyText(findingAsText(f), "the finding") },
    { separator: true }
  ];
  if (!first) {
    items.push({ label: "no occurrence recorded — nothing to send", disabled: true });
    return items;
  }
  items.push({ label: `First occurrence: #${first.exchange_id} ${first.path}`, disabled: true });
  items.push(...exchangeIdMenuItems(first.exchange_id, undefined, { showInHistory: true }));
  return items;
}
function findingAsText(f) {
  return [
    `${f.severity} / ${f.confidence} confidence — ${f.issue_name ?? f.check_name}`,
    `check: ${f.check_name}`,
    `host: ${f.host}`,
    `seen: ${f.times_seen} time(s)`,
    `occurrences: ${f.occurrences.map((o) => `#${o.exchange_id} ${o.path}`).join(", ") || "none recorded"}`,
    "",
    `detail: ${f.detail ?? "none recorded"}`,
    `remediation: ${f.remediation ?? "none recorded"}`
  ].join(`
`);
}
async function load5() {
  const body = $("#scan-body");
  const counts = $("#scan-counts");
  const hint = $("#scan-hint");
  let resp;
  try {
    resp = await getJSON("/api/issues");
  } catch (e) {
    body.innerHTML = `<tr><td colspan="7" class="err">${esc(e.message)}</td></tr>`;
    return;
  }
  if (!resp.enabled) {
    hint.textContent = resp.hint ?? "passive scanning is not enabled";
    counts.textContent = "";
    body.innerHTML = "";
    return;
  }
  hint.textContent = "";
  const c = resp.counts ?? { high: 0, medium: 0, low: 0, info: 0 };
  counts.innerHTML = `<span class="sev-high">${c.high} high</span> · <span class="sev-medium">${c.medium} medium</span> · ` + `<span class="sev-low">${c.low} low</span> · <span class="sev-info">${c.info} info</span>`;
  body.innerHTML = resp.findings.map((f) => `<tr class="clickable" data-id="${f.id}">
      <td class="sev-${esc(f.severity.toLowerCase())}">${esc(f.severity)}</td>
      <td>${esc(f.confidence)}</td>
      <td>${esc(f.check_name)}</td>
      <td>${esc(f.issue_name ?? "")}</td>
      <td>${esc(f.host)}</td>
      <td>${f.times_seen}</td>
      <td>${esc(f.detail ?? "")}</td>
    </tr>`).join("") || `<tr><td colspan="7" class="hint">no findings yet</td></tr>`;
  openFindingId = null;
  $("#scan-detail").innerHTML = "";
  wireRows3(resp.findings);
}
function wireRows3(findings) {
  rendered2 = findings;
  const byId = new Map(findings.map((f) => [f.id, f]));
  if (selected5 && !byId.has(selected5.id))
    selected5 = null;
  $all("#scan-body tr").forEach((tr) => {
    const id = Number(tr.dataset["id"]);
    const f = byId.get(id);
    if (!f)
      return;
    if (selected5 && selected5.id === id) {
      selected5 = f;
      tr.classList.add("on");
    }
    tr.addEventListener("click", () => {
      markSelected3(f);
      toggleDetail(f);
    });
  });
}
function toggleDetail(f) {
  const out = $("#scan-detail");
  if (openFindingId === f.id) {
    openFindingId = null;
    out.innerHTML = "";
    return;
  }
  openFindingId = f.id;
  out.innerHTML = findingDetailHtml(f);
  $("#scan-detail-close").addEventListener("click", () => {
    openFindingId = null;
    out.innerHTML = "";
  });
  $all("button[data-exchange-id]", out).forEach((btn) => {
    btn.addEventListener("click", () => {
      const exchangeId = Number(btn.dataset["exchangeId"]);
      emit(EVT_SHOW_EXCHANGE, { exchangeId });
      switchTab("history");
    });
  });
}
function findingDetailHtml(f) {
  const occurrences = f.occurrences.length ? f.occurrences.map((o) => `<button class="ghost small" data-exchange-id="${o.exchange_id}">#${o.exchange_id} ${esc(o.path)}</button>`).join("") : `<span class="hint">no occurrences recorded</span>`;
  return `
    <div class="card">
      <div class="row">
        <b class="card-title">${esc(f.issue_name ?? f.check_name)}</b>
        <span class="sev-${esc(f.severity.toLowerCase())}">${esc(f.severity)}</span>
        <span class="pill pill-outline">${esc(f.confidence)} confidence</span>
        <span class="grow"></span>
        <button class="ghost small" id="scan-detail-close">Close</button>
      </div>
      <div class="hint">${esc(f.host)}</div>
      <div class="stack" style="margin-top:8px">
        <div>
          <b class="muted">Detail</b>
          <div class="detail-text">${esc(f.detail ?? "no detail recorded")}</div>
        </div>
        <div>
          <b class="muted">Remediation</b>
          <div class="detail-text">${esc(f.remediation ?? "no remediation recorded")}</div>
        </div>
        <div>
          <b class="muted">Occurrences (${f.occurrences.length})</b>
          <div class="actions">${occurrences}</div>
        </div>
      </div>
    </div>
  `;
}
async function runAudit() {
  const idEl = $("#scan-audit-id");
  const out = $("#scan-audit-out");
  const id = Number(idEl.value);
  if (!Number.isFinite(id) || idEl.value.trim() === "") {
    out.innerHTML = `<span class="err">enter a numeric exchange id</span>`;
    return;
  }
  out.textContent = "auditing…";
  try {
    const result = await postJSON(`/api/audit/${id}`);
    out.innerHTML = `<pre>${esc(JSON.stringify(result, null, 2))}</pre>`;
  } catch (e) {
    out.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
  load5();
}

// src/decoder.ts
var LAYERS = ["url", "html", "base64", "base64url", "hex", "gzip", "deflate", "jwt"];
var ENCODABLE_LAYERS = LAYERS.filter((l) => l !== "jwt");
var HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"];
var lastDecode = null;
var paneShowsDecode = false;
function initDecoder() {
  const el = $("#decoder");
  if (!el)
    return;
  el.innerHTML = `
    <div class="two">
      <div class="stack">
        <textarea id="dec-input" placeholder="paste text to decode / encode / hash"></textarea>
        <div class="row">
          <select id="dec-encoding">
            <option value="smart">smart</option>
            ${LAYERS.map((l) => `<option value="${l}">${l}</option>`).join("")}
          </select>
          <label><input type="checkbox" id="dec-guess" /> guess base64/hex</label>
          <button class="go" id="dec-run">Decode</button>
        </div>
        <div class="row">
          <span class="hint">view decoded output as</span>
          <label><input type="radio" name="dec-view" value="text" checked /> Text</label>
          <label><input type="radio" name="dec-view" value="hex" /> Hex</label>
        </div>
        <div class="row">
          <select id="enc-encoding">
            ${ENCODABLE_LAYERS.map((l) => `<option value="${l}">${l}</option>`).join("")}
          </select>
          <button class="go" id="enc-run">Encode</button>
        </div>
        <div class="row">
          <select id="hash-algorithm">
            ${HASH_ALGORITHMS.map((a) => `<option value="${a}">${a}</option>`).join("")}
          </select>
          <button class="go" id="hash-run">Hash</button>
          <span class="hint">one-way — there is no decode back</span>
        </div>
      </div>
      <div><pre id="dec-output"></pre></div>
    </div>
  `;
  $("#dec-run").addEventListener("click", () => void runDecode());
  $("#enc-run").addEventListener("click", () => void runEncode());
  $("#hash-run").addEventListener("click", () => void runHash());
  $all('input[name="dec-view"]').forEach((r) => {
    r.addEventListener("change", () => {
      if (paneShowsDecode && lastDecode)
        $("#dec-output").innerHTML = renderDecodeResp(lastDecode);
    });
  });
}
function viewMode() {
  return $('input[name="dec-view"]:checked')?.value === "hex" ? "hex" : "text";
}
function flagNote(flags) {
  const s = flags.filter(Boolean).join(", ");
  return s ? `
<span class="hint">(${esc(s)})</span>` : "";
}
function bytesLine(b) {
  return `${esc(b.text)}${flagNote([b.utf8 ? "" : "not-utf8", b.truncated ? "truncated" : ""])}`;
}
var HEX_COLS = 16;
var MAX_HEX_BYTES = 8192;
function hexDump(bytes) {
  const shown = bytes.subarray(0, MAX_HEX_BYTES);
  const lines = [];
  for (let off = 0;off < shown.length; off += HEX_COLS) {
    const chunk = shown.subarray(off, off + HEX_COLS);
    const cells = Array.from(chunk, (b) => b.toString(16).padStart(2, "0"));
    const ascii = Array.from(chunk, (b) => b >= 32 && b <= 126 ? String.fromCharCode(b) : ".").join("");
    const pad = "   ".repeat(HEX_COLS - cells.length);
    lines.push(`${off.toString(16).padStart(8, "0")}  ${cells.join(" ")}${pad}  |${esc(ascii)}|`);
  }
  if (!lines.length)
    return `<span class="hint">(0 bytes)</span>`;
  if (bytes.length > shown.length) {
    const rest = bytes.length - shown.length;
    lines.push(`<span class="hint">… ${rest} more bytes not dumped; switch to Text for the whole output</span>`);
  }
  return lines.join(`
`);
}
function bytesHexBlock(b) {
  const bytes = new TextEncoder().encode(b.text);
  return `${hexDump(bytes)}${flagNote([
    b.utf8 ? "" : `not-utf8: dumped from lossy text, ${bytes.length} B here vs ${b.len} B decoded`,
    b.truncated ? "truncated" : ""
  ])}`;
}
function renderDecodeResp(resp) {
  const view = viewMode();
  const lines = [
    `<b>layers:</b> ${resp.layers.length ? esc(resp.layers.join(" → ")) : "(none)"}`,
    `<b>output (${view}):</b>
${view === "hex" ? bytesHexBlock(resp.output) : bytesLine(resp.output)}`
  ];
  if (resp.mode === "smart") {
    resp.passes.forEach((p, i) => {
      lines.push(`<b>pass ${i + 1}:</b>`);
      p.runs.forEach((r) => {
        lines.push(`  ${r.layer ? esc(r.layer) : "plain"}${r.confidence ? ` (${esc(r.confidence)})` : ""} — ${esc(r.why)}`);
      });
    });
  }
  return lines.join(`
`);
}
async function runDecode() {
  const input = $("#dec-input").value;
  const encoding = $("#dec-encoding").value;
  const guess = $("#dec-guess").checked;
  const out = $("#dec-output");
  out.textContent = "decoding…";
  try {
    const resp = await postJSON("/api/tools/decode", {
      input,
      encoding,
      guess_alphabets: guess
    });
    lastDecode = resp;
    paneShowsDecode = true;
    out.innerHTML = renderDecodeResp(resp);
  } catch (e) {
    paneShowsDecode = false;
    out.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
}
async function runEncode() {
  const input = $("#dec-input").value;
  const encoding = $("#enc-encoding").value;
  const out = $("#dec-output");
  paneShowsDecode = false;
  out.textContent = "encoding…";
  try {
    const resp = await postJSON("/api/tools/encode", { input, encoding });
    out.innerHTML = `<b>${esc(resp.encoding)}:</b>
${bytesLine(resp.output)}`;
  } catch (e) {
    out.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
}
async function runHash() {
  const input = $("#dec-input").value;
  const algorithm = $("#hash-algorithm").value;
  const out = $("#dec-output");
  paneShowsDecode = false;
  out.textContent = "hashing…";
  try {
    const resp = await postJSON("/api/tools/hash", { input, algorithm });
    const bytes = resp.output.len / 2;
    out.innerHTML = `<b>${esc(resp.algorithm)}:</b>
${esc(resp.output.text)}
<span class="hint">(${bytes} bytes, hex)</span>`;
  } catch (e) {
    out.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
}

// src/comparer.ts
var hunkCount = 0;
var currentHunk = -1;
function initComparer() {
  const el = $("#comparer");
  if (!el)
    return;
  el.innerHTML = `
    <div class="two">
      <div class="stack">
        <div class="hint" id="cmp-a-label">Side A</div>
        <input id="cmp-a-msg" placeholder="msg id (optional)" style="width:140px" />
        <textarea id="cmp-a-text" placeholder="text for side A"></textarea>
      </div>
      <div class="stack">
        <div class="hint" id="cmp-b-label">Side B</div>
        <input id="cmp-b-msg" placeholder="msg id (optional)" style="width:140px" />
        <textarea id="cmp-b-text" placeholder="text for side B"></textarea>
      </div>
    </div>
    <div class="row">
      <select id="cmp-granularity"><option value="word">word</option><option value="byte">byte</option></select>
      <button class="go" id="cmp-run">Compare</button>
      <span id="cmp-meta" class="hint"></span>
    </div>
    <div class="row">
      <button class="ghost" id="cmp-hunk-prev">◀ Prev</button>
      <span id="cmp-hunk-counter" class="hint">no hunks</span>
      <button class="ghost" id="cmp-hunk-next">Next ▶</button>
    </div>
    <pre id="cmp-output"></pre>
  `;
  $("#cmp-run").addEventListener("click", () => void runCompare());
  $("#cmp-hunk-prev").addEventListener("click", () => jumpHunk(-1));
  $("#cmp-hunk-next").addEventListener("click", () => jumpHunk(1));
  updateHunkNav();
  on(EVT_SEND_TO_COMPARER, (d) => {
    $(`#cmp-${d.side}-msg`).value = String(d.msgId);
    $(`#cmp-${d.side}-label`).textContent = `Side ${d.side.toUpperCase()}: ${d.label} (msg ${d.msgId})`;
  });
}
function jumpHunk(delta) {
  if (hunkCount === 0)
    return;
  currentHunk = currentHunk === -1 ? delta > 0 ? 0 : hunkCount - 1 : (currentHunk + delta + hunkCount) % hunkCount;
  focusHunk(currentHunk);
}
function focusHunk(n) {
  const out = $("#cmp-output");
  $all(".diff-hunk-current", out).forEach((e) => e.classList.remove("diff-hunk-current"));
  const target = document.getElementById(`cmp-hunk-${n}`);
  target?.classList.add("diff-hunk-current");
  target?.scrollIntoView({ block: "center", behavior: "smooth" });
  updateHunkNav();
}
function updateHunkNav() {
  const counter = $("#cmp-hunk-counter");
  const prevBtn = $("#cmp-hunk-prev");
  const nextBtn = $("#cmp-hunk-next");
  if (hunkCount === 0) {
    counter.textContent = "no hunks";
    prevBtn.disabled = true;
    nextBtn.disabled = true;
    return;
  }
  prevBtn.disabled = false;
  nextBtn.disabled = false;
  counter.textContent = currentHunk === -1 ? `${hunkCount} hunk${hunkCount === 1 ? "" : "s"}` : `hunk ${currentHunk + 1} / ${hunkCount}`;
}
async function resolveSideText(prefix) {
  const msgRaw = $(`#cmp-${prefix}-msg`).value.trim();
  if (msgRaw) {
    const m = await getJSON(`/api/message/${msgRaw}`);
    return m.text;
  }
  return $(`#cmp-${prefix}-text`).value;
}
function byteSlice(s, offset, len) {
  const bytes = new TextEncoder().encode(s);
  return new TextDecoder().decode(bytes.slice(offset, offset + len));
}
async function runCompare() {
  const meta = $("#cmp-meta");
  const out = $("#cmp-output");
  meta.textContent = "comparing…";
  try {
    const [a, b] = await Promise.all([resolveSideText("a"), resolveSideText("b")]);
    const resp = await postJSON("/api/tools/compare", {
      a: { text: a },
      b: { text: b },
      granularity: $("#cmp-granularity").value
    });
    meta.textContent = (resp.identical ? "identical" : `${resp.deleted_tokens} deleted, ${resp.inserted_tokens} inserted`) + (resp.truncated ? " (truncated)" : "") + (resp.ops_omitted ? ` · ${resp.ops_omitted} ops omitted` : "");
    let nextHunk = 0;
    out.innerHTML = resp.ops.map((op) => {
      if (op.kind === "equal")
        return esc(byteSlice(a, op.a_offset, op.a_len));
      const cls = op.kind === "delete" ? "diff-delete" : "diff-insert";
      const n = nextHunk++;
      return `<span class="${cls}" data-hunk="${n}" id="cmp-hunk-${n}">${esc(op.text ?? "")}</span>`;
    }).join("");
    hunkCount = nextHunk;
    currentHunk = -1;
    updateHunkNav();
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc(e.message)}</span>`;
    hunkCount = 0;
    currentHunk = -1;
    updateHunkNav();
  }
}

// src/toollog.ts
var rendered3 = [];
function initToolLog() {
  const el = $("#logger");
  if (!el)
    return;
  el.innerHTML = `
    <div class="row">
      <select id="log-filter">
        <option value="">all</option>
        <option value="repeater">repeater</option>
        <option value="intruder">intruder</option>
        <option value="scanner">scanner</option>
        <option value="bcheck">bcheck</option>
      </select>
      <input id="log-search" type="search" placeholder="search host/path/method" class="grow" />
      <button class="ghost" id="log-clear">Clear</button>
      <span id="log-meta" class="hint"></span>
    </div>
    <p class="hint">Right-click a row to copy its host or path, or to filter History by that host.
      There is no send-to-Repeater here: a logged row records what burpsy sent, not a stored request
      that could be reloaded, so there is nothing to hand over.</p>
    <table>
      <thead><tr><th>#</th><th>Tool</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Len</th><th>ms</th><th>Error</th></tr></thead>
      <tbody id="log-body"></tbody>
    </table>
  `;
  $("#log-filter").addEventListener("change", () => void load6());
  $("#log-clear").addEventListener("click", () => void clear());
  let searchTimer;
  $("#log-search").addEventListener("input", () => {
    if (searchTimer)
      clearTimeout(searchTimer);
    searchTimer = setTimeout(() => void load6(), 300);
  });
  attachRowContextMenu({
    container: "#log-body",
    rowSelector: "tr[data-id]",
    resolve: (tr) => rendered3.find((e) => e.id === Number(tr.dataset["id"])) ?? null,
    heading: (e) => `${e.tool}: ${e.method} ${e.path}`,
    select: (e) => $all("#log-body tr").forEach((tr) => tr.classList.toggle("on", Number(tr.dataset["id"]) === e.id)),
    items: (e) => rowMenuItems2(e)
  });
  live({ kinds: ["toollog"], section: "logger", refresh: () => void load6() });
  load6();
}
function rowMenuItems2(e) {
  const hostPort = `${e.host}:${e.port}`;
  return [
    {
      label: `Filter History by ${e.host}`,
      run: () => {
        emit(EVT_FILTER_HISTORY, { search: e.host });
        switchTab("history");
      }
    },
    {
      label: `Filter History by ${e.path}`,
      run: () => {
        emit(EVT_FILTER_HISTORY, { search: e.path });
        switchTab("history");
      }
    },
    { separator: true },
    { label: "Copy host:port", run: () => void copyText(hostPort, hostPort) },
    { label: "Copy path", run: () => void copyText(e.path, "the path") }
  ];
}
async function load6() {
  const body = $("#log-body");
  const meta = $("#log-meta");
  const tool = $("#log-filter").value;
  const q = $("#log-search").value.trim();
  const params = new URLSearchParams;
  if (tool)
    params.set("filter", tool);
  if (q)
    params.set("search", q);
  const qs = params.toString();
  try {
    const resp = await getJSON(`/api/tools/log${qs ? `?${qs}` : ""}`);
    const active = Object.entries(resp.counts).filter(([, n]) => n > 0).map(([name, n]) => `${name} ${n}`);
    meta.textContent = `${resp.total} total${active.length ? ` (${active.join(", ")})` : ""}` + (resp.dropped ? ` · ${resp.dropped} dropped (capacity)` : "");
    rendered3 = resp.entries;
    body.innerHTML = resp.entries.map((e) => `<tr data-id="${e.id}">
        <td>${e.id}</td><td>${esc(e.tool)}</td><td>${esc(e.method)}</td>
        <td>${esc(e.host)}:${e.port}</td><td>${esc(e.path)}</td>
        <td>${statusBadge(e.status)}</td><td>${e.response_len}</td><td>${e.duration_ms}</td>
        <td class="err">${esc(e.error ?? "")}</td>
      </tr>`).join("") || `<tr><td colspan="9" class="hint">nothing logged yet</td></tr>`;
  } catch (e) {
    body.innerHTML = `<tr><td colspan="9" class="err">${esc(e.message)}</td></tr>`;
  }
}
async function clear() {
  try {
    await delJSON("/api/tools/log");
    load6();
  } catch (e) {
    toast(e.message, "error");
  }
}

// src/organizer.ts
var HIGHLIGHTS = ["none", "red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"];
function initOrganizer() {
  const el = $("#organizer");
  if (!el)
    return;
  el.innerHTML = `
    <div class="row">
      <input id="org-add-exchange" placeholder="exchange id" style="width:120px" />
      <button class="ghost" id="org-add">Add</button>
    </div>
    <div id="org-list"></div>
  `;
  $("#org-add").addEventListener("click", () => void add());
  live({ kinds: ["organizer"], section: "organizer", refresh: () => void load7() });
  load7();
}
async function add() {
  const input = $("#org-add-exchange");
  const exchange = Number(input.value);
  if (!Number.isFinite(exchange) || input.value.trim() === "") {
    toast("enter a numeric exchange id", "error");
    return;
  }
  try {
    await postJSON("/api/tools/organizer", { exchange });
    input.value = "";
    load7();
  } catch (e) {
    toast(e.message, "error");
  }
}
async function load7() {
  const list = $("#org-list");
  try {
    const resp = await getJSON("/api/tools/organizer");
    list.innerHTML = resp.items.length ? resp.items.map(itemHtml).join("") : `<p class="hint">nothing saved yet — use "Save" on a History row, or add by exchange id above</p>`;
    wireItems();
  } catch (e) {
    list.innerHTML = `<p class="err">${esc(e.message)}</p>`;
  }
}
function itemHtml(item) {
  return `<div class="card hl-${esc(item.highlight)}" data-id="${item.id}">
    <div class="row">
      <input class="org-title" value="${esc(item.title)}" style="width:260px" />
      <select class="org-highlight">
        ${HIGHLIGHTS.map((h) => `<option value="${h}" ${h === item.highlight ? "selected" : ""}>${h}</option>`).join("")}
      </select>
      <span class="hint">exchange #${item.exchange}</span>
      <span class="grow"></span>
      <button class="ghost small org-save">Save</button>
      <button class="ghost small org-remove">Remove</button>
    </div>
    <textarea class="org-note" placeholder="note" style="min-height:50px">${esc(item.note)}</textarea>
  </div>`;
}
function wireItems() {
  $all("#org-list .card").forEach((card) => {
    const id = Number(card.dataset["id"]);
    card.querySelector(".org-save").addEventListener("click", () => void save(id, card));
    card.querySelector(".org-remove").addEventListener("click", () => void remove(id));
  });
}
async function save(id, card) {
  const title = card.querySelector(".org-title").value;
  const note2 = card.querySelector(".org-note").value;
  const highlight = card.querySelector(".org-highlight").value;
  try {
    await postJSON(`/api/tools/organizer/${id}`, { title, note: note2, highlight });
    toast("saved");
    load7();
  } catch (e) {
    toast(e.message, "error");
  }
}
async function remove(id) {
  try {
    await delJSON(`/api/tools/organizer/${id}`);
    load7();
  } catch (e) {
    toast(e.message, "error");
  }
}

// src/matchreplace.ts
var TARGETS = [
  { value: "request_first_line", label: "Request line" },
  { value: "request_header", label: "Request header" },
  { value: "request_body", label: "Request body" },
  { value: "response_header", label: "Response header" },
  { value: "response_body", label: "Response body" }
];
var CATEGORIES2 = [
  { value: "regex", label: "Regex" },
  { value: "literal", label: "Literal" }
];
var TYPE_LABEL = TARGETS.reduce((acc, t) => ({ ...acc, [t.value]: t.label }), {});
var spec = { rules: [], update_content_length: false };
var editingIndex = null;
var formOpen = false;
var previewTimer;
function initMatchReplace() {
  const el = $("#matchreplace");
  if (!el)
    return;
  el.innerHTML = `
    <div class="row"><b>Rules</b><span id="mr-affects" class="hint"></span></div>
    <div class="row">
      <label><input type="checkbox" id="mr-ucl" /> fix Content-Length after a body rewrite</label>
      <button class="ghost small" id="mr-reload">Reload from server</button>
      <span id="mr-meta" class="hint"></span>
    </div>
    <table>
      <thead><tr><th style="width:40px">On</th><th>Type</th><th>Match</th><th>Replace</th><th>Comment</th><th></th></tr></thead>
      <tbody id="mr-body"></tbody>
    </table>
    <button class="dashed" id="mr-add-rule">+ add rule</button>
    <div id="mr-form"></div>

    <div class="row"><b>Dry-run test</b></div>
    <div class="row">
      <select id="mr-direction"><option value="request">request</option><option value="response">response</option></select>
      <input id="mr-host" placeholder="host" value="localhost" style="width:140px" />
      <input id="mr-port" placeholder="port" value="80" style="width:80px" />
      <input id="mr-path" placeholder="path" value="/" style="width:140px" />
      <input id="mr-method" placeholder="method" value="GET" style="width:90px" />
      <label><input type="checkbox" id="mr-tls" /> tls</label>
    </div>
    <textarea id="mr-test-text" placeholder="raw request/response text to test against" style="min-height:120px"></textarea>
    <div class="row">
      <button class="go" id="mr-test">Test</button>
      <span id="mr-test-meta" class="hint"></span>
    </div>
    <pre id="mr-test-out"></pre>
  `;
  $("#mr-reload").addEventListener("click", () => void loadRules2());
  $("#mr-add-rule").addEventListener("click", () => openForm(null));
  $("#mr-ucl").addEventListener("change", (e) => void toggleUpdateContentLength(e.target.checked));
  $("#mr-test").addEventListener("click", () => void testRules());
  ["mr-direction", "mr-host", "mr-port", "mr-path", "mr-method", "mr-tls", "mr-test-text"].forEach((id) => {
    const field = $(`#${id}`);
    field.addEventListener(changeEventFor(field), () => schedulePreview());
  });
  renderTable();
  loadRules2();
}
function changeEventFor(el) {
  if (el.tagName === "SELECT")
    return "change";
  if (el instanceof HTMLInputElement && el.type === "checkbox")
    return "change";
  return "input";
}
function directionOf(rt) {
  return rt === "response_header" || rt === "response_body" ? "response" : "request";
}
function computeAffects(s) {
  let req = false;
  let res = false;
  for (const r of s.rules) {
    if (!r.enabled)
      continue;
    if (directionOf(r.rule_type) === "request")
      req = true;
    else
      res = true;
  }
  return { req, res };
}
function updateAffectsHint() {
  const { req, res } = computeAffects(spec);
  $("#mr-affects").textContent = `affects requests: ${req} · affects responses: ${res}`;
}
function defaultRule2() {
  return {
    rule_type: "request_header",
    enabled: true,
    string_match: "",
    string_replace: "",
    category: "regex",
    comment: ""
  };
}
async function putSpec(next) {
  try {
    const resp = await putJSON("/api/tools/rules", next);
    return { ok: true, compiled: resp.compiled };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}
async function persistSpec(next) {
  const result = await putSpec(next);
  const meta = $("#mr-meta");
  if (result.ok) {
    spec = next;
    meta.textContent = `compiled ${result.compiled} rule(s)`;
    return true;
  }
  meta.innerHTML = `<span class="err">${esc(result.error)}</span>`;
  return false;
}
async function loadRules2() {
  closeForm();
  const affects = $("#mr-affects");
  try {
    const resp = await getJSON("/api/tools/rules");
    spec = resp.config;
    affects.textContent = `affects requests: ${resp.affects_requests} · affects responses: ${resp.affects_responses}`;
    renderTable();
  } catch (e) {
    affects.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
}
async function toggleEnabled(i, checked) {
  const rules = spec.rules.map((r, idx) => idx === i ? { ...r, enabled: checked } : r);
  await persistSpec({ ...spec, rules });
  renderTable();
  updateAffectsHint();
}
async function deleteRule(i) {
  const rules = spec.rules.filter((_, idx) => idx !== i);
  await persistSpec({ ...spec, rules });
  renderTable();
  updateAffectsHint();
}
async function toggleUpdateContentLength(checked) {
  const ok = await persistSpec({ ...spec, update_content_length: checked });
  if (!ok)
    $("#mr-ucl").checked = spec.update_content_length;
}
function ruleRowHtml2(r, i) {
  const scopedNote = r.scope !== undefined ? ` <span class="hint" title="has a scope condition; not editable from this UI">scoped</span>` : "";
  const queriedNote = r.query !== undefined ? ` <span class="hint" title="${esc(r.query)}">query: ${esc(r.query)}</span>` : "";
  return `<tr data-idx="${i}">
    <td><input type="checkbox" class="mr-row-enabled" ${r.enabled ? "checked" : ""} /></td>
    <td>${esc(TYPE_LABEL[r.rule_type])}</td>
    <td>${r.string_match ? esc(r.string_match) : '<span class="hint">(empty)</span>'}</td>
    <td>${r.string_replace ? esc(r.string_replace) : '<span class="hint">(empty)</span>'}</td>
    <td>${esc(r.comment)}${scopedNote}${queriedNote}</td>
    <td><div class="actions">
      <button class="ghost small mr-row-edit">Edit</button>
      <button class="ghost small mr-row-delete">Delete</button>
    </div></td>
  </tr>`;
}
function renderTable() {
  const body = $("#mr-body");
  body.innerHTML = spec.rules.length ? spec.rules.map((r, i) => ruleRowHtml2(r, i)).join("") : `<tr><td colspan="6" class="hint">no rules yet — click "+ add rule" below</td></tr>`;
  $("#mr-ucl").checked = spec.update_content_length;
  $all("#mr-body tr[data-idx]").forEach((tr) => {
    const i = Number(tr.dataset["idx"]);
    tr.querySelector(".mr-row-enabled").addEventListener("change", (e) => void toggleEnabled(i, e.target.checked));
    tr.querySelector(".mr-row-edit").addEventListener("click", () => openForm(i));
    tr.querySelector(".mr-row-delete").addEventListener("click", () => void deleteRule(i));
  });
}
function optionsHtml2(opts, selected6) {
  return opts.map((o) => `<option value="${o.value}" ${o.value === selected6 ? "selected" : ""}>${o.label}</option>`).join("");
}
function ruleFormHtml(rule, isNew) {
  return `<div class="card">
    <div class="row"><b>${isNew ? "Add rule" : "Edit rule"}</b></div>
    <div class="row">
      <label><input type="checkbox" id="mrf-enabled" ${rule.enabled ? "checked" : ""} /> enabled</label>
      <label>Type <select id="mrf-type">${optionsHtml2(TARGETS, rule.rule_type)}</select></label>
      <label>Category <select id="mrf-category">${optionsHtml2(CATEGORIES2, rule.category)}</select></label>
    </div>
    <div class="row">
      <input id="mrf-match" placeholder="match (empty = add header, header rules only)" style="width:100%" value="${esc(rule.string_match)}" />
    </div>
    <div class="row">
      <input id="mrf-replace" placeholder="replace (empty = delete the matched text)" style="width:100%" value="${esc(rule.string_replace)}" />
    </div>
    <div class="row">
      <input id="mrf-comment" placeholder="comment" style="width:100%" value="${esc(rule.comment)}" />
    </div>
    <div class="row">
      <input id="mrf-query" placeholder='query (DSL-02): status == 200 and method == "POST"' style="width:100%" value="${esc(rule.query ?? "")}" />
    </div>
    <div class="row">
      <button class="go" id="mrf-save">Save rule</button>
      <button class="ghost" id="mrf-cancel">Cancel</button>
      <span id="mrf-meta" class="hint"></span>
    </div>
    <div class="row"><b>Live preview</b><span id="mrf-preview-meta" class="hint"></span></div>
    <div class="two">
      <div class="stack"><div class="hint">Original</div><pre id="mrf-preview-original"></pre></div>
      <div class="stack"><div class="hint">Auto-modified</div><pre id="mrf-preview-modified"></pre></div>
    </div>
  </div>`;
}
function openForm(idx) {
  if (previewTimer)
    clearTimeout(previewTimer);
  editingIndex = idx;
  formOpen = true;
  const rule = idx === null ? defaultRule2() : spec.rules[idx] ?? defaultRule2();
  $("#mr-form").innerHTML = ruleFormHtml(rule, idx === null);
  syncDirectionForType(rule.rule_type);
  wireForm();
  schedulePreview();
}
function closeForm() {
  editingIndex = null;
  formOpen = false;
  const host = $("#mr-form");
  if (host)
    host.innerHTML = "";
}
function syncDirectionForType(rt) {
  const dirSel = $("#mr-direction");
  if (dirSel)
    dirSel.value = directionOf(rt);
}
function wireForm() {
  $("#mrf-type").addEventListener("change", () => {
    syncDirectionForType($("#mrf-type").value);
    schedulePreview();
  });
  $("#mrf-category").addEventListener("change", () => schedulePreview());
  $("#mrf-match").addEventListener("input", () => schedulePreview());
  $("#mrf-replace").addEventListener("input", () => schedulePreview());
  $("#mrf-query").addEventListener("input", () => schedulePreview());
  $("#mrf-enabled").addEventListener("change", () => schedulePreview());
  $("#mrf-save").addEventListener("click", () => void saveForm());
  $("#mrf-cancel").addEventListener("click", () => cancelForm());
}
function readFormRule() {
  const base = editingIndex === null ? undefined : spec.rules[editingIndex];
  const rule = {
    rule_type: $("#mrf-type").value,
    enabled: $("#mrf-enabled").checked,
    string_match: $("#mrf-match").value,
    string_replace: $("#mrf-replace").value,
    category: $("#mrf-category").value,
    comment: $("#mrf-comment").value
  };
  if (base?.scope !== undefined)
    rule.scope = base.scope;
  const query2 = $("#mrf-query").value.trim();
  if (query2)
    rule.query = query2;
  return rule;
}
function buildDraftSpec(draft) {
  const rules = editingIndex === null ? [...spec.rules, draft] : spec.rules.map((r, i) => i === editingIndex ? draft : r);
  return { rules, update_content_length: spec.update_content_length };
}
function schedulePreview() {
  if (!formOpen)
    return;
  if (previewTimer)
    clearTimeout(previewTimer);
  previewTimer = setTimeout(() => void runPreview(), 300);
}
async function runPreview() {
  const metaEl = $("#mrf-preview-meta");
  const origEl = $("#mrf-preview-original");
  const modEl = $("#mrf-preview-modified");
  if (!metaEl || !origEl || !modEl)
    return;
  const sampleText = $("#mr-test-text").value;
  if (!sampleText) {
    metaEl.textContent = "enter sample text in the dry-run section below to preview";
    origEl.textContent = "";
    modEl.textContent = "";
    return;
  }
  const draftRules = buildDraftSpec(readFormRule());
  metaEl.textContent = "testing…";
  try {
    const resp = await postJSON("/api/tools/rules/test", {
      text: sampleText,
      direction: $("#mr-direction").value,
      host: $("#mr-host").value,
      port: Number($("#mr-port").value) || 80,
      path: $("#mr-path").value,
      method: $("#mr-method").value || "GET",
      tls: $("#mr-tls").checked,
      draft_rules: draftRules
    });
    metaEl.textContent = resp.changed ? "changed" : "no change";
    origEl.textContent = sampleText;
    modEl.textContent = resp.output.text;
  } catch (e) {
    metaEl.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
}
async function saveForm() {
  if (previewTimer)
    clearTimeout(previewTimer);
  const next = buildDraftSpec(readFormRule());
  const result = await putSpec(next);
  if (!result.ok) {
    $("#mrf-meta").innerHTML = `<span class="err">${esc(result.error)}</span>`;
    return;
  }
  spec = next;
  $("#mr-meta").textContent = `compiled ${result.compiled} rule(s)`;
  closeForm();
  renderTable();
  updateAffectsHint();
}
function cancelForm() {
  if (previewTimer)
    clearTimeout(previewTimer);
  closeForm();
}
async function testRules() {
  const meta = $("#mr-test-meta");
  const out = $("#mr-test-out");
  meta.textContent = "testing…";
  try {
    const resp = await postJSON("/api/tools/rules/test", {
      text: $("#mr-test-text").value,
      direction: $("#mr-direction").value,
      host: $("#mr-host").value,
      port: Number($("#mr-port").value) || 80,
      path: $("#mr-path").value,
      method: $("#mr-method").value || "GET",
      tls: $("#mr-tls").checked
    });
    meta.textContent = resp.changed ? "changed" : "no change";
    out.textContent = resp.output.text;
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
}

// src/session.ts
var DEFAULT_VALIDITY = JSON.stringify({ status_is: 200 }, null, 2);
var rules = [];
var editing = null;
var promotable = null;
function initSession() {
  const section = $("#session");
  if (!section)
    return;
  section.innerHTML = `
    <div class="card">
      <div class="row"><b>Session handling rules</b><span id="sess-hint" class="hint"></span></div>
      <div id="sess-rule-list"></div>
      <button class="dashed" id="sess-add-rule">+ add rule</button>
    </div>
    <div class="card" id="sess-editor" style="display:none">
      <div class="row"><b id="sess-editor-title">Rule</b><span id="sess-save-meta" class="hint"></span></div>
      <div class="row">
        <label>name <input id="sess-name" style="width:220px" placeholder="admin login" /></label>
        <label><input type="checkbox" id="sess-enabled" /> enabled</label>
        <label>max attempts <input id="sess-max" style="width:80px" placeholder="default" /></label>
      </div>
      <div class="two">
        <label class="stack">scope (JSON — empty applies everywhere)
          <textarea id="sess-scope" style="min-height:110px" placeholder='{"rules":[{"kind":"Include","host":"target.test"}]}'></textarea>
        </label>
        <label class="stack">validity rule (JSON)
          <textarea id="sess-validity" style="min-height:110px">${esc(DEFAULT_VALIDITY)}</textarea>
        </label>
      </div>
      <div class="row"><b>Macro steps</b><span class="hint">a later step can send an earlier step's extracted value as <code>{{name}}</code></span></div>
      <div id="sess-steps" class="stack"></div>
      <button class="dashed" id="sess-add-step">+ add step</button>
      <div class="row">
        <button class="go" id="sess-save">Save rule</button>
        <button class="ghost" id="sess-cancel">Close</button>
      </div>
    </div>
    <div class="card">
      <div class="row"><b>Log in again</b><span id="sess-login-meta" class="hint"></span></div>
      <div class="row">
        <input id="sess-probe-method" placeholder="GET" style="width:80px" />
        <input id="sess-probe-url" placeholder="http://target/whoami" style="width:320px" />
      </div>
      <textarea id="sess-probe-headers" placeholder="Header: value (one per line)" style="min-height:60px"></textarea>
      <textarea id="sess-probe-body" placeholder="body (optional)" style="min-height:60px"></textarea>
      <div class="row">
        <button class="go" id="sess-login">Log in again</button>
        <button class="ghost" id="sess-update-macro" style="display:none">Update macro from this run</button>
        <span id="sess-update-meta" class="hint"></span>
      </div>
      <div id="sess-login-out"></div>
    </div>
    <div class="card">
      <!-- The one Refresh button left on a data pane other than the site map's, and it stays because
           there is nothing to push: the coordinator's cookie jar has no enumeration API and no change
           hook, so /api/session/cookies reports "wired" with an empty table (see api_session.go). A
           live subscription would announce a kind nothing can ever emit. When the jar learns to
           enumerate itself, it gets a change signal and this button goes with the others. -->
      <div class="row"><b>Cookie jar</b><button class="ghost small" id="sess-cookies-refresh">Refresh</button></div>
      <div id="sess-cookies"></div>
    </div>
  `;
  $("#sess-add-rule").addEventListener("click", () => startDraft());
  $("#sess-add-step").addEventListener("click", () => addStepRow());
  $("#sess-save").addEventListener("click", () => void saveRule());
  $("#sess-cancel").addEventListener("click", () => closeEditor());
  $("#sess-login").addEventListener("click", () => void logInAgain());
  $("#sess-update-macro").addEventListener("click", () => void updateMacro());
  $("#sess-cookies-refresh").addEventListener("click", () => void loadCookies());
  loadRules3();
  loadCookies();
}
async function loadRules3() {
  const hint = $("#sess-hint");
  let resp;
  try {
    resp = await getJSON("/api/session/rules");
  } catch (e) {
    hint.innerHTML = `<span class="err">${esc(e.message)}</span>`;
    return;
  }
  rules = resp.rules ?? [];
  if (!resp.wired) {
    hint.textContent = resp.hint ?? "session re-login is not attached to this process";
  } else {
    hint.textContent = rules.length ? `${rules.length} rule(s)` : "no rules yet — add one";
  }
  renderList();
}
function scopeSummary(scope) {
  if (scope === undefined || scope === null)
    return "applies everywhere";
  const s = scope;
  if (s.allow_all)
    return "every host";
  const hosts = (s.rules ?? []).map((r) => `${r.kind === "Exclude" ? "-" : ""}${r.host ?? "*"}`);
  return hosts.length ? hosts.join(", ") : "empty scope";
}
function renderList() {
  const list = $("#sess-rule-list");
  if (rules.length === 0) {
    list.innerHTML = `<span class="hint">A rule names a login: which targets it covers, the steps to
      replay, and what a valid session looks like.</span>`;
    return;
  }
  list.innerHTML = rules.map((r) => `<div class="row" data-id="${r.id ?? ""}">
        <button class="ghost small rule-pick">${esc(r.name)}</button>
        <span class="pill pill-outline">${r.enabled ? "enabled" : "off"}</span>
        <span class="hint">${esc(scopeSummary(r.scope))}</span>
        <span class="hint">${r.steps.length} step(s)${r.steps.some((s) => (s.extract ?? []).length > 0) ? " · extracts" : ""}</span>
        <span class="hint">max ${esc(r.max_attempts)}</span>
        <button class="ghost small rule-del">delete</button>
      </div>`).join("");
  list.querySelectorAll(".row").forEach((row) => {
    const id = Number(row.dataset["id"]);
    row.querySelector(".rule-pick").addEventListener("click", () => openRule(id));
    row.querySelector(".rule-del").addEventListener("click", () => void deleteRule2(id));
  });
}
function openRule(id) {
  const found = rules.find((r) => r.id === id);
  if (!found)
    return;
  editing = JSON.parse(JSON.stringify(found));
  renderEditor();
}
function startDraft() {
  editing = {
    name: "",
    enabled: true,
    steps: [{ method: "POST", url: "", headers: [], body: "" }],
    validity: { status_is: 200 }
  };
  renderEditor();
}
function closeEditor() {
  editing = null;
  $("#sess-editor").style.display = "none";
}
async function deleteRule2(id) {
  const hint = $("#sess-hint");
  try {
    await delJSON(`/api/session/rules/${id}`);
  } catch (e) {
    hint.innerHTML = `<span class="err">${esc(e.message)}</span>`;
    return;
  }
  if (editing?.id === id)
    closeEditor();
  if (promotable === id)
    hideUpdateMacro();
  await loadRules3();
}
function renderEditor() {
  const rule = editing;
  if (!rule)
    return;
  $("#sess-editor").style.display = "";
  $("#sess-editor-title").textContent = rule.id === undefined ? "New rule" : `Rule ${rule.id}: ${rule.name}`;
  $("#sess-save-meta").textContent = "";
  $("#sess-name").value = rule.name;
  $("#sess-enabled").checked = rule.enabled;
  $("#sess-max").value = rule.max_attempts === undefined ? "" : String(rule.max_attempts);
  $("#sess-scope").value = rule.scope === undefined || rule.scope === null ? "" : JSON.stringify(rule.scope, null, 2);
  $("#sess-validity").value = JSON.stringify(rule.validity, null, 2);
  $("#sess-steps").innerHTML = "";
  rule.steps.forEach((s) => addStepRow(s));
}
function stepRowHtml(step, index) {
  const headers = (step?.headers ?? []).map(([k, v]) => `${k}: ${v}`).join(`
`);
  return `<div class="subsection on step">
    <div class="row">
      <span class="pill pill-outline">step ${index}</span>
      <input class="step-method" placeholder="POST" style="width:80px" value="${esc(step?.method ?? "POST")}" />
      <input class="step-url grow" placeholder="http://target/login" value="${esc(step?.url ?? "")}" />
      <button class="ghost small step-remove">remove step</button>
    </div>
    <div class="two">
      <textarea class="step-headers" placeholder="Header: value (one per line)" style="min-height:52px">${esc(headers)}</textarea>
      <textarea class="step-body" placeholder="body" style="min-height:52px">${esc(step?.body ?? "")}</textarea>
    </div>
    <div class="row"><span class="hint">extract from this step's response:</span>
      <button class="ghost small step-add-extract">+ add extraction</button>
    </div>
    <div class="extractions stack"></div>
  </div>`;
}
function addStepRow(step) {
  const container = $("#sess-steps");
  const div = document.createElement("div");
  div.innerHTML = stepRowHtml(step, container.children.length);
  const row = div.firstElementChild;
  container.appendChild(row);
  const extractions = row.querySelector(".extractions");
  row.querySelector(".step-remove").addEventListener("click", () => {
    row.remove();
    renumberSteps();
  });
  row.querySelector(".step-add-extract").addEventListener("click", () => addExtractionRow(extractions));
  (step?.extract ?? []).forEach((e) => addExtractionRow(extractions, e));
}
function renumberSteps() {
  Array.from(document.querySelectorAll("#sess-steps .step")).forEach((row, i) => {
    const label = row.querySelector(".pill");
    if (label)
      label.textContent = `step ${i}`;
  });
}
function extractionRowHtml(e) {
  const from = e?.from;
  const isHeader = typeof from === "object" && from !== null;
  const header = isHeader ? from.header : "";
  const how = e?.how;
  const kind = how === "whole" ? "whole" : how && ("json_path" in how) ? "json_path" : "regex";
  const pattern = how && typeof how === "object" && "regex" in how ? how.regex.pattern : how && typeof how === "object" && ("json_path" in how) ? how.json_path : "";
  const group = how && typeof how === "object" && "regex" in how ? how.regex.group ?? 1 : 1;
  const sel = (v, want) => v === want ? " selected" : "";
  return `<div class="row extraction">
    <input class="ex-name" placeholder="csrf" style="width:110px" value="${esc(e?.name ?? "")}" title="referred to as {{name}} by a later step" />
    <select class="ex-from">
      <option value="body"${sel("body", isHeader ? "header" : "body")}>from body</option>
      <option value="header"${sel("header", isHeader ? "header" : "body")}>from header</option>
    </select>
    <input class="ex-header" placeholder="X-Token" style="width:120px" value="${esc(header)}" />
    <select class="ex-how">
      <option value="regex"${sel("regex", kind)}>regex</option>
      <option value="json_path"${sel("json_path", kind)}>json path</option>
      <option value="whole"${sel("whole", kind)}>whole value</option>
    </select>
    <input class="ex-pattern grow" placeholder='name="csrf" value="([^"]+)"  or  data.token' value="${esc(pattern)}" />
    <input class="ex-group" style="width:56px" title="capture group" value="${esc(group)}" />
    <button class="ghost small ex-remove">remove</button>
  </div>`;
}
function addExtractionRow(container, e) {
  const div = document.createElement("div");
  div.innerHTML = extractionRowHtml(e);
  const row = div.firstElementChild;
  container.appendChild(row);
  row.querySelector(".ex-remove").addEventListener("click", () => row.remove());
  const how = row.querySelector(".ex-how");
  const from = row.querySelector(".ex-from");
  const sync = () => {
    row.querySelector(".ex-header").style.display = from.value === "header" ? "" : "none";
    row.querySelector(".ex-group").style.display = how.value === "regex" ? "" : "none";
    row.querySelector(".ex-pattern").style.display = how.value === "whole" ? "none" : "";
  };
  how.addEventListener("change", sync);
  from.addEventListener("change", sync);
  sync();
}
function parseHeaders(text) {
  return text.split(`
`).map((l) => l.trim()).filter(Boolean).map((l) => {
    const i = l.indexOf(":");
    return i === -1 ? [l, ""] : [l.slice(0, i).trim(), l.slice(i + 1).trim()];
  });
}
function collectExtractions(step) {
  return Array.from(step.querySelectorAll(".extraction")).map((row) => {
    const value = (sel) => row.querySelector(sel).value;
    const from = value(".ex-from") === "header" ? { header: value(".ex-header") } : "body";
    const pattern = value(".ex-pattern");
    let how;
    if (value(".ex-how") === "whole") {
      how = "whole";
    } else if (value(".ex-how") === "json_path") {
      how = { json_path: pattern };
    } else {
      const raw = value(".ex-group").trim();
      const group = raw === "" ? 1 : Number(raw);
      how = { regex: { pattern, group: Number.isInteger(group) && group >= 0 ? group : 1 } };
    }
    return { name: value(".ex-name"), from, how };
  });
}
function collectSteps() {
  return Array.from(document.querySelectorAll("#sess-steps .step")).map((row) => {
    const extract = collectExtractions(row);
    const step = {
      method: row.querySelector(".step-method").value || "GET",
      url: row.querySelector(".step-url").value,
      headers: parseHeaders(row.querySelector(".step-headers").value),
      body: row.querySelector(".step-body").value
    };
    if (extract.length)
      step.extract = extract;
    return step;
  });
}
async function saveRule() {
  const meta = $("#sess-save-meta");
  const fail = (msg) => {
    meta.innerHTML = `<span class="err">${esc(msg)}</span>`;
  };
  const rule = editing;
  if (!rule)
    return;
  const steps = collectSteps();
  if (steps.length === 0)
    return fail("a rule needs at least one step");
  let validity;
  try {
    validity = JSON.parse($("#sess-validity").value);
  } catch {
    return fail("the validity rule is not valid JSON");
  }
  const scopeRaw = $("#sess-scope").value.trim();
  let scope;
  if (scopeRaw) {
    try {
      scope = JSON.parse(scopeRaw);
    } catch {
      return fail("the scope is not valid JSON");
    }
  }
  const body = {
    name: $("#sess-name").value.trim(),
    enabled: $("#sess-enabled").checked,
    steps,
    validity
  };
  if (scope !== undefined)
    body.scope = scope;
  const maxRaw = $("#sess-max").value.trim();
  if (maxRaw)
    body.max_attempts = Number(maxRaw);
  try {
    const saved = rule.id === undefined ? await postJSON("/api/session/rules", body) : await putJSON(`/api/session/rules/${rule.id}`, body);
    meta.textContent = "saved";
    editing = saved.rule;
    await loadRules3();
    renderEditor();
  } catch (e) {
    fail(e.message);
  }
}
function hideUpdateMacro() {
  promotable = null;
  $("#sess-update-macro").style.display = "none";
  $("#sess-update-meta").textContent = "";
}
async function logInAgain() {
  const meta = $("#sess-login-meta");
  const out = $("#sess-login-out");
  const probe = {
    method: $("#sess-probe-method").value || "GET",
    url: $("#sess-probe-url").value,
    headers: parseHeaders($("#sess-probe-headers").value),
    body: $("#sess-probe-body").value
  };
  meta.textContent = "running…";
  out.innerHTML = "";
  hideUpdateMacro();
  try {
    const resp = await postJSON("/api/session/login", { probe });
    meta.textContent = resp.rule ? `rule: ${resp.rule}` : "";
    const good = resp.outcome === "already_valid" || resp.outcome === "recovered";
    const pill = resp.outcome ? `<span class="status-pill ${good ? "good" : "bad"}">${esc(resp.outcome)}</span>` : "";
    out.innerHTML = `${pill}<pre>${esc(JSON.stringify(resp, null, 2))}</pre>`;
    if (resp.outcome === "recovered" && typeof resp.rule_id === "number") {
      promotable = resp.rule_id;
      const button = $("#sess-update-macro");
      button.style.display = "";
      button.textContent = `Update macro of "${resp.rule ?? resp.rule_id}" from this run`;
      $("#sess-update-meta").textContent = "overwrites the stored steps with what just worked";
    }
    loadCookies();
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
}
async function updateMacro() {
  const meta = $("#sess-update-meta");
  if (promotable === null)
    return;
  try {
    const promoted = promotable;
    const resp = await postJSON(`/api/session/rules/${promoted}/update-macro`, {});
    await loadRules3();
    if (editing?.id === promoted)
      openRule(promoted);
    hideUpdateMacro();
    meta.textContent = `macro updated: ${resp.steps.length} step(s) replaced with what the run sent`;
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
}
async function loadCookies() {
  const el = $("#sess-cookies");
  let resp;
  try {
    resp = await getJSON("/api/session/cookies");
  } catch (e) {
    el.innerHTML = `<span class="err">${esc(e.message)}</span>`;
    return;
  }
  if (!resp.wired) {
    el.innerHTML = `<span class="hint">${esc(resp.hint ?? "session re-login is not attached to this process")}</span>`;
    return;
  }
  const hosts = resp.cookies ?? [];
  el.innerHTML = hosts.length ? hosts.map((h) => `<div><b>${esc(h.host)}</b><table><tbody>${h.cookies.map((c) => `<tr><td>${esc(c.name)}</td><td>${esc(c.value)}</td></tr>`).join("")}</tbody></table></div>`).join("") : `<span class="hint">jar is empty</span>`;
}

// src/sequencer.ts
var POSITIONS_SHOWN = 24;
var POLL_MS = 1000;
var pollTimer;
var activeCapture;
var showAllPositions = false;
var lastReport = null;
function initSequencer() {
  const section = $("#sequencer");
  if (!section)
    return;
  section.innerHTML = `
    <div class="card">
      <div class="row">
        <b>Token source</b>
        <label><input type="radio" name="seq-src" value="paste" checked /> paste a list</label>
        <label><input type="radio" name="seq-src" value="live" /> capture from a request</label>
        <label>bits read as
          <select id="seq-encoding">
            <option value="">detect</option>
            <option value="hex">hex</option>
            <option value="base64">base64</option>
            <option value="raw">raw bytes</option>
          </select>
        </label>
      </div>

      <div id="seq-paste-pane">
        <textarea id="seq-tokens" spellcheck="false" style="min-height:150px"
          placeholder="one token per line&#10;a1b2c3d4&#10;e5f60718&#10;..."></textarea>
        <div class="row">
          <button class="go" id="seq-analyse">Analyse</button>
          <span id="seq-paste-meta" class="hint"></span>
        </div>
      </div>

      <div id="seq-live-pane" style="display:none">
        <div class="row">
          <input id="seq-target" placeholder="http://host:port or https://host" style="width:320px" />
          <label>tokens <input id="seq-count" style="width:80px" placeholder="100" /></label>
          <label>req/s <input id="seq-rps" style="width:70px" placeholder="5" /></label>
        </div>
        <textarea id="seq-raw" spellcheck="false" style="min-height:120px">GET /login HTTP/1.1
Host: example.com
Connection: close

</textarea>
        <div class="row">
          <b>Token is</b>
          <select id="seq-part">
            <option value="body">in the body</option>
            <option value="headers">in the headers</option>
            <option value="whole">anywhere in the response</option>
          </select>
          <label><input type="radio" name="seq-how" value="pattern" checked /> matching</label>
          <input id="seq-pattern" placeholder="sid=([0-9a-f]+)" style="width:240px" />
          <label><input type="radio" name="seq-how" value="span" /> at offset</label>
          <input id="seq-offset" placeholder="offset" style="width:80px" />
          <input id="seq-len" placeholder="length" style="width:80px" />
        </div>
        <div class="row">
          <button class="go" id="seq-start">Start capture</button>
          <button class="ghost" id="seq-stop" disabled>Stop</button>
          <span id="seq-live-meta" class="hint"></span>
        </div>
      </div>
    </div>

    <div id="seq-results"></div>
  `;
  $all("input[name=seq-src]").forEach((r) => {
    r.onchange = () => {
      const live2 = r.value === "live" && r.checked;
      const paste = $("#seq-paste-pane");
      const livePane = $("#seq-live-pane");
      if (paste)
        paste.style.display = live2 ? "none" : "";
      if (livePane)
        livePane.style.display = live2 ? "" : "none";
    };
  });
  $("#seq-analyse").addEventListener("click", () => void analysePaste());
  $("#seq-start").addEventListener("click", () => void startCapture());
  $("#seq-stop").addEventListener("click", () => void stopCapture());
}
function chosenEncoding() {
  const v = $("#seq-encoding")?.value ?? "";
  return v === "" ? undefined : v;
}
async function analysePaste() {
  const meta = $("#seq-paste-meta");
  const text = $("#seq-tokens").value;
  if (!text.trim()) {
    meta.innerHTML = `<span class="err">paste at least one token</span>`;
    return;
  }
  meta.textContent = "analysing…";
  const body = { text };
  const encoding = chosenEncoding();
  if (encoding)
    body.encoding = encoding;
  try {
    const report = await postJSON("/api/sequencer/analyse", body);
    meta.textContent = `${report.tokens} token(s)`;
    renderReport2(report);
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
}
function buildExtract() {
  const part = $("#seq-part").value;
  const how = $all("input[name=seq-how]").find((r) => r.checked)?.value;
  if (how === "span") {
    const offset = Number($("#seq-offset").value);
    const len = Number($("#seq-len").value);
    if (!Number.isInteger(offset) || offset < 0)
      return "offset must be a whole number";
    if (!Number.isInteger(len) || len < 1)
      return "length must be at least 1";
    return { part, offset, len };
  }
  const pattern = $("#seq-pattern").value.trim();
  if (!pattern)
    return "give a pattern that matches the token";
  return { part, pattern };
}
async function startCapture() {
  const meta = $("#seq-live-meta");
  const target = $("#seq-target").value.trim();
  const raw = $("#seq-raw").value;
  if (!target) {
    meta.innerHTML = `<span class="err">give a target</span>`;
    return;
  }
  const extract = buildExtract();
  if (typeof extract === "string") {
    meta.innerHTML = `<span class="err">${esc(extract)}</span>`;
    return;
  }
  const body = { target, raw, extract };
  const count = Number($("#seq-count").value);
  if (Number.isInteger(count) && count > 0)
    body.count = count;
  const rps = Number($("#seq-rps").value);
  if (Number.isFinite(rps) && rps > 0)
    body.rps = rps;
  const encoding = chosenEncoding();
  if (encoding)
    body.encoding = encoding;
  meta.textContent = "starting…";
  try {
    const view = await postJSON("/api/sequencer/capture", body);
    activeCapture = view.id;
    if (view.clamped) {
      toast(`count reduced to the ${view.wanted}-token ceiling`, "info");
    }
    $("#seq-stop").disabled = false;
    renderProgress(view);
    if (pollTimer)
      clearInterval(pollTimer);
    pollTimer = setInterval(() => void poll(), POLL_MS);
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
}
async function stopCapture() {
  if (activeCapture === undefined)
    return;
  try {
    renderProgress(await postJSON(`/api/sequencer/capture/${activeCapture}/stop`));
  } catch (e) {
    toast(e.message, "error");
  }
}
async function poll() {
  if (activeCapture === undefined)
    return;
  let view;
  try {
    view = await getJSON(`/api/sequencer/capture/${activeCapture}`);
  } catch (e) {
    stopPolling();
    $("#seq-live-meta").innerHTML = `<span class="err">${esc(e.message)}</span>`;
    return;
  }
  if (view.state === "finished") {
    stopPolling();
    renderProgress(view);
    if (view.report) {
      renderReport2(view.report);
    } else {
      $("#seq-results").innerHTML = `<div class="card">
        <div class="card-title">Captured nothing</div>
        ${failuresHtml(view.failures)}
      </div>`;
    }
    return;
  }
  renderProgress(view);
}
function stopPolling() {
  if (pollTimer)
    clearInterval(pollTimer);
  pollTimer = undefined;
  $("#seq-stop").disabled = true;
}
var ENDED_LABEL = {
  complete: "complete",
  stopped: "stopped by you",
  gave_up: "gave up — too many failures in a row",
  refused: "refused: out of scope"
};
function renderProgress(view) {
  const meta = $("#seq-live-meta");
  const pct = view.wanted > 0 ? Math.round(view.captured / view.wanted * 100) : 0;
  if (view.state === "running") {
    meta.textContent = `${view.captured} / ${view.wanted} tokens (${pct}%), ${view.attempted} request(s) sent`;
    return;
  }
  const ended = ENDED_LABEL[view.ended ?? ""] ?? (view.ended ?? "finished");
  const good = view.ended === "complete" || view.ended === "stopped";
  meta.innerHTML = `<span class="status-pill ${good ? "good" : "bad"}">${esc(ended)}</span> ` + `${view.captured} token(s) from ${view.attempted} request(s) · ` + `sender: ${view.sent ?? 0} sent, ${view.refused ?? 0} refused`;
}
function failuresHtml(failures) {
  if (failures.length === 0)
    return "";
  return `<table><thead><tr><th>Problem</th><th>Times</th></tr></thead><tbody>${failures.map((f) => `<tr><td>${esc(f.message)}</td><td>${f.count}</td></tr>`).join("")}</tbody></table>`;
}
var GRADE_LABEL = {
  pass: "PASS",
  fail: "FAIL",
  insufficient: "NOT TESTED"
};
function renderReport2(report) {
  lastReport = report;
  const grade = report.grade;
  const pill = grade === "pass" ? "good" : grade === "fail" ? "bad" : "";
  const encoding = report.encoding_detected ? `${report.encoding} (detected)` : `${report.encoding} (you chose this)`;
  $("#seq-results").innerHTML = `
    <div class="card">
      <div class="row">
        <span class="status-pill ${pill}">${GRADE_LABEL[grade] ?? esc(grade)}</span>
        <b>Verdict</b>
      </div>
      <div class="detail-text">${esc(report.verdict)}</div>
      ${warningsHtml(report.warnings)}
    </div>

    <div class="card">
      <div class="card-title">Sample</div>
      <div class="row">
        ${tile("Tokens", String(report.tokens))}
        ${tile("Alphabet", String(report.characters.alphabet_size))}
        ${tile("Length", lengthLabel(report.characters))}
        ${tile("Entropy / token", `${report.characters.total_entropy_bits.toFixed(1)} b`)}
        ${tile("Bits read as", encoding)}
      </div>
      <div class="hint">
        Entropy per token is the sum of the per-position figures, which assumes the positions are
        independent — it is an upper estimate, not a measurement. This alphabet and length could carry
        at most ${report.characters.max_possible_bits.toFixed(1)} bits, and
        ${report.tokens} sample(s) cap any single position at
        ${report.characters.entropy_ceiling_bits.toFixed(1)} bits however good the generator is.
      </div>
    </div>

    ${fipsHtml(report)}
    ${positionsHtml(report.characters)}
  `;
  const toggle2 = $("#seq-toggle-positions");
  if (toggle2) {
    toggle2.addEventListener("click", () => {
      showAllPositions = !showAllPositions;
      if (lastReport)
        renderReport2(lastReport);
    });
  }
}
function tile(label, value) {
  return `<div class="stat-tile"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div></div>`;
}
function lengthLabel(c) {
  return c.min_len === c.max_len ? String(c.max_len) : `${c.min_len}–${c.max_len}`;
}
function warningsHtml(warnings) {
  if (warnings.length === 0)
    return "";
  return `<ul class="hint">${warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>`;
}
function fipsHtml(report) {
  const f = report.fips;
  const coverage = `${f.bits_supplied} bit(s) supplied · ${f.blocks_tested} whole ${f.block_bits}-bit block(s) tested` + (f.bits_untested > 0 ? ` · ${f.bits_untested} bit(s) not tested` : "");
  if (f.tests === null) {
    return `<div class="card">
      <div class="card-title">FIPS 140-2 bit-level tests</div>
      <div class="hint">${esc(coverage)}</div>
      <div class="detail-text">Not run. Every FIPS 140-2 threshold is defined on a
        ${f.block_bits}-bit sample, so running them against a shorter one would produce a confident
        answer that means nothing. Capture more tokens.</div>
    </div>`;
  }
  return `<div class="card">
    <div class="card-title">FIPS 140-2 bit-level tests</div>
    <div class="hint">${esc(coverage)}</div>
    <table>
      <thead><tr><th>Test</th><th>Result</th><th>Observed</th><th>Requirement</th><th>Blocks</th></tr></thead>
      <tbody>${f.tests.map((t) => `<tr>
            <td title="${esc(t.spec)}">${esc(t.name)}</td>
            <td><span class="status-pill ${t.passed ? "good" : "bad"}">${t.passed ? "pass" : "fail"}</span></td>
            <td>${esc(t.observed)}</td>
            <td class="muted">${esc(t.requirement)}</td>
            <td>${t.blocks_passed} / ${t.blocks_passed + t.blocks_failed}</td>
          </tr>`).join("")}</tbody>
    </table>
    <div class="hint">Ones: ${report.bits.ones} of ${report.bits.bits}
      (${(report.bits.bit_entropy * 100).toFixed(2)}% of a perfect split) · longest run
      ${report.bits.longest_run} bit(s).</div>
  </div>`;
}
function positionsHtml(c) {
  if (c.positions.length === 0) {
    return `<div class="card"><div class="card-title">Character positions</div>
      <div class="hint">no tokens to analyse</div></div>`;
  }
  const shown = showAllPositions ? c.positions : c.positions.slice(0, POSITIONS_SHOWN);
  const hidden = c.positions.length - shown.length;
  const toggle2 = c.positions.length > POSITIONS_SHOWN ? `<button class="ghost small" id="seq-toggle-positions">${showAllPositions ? `show first ${POSITIONS_SHOWN}` : `show all ${c.positions.length}`}</button>` : "";
  return `<div class="card">
    <div class="row"><b>Character positions</b>${toggle2}
      <span class="hint">alphabet: ${esc(c.alphabet.join(""))}</span></div>
    ${c.positions_truncated ? `<div class="hint">Only the first ${c.positions.length} of ${c.max_len} positions are reported.</div>` : ""}
    <div class="seq-positions">${shown.map(positionHtml).join("")}</div>
    ${hidden > 0 ? `<div class="hint">${hidden} more position(s) not shown.</div>` : ""}
  </div>`;
}
function positionHtml(p) {
  const dead = p.distinct <= 1;
  return `<div class="seq-position${dead ? " dead" : ""}">
    <div class="seq-position-head">
      <b>#${p.index}</b>
      <span class="${dead ? "err" : "muted"}">${p.entropy_bits.toFixed(2)} bits</span>
      <span class="muted">${p.distinct} distinct · ${p.samples} sample(s)</span>
      ${dead ? `<span class="err">never varies</span>` : ""}
    </div>
    <div class="seq-bars">${p.counts.map((ch) => `<div class="seq-bar-row" title="${esc(ch.label)}: ${ch.count} (${(ch.fraction * 100).toFixed(1)}%)">
          <span class="seq-bar-label">${esc(ch.label)}</span>
          <span class="seq-bar-track"><span class="seq-bar-fill" style="width:${(ch.fraction * 100).toFixed(2)}%"></span></span>
          <span class="seq-bar-count">${ch.count}</span>
        </div>`).join("")}</div>
  </div>`;
}

// src/app.ts
initTabs();
initDashboard();
initHistory();
initWshistory();
initSitemap();
initRepeater();
initIntruder();
initIntercept();
initScanner();
initDecoder();
initComparer();
initToolLog();
initOrganizer();
initMatchReplace();
initSession();
initSequencer();
initShortcuts();
async function refreshStats() {
  try {
    const s = await getJSON("/api/stats");
    const el = $("#stats");
    if (el) {
      el.textContent = `${s.exchanges} exchanges · ${s.messages} msgs · ${(s.stored_bytes / 1048576).toFixed(2)} MB stored`;
    }
  } catch {}
}
async function refreshScope2() {
  try {
    const s = await getJSON("/api/scope");
    const el = $("#scope-badge");
    if (!el)
      return;
    el.textContent = s.allow_all ? "scope: everything" : `scope: ${s.rules.length} rule(s)`;
    el.title = s.allow_all ? "everything is in scope" : JSON.stringify(s.rules);
  } catch {}
}
async function refreshCaLink() {
  const a = $("#ca-link");
  if (!a)
    return;
  try {
    const r = await fetch("/ca.crt", { method: "HEAD" });
    a.style.display = r.ok ? "" : "none";
  } catch {
    a.style.display = "none";
  }
}
refreshStats();
refreshScope2();
refreshCaLink();
live({ kinds: ["history"], section: "", refresh: () => void refreshStats(), fallbackMs: 4000 });
for (const section of ["dashboard", "scanner"]) {
  live({
    kinds: ["history", "issues", "dashboard"],
    section,
    refresh: () => void refreshLiveAudit(),
    minGapMs: 1000,
    fallbackMs: 4000
  });
}
initLive();
