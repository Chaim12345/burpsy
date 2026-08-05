// src/common.ts
function $(sel, root = document) {
  return root.querySelector(sel);
}
function $all2(sel, root = document) {
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
  isRetryable;
  constructor(message, status, body, isRetryable = false) {
    super(message);
    this.status = status;
    this.body = body;
    this.isRetryable = isRetryable;
    this.name = "ApiError";
  }
}
function isErrorBody(v) {
  return typeof v === "object" && v !== null && "error" in v;
}
var toastContainer = null;
var toasts = [];
function toast2(msg, kind = "info", opts = {}) {
  if (!toastContainer) {
    toastContainer = createToastContainer();
  }
  const el = document.createElement("div");
  el.className = `toast ${kind} ${opts.persistent ? "persistent" : ""}`;
  el.setAttribute("role", "alert");
  const icon = getToastIcon(kind);
  const dismissible = opts.dismissible !== false;
  el.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <span class="toast-message">${esc(msg)}</span>
    ${dismissible ? '<button class="toast-dismiss" aria-label="Dismiss">&times;</button>' : ""}
  `;
  toastContainer.appendChild(el);
  toasts.push(el);
  if (!opts.persistent) {
    const duration = opts.duration ?? (kind === "error" ? 6000 : 4000);
    setTimeout(() => removeToast(el), duration);
  }
  if (dismissible) {
    const dismissBtn = el.querySelector(".toast-dismiss");
    if (dismissBtn) {
      dismissBtn.addEventListener("click", () => removeToast(el));
    }
  }
  while (toasts.length > 5) {
    removeToast(toasts[0]);
  }
}
function getToastIcon(kind) {
  switch (kind) {
    case "error":
      return "❌";
    case "success":
      return "✅";
    case "warning":
      return "⚠️";
    default:
      return "ℹ️";
  }
}
function createToastContainer() {
  const el = document.createElement("div");
  el.id = "toast-container";
  document.body.appendChild(el);
  return el;
}
function removeToast(el) {
  el.classList.add("hiding");
  setTimeout(() => {
    el.remove();
    toasts = toasts.filter((t) => t !== el);
    if (toasts.length === 0 && toastContainer) {
      toastContainer.remove();
      toastContainer = null;
    }
  }, 200);
}
async function request(method, url, body, retries = 0) {
  const init = { method };
  if (body !== undefined) {
    init.headers = { "content-type": "application/json" };
    init.body = JSON.stringify(body);
  }
  let lastError;
  for (let i = 0;i <= retries; i++) {
    try {
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
        const isRetryable = r.status >= 500 || r.status === 429;
        throw new ApiError(message, r.status, json ?? text, isRetryable);
      }
      return json;
    } catch (e) {
      lastError = e;
      if (i < retries && e.isRetryable) {
        await new Promise((resolve) => setTimeout(resolve, 100 * (i + 1)));
        continue;
      }
      throw e;
    }
  }
  throw lastError;
}
var getJSON = (url) => request("GET", url);
var postJSON = (url, body = {}) => request("POST", url, body);
var putJSON = (url, body = {}) => request("PUT", url, body);
var delJSON = (url) => request("DELETE", url);
function switchTab(id) {
  $all2("nav button[data-t]").forEach((b) => b.classList.toggle("on", b.dataset["t"] === id));
  $all2("main > section").forEach((s) => s.classList.toggle("on", s.id === id));
}
function initTabs() {
  $all2("nav button[data-t]").forEach((b) => {
    b.onclick = () => switchTab(b.dataset["t"]);
  });
}
var listeners = new Map;
function on(event, handler) {
  if (!listeners.has(event)) {
    listeners.set(event, new Set);
  }
  const set = listeners.get(event);
  set.add(handler);
  return () => {
    set.delete(handler);
    if (set.size === 0) {
      listeners.delete(event);
    }
  };
}
function emit(event, detail) {
  const set = listeners.get(event);
  if (set) {
    set.forEach((handler) => handler(detail));
  }
}
function persistFilter(key, input) {
  const save = () => {
    if (input.type === "checkbox") {
      localStorage.setItem(`filter:${key}`, String(input.checked));
    } else {
      localStorage.setItem(`filter:${key}`, input.value);
    }
  };
  input.addEventListener("input", save);
  input.addEventListener("change", save);
  const saved = localStorage.getItem(`filter:${key}`);
  if (saved !== null) {
    if (input.type === "checkbox") {
      input.checked = saved === "true";
    } else {
      input.value = saved;
    }
    if (input.type === "checkbox") {
      input.dispatchEvent(new Event("change"));
    }
  }
}
function highlightSearch(text, query) {
  if (!query)
    return esc(text);
  try {
    const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(escapedQuery, "gi");
    return esc(text).replace(regex, (match) => `<span class="search-highlight">${match}</span>`);
  } catch {
    return esc(text);
  }
}
function makeSortable(tableId, defaultSort = "") {
  const table = $(`#${tableId}`);
  if (!table)
    return;
  const headers = table.querySelectorAll("th[data-sort]");
  let currentSort = defaultSort;
  let ascending = true;
  headers.forEach((th) => {
    th.addEventListener("click", () => {
      const field = th.dataset.sort;
      headers.forEach((h) => {
        h.classList.remove("sorted", "sorted-asc", "sorted-desc");
      });
      if (currentSort === field) {
        ascending = !ascending;
      } else {
        currentSort = field;
        ascending = true;
      }
      th.classList.add("sorted", ascending ? "sorted-asc" : "sorted-desc");
      const event = new CustomEvent("sort", {
        detail: { field, ascending }
      });
      table.dispatchEvent(event);
    });
  });
}
function createSorter(field, ascending) {
  return (a, b) => {
    let aVal = a[field];
    let bVal = b[field];
    if (aVal === null || aVal === undefined)
      return ascending ? 1 : -1;
    if (bVal === null || bVal === undefined)
      return ascending ? -1 : 1;
    if (typeof aVal === "number") {
      return ascending ? aVal - bVal : bVal - aVal;
    }
    aVal = String(aVal);
    bVal = String(bVal);
    return ascending ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  };
}
function initTheme() {
  const saved = localStorage.getItem("theme");
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const theme = saved || (prefersDark ? "dark" : "light");
  document.documentElement.classList.toggle("light", theme === "light");
  const toggle = document.createElement("button");
  toggle.className = "ghost theme-toggle";
  toggle.innerHTML = theme === "dark" ? "☀️" : "\uD83C\uDF19";
  toggle.title = "Toggle theme";
  toggle.onclick = () => {
    const isLight = document.documentElement.classList.toggle("light");
    localStorage.setItem("theme", isLight ? "light" : "dark");
    toggle.innerHTML = isLight ? "\uD83C\uDF19" : "☀️";
    document.documentElement.style.setProperty("--theme", isLight ? "light" : "dark");
  };
  const header = $("header");
  if (header) {
    const h1 = header.querySelector("h1");
    if (h1) {
      h1.after(toggle);
    } else {
      header.prepend(toggle);
    }
  }
}
function addBulkSelect(tableId, onSelectionChange) {
  const selected = new Set;
  const table = $(`#${tableId}`);
  if (!table)
    return selected;
  const headerRow = table.querySelector("thead tr");
  if (headerRow) {
    const th = document.createElement("th");
    th.style.width = "24px";
    th.style.minWidth = "24px";
    th.innerHTML = '<input type="checkbox" class="select-all" />';
    headerRow.insertBefore(th, headerRow.firstChild);
  }
  const rows = table.querySelectorAll("tbody tr[data-id]");
  rows.forEach((row) => {
    const td = document.createElement("td");
    td.style.width = "24px";
    td.style.minWidth = "24px";
    td.innerHTML = '<input type="checkbox" class="row-checkbox" />';
    row.insertBefore(td, row.firstChild);
    const checkbox = td.querySelector("input");
    checkbox.addEventListener("change", () => {
      const id = Number(row.dataset.id);
      if (checkbox.checked) {
        selected.add(id);
      } else {
        selected.delete(id);
      }
      onSelectionChange(selected);
      updateSelectAll();
    });
  });
  const selectAll = table.querySelector(".select-all");
  if (selectAll) {
    selectAll.addEventListener("change", () => {
      rows.forEach((row) => {
        const checkbox = row.querySelector(".row-checkbox");
        if (checkbox) {
          checkbox.checked = selectAll.checked;
          const id = Number(row.dataset.id);
          if (selectAll.checked) {
            selected.add(id);
          } else {
            selected.delete(id);
          }
        }
      });
      onSelectionChange(selected);
    });
  }
  function updateSelectAll() {
    if (selectAll) {
      const allChecked = rows.length > 0 && selected.size === rows.length;
      const someChecked = selected.size > 0;
      selectAll.checked = allChecked;
      selectAll.indeterminate = someChecked && !allChecked;
    }
  }
  return selected;
}
function renderEmptyState(message, hint, icon = "\uD83D\uDCED", cols = 1) {
  return `
    <tr>
      <td colspan="${cols}" class="empty-state">
        <div class="empty-icon">${icon}</div>
        <div class="empty-title">${esc(message)}</div>
        <div class="empty-hint">${esc(hint)}</div>
      </td>
    </tr>
  `;
}
async function copyText(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    toast2(`Copied ${what}`, "success");
    return;
  } catch {}
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("aria-hidden", "true");
  ta.style.position = "fixed";
  ta.style.top = "-1000px";
  ta.style.left = "-1000px";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  ta.remove();
  if (ok) {
    toast2(`Copied ${what}`, "success");
  } else {
    toast2(`Could not copy ${what} - clipboard blocked`, "error");
  }
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
  const button = $(`#${mounts[0]}-audit-toggle`);
  const originalChecked = button.checked;
  try {
    button.disabled = true;
    last = await postJSON("/api/scanner/live", { enabled });
    for (const prefix of mounts)
      applyTo(prefix, last);
  } catch (e) {
    toast2(e.message, "error");
    button.checked = originalChecked;
    await refreshLiveAudit();
  } finally {
    button.disabled = false;
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
  hint.textContent = r.query ? `${state} \x17 filtered to ${r.query}` : state;
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
  if (stream)
    return;
  indicator = document.createElement("span");
  indicator.id = "live-indicator";
  indicator.className = "status-pill off";
  indicator.textContent = "polling";
  indicator.title = "Event stream not connected — falling back to polling";
  const statsEl = $("#stats");
  if (statsEl) {
    statsEl.before(indicator);
  } else {
    const header = $("header");
    if (header) {
      header.appendChild(indicator);
    }
  }
  openStream();
  startWatchdog();
  startFallback();
}
function openStream() {
  connects++;
  const url = new URL("/api/events", window.location.href);
  url.searchParams.set("v", String(connects));
  stream = new EventSource(url);
  stream.onopen = () => {
    delivering = false;
    if (indicator) {
      indicator.className = "status-pill off";
      indicator.textContent = "connecting...";
      indicator.title = "Event stream connecting...";
    }
  };
  stream.onmessage = (e) => {
    delivering = true;
    lastFrameAt = Date.now();
    if (indicator) {
      indicator.className = "status-pill good";
      indicator.textContent = "live";
      indicator.title = "Event stream connected — updates are pushed in real-time";
    }
    let frame;
    try {
      frame = JSON.parse(e.data);
    } catch {
      return;
    }
    const kind = frame.kind;
    const changes = frame.changes;
    for (const p of panes) {
      if (p.kinds.includes(kind)) {
        const section = $(`#${p.section}`);
        if (!section || !section.classList.contains("on")) {
          p.stale = true;
          p.owed += changes;
          continue;
        }
        const now = Date.now();
        if (now - p.lastRun >= p.minGapMs) {
          p.refresh(p.owed + changes);
          p.owed = 0;
          p.lastRun = now;
          p.stale = false;
        } else {
          p.owed += changes;
        }
      }
    }
  };
  stream.onerror = () => {
    if (indicator) {
      indicator.className = "status-pill bad";
      indicator.textContent = "reconnecting...";
      indicator.title = "Event stream disconnected — will retry automatically";
    }
  };
}
function startWatchdog() {
  setInterval(() => {
    if (Date.now() - lastFrameAt > SILENCE_LIMIT_MS) {
      if (stream) {
        stream.close();
        stream = null;
      }
      openStream();
    }
  }, WATCHDOG_TICK_MS);
}
function startFallback() {
  fallbackTimer = setInterval(() => {
    if (delivering)
      return;
    if (indicator) {
      indicator.className = "status-pill bad";
      indicator.textContent = "polling";
      indicator.title = "Event stream not connected — using fallback polling";
    }
    for (const p of panes) {
      const section = $(`#${p.section}`);
      if (!section || !section.classList.contains("on"))
        continue;
      const now = Date.now();
      if (now - p.lastRun >= p.fallbackMs) {
        p.refresh(0);
        p.lastRun = now;
      }
    }
  }, FALLBACK_TICK_MS);
}

// src/dashboard.ts
function initDashboard() {
  const section = $("#dashboard");
  if (!section)
    return;
  section.innerHTML = `
    <div class="four">
      <div class="stat-tile"><div class="label">Exchanges captured</div><div class="value" id="dash-exchanges">\x13</div></div>
      <div class="stat-tile"><div class="label">Storage used</div><div class="value" id="dash-storage">\x13</div></div>
      <div class="stat-tile"><div class="label">Scope rules</div><div class="value" id="dash-scope">\x13</div></div>
      <div class="stat-tile"><div class="label">Tasks running</div><div class="value" id="dash-running">\x13</div></div>
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
        <thead><tr><th data-sort="kind">Kind</th><th data-sort="target">Target</th><th data-sort="state">State</th><th>Progress</th><th>Result</th><th data-sort="elapsed_ms">Elapsed</th></tr></thead>
        <tbody id="dash-tasks"></tbody>
      </table>
      <div id="dash-tasks-meta" class="hint"></div>
    </div>
    <div class="two">
      <div class="card">
        <div class="card-title">Requests sent</div>
        <p class="hint">Every request burpsy's own tools sent. Proxy traffic lives in History.</p>
        <table>
          <thead><tr><th data-sort="at_ms">Time</th><th data-sort="tool">Tool</th><th>Request</th></tr></thead>
          <tbody id="dash-activity"></tbody>
        </table>
        <div id="dash-activity-meta" class="hint"></div>
      </div>
      <div class="card">
        <div class="card-title">What the tool did</div>
        <p class="hint">Tasks starting and finishing, scope edits, bounds hit — the things that are not
          requests, so they are not in the list beside this one.</p>
        <table>
          <thead><tr><th data-sort="at_ms">Time</th><th data-sort="kind">Kind</th><th>Detail</th></tr></thead>
          <tbody id="dash-events"></tbody>
        </table>
        <div id="dash-events-meta" class="hint"></div>
      </div>
    </div>
    <div class="two">
      ${liveAuditCardHtml("dash")}
    </div>
  `;
  makeSortable("dash-tasks", "started_ms");
  makeSortable("dash-activity", "at_ms");
  makeSortable("dash-events", "at_ms");
  mountLiveAudit("dash");
  live({ kinds: ["history", "issues", "toollog", "dashboard"], section: "dashboard", refresh: () => void load(), minGapMs: 500 });
  load();
}
function renderSummary(s) {
  const b = s.breakdown;
  const total = b.found + b.skipped + b.errored + b.gated;
  const caveats = [];
  if (b.skipped > 0)
    caveats.push(`${b.skipped} skipped`);
  if (b.errored > 0)
    caveats.push(`${b.errored} errored`);
  if (b.gated > 0)
    caveats.push(`${b.gated} gated`);
  if (b.unaccounted > 0)
    caveats.push(`${b.unaccounted} unaccounted`);
  const caveat = caveats.length > 0 ? ` (${caveats.join(", ")})` : "";
  const complete = b.complete ? "complete" : "incomplete";
  return `
    <div class="stat-tile">
      <div class="label">${esc(s.label)}</div>
      <div class="value">${total.toLocaleString()}${esc(caveat)}</div>
      <div class="hint" style="font-size:11px;margin-top:4px">${esc(s.summary)}</div>
    </div>
  `;
}
function renderTask(t) {
  const progress = t.progress || (t.fraction_known ? `${Math.round(t.fraction * 100)}%` : "");
  const elapsed = t.elapsed_ms > 0 ? `${(t.elapsed_ms / 1000).toFixed(1)}s` : "";
  const result = renderBreakdown(t.result);
  return `
    <tr>
      <td>${esc(t.kind)}</td>
      <td>${esc(t.target)}</td>
      <td>${esc(t.state)}</td>
      <td>${esc(progress)}</td>
      <td>${result}</td>
      <td>${elapsed}</td>
    </tr>
  `;
}
function renderBreakdown(b) {
  const parts = [];
  if (b.found > 0)
    parts.push(`${b.found} found`);
  if (b.skipped > 0)
    parts.push(`${b.skipped} skipped`);
  if (b.errored > 0)
    parts.push(`${b.errored} errors`);
  if (b.gated > 0)
    parts.push(`${b.gated} gated`);
  if (parts.length === 0)
    return "-";
  return parts.join(", ");
}
function renderActivity(e) {
  const time = new Date(e.at_ms).toLocaleTimeString();
  return `
    <tr>
      <td>${esc(time)}</td>
      <td><span class="tag tag-${esc(e.tool)}">${esc(e.tool)}</span></td>
      <td>${esc(e.request)}</td>
    </tr>
  `;
}
function renderEvent(e) {
  const time = new Date(e.at_ms).toLocaleTimeString();
  const sevClass = e.severity === "error" ? "err" : e.severity === "warn" ? "sev-medium" : "dim";
  return `
    <tr>
      <td>${esc(time)}</td>
      <td><span class="${sevClass}">${esc(e.kind)}</span></td>
      <td>${esc(e.detail)}</td>
    </tr>
  `;
}
async function load() {
  const summariesEl = $("#dash-summaries");
  const tasksEl = $("#dash-tasks");
  const tasksMetaEl = $("#dash-tasks-meta");
  const activityEl = $("#dash-activity");
  const activityMetaEl = $("#dash-activity-meta");
  const eventsEl = $("#dash-events");
  const eventsMetaEl = $("#dash-events-meta");
  summariesEl.innerHTML = '<div class="loading-state"><span class="spinner spinner-medium"></span> Loading...</div>';
  tasksEl.innerHTML = renderEmptyState("Loading tasks...", "", "⏳", 6);
  activityEl.innerHTML = renderEmptyState("Loading activity...", "", "⏳", 3);
  eventsEl.innerHTML = renderEmptyState("Loading events...", "", "⏳", 3);
  let resp;
  try {
    resp = await getJSON("/api/dashboard");
  } catch (e) {
    summariesEl.innerHTML = `<div class="err">${esc(e.message)}</div>`;
    return;
  }
  $("#dash-exchanges").textContent = resp.exchanges.toLocaleString();
  $("#dash-storage").textContent = `${(resp.stored_bytes / 1048576).toFixed(2)} MB`;
  $("#dash-scope").textContent = resp.sources?.scope ? resp.sources.scope.toLocaleString() : "0";
  $("#dash-running").textContent = resp.tasks_running.toLocaleString();
  if (resp.summaries.length > 0) {
    summariesEl.innerHTML = resp.summaries.map(renderSummary).join("");
  } else {
    summariesEl.innerHTML = renderEmptyState("No summaries available", "", "\uD83D\uDCCA", 4);
  }
  if (resp.tasks.length > 0) {
    tasksEl.innerHTML = resp.tasks.map(renderTask).join("");
    tasksMetaEl.textContent = `Showing ${resp.tasks.length} of ${resp.tasks.length + resp.tasks_dropped} tasks`;
  } else {
    tasksEl.innerHTML = renderEmptyState("No tasks running", "Start a scan or crawl to see tasks here", "\uD83D\uDEE0️", 6);
    tasksMetaEl.textContent = "No tasks";
  }
  if (resp.activity.length > 0) {
    activityEl.innerHTML = resp.activity.map(renderActivity).join("");
    activityMetaEl.textContent = `Showing ${resp.activity_shown} of ${resp.activity_total} (${resp.activity_dropped} dropped)`;
  } else {
    activityEl.innerHTML = renderEmptyState("No activity yet", "Requests sent by burpsy will appear here", "\uD83D\uDCE4", 3);
    activityMetaEl.textContent = "No activity";
  }
  if (resp.events.length > 0) {
    eventsEl.innerHTML = resp.events.map(renderEvent).join("");
    eventsMetaEl.textContent = `Showing ${resp.events_shown} of ${resp.events_total} (${resp.events_dropped} dropped)`;
  } else {
    eventsEl.innerHTML = renderEmptyState("No events yet", "Tool actions will appear here", "\uD83D\uDCDD", 3);
    eventsMetaEl.textContent = "No events";
  }
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

// src/shortcuts.ts
var targets = new Map;
function registerRowTarget(id, fn) {
  targets.set(id, fn);
}
function activeTarget() {
  const active = $all("section.on").find((s) => s.id);
  if (!active)
    return null;
  const fn = targets.get(active.id);
  return fn ? fn() : null;
}
function bindShortcuts() {
  document.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA" || e.target.isContentEditable) {
      return;
    }
    if (isContextMenuOpen()) {
      return;
    }
    if (e.ctrlKey && e.key === "r") {
      e.preventDefault();
      const t = activeTarget();
      if (t?.exchange) {
        emit(EVT_SEND_TO_REPEATER, {
          target: `${t.exchange.tls ? "https" : "http"}://${t.exchange.host}:${t.exchange.port}`,
          raw: "",
          protocol: t.exchange.protocol
        });
        toast2(`Sent to Repeater: ${t.label}`);
      } else if (t?.exchangeId) {
        fetchExchangeAndSend(t.exchangeId);
      } else {
        toast2("No row selected", "warning");
      }
    }
    if (e.ctrlKey && e.key === "i") {
      e.preventDefault();
      const t = activeTarget();
      if (t?.exchange) {
        emit(EVT_SEND_TO_INTRUDER, {
          msgId: t.exchange.request,
          target: `${t.exchange.tls ? "https" : "http"}://${t.exchange.host}:${t.exchange.port}`
        });
        toast2(`Sent to Intruder: ${t.label}`);
      } else if (t?.exchangeId) {
        fetchExchangeAndSendToIntruder(t.exchangeId);
      } else {
        toast2("No row selected", "warning");
      }
    }
    if (e.ctrlKey && e.key === "a") {
      e.preventDefault();
      const t = activeTarget();
      if (t?.exchange) {
        emit(EVT_SEND_TO_COMPARER, {
          side: "a",
          msgId: t.exchange.request,
          label: t.label
        });
        toast2(`Sent to Comparer A: ${t.label}`);
      } else {
        toast2("No row selected", "warning");
      }
    }
    if (e.ctrlKey && e.key === "b") {
      e.preventDefault();
      const t = activeTarget();
      if (t?.exchange) {
        emit(EVT_SEND_TO_COMPARER, {
          side: "b",
          msgId: t.exchange.request,
          label: t.label
        });
        toast2(`Sent to Comparer B: ${t.label}`);
      } else {
        toast2("No row selected", "warning");
      }
    }
    if (e.key === "Escape") {
      const backdrop = $(".sheet-backdrop");
      if (backdrop) {
        e.preventDefault();
        backdrop.remove();
      }
    }
  });
}
async function fetchExchangeAndSend(exchangeId) {
  try {
    const response = await fetch(`/api/exchange/${exchangeId}`);
    if (!response.ok)
      throw new Error(`Failed to fetch exchange: ${response.status}`);
    const exchange = await response.json();
    emit(EVT_SEND_TO_REPEATER, {
      target: `${exchange.tls ? "https" : "http"}://${exchange.host}:${exchange.port}`,
      raw: "",
      protocol: exchange.protocol
    });
    toast2(`Sent to Repeater: exchange #${exchangeId}`);
  } catch (e) {
    toast2(e.message, "error");
  }
}
async function fetchExchangeAndSendToIntruder(exchangeId) {
  try {
    const response = await fetch(`/api/exchange/${exchangeId}`);
    if (!response.ok)
      throw new Error(`Failed to fetch exchange: ${response.status}`);
    const exchange = await response.json();
    emit(EVT_SEND_TO_INTRUDER, {
      msgId: exchange.request,
      target: `${exchange.tls ? "https" : "http"}://${exchange.host}:${exchange.port}`
    });
    toast2(`Sent to Intruder: exchange #${exchangeId}`);
  } catch (e) {
    toast2(e.message, "error");
  }
}
var sheetBackdrop = null;
function showShortcutSheet() {
  if (sheetBackdrop) {
    sheetBackdrop.remove();
    sheetBackdrop = null;
    return;
  }
  sheetBackdrop = document.createElement("div");
  sheetBackdrop.className = "sheet-backdrop";
  sheetBackdrop.innerHTML = `
    <div class="sheet">
      <h2>Keyboard Shortcuts</h2>
      <p class="hint">Available globally when not typing in an input field</p>
      <table>
        <thead>
          <tr><th>Key</th><th>Action</th><th>Context</th></tr>
        </thead>
        <tbody>
          <tr>
            <td><kbd>Ctrl+R</kbd></td>
            <td>Send to Repeater</td>
            <td>History, Scanner, Site map, WS History</td>
          </tr>
          <tr>
            <td><kbd>Ctrl+I</kbd></td>
            <td>Send to Intruder</td>
            <td>History, Scanner, Site map, WS History</td>
          </tr>
          <tr>
            <td><kbd>Ctrl+A</kbd></td>
            <td>Send to Comparer (A)</td>
            <td>History, Scanner, Site map, WS History</td>
          </tr>
          <tr>
            <td><kbd>Ctrl+B</kbd></td>
            <td>Send to Comparer (B)</td>
            <td>History, Scanner, Site map, WS History</td>
          </tr>
          <tr>
            <td><kbd>↑</kbd>/<kbd>↓</kbd></td>
            <td>Navigate rows</td>
            <td>All tables</td>
          </tr>
          <tr>
            <td><kbd>Enter</kbd></td>
            <td>Open/Select row</td>
            <td>All tables</td>
          </tr>
          <tr>
            <td><kbd>Esc</kbd></td>
            <td>Close modal/deselect</td>
            <td>All</td>
          </tr>
          <tr>
            <td><kbd>?</kbd></td>
            <td>Show this help</td>
            <td>All</td>
          </tr>
        </tbody>
      </table>
      <div style="margin-top:12px;text-align:right">
        <button class="go" onclick="this.closest('.sheet-backdrop').remove()">Close</button>
      </div>
    </div>
  `;
  document.body.appendChild(sheetBackdrop);
  sheetBackdrop.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      sheetBackdrop?.remove();
      sheetBackdrop = null;
    }
  });
}
function initShortcuts() {
  bindShortcuts();
  document.addEventListener("keydown", (e) => {
    if (e.key === "?" && !isContextMenuOpen() && e.target.tagName !== "INPUT" && e.target.tagName !== "TEXTAREA") {
      e.preventDefault();
      showShortcutSheet();
    }
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
    toast2(e.message, "error");
  }
}
function sendToIntruder(ex) {
  emit(EVT_SEND_TO_INTRUDER, { msgId: ex.request, target: targetOf(ex) });
  switchTab("intruder");
}
function sendToComparer(ex, side) {
  emit(EVT_SEND_TO_COMPARER, { side, msgId: ex.request, label: `${ex.method} ${ex.path}` });
  switchTab("comparer");
  toast2(`sent request #${ex.request} to Comparer ${side.toUpperCase()}`);
}
function showInHistory(ex) {
  emit(EVT_SHOW_EXCHANGE, { exchangeId: ex.id });
  switchTab("history");
}
async function saveToOrganizer(ex) {
  try {
    await postJSON("/api/tools/organizer", { exchange: ex.id });
    toast2(`saved ${ex.method} ${ex.path} to Organizer`);
  } catch (e) {
    toast2(e.message, "error");
  }
}
function openUrl(ex) {
  window.open(urlOf(ex), "_blank", "noopener,noreferrer");
}
async function copyText2(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    toast2(`copied ${what}`);
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
  toast2(ok ? `copied ${what}` : `could not copy ${what} — the clipboard is blocked`, ok ? "info" : "error");
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
    await copyText2(asCurl(ex, req.text), `#${ex.id} as curl`);
  } catch (e) {
    toast2(e.message, "error");
  }
}
function exchangeActions(showHistory) {
  const actions = [
    { label: "Send to Repeater", hint: "Ctrl+R", act: (ex) => sendToRepeater(ex) },
    { label: "Send to Intruder", hint: "Ctrl+I", act: (ex) => sendToIntruder(ex) },
    { label: "Send to Comparer (A)", act: (ex) => sendToComparer(ex, "a") },
    { label: "Send to Comparer (B)", act: (ex) => sendToComparer(ex, "b") },
    { label: "Save to Organizer", before: true, act: (ex) => saveToOrganizer(ex) },
    { label: "Copy URL", before: true, act: (ex) => copyText2(urlOf(ex), `#${ex.id} URL`) },
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
    toast2(e.message, "error");
  }
}

// src/history.ts
var allRows = [];
var cachedScope = null;
var queryTimer;
var selected = null;
var rendered = new Map;
var bulkSelected = new Set;
function initHistory() {
  const section = $("#history");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">right-click a row for send-to actions \x17 Ctrl+R Repeater \x17 Ctrl+I Intruder \x17 ? for all shortcuts</span>
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
    <div class="bulk-actions" id="hist-bulk-actions" style="display: none;">
      <span class="count" id="hist-bulk-count">0 selected</span>
      <span class="grow"></span>
      <button class="ghost small" onclick="bulkSendToIntruder()">Send to Intruder</button>
      <button class="ghost small" onclick="bulkSaveToOrganizer()">Save to Organizer</button>
      <button class="ghost small" onclick="clearBulkSelection()">Clear</button>
    </div>
    <table>
      <thead>
        <tr>
          <th class="select-col"><input type="checkbox" class="select-all" /></th>
          <th data-sort="id">#</th>
          <th data-sort="method">Method</th>
          <th data-sort="host">Host</th>
          <th data-sort="path">Path</th>
          <th data-sort="status">Status</th>
          <th data-sort="response_len">Len</th>
          <th data-sort="duration_ms">ms</th>
          <th>TLS</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="hist-body"></tbody>
    </table>
    <div class="two" style="margin-top:10px">
      <div>
        <div class="viewer-header">
          <b class="muted">Request</b>
          <button class="ghost small" onclick="copyRequest()">Copy</button>
          <span class="viewer-meta" id="hist-req-meta"></span>
        </div>
        <div class="code-viewer" id="hist-req-container">
          <div class="code-lines" id="hist-req-lines"></div>
          <pre id="hist-req" spellcheck="false"></pre>
        </div>
      </div>
      <div>
        <div class="viewer-header">
          <b class="muted">Response</b>
          <button class="ghost small" onclick="copyResponse()">Copy</button>
          <span class="viewer-meta" id="hist-res-meta"></span>
        </div>
        <div class="code-viewer" id="hist-res-container">
          <div class="code-lines" id="hist-res-lines"></div>
          <pre id="hist-res" spellcheck="false"></pre>
        </div>
      </div>
    </div>
  `;
  bulkSelected = addBulkSelect("hist-body", (selected2) => {
    const countEl = $("#hist-bulk-count");
    if (countEl) {
      countEl.textContent = `${selected2.size} selected`;
    }
    $("#hist-bulk-actions").style.display = selected2.size > 0 ? "flex" : "none";
  });
  makeSortable("hist-body", "started_ms");
  $("#hist-body")?.addEventListener("sort", (e) => {
    const { field, ascending } = e.detail;
    allRows.sort(createSorter(field, ascending));
    applyFilter();
  });
  $all2(".hist-status").forEach((c) => c.addEventListener("change", () => applyFilter()));
  persistFilter("history-search", $("#hist-search"));
  persistFilter("history-query", $("#hist-query"));
  persistFilter("history-regex", $("#hist-regex"));
  const scopeOnly = $("#hist-scope-only");
  persistFilter("history-scope-only", scopeOnly);
  scopeOnly.addEventListener("change", () => {
    if (scopeOnly.checked) {
      ensureScopeLoaded().then(() => applyFilter());
    } else {
      applyFilter();
    }
  });
  $("#hist-search").addEventListener("input", () => applyFilter());
  $("#hist-regex").addEventListener("change", () => applyFilter());
  $("#hist-query").addEventListener("input", () => {
    if (queryTimer)
      clearTimeout(queryTimer);
    queryTimer = setTimeout(() => void load2(), 300);
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
  live({ kinds: ["history"], section: "history", refresh: () => void load2() });
  load2();
}
window.bulkSendToIntruder = function() {
  if (bulkSelected.size === 0)
    return;
  toast2(`Sending ${bulkSelected.size} items to Intruder`, "info");
  clearBulkSelection();
};
window.bulkSaveToOrganizer = function() {
  if (bulkSelected.size === 0)
    return;
  toast2(`Saving ${bulkSelected.size} items to Organizer`, "info");
  clearBulkSelection();
};
window.clearBulkSelection = function() {
  bulkSelected.clear();
  $("#hist-bulk-actions").style.display = "none";
  $all2("#hist-body .row-checkbox").forEach((cb) => cb.checked = false);
  const selectAll = $(".select-all");
  if (selectAll) {
    selectAll.checked = false;
    selectAll.indeterminate = false;
  }
};
window.copyRequest = function() {
  const el = $("#hist-req");
  if (el)
    copyText(el.textContent || "", "request");
};
window.copyResponse = function() {
  const el = $("#hist-res");
  if (el)
    copyText(el.textContent || "", "response");
};
function markSelected(ex) {
  selected = ex;
  $all2("#hist-body tr").forEach((tr) => tr.classList.toggle("on", Number(tr.dataset["id"]) === ex.id));
}
async function loadExchangeById(id) {
  try {
    const ex = await getJSON(`/api/exchange/${id}`);
    await openExchange(ex);
  } catch (e) {
    toast2(e.message, "error");
  }
}
function updateViewerLines(containerId, content) {
  const container = $(`#${containerId}`);
  const linesEl = $(`#${containerId}-lines`);
  if (!container || !linesEl)
    return;
  const lines = content.split(`
`).length;
  linesEl.innerHTML = Array.from({ length: lines }, (_, i) => i + 1).join(`
`);
}
async function load2() {
  const body = $("#hist-body");
  const q = $("#hist-query").value.trim();
  const qs = q ? `?limit=300&q=${encodeURIComponent(q)}` : "?limit=300";
  body.innerHTML = `<tr><td colspan="10" class="loading-state"><span class="spinner spinner-medium"></span> Loading...</td></tr>`;
  try {
    allRows = await getJSON(`/api/history${qs}`);
  } catch (e) {
    allRows = [];
    body.innerHTML = `<tr><td colspan="10" class="err"><pre style="white-space:pre;margin:0">${esc(e.message)}</pre></td></tr>`;
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
    toast2(e.message, "error");
  }
}
function applyFilter() {
  const body = $("#hist-body");
  const search = $("#hist-search").value.toLowerCase();
  const useRegex = $("#hist-regex").checked;
  const scopeOnly = $("#hist-scope-only").checked;
  const statuses = $all2(".hist-status:checked").map((c) => c.value);
  let rows = allRows;
  if (statuses.length > 0) {
    rows = rows.filter((ex) => {
      if (ex.status === null)
        return false;
      return statuses.includes(String(ex.status)[0]);
    });
  }
  if (scopeOnly && cachedScope && !cachedScope.allow_all) {
    rows = rows;
  }
  if (search) {
    const pattern = useRegex ? new RegExp(search, "i") : search;
    rows = rows.filter((ex) => {
      const haystack = `${ex.method} ${ex.host} ${ex.path}`.toLowerCase();
      if (useRegex) {
        return pattern.test(haystack);
      }
      return haystack.includes(search);
    });
  }
  if (rows.length === 0) {
    body.innerHTML = renderEmptyState("No traffic captured yet", `Configure your browser to use burpsy as proxy:
http://localhost:8080`, "\uD83D\uDCED", 10);
    return;
  }
  body.innerHTML = rows.map(renderRow).join("");
  attachRowListeners();
}
function renderRow(ex) {
  const search = $("#hist-search")?.value.toLowerCase() || "";
  const useRegex = $("#hist-regex")?.checked || false;
  const host = highlightSearch(ex.host, useRegex ? search : "");
  const path = highlightSearch(ex.path, useRegex ? search : "");
  const method = highlightSearch(ex.method, useRegex ? search : "");
  const displayHost = ex.host.length > 40 ? ex.host.slice(0, 38) + "…" : ex.host;
  const displayPath = ex.path.length > 50 ? ex.path.slice(0, 48) + "…" : ex.path;
  const isTruncated = ex.host.length > 40 || ex.path.length > 50;
  return `
    <tr data-id="${ex.id}" ${isTruncated ? `data-full="${esc(ex.host + " - " + ex.path)}"` : ""} ${bulkSelected.has(ex.id) ? 'class="on"' : ""}>
      <td class="select-col"><input type="checkbox" class="row-checkbox" ${bulkSelected.has(ex.id) ? "checked" : ""} /></td>
      <td>${ex.id}</td>
      <td>${method}</td>
      <td class="${ex.host.length > 40 ? "ellipsis" : ""}">${displayHost}</td>
      <td class="${ex.path.length > 50 ? "ellipsis" : ""}">${displayPath}</td>
      <td>${statusBadge(ex.status)}</td>
      <td>${fmtBytes(ex.response_len)}</td>
      <td>${ex.duration_ms}</td>
      <td>${ex.tls ? "✓" : ""}</td>
      <td></td>
    </tr>
  `;
}
function attachRowListeners() {
  rendered.clear();
  $all2("#hist-body tr[data-id]").forEach((tr) => {
    const id = Number(tr.dataset["id"]);
    const ex = allRows.find((e) => e.id === id);
    if (ex) {
      rendered.set(id, ex);
      tr.onclick = (e) => {
        if (e.target.tagName === "INPUT" || e.target.closest(".row-checkbox") || e.target.closest("button")) {
          return;
        }
        openExchange(ex);
        markSelected(ex);
      };
    }
  });
}
async function openExchange(ex) {
  markSelected(ex);
  try {
    const [req, res] = await Promise.all([
      getJSON(`/api/message/${ex.request}`),
      ex.response ? getJSON(`/api/message/${ex.response}`) : Promise.resolve({ id: 0, len: 0, text: "" })
    ]);
    const reqEl = $("#hist-req");
    const resEl = $("#hist-res");
    reqEl.textContent = req.text;
    resEl.textContent = res.text;
    updateViewerLines("hist-req-container", req.text);
    updateViewerLines("hist-res-container", res.text);
    const reqMeta = $("#hist-req-meta");
    const resMeta = $("#hist-res-meta");
    reqMeta.textContent = `${ex.method} ${ex.path} - ${fmtBytes(req.len)}`;
    resMeta.textContent = res.len > 0 ? `Status: ${ex.status} - ${fmtBytes(res.len)}` : "No response";
  } catch (e) {
    toast2(e.message, "error");
  }
}

// src/wshistory.ts
function initWshistory() {
  const section = $("#wshistory");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">WebSocket messages captured by the proxy</span>
      <span class="grow"></span>
      <button class="ghost" onclick="refreshWSHistory()">Refresh</button>
      <button class="ghost" onclick="clearWSHistory()">Clear</button>
    </div>
    <div class="row">
      <input id="ws-search" placeholder="Search messages..." style="width:300px" />
      <select id="ws-direction-filter">
        <option value="">All directions</option>
        <option value="client">Client → Server</option>
        <option value="server">Server → Client</option>
      </select>
      <button class="ghost" onclick="applyWSFilter()">Apply</button>
    </div>
    <table>
      <thead>
        <tr>
          <th data-sort="id">#</th>
          <th data-sort="exchange_id">Exchange</th>
          <th data-sort="direction">Direction</th>
          <th data-sort="opcode">Opcode</th>
          <th>Payload</th>
          <th data-sort="payload_len">Len</th>
          <th data-sort="at_ms">Time</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="ws-body"></tbody>
    </table>
    <div id="ws-empty" class="hint" style="margin-top:8px"></div>
    <div id="ws-meta" class="hint" style="margin-top:8px"></div>
    
    <div class="card" style="margin-top:10px">
      <div class="card-title">Message Detail</div>
      <div class="two">
        <div>
          <div class="viewer-header"><b class="muted">Selected Message</b></div>
          <div class="code-viewer" id="ws-detail-container">
            <div class="code-lines" id="ws-detail-lines"></div>
            <pre id="ws-detail" spellcheck="false"></pre>
          </div>
        </div>
      </div>
    </div>
  `;
  makeSortable("ws-body", "id");
  loadWSHistory();
  const searchInput = $("#ws-search");
  const directionFilter = $("#ws-direction-filter");
  searchInput?.addEventListener("input", () => applyWSFilter());
  directionFilter?.addEventListener("change", () => applyWSFilter());
}
var allMessages = [];
async function loadWSHistory() {
  try {
    const response = await fetch("/api/ws?limit=500");
    if (!response.ok)
      throw new Error(`Failed to load WS history: ${response.status}`);
    const state = await response.json();
    allMessages = state.messages;
    const metaEl = $("#ws-meta");
    metaEl.textContent = `Showing ${Math.min(allMessages.length, 500)} of ${state.total.toLocaleString()} messages`;
    applyWSFilter();
  } catch (e) {
    const body = $("#ws-body");
    body.innerHTML = `<tr><td colspan="8" class="err">${esc(e.message)}</td></tr>`;
  }
}
function applyWSFilter() {
  const search = $("#ws-search")?.value.toLowerCase() || "";
  const direction = $("#ws-direction-filter")?.value || "";
  let messages = allMessages;
  if (direction) {
    messages = messages.filter((m) => m.direction === direction);
  }
  if (search) {
    messages = messages.filter((m) => m.payload.toLowerCase().includes(search));
  }
  renderMessages(messages);
}
function renderMessages(messages) {
  const tbody = $("#ws-body");
  const emptyEl = $("#ws-empty");
  if (messages.length === 0) {
    tbody.innerHTML = "";
    emptyEl.innerHTML = renderEmptyState("No WebSocket messages captured yet", "WebSocket messages will appear here when captured by the proxy", "\uD83D\uDD04", 8);
    return;
  }
  emptyEl.innerHTML = "";
  tbody.innerHTML = messages.slice(0, 100).map((m) => `
    <tr onclick="showWSMessage(${m.id})" style="cursor:pointer">
      <td>${m.id}</td>
      <td>${m.exchange_id}</td>
      <td><span class="tag tag-${m.direction}">${m.direction === "client" ? "→" : "←"}</span></td>
      <td>${m.opcode}</td>
      <td>${esc(m.payload.slice(0, 50))}${m.payload.length > 50 ? "..." : ""}</td>
      <td>${fmtBytes2(m.payload_len)}</td>
      <td>${new Date(m.at_ms).toLocaleTimeString()}</td>
      <td><button class="ghost small" onclick="event.stopPropagation(); copyWSMessage(${m.id})">Copy</button></td>
    </tr>
  `).join("");
  if (messages.length > 100) {
    tbody.innerHTML += `<tr><td colspan="8" class="hint">Showing 100 of ${messages.length.toLocaleString()} messages</td></tr>`;
  }
}
function fmtBytes2(n) {
  if (n < 1024)
    return `${n} B`;
  if (n < 1024 * 1024)
    return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
window.refreshWSHistory = function() {
  loadWSHistory();
};
window.clearWSHistory = async function() {
  if (!confirm("Are you sure you want to clear the entire WebSocket history?"))
    return;
  try {
    await fetch("/api/ws", { method: "DELETE" });
    toast("WebSocket history cleared", "success");
    loadWSHistory();
  } catch (e) {
    toast(e.message, "error");
  }
};
window.copyWSMessage = async function(id) {
  const msg = allMessages.find((m) => m.id === id);
  if (msg) {
    copyText(msg.payload, "WebSocket message");
  }
};
window.applyWSFilter = function() {
  applyWSFilter();
};

// src/sitemap.ts
function initSitemap() {
  const section = $("#sitemap");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">Tree view of all URLs seen by the proxy, grouped by host</span>
      <span class="grow"></span>
      <button class="ghost" onclick="refreshSitemap()">Refresh</button>
      <button class="ghost" onclick="expandAll()">Expand All</button>
      <button class="ghost" onclick="collapseAll()">Collapse All</button>
    </div>
    <div class="row">
      <input id="sitemap-search" placeholder="Search hosts and paths..." style="width:300px" />
      <button class="ghost" onclick="applySitemapFilter()">Search</button>
    </div>
    <div id="sitemap-tree" class="tree"></div>
    <div id="sitemap-empty" class="hint"></div>
    
    <div class="card" style="margin-top:10px">
      <div class="card-title">Selected URL Requests</div>
      <div id="sitemap-requests"></div>
    </div>
  `;
  loadSitemap();
  const searchInput = $("#sitemap-search");
  searchInput?.addEventListener("input", () => applySitemapFilter());
}
var allRoots = [];
var filteredRoots = [];
async function loadSitemap() {
  try {
    const response = await fetch("/api/sitemap");
    if (!response.ok)
      throw new Error(`Failed to load sitemap: ${response.status}`);
    const state = await response.json();
    allRoots = state.roots;
    filteredRoots = allRoots;
    renderTree();
  } catch (e) {
    const treeEl = $("#sitemap-tree");
    treeEl.innerHTML = `<div class="err">${esc(e.message)}</div>`;
  }
}
function renderTree(nodes = filteredRoots) {
  const treeEl = $("#sitemap-tree");
  const emptyEl = $("#sitemap-empty");
  if (nodes.length === 0) {
    treeEl.innerHTML = "";
    emptyEl.innerHTML = renderEmptyState("No URLs captured yet", "Browse through the proxy to build the site map", "\uD83D\uDDFA️", 1);
    return;
  }
  emptyEl.innerHTML = "";
  treeEl.innerHTML = nodes.map(renderNode).join("");
}
function renderNode(node, depth = 0) {
  const hasChildren = node.children.length > 0;
  const isExpanded = depth < 2;
  const count = node.request_count > 0 ? ` (${node.request_count})` : "";
  const name = esc(node.name) + count;
  if (hasChildren) {
    return `
      <ul>
        <li>
          <span class="node ${node.exchange_ids.length === 0 ? "unrequested" : ""}" 
                onclick="toggleNode(this)"
                data-path="${esc(node.full_path)}">
            <span class="seg">${name}</span>
            <span class="count">${node.exchange_ids.length} exchanges</span>
          </span>
          <div style="display: ${isExpanded ? "block" : "none"}" class="children">
            ${node.children.map((c) => renderNode(c, depth + 1)).join("")}
          </div>
        </li>
      </ul>
    `;
  } else {
    return `
      <ul>
        <li>
          <span class="node leaf ${node.exchange_ids.length === 0 ? "unrequested" : ""}" 
                onclick="showNodeRequests('${esc(node.full_path)}')"
                data-path="${esc(node.full_path)}">
            <span class="seg">${name}</span>
            <span class="count">${node.exchange_ids.length} exchanges</span>
          </span>
        </li>
      </ul>
    `;
  }
}
function applySitemapFilter() {
  const search = $("#sitemap-search")?.value.toLowerCase() || "";
  if (!search) {
    filteredRoots = allRoots;
  } else {
    filteredRoots = allRoots.map(filterNode);
  }
  renderTree();
}
function filterNode(node) {
  const search = $("#sitemap-search")?.value.toLowerCase() || "";
  const filteredChildren = node.children.map(filterNode).filter((c) => c.children.length > 0 || c.name.toLowerCase().includes(search) || c.full_path.toLowerCase().includes(search));
  const matches = node.name.toLowerCase().includes(search) || node.full_path.toLowerCase().includes(search) || filteredChildren.length > 0;
  return matches ? { ...node, children: filteredChildren } : { ...node, children: [] };
}
window.refreshSitemap = function() {
  loadSitemap();
};
window.expandAll = function() {
  const nodes = $all(".node");
  nodes.forEach((n) => {
    const children = n.nextElementSibling;
    if (children && children.classList.contains("children")) {
      children.style.display = "block";
    }
  });
};
window.collapseAll = function() {
  const nodes = $all(".node");
  nodes.forEach((n) => {
    const children = n.nextElementSibling;
    if (children && children.classList.contains("children")) {
      children.style.display = "none";
    }
  });
};
window.toggleNode = function(el) {
  const children = el.nextElementSibling;
  if (children && children.classList.contains("children")) {
    children.style.display = children.style.display === "none" ? "block" : "none";
  }
};
window.showExchange = function(id) {
  emit(EVT_FILTER_HISTORY, { search: String(id) });
  toast2(`Showing exchange #${id} in History`, "info");
};
window.filterHistoryByPath = function(path) {
  emit(EVT_FILTER_HISTORY, { search: path });
  toast2(`Filtering History by path: ${path}`, "info");
};
window.applySitemapFilter = function() {
  applySitemapFilter();
};

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
      <div>
        <div class="viewer-header">
          <b class="muted">Request</b>
          <button class="ghost small" onclick="copyRequest()">Copy</button>
          <span class="viewer-meta" id="rep-req-meta"></span>
        </div>
        <div class="code-viewer" id="rep-req-container">
          <div class="code-lines" id="rep-req-lines"></div>
          <textarea id="rep-raw" spellcheck="false"></textarea>
        </div>
      </div>
      <div>
        <div class="viewer-header">
          <b class="muted">Response</b>
          <button class="ghost small" onclick="copyResponse()">Copy</button>
          <span class="viewer-meta" id="rep-res-meta"></span>
        </div>
        <div class="code-viewer" id="rep-res-container">
          <div class="code-lines" id="rep-res-lines"></div>
          <pre id="rep-res" spellcheck="false"></pre>
        </div>
      </div>
    </div>
  `;
  const textarea = $("#rep-raw");
  if (textarea) {
    textarea.style.background = "transparent";
    textarea.style.border = "none";
    textarea.style.padding = "8px 8px 8px 40px";
    textarea.style.minHeight = "220px";
    textarea.style.resize = "none";
    textarea.style.fontFamily = "var(--font-mono)";
    textarea.style.fontSize = "13px";
    textarea.style.lineHeight = "1.5";
    textarea.style.width = "100%";
  }
  $("#rep-send").addEventListener("click", () => void send());
  $("#rep-tabs").addEventListener("click", (e) => onTabStripClick(e));
  addTab();
  on(EVT_SEND_TO_REPEATER, (d) => {
    addTab({ target: d.target, raw: d.raw, protocol: d.protocol });
    toast2(`loaded into Repeater (tab ${activeId})`, "success");
  });
}
window.copyRequest = function() {
  const textarea = $("#rep-raw");
  if (textarea)
    copyText(textarea.value, "request");
};
window.copyResponse = function() {
  const pre = $("#rep-res");
  if (pre)
    copyText(pre.textContent || "", "response");
};
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
  const metaEl = $("#rep-meta");
  if (tab.request_msg_id) {
    metaEl.innerHTML = `${statusBadge(tab.status)} \x17 ${tab.duration_ms} ms \x17 req msg ${tab.request_msg_id}`;
  } else {
    metaEl.innerHTML = "";
  }
  const resEl = $("#rep-res");
  if (resEl) {
    resEl.textContent = tab.response;
    updateViewerLines2("rep-res-container", tab.response);
  }
  updateViewerLines2("rep-req-container", tab.raw);
  const reqMeta = $("#rep-req-meta");
  const resMeta = $("#rep-res-meta");
  reqMeta.textContent = tab.raw.length > 0 ? `${fmtBytes3(tab.raw.length)}` : "Empty";
  resMeta.textContent = tab.response.length > 0 ? `${fmtBytes3(tab.response.length)}` : "No response";
}
function updateViewerLines2(containerId, content) {
  const container = $(`#${containerId}`);
  const linesEl = $(`#${containerId}-lines`);
  if (!container || !linesEl)
    return;
  const lines = content.split(`
`).length;
  linesEl.innerHTML = Array.from({ length: lines }, (_, i) => i + 1).join(`
`);
}
function fmtBytes3(n) {
  if (n < 1024)
    return `${n} B`;
  if (n < 1024 * 1024)
    return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
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
    if (activeId === id) {
      activeId = tabs[Math.min(idx, tabs.length - 1)].id;
    }
  }
  renderTabs();
  loadActiveIntoEditor();
}
async function send() {
  saveEditorIntoActiveTab();
  const tab = tabs.find((t) => t.id === activeId);
  if (!tab)
    return;
  const button = $("#rep-send");
  const originalText = button.textContent;
  try {
    button.classList.add("loading");
    button.disabled = true;
    const res = await postJSON(`/api/repeater/send`, {
      target: tab.target,
      raw: tab.raw,
      protocol: tab.protocol
    });
    tab.status = res.status;
    tab.duration_ms = res.duration_ms;
    tab.request_msg_id = res.request_msg_id;
    tab.response = res.response;
    loadActiveIntoEditor();
    const resMeta = $("#rep-res-meta");
    resMeta.textContent = res.response.length > 0 ? `Status: ${res.status} - ${fmtBytes3(res.response.length)}` : "No response";
    toast2(`Request sent: ${res.status || "No response"} in ${res.duration_ms}ms`, "success");
  } catch (e) {
    toast2(e.message, "error");
  } finally {
    button.classList.remove("loading");
    button.disabled = false;
    button.textContent = originalText;
  }
}

// src/intruder.ts
var MODES = [
  { value: "sniper", label: "Sniper" },
  { value: "battering_ram", label: "Battering Ram" },
  { value: "pitchfork", label: "Pitchfork" },
  { value: "cluster_bomb", label: "Cluster Bomb" }
];
var currentRequest = null;
var points = [];
var selectedPoints = new Set;
var currentReport = null;
var attackRunning = false;
function initIntruder() {
  const section = $("#intruder");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">right-click a row for send-to actions \x17 Ctrl+R Repeater \x17 Ctrl+I Intruder \x17 ? for shortcuts</span>
      <span class="grow"></span>
      <span class="hint">Request:</span>
      <input id="intr-req-id" placeholder="message id" style="width:100px" />
      <button class="ghost" id="intr-load" onclick="loadRequest()">Load</button>
    </div>
    <div class="row">
      <span class="hint">Target:</span>
      <input id="intr-target" placeholder="http://host:port" style="width:300px" />
      <span class="grow"></span>
      <span class="hint">Attack mode:</span>
      <select id="intr-mode">
        ${MODES.map((m) => `<option value="${m.value}">${m.label}</option>`).join("")}
      </select>
    </div>
    <div class="row">
      <button class="go" id="intr-attack" onclick="startAttack()" ${attackRunning ? "disabled" : ""}>
        ${attackRunning ? '<span class="spinner spinner-small"></span> Attacking...' : "Start Attack"}
      </button>
      <button class="ghost" id="intr-stop" onclick="stopAttack()" style="display:none">Stop</button>
      <span id="intr-progress" class="hint"></span>
    </div>
    
    <div class="card" style="margin-top:10px">
      <div class="card-title">Insertion Points</div>
      <p class="hint">Select the positions to attack. Click a row to toggle selection.</p>
      <table>
        <thead>
          <tr>
            <th class="select-col"><input type="checkbox" id="intr-select-all" /></th>
            <th>#</th>
            <th>Type</th>
            <th>Label</th>
            <th>Current Value</th>
            <th>Offset</th>
            <th>Length</th>
          </tr>
        </thead>
        <tbody id="intr-points"></tbody>
      </table>
      <div id="intr-points-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Payload Sets</div>
      <div class="row">
        <select id="intr-payload-type">
          <option value="list">Simple List</option>
          <option value="numbers">Numbers</option>
          <option value="dates">Dates</option>
          <option value="brute_force">Brute Force</option>
        </select>
        <textarea id="intr-payload-list" placeholder="One payload per line" style="width:300px;height:80px;display:none"></textarea>
        <div id="intr-payload-config" style="display:none"></div>
        <button class="ghost" id="intr-add-payload" onclick="addPayloadSet()">Add Payload Set</button>
      </div>
      <div id="intr-payload-sets" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Results</div>
      <div id="intr-results"></div>
    </div>
  `;
  const selectAll = $("#intr-select-all");
  selectAll.addEventListener("change", () => {
    points.forEach((p) => {
      const cb = $(`#intr-point-${p.index}`);
      if (cb)
        cb.checked = selectAll.checked;
    });
    selectedPoints = selectAll.checked ? new Set(points.map((p) => p.index)) : new Set;
    updateSelectedCount();
  });
  const payloadType = $("#intr-payload-type");
  const payloadList = $("#intr-payload-list");
  const payloadConfig = $("#intr-payload-config");
  payloadType.addEventListener("change", () => {
    payloadList.style.display = payloadType.value === "list" ? "block" : "none";
    payloadConfig.style.display = payloadType.value !== "list" ? "block" : "none";
    payloadConfig.innerHTML = getPayloadConfigHTML(payloadType.value);
  });
  on(EVT_SEND_TO_INTRUDER, (d) => {
    currentRequest = { id: d.msgId, raw: "", target: d.target };
    $("#intr-req-id").value = String(d.msgId);
    $("#intr-target").value = d.target;
    loadRequest();
    toast2(`Loaded request #${d.msgId} into Intruder`, "success");
  });
}
function getPayloadConfigHTML(kind) {
  switch (kind) {
    case "numbers":
      return `
        <div class="stack">
          <div class="row">
            <label>From: <input type="number" id="intr-num-from" value="1" style="width:80px" /></label>
            <label>To: <input type="number" id="intr-num-to" value="10" style="width:80px" /></label>
            <label>Step: <input type="number" id="intr-num-step" value="1" style="width:80px" /></label>
          </div>
          <div class="row">
            <label>Base: <select id="intr-num-base"><option value="decimal">Decimal</option><option value="hex">Hex</option></select></label>
            <label>Pad to: <input type="number" id="intr-num-pad" value="0" style="width:80px" /></label>
          </div>
        </div>
      `;
    case "dates":
      return `
        <div class="stack">
          <div class="row">
            <label>From: <input type="date" id="intr-date-from" style="width:150px" /></label>
            <label>To: <input type="date" id="intr-date-to" style="width:150px" /></label>
          </div>
          <div class="row">
            <label>Step (days): <input type="number" id="intr-date-step" value="1" style="width:80px" /></label>
            <label>Format: <input type="text" id="intr-date-format" value="YYYY-MM-DD" style="width:120px" /></label>
          </div>
        </div>
      `;
    case "brute_force":
      return `
        <div class="stack">
          <div class="row">
            <label>Charset: <input type="text" id="intr-bf-charset" value="abcdefghijklmnopqrstuvwxyz" style="width:200px" /></label>
          </div>
          <div class="row">
            <label>Min length: <input type="number" id="intr-bf-min" value="1" style="width:80px" /></label>
            <label>Max length: <input type="number" id="intr-bf-max" value="5" style="width:80px" /></label>
          </div>
        </div>
      `;
    default:
      return "";
  }
}
window.loadRequest = async function() {
  const input = $("#intr-req-id");
  const id = parseInt(input.value, 10);
  if (isNaN(id)) {
    toast2("Please enter a valid message ID", "error");
    return;
  }
  const button = $("#intr-load");
  const originalText = button.textContent;
  try {
    button.classList.add("loading");
    button.disabled = true;
    button.textContent = "Loading...";
    const response = await fetch(`/api/message/${id}`);
    if (!response.ok)
      throw new Error(`Failed to load message: ${response.status}`);
    const msg = await response.json();
    currentRequest = {
      id,
      raw: msg.text,
      target: $("#intr-target").value || ""
    };
    const pointsResp = await fetch(`/api/intruder/points/${id}`);
    if (pointsResp.ok) {
      points = await pointsResp.json();
      renderPoints();
    }
    toast2(`Loaded request #${id}`, "success");
  } catch (e) {
    toast2(e.message, "error");
  } finally {
    button.classList.remove("loading");
    button.disabled = false;
    button.textContent = originalText;
  }
};
window.startAttack = async function() {
  if (!currentRequest) {
    toast2("Please load a request first", "error");
    return;
  }
  if (selectedPoints.size === 0) {
    toast2("Please select at least one insertion point", "error");
    return;
  }
  const mode = $("#intr-mode").value;
  const target = $("#intr-target").value;
  if (!target) {
    toast2("Please specify a target", "error");
    return;
  }
  const button = $("#intr-attack");
  const stopButton = $("#intr-stop");
  const progressEl = $("#intr-progress");
  try {
    attackRunning = true;
    button.disabled = true;
    stopButton.style.display = "inline-block";
    progressEl.innerHTML = '<span class="spinner spinner-small"></span> Starting attack...';
    const payloadSets = [];
    const response = await postJSON(`/api/intruder/attack`, {
      request_id: currentRequest.id,
      target,
      mode,
      points: Array.from(selectedPoints),
      payload_sets: payloadSets
    });
    currentReport = response;
    renderResults();
    toast2(`Attack completed: ${response.report.sent} requests sent`, "success");
  } catch (e) {
    toast2(e.message, "error");
  } finally {
    attackRunning = false;
    button.disabled = false;
    stopButton.style.display = "none";
    progressEl.textContent = "";
  }
};
window.stopAttack = function() {
  toast2("Attack stop requested", "info");
  attackRunning = false;
  $("#intr-attack").disabled = false;
  $("#intr-stop").style.display = "none";
  $("#intr-progress").textContent = "";
};
window.addPayloadSet = function() {
  const type = $("#intr-payload-type").value;
  const setsEl = $("#intr-payload-sets");
  let payloadSet;
  switch (type) {
    case "list":
      const text = $("#intr-payload-list").value;
      payloadSet = { type: "list", items: text.split(`
`).filter((l) => l.trim()) };
      break;
    case "numbers":
      payloadSet = {
        type: "numbers",
        from: parseInt($("#intr-num-from").value) || 1,
        to: parseInt($("#intr-num-to").value) || 10,
        step: parseInt($("#intr-num-step").value) || 1,
        order: "sequential",
        count: 0,
        base: $("#intr-num-base").value,
        pad_to: parseInt($("#intr-num-pad").value) || 0
      };
      break;
    case "dates":
      payloadSet = {
        type: "dates",
        from: $("#intr-date-from").value,
        to: $("#intr-date-to").value,
        step: parseInt($("#intr-date-step").value) || 1,
        format: $("#intr-date-format").value
      };
      break;
    case "brute_force":
      payloadSet = {
        type: "brute_force",
        charset: $("#intr-bf-charset").value,
        min_len: parseInt($("#intr-bf-min").value) || 1,
        max_len: parseInt($("#intr-bf-max").value) || 5
      };
      break;
    default:
      return;
  }
  const setId = Date.now();
  const setEl = document.createElement("div");
  setEl.className = "payload-set";
  setEl.dataset.id = String(setId);
  setEl.innerHTML = `
    <span class="pill pill-outline">${type}</span>
    <span>${describePayloadSet(payloadSet)}</span>
    <button class="ghost small" onclick="removePayloadSet(${setId})">Remove</button>
  `;
  setsEl.appendChild(setEl);
  toast2(`Added ${type} payload set`, "success");
};
window.removePayloadSet = function(id) {
  const setEl = $(`[data-id="${id}"]`);
  if (setEl) {
    setEl.remove();
    toast2("Payload set removed", "success");
  }
};
function describePayloadSet(set) {
  switch (set.type) {
    case "list":
      return `${set.items.length} items`;
    case "numbers":
      return `Numbers: ${set.from}-${set.to} step ${set.step}`;
    case "dates":
      return `Dates: ${set.from} to ${set.to}`;
    case "brute_force":
      return `Brute force: ${set.charset} (${set.min_len}-${set.max_len} chars)`;
    default:
      return set.type;
  }
}
function renderPoints() {
  const tbody = $("#intr-points");
  const emptyEl = $("#intr-points-empty");
  if (points.length === 0) {
    tbody.innerHTML = "";
    emptyEl.innerHTML = renderEmptyState("No insertion points found", "Load a request to find injectable positions", "\uD83C\uDFAF", 7);
    return;
  }
  emptyEl.innerHTML = "";
  tbody.innerHTML = points.map((p) => `
    <tr data-id="${p.index}" ${selectedPoints.has(p.index) ? 'class="on"' : ""}>
      <td class="select-col"><input type="checkbox" id="intr-point-${p.index}" ${selectedPoints.has(p.index) ? "checked" : ""} onchange="togglePoint(${p.index})" /></td>
      <td>${p.index}</td>
      <td>${esc(p.kind)}</td>
      <td>${esc(p.label)}</td>
      <td>${esc(p.current)}</td>
      <td>${p.offset}</td>
      <td>${p.len}</td>
    </tr>
  `).join("");
  points.forEach((p) => {
    const tr = $(`#intr-points tr[data-id="${p.index}"]`);
    tr.onclick = (e) => {
      if (e.target.tagName === "INPUT")
        return;
      togglePoint(p.index);
    };
  });
}
function togglePoint(index) {
  if (selectedPoints.has(index)) {
    selectedPoints.delete(index);
  } else {
    selectedPoints.add(index);
  }
  const cb = $(`#intr-point-${index}`);
  if (cb)
    cb.checked = selectedPoints.has(index);
  const tr = $(`#intr-points tr[data-id="${index}"]`);
  if (tr)
    tr.classList.toggle("on", selectedPoints.has(index));
  const selectAll = $("#intr-select-all");
  if (selectAll) {
    selectAll.checked = selectedPoints.size === points.length;
    selectAll.indeterminate = selectedPoints.size > 0 && selectedPoints.size < points.length;
  }
  updateSelectedCount();
}
function updateSelectedCount() {
  const countEl = $("#intr-selected-count");
  if (countEl) {
    countEl.textContent = `${selectedPoints.size} selected`;
  }
}
function renderResults() {
  const el = $("#intr-results");
  if (!currentReport) {
    el.innerHTML = renderEmptyState("No attack results yet", "Run an attack to see results here", "\uD83C\uDFAF", 1);
    return;
  }
  const r = currentReport.report;
  el.innerHTML = `
    <div class="row">
      <span class="hint">Attack: ${esc(r.kind)}</span>
      <span class="grow"></span>
      <span class="hint">Sent: ${r.sent.toLocaleString()} / ${r.combinations.toLocaleString()}</span>
    </div>
    <div class="row">
      <span class="hint">Elapsed: ${(r.elapsed_ms / 1000).toFixed(2)}s</span>
      <span class="hint">Failed: ${r.failed.toLocaleString()}</span>
      <span class="hint">Throttled: ${r.auto_throttle_engaged.toLocaleString()}</span>
    </div>
    
    ${r.buckets.length > 0 ? `
      <table style="margin-top:10px">
        <thead>
          <tr>
            <th>Status</th>
            <th>Count</th>
            <th>Response Len</th>
            <th>Reflected</th>
            <th>Grep Matches</th>
          </tr>
        </thead>
        <tbody>
          ${r.buckets.map((b) => `
            <tr>
              <td>${statusBadge(b.status)}</td>
              <td>${b.count.toLocaleString()}</td>
              <td>${fmtBytes4(b.response_len)}</td>
              <td>${b.reflected ? "✓" : ""}</td>
              <td>${b.grep_matches > 0 ? b.grep_matches.toLocaleString() : ""}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    ` : ""}
    
    ${r.errors.length > 0 ? `
      <div style="margin-top:10px">
        <b>Errors:</b>
        <ul>
          ${r.errors.map((e) => `<li>${esc(e.error)}: ${e.count.toLocaleString()} times</li>`).join("")}
        </ul>
      </div>
    ` : ""}
  `;
}
function fmtBytes4(n) {
  if (n < 1024)
    return `${n} B`;
  if (n < 1024 * 1024)
    return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
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
      <thead>
        <tr>
          <th>#</th>
          <th data-sort="direction">Dir</th>
          <th data-sort="method">Method</th>
          <th data-sort="host">Host</th>
          <th data-sort="path">Path</th>
          <th data-sort="status">Status</th>
          <th>Held</th>
          <th data-sort="len">Len</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="ic-body"></tbody>
    </table>
    <div id="ic-editor"></div>
  `;
  makeSortable("ic-body", "id");
  $("#ic-body")?.addEventListener("sort", (e) => {
    load3();
  });
  $("#ic-enabled").addEventListener("change", (e) => void setEnabled(e.target.checked));
  ["request", "response"].forEach(wireRulesSection);
  load3();
  loadRules("request");
  loadRules("response");
  live({ kinds: ["intercept"], section: "intercept", refresh: () => void load3(), minGapMs: 0, fallbackMs: 1500 });
}
function rulesSectionHtml(dir) {
  return `
    <details ${lists[dir].active ? "open" : ""}>
      <summary>
        <label class="switch"><input type="checkbox" class="ic-list-active" data-dir="${dir}" ${lists[dir].active ? "checked" : ""} /><span class="slider"></span></label>
        <span>${dir} rules</span>
        <span class="hint">match on ${dir}</span>
      </summary>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Match</th>
            <th>Type</th>
            <th>Comment</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody class="ic-rules ic-rules-${dir}"></tbody>
      </table>
      <div class="row" style="margin-top:4px">
        <select class="ic-field" data-dir="${dir}">
          ${FIELDS.map((f) => `<option value="${f.value}">${f.label}</option>`).join("")}
        </select>
        <select class="ic-category" data-dir="${dir}">
          ${CATEGORIES.map((c) => `<option value="${c.value}">${c.label}</option>`).join("")}
        </select>
        <input type="text" class="ic-pattern" data-dir="${dir}" placeholder="pattern" style="width:200px" />
        <input type="text" class="ic-comment" data-dir="${dir}" placeholder="comment" style="width:150px" />
        <button class="ghost small" data-dir="${dir}" onclick="addRule('${dir}')">Add</button>
      </div>
    </details>
  `;
}
function wireRulesSection(dir) {
  const activeCb = $(`.ic-list-active[data-dir="${dir}"]`);
  activeCb.addEventListener("change", () => {
    lists[dir].active = activeCb.checked;
    saveRules(dir);
  });
  const addBtn = $(`button[data-dir="${dir}"]`);
  addBtn.addEventListener("click", () => addRule(dir));
  loadRules(dir);
}
window.addRule = function(dir) {
  const field = $(`.ic-field[data-dir="${dir}"]`);
  const category = $(`.ic-category[data-dir="${dir}"]`);
  const pattern = $(`.ic-pattern[data-dir="${dir}"]`);
  const comment = $(`.ic-comment[data-dir="${dir}"]`);
  if (!field || !category || !pattern)
    return;
  const rule = {
    field: field.value,
    enabled: true,
    string_match: pattern.value,
    category: category.value,
    comment: comment.value
  };
  lists[dir].rules.push(rule);
  pattern.value = "";
  comment.value = "";
  renderRules(dir);
  saveRules(dir);
};
function renderRules(dir) {
  const tbody = $(`.ic-rules-${dir}`);
  if (!tbody)
    return;
  if (lists[dir].rules.length === 0) {
    tbody.innerHTML = renderEmptyState("No rules defined", `Add rules to intercept ${dir}s matching specific criteria`, "\uD83D\uDCDD", 5);
    return;
  }
  tbody.innerHTML = lists[dir].rules.map((r, i) => `
    <tr>
      <td>${FIELDS.find((f) => f.value === r.field)?.label || r.field}</td>
      <td>${esc(r.string_match)}</td>
      <td>${CATEGORIES.find((c) => c.value === r.category)?.label || r.category}</td>
      <td>${esc(r.comment)}</td>
      <td>
        <button class="ghost small" onclick="toggleRule('${dir}', ${i})">${r.enabled ? "Disable" : "Enable"}</button>
        <button class="ghost small" onclick="removeRule('${dir}', ${i})">Remove</button>
      </td>
    </tr>
  `).join("");
}
window.toggleRule = function(dir, index) {
  const rule = lists[dir].rules[index];
  if (rule) {
    rule.enabled = !rule.enabled;
    renderRules(dir);
    saveRules(dir);
  }
};
window.removeRule = function(dir, index) {
  lists[dir].rules.splice(index, 1);
  renderRules(dir);
  saveRules(dir);
};
async function saveRules(dir) {
  try {
    await putJSON(`/api/intercept/rules/${dir}`, { rules: lists[dir].rules });
    toast2(`Saved ${dir} rules`, "success");
  } catch (e) {
    toast2(e.message, "error");
  }
}
async function loadRules(dir) {
  try {
    const resp = await getJSON(`/api/intercept/rules/${dir}`);
    if (resp.rules) {
      lists[dir].rules = resp.rules;
      lists[dir].active = resp.active ?? false;
      renderRules(dir);
      const activeCb = $(`.ic-list-active[data-dir="${dir}"]`);
      activeCb.checked = lists[dir].active;
    }
  } catch (e) {}
}
async function setEnabled(enabled) {
  try {
    await postJSON("/api/intercept/enable", { enabled });
  } catch (e) {
    $("#ic-status").innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
  load3();
}
async function load3() {
  const body = $("#ic-body");
  const status = $("#ic-status");
  const checkbox = $("#ic-enabled");
  const queueHint = $("#ic-queue-hint");
  body.innerHTML = `<tr><td colspan="9" class="loading-state"><span class="spinner spinner-medium"></span> Loading queue...</td></tr>`;
  let resp;
  try {
    resp = await getJSON("/api/intercept");
  } catch (e) {
    status.innerHTML = `<span class="err">${esc(e.message)}</span>`;
    body.innerHTML = renderEmptyState("Error loading intercept queue", e.message, "⚠️", 9);
    return;
  }
  checkbox.checked = resp.enabled;
  status.innerHTML = !resp.wired ? esc(resp.hint ?? "interception is not wired up") : `<span class="status-pill ${resp.pending ? "bad" : "off"}">${resp.pending} pending</span>`;
  queueHint.textContent = queueHint(resp);
  if (resp.held.length === 0) {
    body.innerHTML = renderEmptyState("No requests held", resp.enabled ? "Requests matching your rules will appear here" : "Enable interception to start holding requests", "\uD83D\uDEA6", 9);
    stopHeldClock();
    return;
  }
  body.innerHTML = resp.held.map(renderHeld).join("");
  startHeldClock();
}
function renderHeld(h) {
  const heldSecs = Math.floor(h.held_ms / 1000);
  const held = heldSecs > 60 ? `${Math.floor(heldSecs / 60)}m ${heldSecs % 60}s` : `${heldSecs}s`;
  return `
    <tr data-id="${h.id}" ${selectedId === h.id ? 'class="on"' : ""}>
      <td>${h.id}</td>
      <td>${h.direction === "request" ? "→" : "←"}</td>
      <td>${esc(h.method)}</td>
      <td>${esc(h.host)}</td>
      <td>${esc(h.path)}</td>
      <td>${h.status ? h.status : "-"}</td>
      <td class="held-time" data-start="${h.held_ms}">${held}</td>
      <td>${fmtBytes5(h.len)}</td>
      <td>
        <button class="ghost small" onclick="forwardHeld(${h.id})">Forward</button>
        <button class="ghost small" onclick="dropHeld(${h.id})">Drop</button>
      </td>
    </tr>
  `;
}
function fmtBytes5(n) {
  if (n < 1024)
    return `${n} B`;
  if (n < 1024 * 1024)
    return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
function startHeldClock() {
  if (heldClock)
    return;
  heldClock = setInterval(() => {
    $all2(".held-time").forEach((el) => {
      const start = parseInt(el.getAttribute("data-start") || "0");
      const heldSecs = Math.floor((Date.now() - start) / 1000);
      const held = heldSecs > 60 ? `${Math.floor(heldSecs / 60)}m ${heldSecs % 60}s` : `${heldSecs}s`;
      el.textContent = held;
    });
  }, 1000);
}
function stopHeldClock() {
  if (heldClock) {
    clearInterval(heldClock);
    heldClock = undefined;
  }
}
function markSelected2(id) {
  selectedId = id;
  $all2("#ic-body tr").forEach((tr) => tr.classList.toggle("on", Number(tr.dataset["id"]) === id));
}
window.forwardHeld = async function(id) {
  try {
    await postJSON(`/api/intercept/forward/${id}`, {});
    toast2(`Forwarded message #${id}`, "success");
    markSelected2(null);
    load3();
  } catch (e) {
    toast2(e.message, "error");
  }
};
window.dropHeld = async function(id) {
  try {
    await postJSON(`/api/intercept/drop/${id}`, {});
    toast2(`Dropped message #${id}`, "success");
    markSelected2(null);
    load3();
  } catch (e) {
    toast2(e.message, "error");
  }
};

// src/scanner.ts
var openFindingId = null;
var rendered2 = [];
var selected2 = null;
function initScanner() {
  const section = $("#scanner");
  if (!section)
    return;
  section.innerHTML = `
    ${liveAuditCardHtml("scan")}
    <div class="row">
      <span id="scan-counts"></span>
      <span class="hint">right-click a finding to open or send its first occurrence \x17 ? for shortcuts</span>
      <span class="grow"></span>
      <span class="hint">Audit exchange:</span>
      <input id="scan-audit-id" placeholder="exchange id" style="width:110px" />
      <button class="go" id="scan-audit-run">Audit</button>
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
      <thead>
        <tr>
          <th data-sort="severity">Sev</th>
          <th data-sort="confidence">Conf</th>
          <th data-sort="check_name">Check</th>
          <th data-sort="issue_name">Issue</th>
          <th data-sort="host">Host</th>
          <th data-sort="times_seen">Seen</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody id="scan-body"></tbody>
    </table>
    <div id="scan-detail"></div>
  `;
  makeSortable("scan-body", "severity");
  $("#scan-body")?.addEventListener("sort", (e) => {
    const { field, ascending } = e.detail;
    if (rendered2.length > 0) {
      rendered2.sort(createSorter(field, ascending));
      renderBody();
    }
  });
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
    if (!selected2)
      return null;
    const first = selected2.occurrences[0];
    return {
      label: `finding "${selected2.issue_name ?? selected2.check_name}"`,
      ...first ? { exchangeId: first.exchange_id } : {},
      note: "this finding has no recorded occurrence, so there is no request to send"
    };
  });
  live({ kinds: ["issues"], section: "scanner", refresh: () => void load4() });
  load4();
}
function markSelected3(f) {
  selected2 = f;
  $all2("#scan-body tr").forEach((tr) => tr.classList.toggle("on", Number(tr.dataset["id"]) === f.id));
}
function findingMenuItems(f) {
  const first = f.occurrences[0];
  const items = [
    { label: "Copy finding as text", run: () => void copyText2(findingAsText(f), "the finding") },
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
function renderSeverity(sev) {
  const classes = {
    High: "sev-high",
    Medium: "sev-medium",
    Low: "sev-low",
    Information: "sev-info"
  };
  return `<span class="${classes[sev] || "sev-info"}">${esc(sev)}</span>`;
}
function renderConfidence(conf) {
  const classes = {
    Certain: "ok",
    Firm: "ok",
    Tentative: "dim"
  };
  return `<span class="${classes[conf] || "dim"}">${esc(conf)}</span>`;
}
function renderRow2(f) {
  const sev = renderSeverity(f.severity);
  const conf = renderConfidence(f.confidence);
  const issue = esc(f.issue_name || f.check_name);
  const check = esc(f.check_name);
  const host = esc(f.host);
  const seen = f.times_seen.toLocaleString();
  const detail = f.detail ? `<button class="ghost small" onclick="toggleDetail(${f.id})">Show</button>` : "-";
  return `
    <tr data-id="${f.id}" ${selected2?.id === f.id ? 'class="on"' : ""}>
      <td>${sev}</td>
      <td>${conf}</td>
      <td>${check}</td>
      <td>${issue}</td>
      <td>${host}</td>
      <td>${seen}</td>
      <td>${detail}</td>
    </tr>
  `;
}
function renderDetail(f) {
  return `
    <div class="card" style="margin-top:10px">
      <div class="card-title">Finding Details</div>
      <div class="detail-text">${esc(f.detail || "No detail available")}</div>
      ${f.remediation ? `<div style="margin-top:8px"><b>Remediation:</b><div class="detail-text">${esc(f.remediation)}</div></div>` : ""}
      ${f.occurrences.length > 0 ? `
        <div style="margin-top:8px"><b>Occurrences:</b>
        <ul style="margin:4px 0;padding-left:20px">
          ${f.occurrences.map((o) => `<li>Exchange #${o.exchange_id} - ${esc(o.path)}</li>`).join("")}
        </ul>
        </div>
      ` : ""}
    </div>
  `;
}
window.toggleDetail = function(id) {
  const detailEl = $("#scan-detail");
  const finding = rendered2.find((f) => f.id === id);
  if (!finding)
    return;
  if (openFindingId === id) {
    openFindingId = null;
    detailEl.innerHTML = "";
  } else {
    openFindingId = id;
    detailEl.innerHTML = renderDetail(finding);
  }
};
function renderCounts(counts) {
  if (!counts)
    return "";
  const total = counts.high + counts.medium + counts.low + counts.info;
  return `
    <span class="pill sev-high">${counts.high}</span>
    <span class="pill sev-medium">${counts.medium}</span>
    <span class="pill sev-low">${counts.low}</span>
    <span class="pill sev-info">${counts.info}</span>
    <span style="margin-left:8px">Total: ${total.toLocaleString()}</span>
  `;
}
async function load4() {
  const body = $("#scan-body");
  const counts = $("#scan-counts");
  const hint = $("#scan-hint");
  body.innerHTML = `<tr><td colspan="7" class="loading-state"><span class="spinner spinner-medium"></span> Loading findings...</td></tr>`;
  let resp;
  try {
    resp = await getJSON("/api/issues");
  } catch (e) {
    body.innerHTML = `<tr><td colspan="7" class="err">${esc(e.message)}</td></tr>`;
    return;
  }
  if (!resp.enabled) {
    body.innerHTML = renderEmptyState("Passive scanning not enabled", resp.hint || "Enable passive scanning to see findings here", "\uD83D\uDD0D", 7);
    counts.innerHTML = "";
    hint.textContent = resp.hint || "";
    return;
  }
  rendered2 = resp.findings;
  if (rendered2.length === 0) {
    body.innerHTML = renderEmptyState("No findings yet", "Passive findings will appear here as traffic is captured", "✅", 7);
    counts.innerHTML = "";
    hint.textContent = "No issues detected";
    return;
  }
  counts.innerHTML = renderCounts(resp.counts);
  hint.textContent = "";
  body.innerHTML = rendered2.map(renderRow2).join("");
}
async function runAudit() {
  const input = $("#scan-audit-id");
  const id = parseInt(input.value, 10);
  if (isNaN(id)) {
    toast2("Please enter a valid exchange ID", "error");
    return;
  }
  const button = $("#scan-audit-run");
  const originalText = button.textContent;
  try {
    button.classList.add("loading");
    button.textContent = "Auditing...";
    const out = $("#scan-audit-out");
    out.innerHTML = '<div class="hint"><span class="spinner spinner-small"></span> Starting audit...</div>';
    const result = await postJSON(`/api/scanner/audit/${id}`, {});
    out.innerHTML = `<div class="hint ok">Audit started: Task #${result.task_id} - ${esc(result.message)}</div>`;
    input.value = "";
    toast2(`Audit started for exchange #${id}`, "success");
  } catch (e) {
    toast2(e.message, "error");
  } finally {
    button.classList.remove("loading");
    button.textContent = originalText;
  }
}

// src/decoder.ts
var OPERATIONS = [
  {
    category: "Decode",
    ops: [
      { value: "url_decode", label: "URL decode" },
      { value: "html_decode", label: "HTML decode" },
      { value: "base64_decode", label: "Base64 decode" },
      { value: "hex_decode", label: "Hex decode" },
      { value: "gzip_decompress", label: "Gzip decompress" },
      { value: "deflate_decompress", label: "Deflate decompress" }
    ]
  },
  {
    category: "Encode",
    ops: [
      { value: "url_encode", label: "URL encode" },
      { value: "html_encode", label: "HTML encode" },
      { value: "base64_encode", label: "Base64 encode" },
      { value: "hex_encode", label: "Hex encode" },
      { value: "gzip_compress", label: "Gzip compress" },
      { value: "deflate_compress", label: "Deflate compress" }
    ]
  },
  {
    category: "Hash",
    ops: [
      { value: "md5", label: "MD5" },
      { value: "sha1", label: "SHA-1" },
      { value: "sha256", label: "SHA-256" }
    ]
  }
];
function initDecoder() {
  const section = $("#decoder");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">Apply an operation to the input text below.</span>
      <span class="grow"></span>
      <button class="ghost small" onclick="swapDecoder()">Swap</button>
      <button class="ghost small" onclick="clearDecoder()">Clear</button>
    </div>
    <div class="two">
      <div>
        <div class="viewer-header">
          <b class="muted">Input</b>
          <button class="ghost small" onclick="copyInput()">Copy</button>
        </div>
        <textarea id="dec-input" placeholder="Paste text or hex to decode/encode..." spellcheck="false" style="min-height:150px"></textarea>
      </div>
      <div>
        <div class="viewer-header">
          <b class="muted">Output</b>
          <button class="ghost small" onclick="copyOutput()">Copy</button>
        </div>
        <textarea id="dec-output" readonly spellcheck="false" style="min-height:150px"></textarea>
      </div>
    </div>
    <div class="row" style="margin-top:10px">
      <div class="stack">
        ${OPERATIONS.map((g) => `
            <div>
              <b class="muted" style="font-size:11px">${esc(g.category)}:</b>
              <select style="width:200px" onchange="applyOp(this)">
                <option value="">— select —</option>
                ${g.ops.map((o) => `<option value="${o.value}">${esc(o.label)}</option>`).join("")}
              </select>
            </div>
          `).join("")}
      </div>
    </div>
  `;
}
window.copyInput = function() {
  const el = $("#dec-input");
  if (el)
    copyText(el.value, "input");
};
window.copyOutput = function() {
  const el = $("#dec-output");
  if (el)
    copyText(el.value, "output");
};
window.swapDecoder = function() {
  const input = $("#dec-input");
  const output = $("#dec-output");
  if (input && output) {
    const temp = input.value;
    input.value = output.value;
    output.value = temp;
    toast2("Swapped input and output", "success");
  }
};
window.clearDecoder = function() {
  const input = $("#dec-input");
  const output = $("#dec-output");
  if (input)
    input.value = "";
  if (output)
    output.value = "";
  toast2("Cleared", "success");
};

// src/comparer.ts
var left = { msgId: null, text: "" };
var right = { msgId: null, text: "" };
function initComparer() {
  const section = $("#comparer");
  if (!section)
    return;
  section.innerHTML = `
    <div class="two">
      <div>
        <div class="viewer-header">
          <b class="muted">Side A</b>
          <button class="ghost small" onclick="copySide('a')">Copy</button>
          <button class="ghost small" onclick="clearSide('a')">Clear</button>
          <span id="comp-a-meta" class="viewer-meta"></span>
        </div>
        <div class="code-viewer" id="comp-a-container">
          <div class="code-lines" id="comp-a-lines"></div>
          <textarea id="comp-a" placeholder="Paste or send from History..." spellcheck="false"></textarea>
        </div>
      </div>
      <div>
        <div class="viewer-header">
          <b class="muted">Side B</b>
          <button class="ghost small" onclick="copySide('b')">Copy</button>
          <button class="ghost small" onclick="clearSide('b')">Clear</button>
          <span id="comp-b-meta" class="viewer-meta"></span>
        </div>
        <div class="code-viewer" id="comp-b-container">
          <div class="code-lines" id="comp-b-lines"></div>
          <textarea id="comp-b" placeholder="Paste or send from History..." spellcheck="false"></textarea>
        </div>
      </div>
    </div>
    <div class="row" style="margin-top:10px">
      <button class="go" onclick="computeDiff()">Diff</button>
      <button class="ghost" onclick="swapSides()">Swap Sides</button>
      <button class="ghost" onclick="clearBoth()">Clear Both</button>
      <span class="grow"></span>
      <span class="hint" id="comp-status"></span>
    </div>
    <div id="comp-diff" style="margin-top:10px"></div>
  `;
  [$("#comp-a"), $("#comp-b")].forEach((el) => {
    if (el) {
      el.style.background = "transparent";
      el.style.border = "none";
      el.style.padding = "8px 8px 8px 40px";
      el.style.minHeight = "200px";
      el.style.resize = "none";
      el.style.fontFamily = "var(--font-mono)";
      el.style.fontSize = "13px";
      el.style.lineHeight = "1.5";
      el.style.width = "100%";
    }
  });
  on(EVT_SEND_TO_COMPARER, (d) => {
    if (d.side === "a") {
      left.msgId = d.msgId;
      left.text = "";
      $("#comp-a-meta").textContent = d.label;
      loadMessage(d.msgId, "a");
      toast2(`Loaded ${d.label} into Comparer A`, "success");
    } else {
      right.msgId = d.msgId;
      right.text = "";
      $("#comp-b-meta").textContent = d.label;
      loadMessage(d.msgId, "b");
      toast2(`Loaded ${d.label} into Comparer B`, "success");
    }
  });
}
window.copySide = function(side) {
  const el = $(`#comp-${side}`);
  if (el)
    copyText(el.value, `side ${side.toUpperCase()}`);
};
window.clearSide = function(side) {
  const el = $(`#comp-${side}`);
  if (el) {
    el.value = "";
    if (side === "a") {
      left.text = "";
      left.msgId = null;
      $("#comp-a-meta").textContent = "";
    } else {
      right.text = "";
      right.msgId = null;
      $("#comp-b-meta").textContent = "";
    }
    updateLineNumbers(side);
    toast2(`Cleared side ${side.toUpperCase()}`, "success");
  }
};
window.clearBoth = function() {
  clearSide("a");
  clearSide("b");
  $("#comp-diff").innerHTML = "";
  $("#comp-status").textContent = "";
  toast2("Cleared both sides", "success");
};
window.swapSides = function() {
  const aEl = $("#comp-a");
  const bEl = $("#comp-b");
  const aMeta = $("#comp-a-meta");
  const bMeta = $("#comp-b-meta");
  if (aEl && bEl) {
    const tempText = aEl.value;
    const tempMeta = aMeta.textContent;
    const tempMsgId = left.msgId;
    aEl.value = bEl.value;
    left.text = bEl.value;
    left.msgId = right.msgId;
    aMeta.textContent = bMeta.textContent;
    bEl.value = tempText;
    right.text = tempText;
    right.msgId = tempMsgId;
    bMeta.textContent = tempMeta;
    updateLineNumbers("a");
    updateLineNumbers("b");
    if (left.text && right.text) {
      computeDiff();
    }
    toast2("Swapped sides", "success");
  }
};
window.computeDiff = async function() {
  const aEl = $("#comp-a");
  const bEl = $("#comp-b");
  const statusEl = $("#comp-status");
  const diffEl = $("#comp-diff");
  if (!aEl || !bEl)
    return;
  if (!aEl.value || !bEl.value) {
    toast2("Please enter text in both sides", "warning");
    return;
  }
  try {
    statusEl.innerHTML = '<span class="spinner spinner-small"></span> Computing diff...';
    diffEl.innerHTML = "";
    const response = await fetch("/api/tools/diff", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ a: aEl.value, b: bEl.value })
    });
    if (!response.ok)
      throw new Error(`Diff failed: ${response.status}`);
    const result = await response.json();
    statusEl.textContent = `${result.diff.filter((d) => d.type === "delete").length} deletions, ${result.diff.filter((d) => d.type === "insert").length} insertions`;
    diffEl.innerHTML = `
      <div class="card">
        <div class="card-title">Diff Result</div>
        <pre class="diff-viewer">${renderDiff(result.diff)}</pre>
      </div>
    `;
    toast2("Diff computed", "success");
  } catch (e) {
    toast2(e.message, "error");
    statusEl.textContent = "";
  }
};
function renderDiff(diff) {
  return diff.map((d) => {
    switch (d.type) {
      case "delete":
        return `<span class="diff-delete">${esc(d.text)}</span>`;
      case "insert":
        return `<span class="diff-insert">${esc(d.text)}</span>`;
      default:
        return esc(d.text);
    }
  }).join("");
}
async function loadMessage(msgId, side) {
  try {
    const response = await fetch(`/api/message/${msgId}`);
    if (!response.ok)
      throw new Error(`Failed to load message: ${response.status}`);
    const msg = await response.json();
    const el = $(`#comp-${side}`);
    if (el) {
      el.value = msg.text;
      if (side === "a") {
        left.text = msg.text;
      } else {
        right.text = msg.text;
      }
      updateLineNumbers(side);
      $("#comp-status").textContent = "";
      $("#comp-diff").innerHTML = "";
    }
  } catch (e) {
    toast2(e.message, "error");
  }
}
function updateLineNumbers(side) {
  const el = $(`#comp-${side}`);
  const linesEl = $(`#comp-${side}-lines`);
  if (el && linesEl) {
    const lines = el.value.split(`
`).length;
    linesEl.innerHTML = Array.from({ length: lines }, (_, i) => i + 1).join(`
`);
  }
}

// src/toollog.ts
function initToolLog() {
  const section = $("#logger");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">Requests sent by burpsy's own tools (scanner, intruder, repeater, etc.)</span>
      <span class="grow"></span>
      <button class="ghost" onclick="refreshToolLog()">Refresh</button>
      <button class="ghost" onclick="clearToolLog()">Clear</button>
    </div>
    <div class="row">
      <input id="log-search" placeholder="Search requests..." style="width:300px" />
      <select id="log-tool-filter">
        <option value="">All tools</option>
        <option value="repeater">Repeater</option>
        <option value="intruder">Intruder</option>
        <option value="scanner">Scanner</option>
      </select>
      <button class="ghost" onclick="applyFilter()">Apply</button>
    </div>
    <table>
      <thead>
        <tr>
          <th data-sort="at_ms">Time</th>
          <th data-sort="tool">Tool</th>
          <th>Request</th>
          <th data-sort="status">Status</th>
          <th data-sort="response_len">Len</th>
          <th data-sort="duration_ms">ms</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="log-body"></tbody>
    </table>
    <div id="log-empty" class="hint" style="margin-top:8px"></div>
    <div id="log-meta" class="hint" style="margin-top:8px"></div>
  `;
  makeSortable("log-body", "at_ms");
  loadToolLog();
  const searchInput = $("#log-search");
  const toolFilter = $("#log-tool-filter");
  searchInput?.addEventListener("input", () => applyFilter2());
  toolFilter?.addEventListener("change", () => applyFilter2());
}
var allEntries = [];
async function loadToolLog() {
  try {
    const response = await fetch("/api/tools/log?limit=500");
    if (!response.ok)
      throw new Error(`Failed to load tool log: ${response.status}`);
    const state = await response.json();
    allEntries = state.entries;
    const metaEl = $("#log-meta");
    metaEl.textContent = `Showing ${Math.min(allEntries.length, 500)} of ${state.total.toLocaleString()} (${state.dropped.toLocaleString()} dropped)`;
    applyFilter2();
  } catch (e) {
    const body = $("#log-body");
    body.innerHTML = `<tr><td colspan="7" class="err">${esc(e.message)}</td></tr>`;
  }
}
function applyFilter2() {
  const search = $("#log-search")?.value.toLowerCase() || "";
  const tool = $("#log-tool-filter")?.value || "";
  let entries = allEntries;
  if (tool) {
    entries = entries.filter((e) => e.tool === tool);
  }
  if (search) {
    entries = entries.filter((e) => e.request.toLowerCase().includes(search) || e.tool.toLowerCase().includes(search));
  }
  renderEntries(entries);
}
function renderEntries(entries) {
  const tbody = $("#log-body");
  const emptyEl = $("#log-empty");
  if (entries.length === 0) {
    tbody.innerHTML = "";
    emptyEl.innerHTML = renderEmptyState("No tool requests logged yet", "Requests from burpsy's tools will appear here", "\uD83D\uDCDD", 7);
    return;
  }
  emptyEl.innerHTML = "";
  tbody.innerHTML = entries.slice(0, 100).map((e) => `
    <tr>
      <td>${new Date(e.at_ms).toLocaleTimeString()}</td>
      <td><span class="tag tag-${esc(e.tool)}">${esc(e.tool)}</span></td>
      <td>${esc(e.request.slice(0, 60))}${e.request.length > 60 ? "..." : ""}</td>
      <td>${e.status ? e.status : "-"}</td>
      <td>${fmtBytes6(e.response_len)}</td>
      <td>${e.duration_ms}</td>
      <td>
        <button class="ghost small" onclick="copyRequest(${e.id})">Copy</button>
      </td>
    </tr>
  `).join("");
  if (entries.length > 100) {
    tbody.innerHTML += `<tr><td colspan="7" class="hint">Showing 100 of ${entries.length.toLocaleString()} entries</td></tr>`;
  }
}
function fmtBytes6(n) {
  if (n < 1024)
    return `${n} B`;
  if (n < 1024 * 1024)
    return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
window.refreshToolLog = function() {
  loadToolLog();
};
window.clearToolLog = async function() {
  if (!confirm("Are you sure you want to clear the entire tool log?"))
    return;
  try {
    await fetch("/api/tools/log", { method: "DELETE" });
    toast("Tool log cleared", "success");
    loadToolLog();
  } catch (e) {
    toast(e.message, "error");
  }
};
window.copyRequest = async function(id) {
  try {
    const response = await fetch(`/api/tools/log/${id}`);
    if (!response.ok)
      throw new Error(`Failed to load request: ${response.status}`);
    const entry = await response.json();
    copyText(entry.request, "tool request");
  } catch (e) {
    toast(e.message, "error");
  }
};

// src/organizer.ts
function initOrganizer() {
  const section = $("#organizer");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">Save interesting requests with notes and colors for later review</span>
      <span class="grow"></span>
      <button class="ghost" onclick="exportOrganizer()">Export</button>
    </div>
    <div class="row">
      <input id="org-search" placeholder="Search notes..." style="width:300px" />
      <select id="org-color-filter">
        <option value="">All colors</option>
      </select>
      <button class="ghost" onclick="clearFilter()">Clear</button>
    </div>
    <table>
      <thead>
        <tr>
          <th data-sort="exchange_id">Exchange ID</th>
          <th data-sort="note">Note</th>
          <th>Color</th>
          <th data-sort="created_ms">Created</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="org-body"></tbody>
    </table>
    <div id="org-empty" class="hint" style="margin-top:8px"></div>
    
    <div class="card" style="margin-top:10px">
      <div class="card-title">Add to Organizer</div>
      <div class="row">
        <input id="org-exchange-id" type="number" placeholder="Exchange ID" style="width:120px" />
        <input id="org-note" placeholder="Note" style="width:300px" />
        <select id="org-color">
          <option value="">No color</option>
        </select>
        <button class="go" onclick="addToOrganizer()">Add</button>
      </div>
    </div>
  `;
  makeSortable("org-body", "created_ms");
  loadColors();
  loadItems();
  const searchInput = $("#org-search");
  const colorFilter = $("#org-color-filter");
  searchInput?.addEventListener("input", () => filterItems());
  colorFilter?.addEventListener("change", () => filterItems());
}
var allItems = [];
var allColors = [];
async function loadColors() {
  try {
    const response = await fetch("/api/tools/organizer/colors");
    if (response.ok) {
      allColors = await response.json();
      const colorSelect = $("#org-color");
      const colorFilter = $("#org-color-filter");
      if (colorSelect) {
        colorSelect.innerHTML = '<option value="">No color</option>' + allColors.map((c) => `<option value="${c}">${esc(c)}</option>`).join("");
      }
      if (colorFilter) {
        colorFilter.innerHTML = '<option value="">All colors</option>' + allColors.map((c) => `<option value="${c}">${esc(c)}</option>`).join("");
      }
    }
  } catch (e) {
    toast2(e.message, "error");
  }
}
async function loadItems() {
  try {
    const response = await fetch("/api/tools/organizer");
    if (!response.ok)
      throw new Error(`Failed to load organizer items: ${response.status}`);
    allItems = await response.json();
    filterItems();
  } catch (e) {
    toast2(e.message, "error");
  }
}
function filterItems() {
  const search = $("#org-search")?.value.toLowerCase() || "";
  const color = $("#org-color-filter")?.value || "";
  let items = allItems;
  if (search) {
    items = items.filter((i) => i.note.toLowerCase().includes(search));
  }
  if (color) {
    items = items.filter((i) => i.color === color);
  }
  renderItems(items);
}
function renderItems(items) {
  const tbody = $("#org-body");
  const emptyEl = $("#org-empty");
  if (items.length === 0) {
    tbody.innerHTML = "";
    emptyEl.innerHTML = renderEmptyState("No items in organizer", "Add requests to organize them for later review", "\uD83D\uDCDA", 5);
    return;
  }
  emptyEl.innerHTML = "";
  tbody.innerHTML = items.map((i) => `
    <tr>
      <td>${i.exchange_id}</td>
      <td>${esc(i.note)}</td>
      <td>${i.color ? `<span class="pill hl-${i.color}">${esc(i.color)}</span>` : ""}</td>
      <td>${new Date(i.created_ms).toLocaleString()}</td>
      <td>
        <button class="ghost small" onclick="viewItem(${i.id})">View</button>
        <button class="ghost small" onclick="copyItem(${i.id})">Copy</button>
        <button class="ghost small" onclick="deleteItem(${i.id})">Delete</button>
      </td>
    </tr>
  `).join("");
}
window.addToOrganizer = async function() {
  const exchangeIdInput = $("#org-exchange-id");
  const noteInput = $("#org-note");
  const colorSelect = $("#org-color");
  if (!exchangeIdInput || !noteInput)
    return;
  const exchangeId = parseInt(exchangeIdInput.value, 10);
  const note = noteInput.value.trim();
  const color = colorSelect?.value || "";
  if (isNaN(exchangeId)) {
    toast2("Please enter a valid exchange ID", "error");
    return;
  }
  if (!note) {
    toast2("Please enter a note", "error");
    return;
  }
  try {
    await postJSON("/api/tools/organizer", {
      exchange_id: exchangeId,
      note,
      color
    });
    toast2("Added to organizer", "success");
    exchangeIdInput.value = "";
    noteInput.value = "";
    colorSelect.value = "";
    loadItems();
  } catch (e) {
    toast2(e.message, "error");
  }
};
window.viewItem = function(id) {
  toast2(`View item #${id} functionality would show the request details`, "info");
};
window.copyItem = async function(id) {
  try {
    const response = await fetch(`/api/tools/organizer/${id}`);
    if (!response.ok)
      throw new Error(`Failed to load item: ${response.status}`);
    const item = await response.json();
    copyText(`Exchange #${item.exchange_id}: ${item.note}`, "organizer item");
  } catch (e) {
    toast2(e.message, "error");
  }
};
window.deleteItem = async function(id) {
  if (!confirm("Are you sure you want to delete this item?"))
    return;
  try {
    await delJSON(`/api/tools/organizer/${id}`);
    toast2("Item deleted", "success");
    loadItems();
  } catch (e) {
    toast2(e.message, "error");
  }
};
window.clearFilter = function() {
  $("#org-search").value = "";
  $("#org-color-filter").value = "";
  filterItems();
};
window.exportOrganizer = function() {
  toast2("Export functionality would download organizer items as JSON", "info");
};

// src/matchreplace.ts
function initMatchReplace() {
  const section = $("#matchreplace");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <label class="switch"><input type="checkbox" id="mr-enabled" /><span class="slider"></span></label>
      <span>Match & Replace is on</span>
      <span class="grow"></span>
      <button class="ghost" onclick="addRule()">+ Add Rule</button>
    </div>
    <div class="card">
      <div class="card-title">Rules</div>
      <p class="hint">Rules are applied in order. First match wins.</p>
      <table>
        <thead>
          <tr>
            <th data-sort="name">Name</th>
            <th data-sort="match">Match</th>
            <th data-sort="replacement">Replacement</th>
            <th>Type</th>
            <th>Scope</th>
            <th>Enabled</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="mr-body"></tbody>
      </table>
      <div id="mr-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Test Rule</div>
      <p class="hint">Test a rule against sample input to verify it works as expected</p>
      <div class="row">
        <select id="mr-test-rule">
          <option value="">Select a rule to test</option>
        </select>
      </div>
      <div class="two" style="margin-top:8px">
        <div>
          <div class="viewer-header"><b class="muted">Input</b></div>
          <textarea id="mr-test-input" placeholder="Sample input..." spellcheck="false" style="min-height:100px"></textarea>
        </div>
        <div>
          <div class="viewer-header"><b class="muted">Output</b></div>
          <textarea id="mr-test-output" readonly spellcheck="false" style="min-height:100px"></textarea>
        </div>
      </div>
      <div class="row" style="margin-top:8px">
        <button class="go" onclick="testRule()">Test</button>
        <button class="ghost" onclick="clearTest()">Clear</button>
      </div>
    </div>
  `;
  makeSortable("mr-body", "name");
  loadState();
  const enabledCb = $("#mr-enabled");
  enabledCb.addEventListener("change", () => {
    setEnabled2(enabledCb.checked);
  });
}
var allRules = [];
async function loadState() {
  try {
    const response = await fetch("/api/tools/matchreplace");
    if (!response.ok)
      throw new Error(`Failed to load match & replace state: ${response.status}`);
    const state = await response.json();
    allRules = state.rules;
    const enabledCb = $("#mr-enabled");
    enabledCb.checked = state.enabled;
    renderRules2();
    updateTestRuleSelect();
  } catch (e) {
    toast2(e.message, "error");
  }
}
function renderRules2(rules = allRules) {
  const tbody = $("#mr-body");
  const emptyEl = $("#mr-empty");
  if (rules.length === 0) {
    tbody.innerHTML = "";
    emptyEl.innerHTML = renderEmptyState("No rules defined", "Add rules to rewrite requests and responses on the fly", "\uD83D\uDD04", 7);
    return;
  }
  emptyEl.innerHTML = "";
  tbody.innerHTML = rules.map((r) => `
    <tr>
      <td>${esc(r.name)}</td>
      <td>${esc(r.match)}</td>
      <td>${esc(r.replacement)}</td>
      <td>${r.is_regex ? "Regex" : "Literal"}</td>
      <td>${esc(r.scope)}</td>
      <td><span class="status-pill ${r.enabled ? "good" : "off"}">${r.enabled ? "Enabled" : "Disabled"}</span></td>
      <td>
        <button class="ghost small" onclick="toggleRule(${r.id})">${r.enabled ? "Disable" : "Enable"}</button>
        <button class="ghost small" onclick="editRule(${r.id})">Edit</button>
        <button class="ghost small" onclick="deleteRule(${r.id})">Delete</button>
      </td>
    </tr>
  `).join("");
}
function updateTestRuleSelect() {
  const select = $("#mr-test-rule");
  if (!select)
    return;
  select.innerHTML = '<option value="">Select a rule to test</option>' + allRules.map((r) => `<option value="${r.id}">${esc(r.name)}</option>`).join("");
}
window.addRule = function() {
  toast2("Add rule functionality would open a modal here", "info");
};
window.editRule = function(id) {
  toast2(`Edit rule #${id} functionality would open a modal here`, "info");
};
window.toggleRule = async function(id) {
  try {
    await putJSON(`/api/tools/matchreplace/rules/${id}/toggle`, {});
    toast2("Rule toggled", "success");
    loadState();
  } catch (e) {
    toast2(e.message, "error");
  }
};
window.deleteRule = async function(id) {
  if (!confirm("Are you sure you want to delete this rule?"))
    return;
  try {
    await delJSON(`/api/tools/matchreplace/rules/${id}`);
    toast2("Rule deleted", "success");
    loadState();
  } catch (e) {
    toast2(e.message, "error");
  }
};
async function setEnabled2(enabled) {
  try {
    await postJSON("/api/tools/matchreplace/enable", { enabled });
    toast2(`Match & Replace ${enabled ? "enabled" : "disabled"}`, "success");
  } catch (e) {
    toast2(e.message, "error");
  }
}
window.testRule = async function() {
  const select = $("#mr-test-rule");
  const input = $("#mr-test-input");
  const output = $("#mr-test-output");
  if (!select || !input || !output)
    return;
  const ruleId = parseInt(select.value, 10);
  if (isNaN(ruleId)) {
    toast2("Please select a rule to test", "error");
    return;
  }
  if (!input.value) {
    toast2("Please enter test input", "error");
    return;
  }
  try {
    const response = await fetch(`/api/tools/matchreplace/test/${ruleId}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input: input.value })
    });
    if (!response.ok)
      throw new Error(`Test failed: ${response.status}`);
    const result = await response.json();
    output.value = result.output;
    toast2("Rule tested successfully", "success");
  } catch (e) {
    toast2(e.message, "error");
  }
};
window.clearTest = function() {
  const input = $("#mr-test-input");
  const output = $("#mr-test-output");
  if (input)
    input.value = "";
  if (output)
    output.value = "";
  toast2("Test cleared", "success");
};

// src/session.ts
function initSession() {
  const section = $("#session");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">Configure how burpsy maintains session state across requests</span>
      <span class="grow"></span>
      <button class="go" onclick="checkSession()">Check Session</button>
    </div>
    
    <div class="card">
      <div class="card-title">Session Rules</div>
      <p class="hint">Rules for managing cookies, headers, and parameters across requests</p>
      <div class="row">
        <button class="ghost" onclick="addRule()">+ Add Rule</button>
        <span class="grow"></span>
        <span class="hint" id="session-rules-count">0 rules</span>
      </div>
      <table>
        <thead>
          <tr>
            <th data-sort="name">Name</th>
            <th data-sort="kind">Type</th>
            <th data-sort="action">Action</th>
            <th>Match</th>
            <th>Value</th>
            <th>Scope</th>
            <th>Enabled</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="session-rules-body"></tbody>
      </table>
      <div id="session-rules-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Login Macros</div>
      <p class="hint">Automatically re-authenticate when session is lost</p>
      <div class="row">
        <button class="ghost" onclick="addMacro()">+ Add Macro</button>
        <span class="grow"></span>
        <span class="hint" id="session-macros-count">0 macros</span>
      </div>
      <table>
        <thead>
          <tr>
            <th data-sort="name">Name</th>
            <th>Request</th>
            <th>Success Pattern</th>
            <th>Enabled</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="session-macros-body"></tbody>
      </table>
      <div id="session-macros-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Session Status</div>
      <div id="session-status" class="hint">Loading...</div>
    </div>
  `;
  makeSortable("session-rules-body", "name");
  makeSortable("session-macros-body", "name");
  loadSessionState();
}
async function loadSessionState() {
  try {
    const response = await fetch("/api/session");
    if (!response.ok)
      throw new Error(`Failed to load session state: ${response.status}`);
    const state = await response.json();
    renderRules3(state.rules);
    renderMacros(state.macros);
    renderStatus(state);
  } catch (e) {
    toast2(e.message, "error");
  }
}
function renderRules3(rules) {
  const tbody = $("#session-rules-body");
  const emptyEl = $("#session-rules-empty");
  const countEl = $("#session-rules-count");
  countEl.textContent = `${rules.length} rules`;
  if (rules.length === 0) {
    tbody.innerHTML = "";
    emptyEl.innerHTML = renderEmptyState("No session rules defined", "Add rules to manage cookies, headers, and parameters", "\uD83C\uDF6A", 7);
    return;
  }
  emptyEl.innerHTML = "";
  tbody.innerHTML = rules.map((r) => `
    <tr>
      <td>${esc(r.name)}</td>
      <td>${esc(r.kind)}</td>
      <td>${esc(r.action)}</td>
      <td>${esc(r.match)}</td>
      <td>${esc(r.value)}</td>
      <td>${typeof r.scope === "string" ? "All" : esc(r.scope.hosts.join(", "))}</td>
      <td><span class="status-pill ${r.enabled ? "good" : "off"}">${r.enabled ? "Enabled" : "Disabled"}</span></td>
      <td>
        <button class="ghost small" onclick="toggleRule(${r.id})">${r.enabled ? "Disable" : "Enable"}</button>
        <button class="ghost small" onclick="editRule(${r.id})">Edit</button>
        <button class="ghost small" onclick="deleteRule(${r.id})">Delete</button>
      </td>
    </tr>
  `).join("");
}
function renderMacros(macros) {
  const tbody = $("#session-macros-body");
  const emptyEl = $("#session-macros-empty");
  const countEl = $("#session-macros-count");
  countEl.textContent = `${macros.length} macros`;
  if (macros.length === 0) {
    tbody.innerHTML = "";
    emptyEl.innerHTML = renderEmptyState("No login macros defined", "Add macros to automatically re-authenticate", "\uD83D\uDD11", 5);
    return;
  }
  emptyEl.innerHTML = "";
  tbody.innerHTML = macros.map((m) => `
    <tr>
      <td>${esc(m.name)}</td>
      <td>${esc(m.request.slice(0, 50))}${m.request.length > 50 ? "..." : ""}</td>
      <td>${esc(m.success_pattern)}</td>
      <td><span class="status-pill ${m.enabled ? "good" : "off"}">${m.enabled ? "Enabled" : "Disabled"}</span></td>
      <td>
        <button class="ghost small" onclick="toggleMacro(${m.id})">${m.enabled ? "Disable" : "Enable"}</button>
        <button class="ghost small" onclick="editMacro(${m.id})">Edit</button>
        <button class="ghost small" onclick="deleteMacro(${m.id})">Delete</button>
      </td>
    </tr>
  `).join("");
}
function renderStatus(state) {
  const el = $("#session-status");
  if (state.session_valid) {
    const lastCheck = new Date(state.last_check_ms).toLocaleString();
    el.innerHTML = `
      <div class="status-pill good">Session Valid</div>
      <span class="hint" style="margin-left:8px">Last checked: ${lastCheck}</span>
    `;
  } else {
    el.innerHTML = `
      <div class="status-pill bad">Session Invalid</div>
      <span class="hint" style="margin-left:8px">Session may have expired</span>
    `;
  }
}
window.checkSession = async function() {
  const el = $("#session-status");
  const originalHTML = el.innerHTML;
  try {
    el.innerHTML = '<span class="spinner spinner-small"></span> Checking session...';
    const response = await fetch("/api/session/check", { method: "POST" });
    if (!response.ok)
      throw new Error(`Session check failed: ${response.status}`);
    const result = await response.json();
    renderStatus({
      rules: [],
      macros: [],
      session_valid: result.valid,
      last_check_ms: result.last_check_ms
    });
    toast2(result.valid ? "Session is valid" : "Session is invalid", result.valid ? "success" : "warning");
  } catch (e) {
    toast2(e.message, "error");
    el.innerHTML = originalHTML;
  }
};
window.addRule = function() {
  toast2("Add rule functionality would open a modal here", "info");
};
window.editRule = function(id) {
  toast2(`Edit rule #${id} functionality would open a modal here`, "info");
};
window.toggleRule = async function(id) {
  try {
    await putJSON(`/api/session/rules/${id}/toggle`, {});
    toast2("Rule toggled", "success");
    loadSessionState();
  } catch (e) {
    toast2(e.message, "error");
  }
};
window.deleteRule = async function(id) {
  if (!confirm("Are you sure you want to delete this rule?"))
    return;
  try {
    await delJSON(`/api/session/rules/${id}`);
    toast2("Rule deleted", "success");
    loadSessionState();
  } catch (e) {
    toast2(e.message, "error");
  }
};
window.addMacro = function() {
  toast2("Add macro functionality would open a modal here", "info");
};
window.editMacro = function(id) {
  toast2(`Edit macro #${id} functionality would open a modal here`, "info");
};
window.toggleMacro = async function(id) {
  try {
    await putJSON(`/api/session/macros/${id}/toggle`, {});
    toast2("Macro toggled", "success");
    loadSessionState();
  } catch (e) {
    toast2(e.message, "error");
  }
};
window.deleteMacro = async function(id) {
  if (!confirm("Are you sure you want to delete this macro?"))
    return;
  try {
    await delJSON(`/api/session/macros/${id}`);
    toast2("Macro deleted", "success");
    loadSessionState();
  } catch (e) {
    toast2(e.message, "error");
  }
};

// src/sequencer.ts
function initSequencer() {
  const section = $("#sequencer");
  if (!section)
    return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">Analyse token randomness to detect predictable values</span>
      <span class="grow"></span>
      <button class="go" id="seq-start" onclick="startSequencer()">Start Capture</button>
      <button class="ghost" id="seq-stop" onclick="stopSequencer()" style="display:none">Stop</button>
      <span id="seq-progress" class="hint" style="margin-left:8px"></span>
    </div>
    
    <div class="card">
      <div class="card-title">Token Positions</div>
      <p class="hint">Positions where tokens were found in responses</p>
      <table>
        <thead>
          <tr>
            <th data-sort="position">Position</th>
            <th data-sort="name">Name</th>
            <th data-sort="samples">Samples</th>
            <th data-sort="avg_entropy">Avg Entropy</th>
            <th data-sort="is_random">Random?</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="seq-positions-body"></tbody>
      </table>
      <div id="seq-positions-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Recent Samples</div>
      <p class="hint">Most recent token samples captured</p>
      <table>
        <thead>
          <tr>
            <th data-sort="position">Position</th>
            <th>Token</th>
            <th data-sort="length">Length</th>
            <th data-sort="entropy">Entropy</th>
            <th data-sort="is_random">Random?</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="seq-samples-body"></tbody>
      </table>
      <div id="seq-samples-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div id="seq-analysis" style="margin-top:10px"></div>
  `;
  makeSortable("seq-positions-body", "position");
  makeSortable("seq-samples-body", "position");
  loadSequencerState();
}
async function loadSequencerState() {
  try {
    const response = await fetch("/api/sequencer");
    if (!response.ok)
      throw new Error(`Failed to load sequencer state: ${response.status}`);
    const state = await response.json();
    renderPositions(state.positions);
    renderSamples(state.samples);
    updateProgress(state);
  } catch (e) {
    toast2(e.message, "error");
  }
}
function renderPositions(positions) {
  const tbody = $("#seq-positions-body");
  const emptyEl = $("#seq-positions-empty");
  if (positions.length === 0) {
    tbody.innerHTML = "";
    emptyEl.innerHTML = renderEmptyState("No token positions found", "Start capture to analyse tokens from responses", "\uD83C\uDFB2", 6);
    return;
  }
  emptyEl.innerHTML = "";
  tbody.innerHTML = positions.map((p) => `
    <tr>
      <td>${p.position}</td>
      <td>${esc(p.name)}</td>
      <td>${p.samples.toLocaleString()}</td>
      <td>${p.avg_entropy.toFixed(2)}</td>
      <td><span class="status-pill ${p.is_random ? "good" : "bad"}">${p.is_random ? "Random" : "Predictable"}</span></td>
      <td>
        <button class="ghost small" onclick="showPositionAnalysis(${p.position})">Analyse</button>
        <button class="ghost small" onclick="copyPosition(${p.position})">Copy</button>
      </td>
    </tr>
  `).join("");
}
function renderSamples(samples) {
  const tbody = $("#seq-samples-body");
  const emptyEl = $("#seq-samples-empty");
  if (samples.length === 0) {
    tbody.innerHTML = "";
    emptyEl.innerHTML = renderEmptyState("No samples captured yet", "Start capture to see token samples here", "\uD83D\uDCCA", 6);
    return;
  }
  emptyEl.innerHTML = "";
  tbody.innerHTML = samples.slice(0, 50).map((s) => `
    <tr>
      <td>${s.position}</td>
      <td>${esc(s.token.slice(0, 30))}${s.token.length > 30 ? "..." : ""}</td>
      <td>${s.length}</td>
      <td>${s.entropy.toFixed(2)}</td>
      <td><span class="status-pill ${s.is_random ? "good" : "bad"}">${s.is_random ? "Random" : "Predictable"}</span></td>
      <td>
        <button class="ghost small" onclick="copyToken('${esc(s.token)}')">Copy</button>
      </td>
    </tr>
  `).join("");
  if (samples.length > 50) {
    tbody.innerHTML += `<tr><td colspan="6" class="hint">Showing 50 of ${samples.length.toLocaleString()} samples</td></tr>`;
  }
}
function updateProgress(state) {
  const startBtn = $("#seq-start");
  const stopBtn = $("#seq-stop");
  const progressEl = $("#seq-progress");
  if (state.running) {
    startBtn.style.display = "none";
    stopBtn.style.display = "inline-block";
    progressEl.innerHTML = `<span class="spinner spinner-small"></span> ${state.progress.toLocaleString()} / ${state.total.toLocaleString()}`;
  } else {
    startBtn.style.display = "inline-block";
    stopBtn.style.display = "none";
    progressEl.textContent = "";
  }
}
window.startSequencer = async function() {
  try {
    await postJSON("/api/sequencer/start", {});
    toast2("Sequencer started", "success");
    loadSequencerState();
  } catch (e) {
    toast2(e.message, "error");
  }
};
window.stopSequencer = async function() {
  try {
    await postJSON("/api/sequencer/stop", {});
    toast2("Sequencer stopped", "success");
    loadSequencerState();
  } catch (e) {
    toast2(e.message, "error");
  }
};
window.showPositionAnalysis = function(position2) {
  toast2(`Showing analysis for position ${position2}`, "info");
};
window.copyPosition = function(position2) {
  toast2(`Copy position ${position2} functionality would copy the position data`, "info");
};
window.copyToken = function(token) {
  copyText(token, "token");
};

// src/app.ts
initTheme();
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
var header = $("header");
if (header) {
  const shortcutHelp = document.createElement("button");
  shortcutHelp.id = "shortcut-help";
  shortcutHelp.className = "ghost";
  shortcutHelp.innerHTML = "<kbd>?</kbd>";
  shortcutHelp.title = "Keyboard Shortcuts";
  shortcutHelp.onclick = () => showShortcutSheet();
  header.appendChild(shortcutHelp);
}
initShortcuts();
async function refreshStats() {
  try {
    const s = await getJSON("/api/stats");
    const el = $("#stats");
    if (el) {
      el.textContent = `${s.exchanges} exchanges \x17 ${s.messages} msgs \x17 ${(s.stored_bytes / 1048576).toFixed(2)} MB stored`;
    }
  } catch {}
}
async function refreshScope() {
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
refreshScope();
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
