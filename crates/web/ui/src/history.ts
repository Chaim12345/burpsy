// History tab: the proxy capture table, a request/response viewer, and hand-off actions to the
// other tools — today's operator has no way to learn a message id except by reading it here.
//
// Filtering (status-class checkboxes, in-scope-only, method/host/path search) is purely client-side:
// every row from `GET /api/history?limit=300` is already fetched, so a filter change just re-renders
// a filtered slice of the last fetch — no new backend endpoint or re-fetch involved.

import { $, $all, esc, statusBadge, getJSON, postJSON, emit, switchTab, toast, on } from "./common";
import type { Exchange, MessageView, ScopeInfo, ShowExchangeDetail } from "./types";
import { EVT_SEND_TO_REPEATER, EVT_SEND_TO_INTRUDER, EVT_SEND_TO_COMPARER, EVT_SHOW_EXCHANGE } from "./types";

/** All rows from the last `load()`, before any filter is applied. */
let allRows: Exchange[] = [];
/** Fetched lazily the first time "in scope only" is checked, then reused for the session. */
let cachedScope: ScopeInfo | null = null;

export function initHistory(): void {
  const section = $("#history");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <button class="go" id="hist-refresh">Refresh</button>
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
  $("#hist-refresh")!.addEventListener("click", () => void load());
  $all<HTMLInputElement>(".hist-status").forEach((c) => c.addEventListener("change", () => applyFilter()));
  $("#hist-search")!.addEventListener("input", () => applyFilter());
  $("#hist-regex")!.addEventListener("change", () => applyFilter());
  const scopeOnly = $<HTMLInputElement>("#hist-scope-only")!;
  scopeOnly.addEventListener("change", () => {
    if (scopeOnly.checked) {
      void ensureScopeLoaded().then(() => applyFilter());
    } else {
      applyFilter();
    }
  });
  on<ShowExchangeDetail>(EVT_SHOW_EXCHANGE, (d) => void loadExchangeById(d.exchangeId));
  void load();
}

/** Loads one exchange by id straight from the server (bypassing `allRows`/the current filter) —
 * used by Scanner's "open this occurrence" hand-off, which may reference an exchange outside the
 * last-fetched/filtered slice of History. */
async function loadExchangeById(id: number): Promise<void> {
  try {
    const ex = await getJSON<Exchange>(`/api/exchange/${id}`);
    await openExchange(ex);
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

async function load(): Promise<void> {
  const body = $("#hist-body")!;
  try {
    allRows = await getJSON<Exchange[]>("/api/history?limit=300");
  } catch (e) {
    body.innerHTML = `<tr><td colspan="9" class="err">${esc((e as Error).message)}</td></tr>`;
    return;
  }
  applyFilter();
}

async function ensureScopeLoaded(): Promise<void> {
  if (cachedScope) return;
  try {
    cachedScope = await getJSON<ScopeInfo>("/api/scope");
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

/** Re-renders `#hist-body` from `allRows` filtered by the current filter-row controls. Called
 * whenever a filter control changes — never re-fetches from the server. */
function applyFilter(): void {
  const body = $("#hist-body")!;
  const note = $("#hist-note")!;

  if (allRows.length === 0) {
    body.innerHTML = "";
    note.textContent = "no traffic yet — set your browser proxy to this host:8080";
    return;
  }

  const checkedClasses = new Set(
    $all<HTMLInputElement>(".hist-status")
      .filter((c) => c.checked)
      .map((c) => c.value),
  );
  const query = $<HTMLInputElement>("#hist-search")!.value.trim();
  const useRegex = $<HTMLInputElement>("#hist-regex")!.checked;
  const scopeOnly = $<HTMLInputElement>("#hist-scope-only")!.checked;

  let re: RegExp | null = null;
  let regexInvalid = false;
  if (useRegex && query) {
    try {
      re = new RegExp(query, "i");
    } catch {
      regexInvalid = true;
    }
  }

  const rows = allRows.filter((ex) => {
    if (!matchesStatusClass(ex, checkedClasses)) return false;
    if (!regexInvalid && !matchesSearch(ex, query, re)) return false;
    if (scopeOnly && cachedScope && !isInScope(ex, cachedScope)) return false;
    return true;
  });

  body.innerHTML = rows.length
    ? rows.map(rowHtml).join("")
    : `<tr><td colspan="9" class="hint">no rows match the current filter</td></tr>`;
  wireRows(rows);
  note.textContent = regexInvalid ? "invalid regex — search ignored" : "";
}

/** Rows with no status yet (still in flight) always pass — there is no class to filter on. */
function matchesStatusClass(ex: Exchange, checkedClasses: Set<string>): boolean {
  if (ex.status === null || ex.status === undefined) return true;
  const cls = String(ex.status)[0] ?? "";
  if (!["2", "3", "4", "5"].includes(cls)) return true;
  return checkedClasses.has(cls);
}

function matchesSearch(ex: Exchange, query: string, re: RegExp | null): boolean {
  if (!query) return true;
  const haystack = `${ex.method} ${ex.host} ${ex.path}`;
  if (re) return re.test(haystack);
  return haystack.toLowerCase().includes(query.toLowerCase());
}

/** Approximates the last-match-wins host matching that `Scope`/`ScopeRule` do in
 * crates/core/src/scope.rs, with a plain substring check on `host` — no port/path_prefix/tls
 * matching, no `*.` wildcard expansion. This is a UI filter approximation, not a re-implementation;
 * the proxy's own scope enforcement is the source of truth for what traffic is actually in scope. */
function isInScope(ex: Exchange, scope: ScopeInfo): boolean {
  if (scope.allow_all) return true;
  let inScope = false;
  for (const rule of scope.rules as { kind: string; host: string | null }[]) {
    if (rule.host && ex.host.includes(rule.host)) {
      inScope = rule.kind === "Include";
    }
  }
  return inScope;
}

function rowHtml(r: Exchange): string {
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

function wireRows(rows: Exchange[]): void {
  const byId = new Map(rows.map((r) => [r.id, r]));
  $all("#hist-body tr").forEach((tr) => {
    const id = Number(tr.dataset["id"]);
    const ex = byId.get(id);
    if (!ex) return;
    tr.addEventListener("click", (e) => {
      if ((e.target as HTMLElement).closest("button")) return;
      void openExchange(ex);
    });
    $all("button", tr).forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        void handleAction(btn.dataset["act"] ?? "", ex);
      });
    });
  });
}

async function openExchange(ex: Exchange): Promise<void> {
  const reqEl = $("#hist-req")!;
  const resEl = $("#hist-res")!;
  reqEl.textContent = "loading…";
  resEl.textContent = "";
  try {
    const req = await getJSON<MessageView>(`/api/message/${ex.request}`);
    reqEl.textContent = req.text;
  } catch (e) {
    reqEl.textContent = (e as Error).message;
  }
  if (ex.response !== null) {
    try {
      const res = await getJSON<MessageView>(`/api/message/${ex.response}`);
      resEl.textContent = res.text;
    } catch (e) {
      resEl.textContent = (e as Error).message;
    }
  }
}

function targetOf(ex: Exchange): string {
  return `${ex.tls ? "https" : "http"}://${ex.host}:${ex.port}`;
}

async function handleAction(act: string, ex: Exchange): Promise<void> {
  switch (act) {
    case "repeater": {
      try {
        const req = await getJSON<MessageView>(`/api/message/${ex.request}`);
        emit(EVT_SEND_TO_REPEATER, { target: targetOf(ex), raw: req.text });
        switchTab("repeater");
      } catch (e) {
        toast((e as Error).message, "error");
      }
      break;
    }
    case "intruder": {
      emit(EVT_SEND_TO_INTRUDER, { msgId: ex.request, target: targetOf(ex) });
      switchTab("intruder");
      break;
    }
    case "cmp-a":
    case "cmp-b": {
      const side = act === "cmp-a" ? "a" : "b";
      emit(EVT_SEND_TO_COMPARER, { side, msgId: ex.request, label: `${ex.method} ${ex.path}` });
      switchTab("comparer");
      toast(`sent request #${ex.request} to Comparer ${side.toUpperCase()}`);
      break;
    }
    case "organize": {
      try {
        await postJSON("/api/tools/organizer", { exchange: ex.id });
        toast(`saved ${ex.method} ${ex.path} to Organizer`);
      } catch (e) {
        toast((e as Error).message, "error");
      }
      break;
    }
    default:
      break;
  }
}
