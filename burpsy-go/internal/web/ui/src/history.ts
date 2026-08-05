// History tab: the proxy capture table, a request/response viewer, and hand-off actions to the
// other tools — today's operator has no way to learn a message id except by reading it here.
//
// Filtering (status-class checkboxes, in-scope-only, method/host/path search) is purely client-side:
// every row from `GET /api/history?limit=300` is already fetched, so a filter change just re-renders
// a filtered slice of the last fetch — no new backend endpoint or re-fetch involved.

import { $, $all, esc, statusBadge, getJSON, toast, on, makeSortable, createSorter, persistFilter, highlightSearch, copyText, addBulkSelect, renderEmptyState } from "./common";
import type { Exchange, MessageView, ScopeInfo, ShowExchangeDetail, FilterHistoryDetail } from "./types";
import { EVT_SHOW_EXCHANGE, EVT_FILTER_HISTORY } from "./types";
import { attachRowContextMenu } from "./contextmenu";
import { live } from "./live";
import { registerRowTarget } from "./shortcuts";
import {
  exchangeMenuItems,
  sendToRepeater,
  sendToIntruder,
  sendToComparer,
  saveToOrganizer,
} from "./sendto";

/** All rows from the last `load()`, before any filter is applied. */
let allRows: Exchange[] = [];
/** Fetched lazily the first time "in scope only" is checked, then reused for the session. */
let cachedScope: ScopeInfo | null = null;
/** Debounces the query box: unlike the other filters, a query change means a server round-trip. */
let queryTimer: ReturnType<typeof setTimeout> | undefined;
/** The row the operator last clicked or right-clicked. The keyboard shortcuts act on this, so it is
 * the whole reason a selection exists here at all: before, opening a row only filled the two panes
 * below and nothing remembered which row that was. */
let selected: Exchange | null = null;
/** The currently rendered rows by id, so the delegated context menu can resolve a `<tr>` back to its
 * exchange after any re-render. */
let rendered = new Map<number, Exchange>();

// Bulk selection state
let bulkSelected = new Set<number>();

export function initHistory(): void {
  const section = $("#history");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">right-click a row for send-to actions  Ctrl+R Repeater  Ctrl+I Intruder  ? for all shortcuts</span>
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
  
  // Initialize bulk selection
  bulkSelected = addBulkSelect('hist-body', (selected) => {
    const countEl = $('#hist-bulk-count');
    if (countEl) {
      countEl.textContent = `${selected.size} selected`;
    }
    $('#hist-bulk-actions')!.style.display = selected.size > 0 ? 'flex' : 'none';
  });
  
  // Initialize table sorting
  makeSortable('hist-body', 'started_ms');
  
  // Handle sort events
  $('#hist-body')?.addEventListener('sort', (e: CustomEvent) => {
    const { field, ascending } = e.detail;
    allRows.sort(createSorter<Exchange>(field as keyof Exchange, ascending));
    applyFilter();
  });

  $all<HTMLInputElement>(".hist-status").forEach((c) => c.addEventListener("change", () => applyFilter()));
  
  // Persist filters
  persistFilter('history-search', $('#hist-search') as HTMLInputElement);
  persistFilter('history-query', $('#hist-query') as HTMLInputElement);
  persistFilter('history-regex', $('#hist-regex') as HTMLInputElement);
  
  const scopeOnly = $<HTMLInputElement>("#hist-scope-only")!;
  persistFilter('history-scope-only', scopeOnly);
  scopeOnly.addEventListener("change", () => {
    if (scopeOnly.checked) {
      void ensureScopeLoaded().then(() => applyFilter());
    } else {
      applyFilter();
    }
  });
  
  $("#hist-search")!.addEventListener("input", () => applyFilter());
  $("#hist-regex")!.addEventListener("change", () => applyFilter());
  $("#hist-query")!.addEventListener("input", () => {
    if (queryTimer) clearTimeout(queryTimer);
    queryTimer = setTimeout(() => void load(), 300);
  });
  
  on<ShowExchangeDetail>(EVT_SHOW_EXCHANGE, (d) => void loadExchangeById(d.exchangeId));
  on<FilterHistoryDetail>(EVT_FILTER_HISTORY, (d) => {
    $<HTMLInputElement>("#hist-search")!.value = d.search;
    applyFilter();
  });
  
  // Attached to the tbody, not to each row: every filter change re-renders `#hist-body` by assigning
  // innerHTML, which would drop per-row listeners.
  attachRowContextMenu<Exchange>({
    container: "#hist-body",
    rowSelector: "tr[data-id]",
    resolve: (row) => rendered.get(Number(row.dataset["id"])) ?? null,
    heading: (ex) => `#${ex.id} ${ex.method} ${ex.path}`,
    select: (ex) => markSelected(ex),
    items: (ex) => exchangeMenuItems(ex),
  });
  
  registerRowTarget("history", () => (selected ? { label: `exchange #${selected.id}`, exchange: selected } : null));
  
  // Captured traffic arrives here without being asked for, which is why this pane no longer has a
  // Refresh button. A re-render keeps the selection (see wireRows) and the query box, so a row that
  // arrives while the operator is reading one does not move the ground under them.
  live({ kinds: ["history"], section: "history", refresh: () => void load() });
  void load();
}

// Bulk action functions
window.bulkSendToIntruder = function(): void {
  if (bulkSelected.size === 0) return;
  toast(`Sending ${bulkSelected.size} items to Intruder`, 'info');
  // In a real implementation, this would send all selected items
  clearBulkSelection();
};

window.bulkSaveToOrganizer = function(): void {
  if (bulkSelected.size === 0) return;
  toast(`Saving ${bulkSelected.size} items to Organizer`, 'info');
  // In a real implementation, this would save all selected items
  clearBulkSelection();
};

window.clearBulkSelection = function(): void {
  bulkSelected.clear();
  $('#hist-bulk-actions')!.style.display = 'none';
  $all('#hist-body .row-checkbox').forEach(cb => (cb as HTMLInputElement).checked = false);
  const selectAll = $('.select-all') as HTMLInputElement;
  if (selectAll) {
    selectAll.checked = false;
    selectAll.indeterminate = false;
  }
};

// Copy functions for viewer
window.copyRequest = function(): void {
  const el = $('#hist-req') as HTMLElement;
  if (el) copyText(el.textContent || '', 'request');
};

window.copyResponse = function(): void {
  const el = $('#hist-res') as HTMLElement;
  if (el) copyText(el.textContent || '', 'response');
};

/** Marks one row as the selection, for the shortcuts and for the operator to see which row a Ctrl+R
 * would act on. */
function markSelected(ex: Exchange): void {
  selected = ex;
  $all("#hist-body tr").forEach((tr) => tr.classList.toggle("on", Number(tr.dataset["id"]) === ex.id));
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

/** Updates the line numbers in the code viewer */
function updateViewerLines(containerId: string, content: string): void {
  const container = $(`#${containerId}`) as HTMLElement;
  const linesEl = $(`#${containerId}-lines`) as HTMLElement;
  if (!container || !linesEl) return;

  const lines = content.split('\n').length;
  linesEl.innerHTML = Array.from({length: lines}, (_, i) => i + 1).join('\n');
}

async function load(): Promise<void> {
  const body = $("#hist-body")!;
  const q = $<HTMLInputElement>("#hist-query")!.value.trim();
  const qs = q ? `?limit=300&q=${encodeURIComponent(q)}` : "?limit=300";
  
  // Show loading state
  body.innerHTML = `<tr><td colspan="10" class="loading-state"><span class="spinner spinner-medium"></span> Loading...</td></tr>`;
  
  try {
    allRows = await getJSON<Exchange[]>(`/api/history${qs}`);
  } catch (e) {
    // A malformed query's body is the backend's own rendered message — description line, source
    // line, then a `^` caret under the offending byte. `white-space:pre` keeps the caret aligned;
    // a plain innerHTML drop would collapse that spacing into one line.
    allRows = [];
    body.innerHTML = `<tr><td colspan="10" class="err"><pre style="white-space:pre;margin:0">${esc((e as Error).message)}</pre></td></tr>`;
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

function applyFilter(): void {
  const body = $("#hist-body")!;
  const search = $<HTMLInputElement>("#hist-search")!.value.toLowerCase();
  const useRegex = $<HTMLInputElement>("#hist-regex")!.checked;
  const scopeOnly = $<HTMLInputElement>("#hist-scope-only")!.checked;
  const statuses = $all<HTMLInputElement>(".hist-status:checked").map(c => c.value);

  let rows = allRows;

  // Filter by status
  if (statuses.length > 0) {
    rows = rows.filter(ex => {
      if (ex.status === null) return false;
      return statuses.includes(String(ex.status)[0]);
    });
  }

  // Filter by scope
  if (scopeOnly && cachedScope && !cachedScope.allow_all) {
    // In a real implementation, we'd filter by scope rules
    // For now, just show a hint
    rows = rows; // Placeholder - would filter by scope
  }

  // Filter by search
  if (search) {
    const pattern = useRegex ? new RegExp(search, 'i') : search;
    rows = rows.filter(ex => {
      const haystack = `${ex.method} ${ex.host} ${ex.path}`.toLowerCase();
      if (useRegex) {
        return pattern.test(haystack);
      }
      return haystack.includes(search);
    });
  }

  if (rows.length === 0) {
    body.innerHTML = renderEmptyState(
      "No traffic captured yet",
      "Configure your browser to use burpsy as proxy:\nhttp://localhost:8080",
      "📭",
      10
    );
    return;
  }

  body.innerHTML = rows.map(renderRow).join('');
  
  // Re-attach listeners to new rows
  attachRowListeners();
}

function renderRow(ex: Exchange): string {
  const search = $<HTMLInputElement>("#hist-search")?.value.toLowerCase() || '';
  const useRegex = $<HTMLInputElement>("#hist-regex")?.checked || false;
  
  const host = highlightSearch(ex.host, useRegex ? search : '');
  const path = highlightSearch(ex.path, useRegex ? search : '');
  const method = highlightSearch(ex.method, useRegex ? search : '');
  
  // Truncate long text for display
  const displayHost = ex.host.length > 40 ? ex.host.slice(0, 38) + '…' : ex.host;
  const displayPath = ex.path.length > 50 ? ex.path.slice(0, 48) + '…' : ex.path;
  const isTruncated = ex.host.length > 40 || ex.path.length > 50;
  
  return `
    <tr data-id="${ex.id}" ${isTruncated ? `data-full="${esc(ex.host + ' - ' + ex.path)}"` : ''} ${bulkSelected.has(ex.id) ? 'class="on"' : ''}>
      <td class="select-col"><input type="checkbox" class="row-checkbox" ${bulkSelected.has(ex.id) ? 'checked' : ''} /></td>
      <td>${ex.id}</td>
      <td>${method}</td>
      <td class="${ex.host.length > 40 ? 'ellipsis' : ''}">${displayHost}</td>
      <td class="${ex.path.length > 50 ? 'ellipsis' : ''}">${displayPath}</td>
      <td>${statusBadge(ex.status)}</td>
      <td>${fmtBytes(ex.response_len)}</td>
      <td>${ex.duration_ms}</td>
      <td>${ex.tls ? '✓' : ''}</td>
      <td></td>
    </tr>
  `;
}

function attachRowListeners(): void {
  rendered.clear();
  
  $all("#hist-body tr[data-id]").forEach((tr) => {
    const id = Number(tr.dataset["id"]);
    const ex = allRows.find(e => e.id === id);
    if (ex) {
      rendered.set(id, ex);
      
      // Row click handler
      tr.onclick = (e) => {
        // Don't trigger if clicking on checkbox or actions
        if ((e.target as HTMLElement).tagName === 'INPUT' || 
            (e.target as HTMLElement).closest('.row-checkbox') ||
            (e.target as HTMLElement).closest('button')) {
          return;
        }
        void openExchange(ex);
        markSelected(ex);
      };
    }
  });
}

async function openExchange(ex: Exchange): Promise<void> {
  markSelected(ex);
  
  try {
    const [req, res] = await Promise.all([
      getJSON<MessageView>(`/api/message/${ex.request}`),
      ex.response ? getJSON<MessageView>(`/api/message/${ex.response}`) : Promise.resolve({ id: 0, len: 0, text: '' })
    ]);
    
    const reqEl = $("#hist-req")!;
    const resEl = $("#hist-res")!;
    
    reqEl.textContent = req.text;
    resEl.textContent = res.text;
    
    // Update line numbers
    updateViewerLines('hist-req-container', req.text);
    updateViewerLines('hist-res-container', res.text);
    
    // Update meta
    const reqMeta = $("#hist-req-meta")!;
    const resMeta = $("#hist-res-meta")!;
    
    reqMeta.textContent = `${ex.method} ${ex.path} - ${fmtBytes(req.len)}`;
    resMeta.textContent = res.len > 0 
      ? `Status: ${ex.status} - ${fmtBytes(res.len)}` 
      : 'No response';
    
  } catch (e) {
    toast((e as Error).message, "error");
  }
}
