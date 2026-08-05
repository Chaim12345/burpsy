// Tool Log tab: a log of every request burpsy's own tools have sent. This is separate from
// the proxy's History (which is requests *through* burpsy) because tool requests are generated
// internally and have different semantics: they may be retries, they may be part of a larger
// operation, and they are always initiated by burpsy itself.

import { $, esc, getJSON, makeSortable, renderEmptyState, copyText } from "./common";

interface ToolLogEntry {
  id: number;
  tool: string;
  request: string;
  at_ms: number;
  status: number | null;
  response_len: number;
  duration_ms: number;
}

interface ToolLogState {
  entries: ToolLogEntry[];
  total: number;
  dropped: number;
}

export function initToolLog(): void {
  const section = $("#logger");
  if (!section) return;
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

  // Initialize table sorting
  makeSortable('log-body', 'at_ms');
  
  // Load initial data
  void loadToolLog();
  
  // Search and filter
  const searchInput = $("#log-search") as HTMLInputElement;
  const toolFilter = $("#log-tool-filter") as HTMLSelectElement;
  
  searchInput?.addEventListener('input', () => applyFilter());
  toolFilter?.addEventListener('change', () => applyFilter());
}

let allEntries: ToolLogEntry[] = [];

async function loadToolLog(): Promise<void> {
  try {
    const response = await fetch("/api/tools/log?limit=500");
    if (!response.ok) throw new Error(`Failed to load tool log: ${response.status}`);
    
    const state = await response.json() as ToolLogState;
    allEntries = state.entries;
    
    const metaEl = $("#log-meta")!;
    metaEl.textContent = `Showing ${Math.min(allEntries.length, 500)} of ${state.total.toLocaleString()} (${state.dropped.toLocaleString()} dropped)`;
    
    applyFilter();
  } catch (e) {
    const body = $("#log-body")!;
    body.innerHTML = `<tr><td colspan="7" class="err">${esc((e as Error).message)}</td></tr>`;
  }
}

function applyFilter(): void {
  const search = ($("#log-search") as HTMLInputElement)?.value.toLowerCase() || '';
  const tool = ($("#log-tool-filter") as HTMLSelectElement)?.value || '';
  
  let entries = allEntries;
  
  if (tool) {
    entries = entries.filter(e => e.tool === tool);
  }
  
  if (search) {
    entries = entries.filter(e => 
      e.request.toLowerCase().includes(search) ||
      e.tool.toLowerCase().includes(search)
    );
  }
  
  renderEntries(entries);
}

function renderEntries(entries: ToolLogEntry[]): void {
  const tbody = $("#log-body")!;
  const emptyEl = $("#log-empty")!;
  
  if (entries.length === 0) {
    tbody.innerHTML = '';
    emptyEl.innerHTML = renderEmptyState(
      "No tool requests logged yet",
      "Requests from burpsy's tools will appear here",
      "📝",
      7
    );
    return;
  }
  
  emptyEl.innerHTML = '';
  tbody.innerHTML = entries.slice(0, 100).map(e => `
    <tr>
      <td>${new Date(e.at_ms).toLocaleTimeString()}</td>
      <td><span class="tag tag-${esc(e.tool)}">${esc(e.tool)}</span></td>
      <td>${esc(e.request.slice(0, 60))}${e.request.length > 60 ? '...' : ''}</td>
      <td>${e.status ? e.status : '-'}</td>
      <td>${fmtBytes(e.response_len)}</td>
      <td>${e.duration_ms}</td>
      <td>
        <button class="ghost small" onclick="copyRequest(${e.id})">Copy</button>
      </td>
    </tr>
  `).join('');
  
  if (entries.length > 100) {
    tbody.innerHTML += `<tr><td colspan="7" class="hint">Showing 100 of ${entries.length.toLocaleString()} entries</td></tr>`;
  }
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

// Global functions
window.refreshToolLog = function(): void {
  void loadToolLog();
};

window.clearToolLog = async function(): Promise<void> {
  if (!confirm("Are you sure you want to clear the entire tool log?")) return;
  
  try {
    await fetch("/api/tools/log", { method: "DELETE" });
    toast("Tool log cleared", 'success');
    void loadToolLog();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.copyRequest = async function(id: number): Promise<void> {
  try {
    const response = await fetch(`/api/tools/log/${id}`);
    if (!response.ok) throw new Error(`Failed to load request: ${response.status}`);
    
    const entry = await response.json() as ToolLogEntry;
    copyText(entry.request, 'tool request');
  } catch (e) {
    toast((e as Error).message, "error");
  }
};
