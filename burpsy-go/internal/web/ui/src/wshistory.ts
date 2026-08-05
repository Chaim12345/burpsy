// WS History tab: WebSocket message history. Unlike HTTP, WebSocket is a bidirectional protocol
// with messages that can be sent by either side at any time. This tab shows all captured WebSocket
// messages, with their direction (client → server or server → client) and payload.

import { $, esc, getJSON, makeSortable, renderEmptyState, copyText } from "./common";

interface WSMessage {
  id: number;
  exchange_id: number;
  direction: "client" | "server";
  payload: string;
  payload_len: number;
  at_ms: number;
  opcode: number;
}

interface WSHistoryState {
  messages: WSMessage[];
  total: number;
}

export function initWshistory(): void {
  const section = $("#wshistory");
  if (!section) return;
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

  // Initialize table sorting
  makeSortable('ws-body', 'id');
  
  // Load initial data
  void loadWSHistory();
  
  // Search and filter
  const searchInput = $("#ws-search") as HTMLInputElement;
  const directionFilter = $("#ws-direction-filter") as HTMLSelectElement;
  
  searchInput?.addEventListener('input', () => applyWSFilter());
  directionFilter?.addEventListener('change', () => applyWSFilter());
}

let allMessages: WSMessage[] = [];

async function loadWSHistory(): Promise<void> {
  try {
    const response = await fetch("/api/ws?limit=500");
    if (!response.ok) throw new Error(`Failed to load WS history: ${response.status}`);
    
    const state = await response.json() as WSHistoryState;
    allMessages = state.messages;
    
    const metaEl = $("#ws-meta")!;
    metaEl.textContent = `Showing ${Math.min(allMessages.length, 500)} of ${state.total.toLocaleString()} messages`;
    
    applyWSFilter();
  } catch (e) {
    const body = $("#ws-body")!;
    body.innerHTML = `<tr><td colspan="8" class="err">${esc((e as Error).message)}</td></tr>`;
  }
}

function applyWSFilter(): void {
  const search = ($("#ws-search") as HTMLInputElement)?.value.toLowerCase() || '';
  const direction = ($("#ws-direction-filter") as HTMLSelectElement)?.value || '';
  
  let messages = allMessages;
  
  if (direction) {
    messages = messages.filter(m => m.direction === direction);
  }
  
  if (search) {
    messages = messages.filter(m => 
      m.payload.toLowerCase().includes(search)
    );
  }
  
  renderMessages(messages);
}

function renderMessages(messages: WSMessage[]): void {
  const tbody = $("#ws-body")!;
  const emptyEl = $("#ws-empty")!;
  
  if (messages.length === 0) {
    tbody.innerHTML = '';
    emptyEl.innerHTML = renderEmptyState(
      "No WebSocket messages captured yet",
      "WebSocket messages will appear here when captured by the proxy",
      "🔄",
      8
    );
    return;
  }
  
  emptyEl.innerHTML = '';
  tbody.innerHTML = messages.slice(0, 100).map(m => `
    <tr onclick="showWSMessage(${m.id})" style="cursor:pointer">
      <td>${m.id}</td>
      <td>${m.exchange_id}</td>
      <td><span class="tag tag-${m.direction}">${m.direction === 'client' ? '→' : '←'}</span></td>
      <td>${m.opcode}</td>
      <td>${esc(m.payload.slice(0, 50))}${m.payload.length > 50 ? '...' : ''}</td>
      <td>${fmtBytes(m.payload_len)}</td>
      <td>${new Date(m.at_ms).toLocaleTimeString()}</td>
      <td><button class="ghost small" onclick="event.stopPropagation(); copyWSMessage(${m.id})">Copy</button></td>
    </tr>
  `).join('');
  
  if (messages.length > 100) {
    tbody.innerHTML += `<tr><td colspan="8" class="hint">Showing 100 of ${messages.length.toLocaleString()} messages</td></tr>`;
  }
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function showWSMessage(id: number): void {
  const msg = allMessages.find(m => m.id === id);
  if (!msg) return;
  
  const detailEl = $("#ws-detail") as HTMLElement;
  if (detailEl) {
    detailEl.textContent = msg.payload;
    updateWSDetailLines(msg.payload);
  }
}

function updateWSDetailLines(payload: string): void {
  const linesEl = $("#ws-detail-lines") as HTMLElement;
  if (linesEl) {
    const lines = payload.split('\n').length;
    linesEl.innerHTML = Array.from({length: lines}, (_, i) => i + 1).join('\n');
  }
}

// Global functions
window.refreshWSHistory = function(): void {
  void loadWSHistory();
};

window.clearWSHistory = async function(): Promise<void> {
  if (!confirm("Are you sure you want to clear the entire WebSocket history?")) return;
  
  try {
    await fetch("/api/ws", { method: "DELETE" });
    toast("WebSocket history cleared", 'success');
    void loadWSHistory();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.copyWSMessage = async function(id: number): Promise<void> {
  const msg = allMessages.find(m => m.id === id);
  if (msg) {
    copyText(msg.payload, 'WebSocket message');
  }
};

window.applyWSFilter = function(): void {
  applyWSFilter();
};
