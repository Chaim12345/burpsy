// WS History tab: the messages captured off upgraded WebSocket connections — a parallel surface to
// proxy History, because a WS row is a one-way message keyed by its connection rather than a
// request/response pair. See crates/web/src/routes/websockets.rs for why the two are separate.

import { $, $all, esc, getJSON } from "./common";

interface RowView {
  id: number;
  exchange: number;
  payload: number;
  direction: "client_to_server" | "server_to_client";
  opcode: string;
  len: number;
  dropped: number;
  truncated: boolean;
  fragments: number;
  at_ms: number;
  note?: string;
}

interface HistoryResp {
  total: number;
  rows: RowView[];
}

interface CloseView {
  code: number;
  reason: string;
}

interface MessageResp extends RowView {
  text: string;
  hex: string;
  close?: CloseView;
}

interface ConnectionView {
  exchange: number;
  host: string;
  port: number;
  tls: boolean;
  path: string;
  messages: number;
  sent: number;
  received: number;
  last_ms: number;
}

/** Connection metadata, keyed by exchange id, so rows can be joined to a host/path without a
 * per-row fetch. */
let connectionsByExchange = new Map<number, ConnectionView>();
let currentRows: RowView[] = [];

export function initWshistory(): void {
  const section = $("#wshistory");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <label>connection
        <select id="ws-conn"><option value="">all connections</option></select>
      </label>
      <button class="ghost" id="ws-refresh">Refresh</button>
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
  $("#ws-refresh")!.addEventListener("click", () => void loadAll());
  $("#ws-conn")!.addEventListener("change", () => void load());
  void loadAll();
}

/** Refreshes the connection picker, then loads the currently-selected connection's rows. */
async function loadAll(): Promise<void> {
  try {
    const conns = await getJSON<ConnectionView[]>("/api/ws/connections");
    connectionsByExchange = new Map(conns.map((c) => [c.exchange, c]));
    renderConnectionOptions(conns);
  } catch (e) {
    $("#ws-meta")!.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    return;
  }
  await load();
}

function renderConnectionOptions(conns: ConnectionView[]): void {
  const sel = $<HTMLSelectElement>("#ws-conn")!;
  const prev = sel.value;
  sel.innerHTML =
    `<option value="">all connections</option>` +
    conns
      .map(
        (c) =>
          `<option value="${c.exchange}">${esc(c.host)}:${c.port}${esc(c.path)} (${c.messages} messages)</option>`,
      )
      .join("");
  if (conns.some((c) => String(c.exchange) === prev)) sel.value = prev;
}

async function load(): Promise<void> {
  const body = $("#ws-body")!;
  const meta = $("#ws-meta")!;
  const exchange = $<HTMLSelectElement>("#ws-conn")!.value;
  const qs = exchange ? `?exchange=${encodeURIComponent(exchange)}&limit=300` : "?limit=300";
  try {
    const resp = await getJSON<HistoryResp>(`/api/ws/history${qs}`);
    currentRows = resp.rows;
    meta.textContent = `${resp.rows.length} of ${resp.total} message(s)`;
    body.innerHTML =
      resp.rows.map(rowHtml).join("") ||
      `<tr><td colspan="8" class="hint">no WebSocket traffic captured yet</td></tr>`;
    wireRows();
  } catch (e) {
    body.innerHTML = `<tr><td colspan="8" class="err">${esc((e as Error).message)}</td></tr>`;
  }
}

function directionLabel(d: RowView["direction"]): string {
  return d === "client_to_server" ? "→ server" : "← client";
}

function rowHtml(r: RowView): string {
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

function wireRows(): void {
  const byId = new Map(currentRows.map((r) => [r.id, r]));
  $all("#ws-body tr").forEach((tr) => {
    const id = Number(tr.dataset["id"]);
    const row = byId.get(id);
    if (!row) return;
    tr.addEventListener("click", () => void openMessage(row));
  });
}

async function openMessage(row: RowView): Promise<void> {
  const el = $("#ws-payload")!;
  el.textContent = "loading…";
  let msg: MessageResp;
  try {
    msg = await getJSON<MessageResp>(`/api/ws/message/${row.id}`);
  } catch (e) {
    el.textContent = (e as Error).message;
    return;
  }
  const warning = row.truncated
    ? `<div class="hint err">truncated: ${row.dropped} byte(s) dropped, showing only what was kept</div>`
    : "";
  const closeLine = msg.close ? `close ${msg.close.code}: ${msg.close.reason}\n\n` : "";
  const body = msg.opcode === "text" ? msg.text : msg.hex;
  el.innerHTML = "";
  $("#ws-detail")!.querySelector(".hint.err")?.remove();
  if (warning) el.insertAdjacentHTML("beforebegin", warning);
  el.textContent = closeLine + body;
}
