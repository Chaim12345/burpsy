// Logger tab: every request burpsy's own tools sent (Repeater/Intruder/Scanner/BCheck), kept apart
// from proxy History by construction — see crates/tools/src/logger.rs.

import { $, $all, esc, statusBadge, getJSON, delJSON, emit, switchTab, toast } from "./common";
import { EVT_FILTER_HISTORY } from "./types";
import { attachRowContextMenu } from "./contextmenu";
import type { MenuItem } from "./contextmenu";
import { copyText } from "./sendto";
import { live } from "./live";

export interface LogEntry {
  id: number;
  tool: string;
  host: string;
  port: number;
  method: string;
  path: string;
  status: number | null;
  response_len: number;
  started_ms: number;
  duration_ms: number;
  error: string | null;
}
interface LogResp {
  total: number;
  shown: number;
  dropped: number;
  // Keyed by tool name rather than a fixed set of four. The old shape named a "bcheck" tool that
  // does not exist (so it read a permanent 0) and had no key for session, sequencer, comparer,
  // decoder or crawler activity, so those rows were counted into nothing.
  counts: Record<string, number>;
  entries: LogEntry[];
}

/** The rows currently rendered, so the delegated right-click menu can resolve a `<tr>` back to one. */
let rendered: LogEntry[] = [];

export function initToolLog(): void {
  const el = $("#logger");
  if (!el) return;
  el.innerHTML = `
    <div class="command-bar">
      <select id="log-filter">
        <option value="">all</option>
        <option value="repeater">repeater</option>
        <option value="intruder">intruder</option>
        <option value="scanner">scanner</option>
        <option value="bcheck">bcheck</option>
      </select>
      <input id="log-search" type="search" placeholder="search host/path/method" class="grow" />
      <button class="ghost danger" id="log-clear">Clear log</button>
      <span id="log-meta" class="hint"></span>
    </div>
    <div class="page-actions"><span class="hint">Right-click a row to copy its host or path, or filter History to matching traffic.</span></div>
    <div class="table-panel"><div class="panel-head"><div><div class="eyebrow">Tool traffic</div><div class="panel-title">Requests sent by burpsy</div></div></div><div class="table-scroll"><table>
      <thead><tr><th>#</th><th>Tool</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Len</th><th>ms</th><th>Error</th></tr></thead>
      <tbody id="log-body"></tbody>
    </table></div></div>
  `;
  $("#log-filter")!.addEventListener("change", () => void load());
  $("#log-clear")!.addEventListener("click", () => void clear());
  let searchTimer: ReturnType<typeof setTimeout> | undefined;
  $("#log-search")!.addEventListener("input", () => {
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => void load(), 300);
  });
  attachRowContextMenu<LogEntry>({
    container: "#log-body",
    rowSelector: "tr[data-id]",
    resolve: (tr) => rendered.find((e) => e.id === Number(tr.dataset["id"])) ?? null,
    heading: (e) => `${e.tool}: ${e.method} ${e.path}`,
    select: (e) => $all("#log-body tr").forEach((tr) => tr.classList.toggle("on", Number(tr.dataset["id"]) === e.id)),
    items: (e) => rowMenuItems(e),
  });
  // Every request one of burpsy's own tools sends lands here, so the pane follows the stream rather than
  // a Refresh button. The filter and the search box are re-applied by load() itself.
  live({ kinds: ["toollog"], section: "logger", refresh: () => void load() });
  void load();
}

/** A logged row is a request burpsy itself sent, so it is never *in* proxy History and there is no
 * stored message to reload — the tool log carries no message ids and no TLS flag, so this pane cannot
 * honestly build a URL scheme or a raw request from a row. What it can do is point at the same host's
 * captured traffic, which is what the History filter entry does. */
function rowMenuItems(e: LogEntry): MenuItem[] {
  const hostPort = `${e.host}:${e.port}`;
  return [
    {
      label: `Filter History by ${e.host}`,
      run: () => {
        emit(EVT_FILTER_HISTORY, { search: e.host });
        switchTab("history");
      },
    },
    {
      label: `Filter History by ${e.path}`,
      run: () => {
        emit(EVT_FILTER_HISTORY, { search: e.path });
        switchTab("history");
      },
    },
    { separator: true },
    { label: "Copy host:port", run: () => void copyText(hostPort, hostPort) },
    { label: "Copy path", run: () => void copyText(e.path, "the path") },
  ];
}

async function load(): Promise<void> {
  const body = $("#log-body")!;
  const meta = $("#log-meta")!;
  const tool = $<HTMLSelectElement>("#log-filter")!.value;
  const q = $<HTMLInputElement>("#log-search")!.value.trim();
  // "filter" and "tool", "search" and "q": the handler has always read the first of each pair, so
  // the tab's own filter and search box sent parameters nothing looked at and silently returned the
  // unfiltered log.
  const params = new URLSearchParams();
  if (tool) params.set("filter", tool);
  if (q) params.set("search", q);
  const qs = params.toString();
  try {
    const resp = await getJSON<LogResp>(`/api/tools/log${qs ? `?${qs}` : ""}`);
    const active = Object.entries(resp.counts)
      .filter(([, n]) => n > 0)
      .map(([name, n]) => `${name} ${n}`);
    meta.textContent =
      `${resp.total} total${active.length ? ` (${active.join(", ")})` : ""}` +
      (resp.dropped ? ` · ${resp.dropped} dropped (capacity)` : "");
    rendered = resp.entries;
    body.innerHTML =
      resp.entries
        .map(
          (e) => `<tr data-id="${e.id}">
        <td>${e.id}</td><td>${esc(e.tool)}</td><td>${esc(e.method)}</td>
        <td>${esc(e.host)}:${e.port}</td><td>${esc(e.path)}</td>
        <td>${statusBadge(e.status)}</td><td>${e.response_len}</td><td>${e.duration_ms}</td>
        <td class="err">${esc(e.error ?? "")}</td>
      </tr>`,
        )
        .join("") || `<tr><td colspan="9" class="empty-cell">No tool traffic yet. Requests from Repeater, Intruder, and Scanner will appear here.</td></tr>`;
  } catch (e) {
    body.innerHTML = `<tr><td colspan="9" class="err">${esc((e as Error).message)}</td></tr>`;
  }
}

async function clear(): Promise<void> {
  try {
    await delJSON("/api/tools/log");
    void load();
  } catch (e) {
    toast((e as Error).message, "error");
  }
}
