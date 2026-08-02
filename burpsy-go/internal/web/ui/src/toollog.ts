// Logger tab: every request burpsy's own tools sent (Repeater/Intruder/Scanner/BCheck), kept apart
// from proxy History by construction — see crates/tools/src/logger.rs.

import { $, esc, statusBadge, getJSON, delJSON, toast } from "./common";

interface LogEntry {
  id: number;
  tool: string;
  host: string;
  port: number;
  method: string;
  path: string;
  status: number | null;
  response_len: number;
  duration_ms: number;
  error: string | null;
}
interface LogResp {
  total: number;
  dropped: number;
  counts: { repeater: number; intruder: number; scanner: number; bcheck: number };
  entries: LogEntry[];
}

export function initToolLog(): void {
  const el = $("#logger");
  if (!el) return;
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
      <button class="ghost" id="log-refresh">Refresh</button>
      <button class="ghost" id="log-clear">Clear</button>
      <span id="log-meta" class="hint"></span>
    </div>
    <table>
      <thead><tr><th>#</th><th>Tool</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Len</th><th>ms</th><th>Error</th></tr></thead>
      <tbody id="log-body"></tbody>
    </table>
  `;
  $("#log-refresh")!.addEventListener("click", () => void load());
  $("#log-filter")!.addEventListener("change", () => void load());
  $("#log-clear")!.addEventListener("click", () => void clear());
  let searchTimer: ReturnType<typeof setTimeout> | undefined;
  $("#log-search")!.addEventListener("input", () => {
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => void load(), 300);
  });
  void load();
}

async function load(): Promise<void> {
  const body = $("#log-body")!;
  const meta = $("#log-meta")!;
  const tool = $<HTMLSelectElement>("#log-filter")!.value;
  const q = $<HTMLInputElement>("#log-search")!.value.trim();
  const params = new URLSearchParams();
  if (tool) params.set("tool", tool);
  if (q) params.set("q", q);
  const qs = params.toString();
  try {
    const resp = await getJSON<LogResp>(`/api/tools/log${qs ? `?${qs}` : ""}`);
    meta.textContent =
      `${resp.total} total (repeater ${resp.counts.repeater}, intruder ${resp.counts.intruder}, ` +
      `scanner ${resp.counts.scanner}, bcheck ${resp.counts.bcheck})` +
      (resp.dropped ? ` · ${resp.dropped} dropped (capacity)` : "");
    body.innerHTML =
      resp.entries
        .map(
          (e) => `<tr>
        <td>${e.id}</td><td>${esc(e.tool)}</td><td>${esc(e.method)}</td>
        <td>${esc(e.host)}:${e.port}</td><td>${esc(e.path)}</td>
        <td>${statusBadge(e.status)}</td><td>${e.response_len}</td><td>${e.duration_ms}</td>
        <td class="err">${esc(e.error ?? "")}</td>
      </tr>`,
        )
        .join("") || `<tr><td colspan="9" class="hint">nothing logged yet</td></tr>`;
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
