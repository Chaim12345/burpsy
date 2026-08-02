// Scanner/Issues tab: passive findings, an operator-triggered active audit on one exchange, and
// report downloads. Every request mirrors the API's own "not configured" convention (a plain 200
// with enabled:false, never a broken-looking empty panel).

import { $, $all, esc, getJSON, postJSON, emit, switchTab } from "./common";
import { EVT_SHOW_EXCHANGE } from "./types";

interface Occurrence {
  exchange_id: number;
  response: number;
  path: string;
}

interface Finding {
  id: number;
  check_name: string;
  issue_name: string | null;
  severity: string;
  confidence: string;
  host: string;
  detail: string | null;
  remediation: string | null;
  occurrences: Occurrence[];
  times_seen: number;
}

interface IssuesResp {
  enabled: boolean;
  hint?: string;
  counts?: { high: number; medium: number; low: number; info: number };
  findings: Finding[];
}

/** id of the finding whose detail panel is currently open, or null when the panel is closed. */
let openFindingId: number | null = null;

export function initScanner(): void {
  const section = $("#scanner");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <button class="go" id="scan-refresh">Refresh</button>
      <span id="scan-counts"></span>
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
  $("#scan-refresh")!.addEventListener("click", () => void load());
  $("#scan-audit-run")!.addEventListener("click", () => void runAudit());
  void load();
}

async function load(): Promise<void> {
  const body = $("#scan-body")!;
  const counts = $("#scan-counts")!;
  const hint = $("#scan-hint")!;
  let resp: IssuesResp;
  try {
    resp = await getJSON<IssuesResp>("/api/issues");
  } catch (e) {
    body.innerHTML = `<tr><td colspan="7" class="err">${esc((e as Error).message)}</td></tr>`;
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
  counts.innerHTML =
    `<span class="sev-high">${c.high} high</span> · <span class="sev-medium">${c.medium} medium</span> · ` +
    `<span class="sev-low">${c.low} low</span> · <span class="sev-info">${c.info} info</span>`;
  body.innerHTML =
    resp.findings
      .map(
        (f) => `<tr class="clickable" data-id="${f.id}">
      <td class="sev-${esc(f.severity.toLowerCase())}">${esc(f.severity)}</td>
      <td>${esc(f.confidence)}</td>
      <td>${esc(f.check_name)}</td>
      <td>${esc(f.issue_name ?? "")}</td>
      <td>${esc(f.host)}</td>
      <td>${f.times_seen}</td>
      <td>${esc(f.detail ?? "")}</td>
    </tr>`,
      )
      .join("") || `<tr><td colspan="7" class="hint">no findings yet</td></tr>`;
  // A refresh may change ids/contents underneath an open panel, so close it rather than show stale data.
  openFindingId = null;
  $("#scan-detail")!.innerHTML = "";
  wireRows(resp.findings);
}

function wireRows(findings: Finding[]): void {
  const byId = new Map(findings.map((f) => [f.id, f]));
  $all("#scan-body tr").forEach((tr) => {
    const id = Number(tr.dataset["id"]);
    const f = byId.get(id);
    if (!f) return;
    tr.addEventListener("click", () => toggleDetail(f));
  });
}

function toggleDetail(f: Finding): void {
  const out = $("#scan-detail")!;
  if (openFindingId === f.id) {
    openFindingId = null;
    out.innerHTML = "";
    return;
  }
  openFindingId = f.id;
  out.innerHTML = findingDetailHtml(f);
  $("#scan-detail-close")!.addEventListener("click", () => {
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

function findingDetailHtml(f: Finding): string {
  const occurrences = f.occurrences.length
    ? f.occurrences
        .map(
          (o) =>
            `<button class="ghost small" data-exchange-id="${o.exchange_id}">#${o.exchange_id} ${esc(o.path)}</button>`,
        )
        .join("")
    : `<span class="hint">no occurrences recorded</span>`;
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

async function runAudit(): Promise<void> {
  const idEl = $<HTMLInputElement>("#scan-audit-id")!;
  const out = $("#scan-audit-out")!;
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
    out.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
  void load();
}
