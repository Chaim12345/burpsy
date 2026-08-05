// Scanner/Issues tab: passive findings, an operator-triggered active audit on one exchange, and
// report downloads. Every request mirrors the API's own "not configured" convention (a plain 200
// with enabled:false, never a broken-looking empty panel).

import { $, $all, esc, getJSON, postJSON, emit, switchTab } from "./common";
import { EVT_SHOW_EXCHANGE } from "./types";
import { liveAuditCardHtml, mountLiveAudit } from "./liveaudit";
import { attachRowContextMenu } from "./contextmenu";
import type { MenuItem } from "./contextmenu";
import { exchangeIdMenuItems, copyText } from "./sendto";
import { registerRowTarget } from "./shortcuts";
import { live } from "./live";

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
/** The findings currently rendered, so the delegated right-click menu can resolve a `<tr>` back to
 * one after any reload. */
let rendered: Finding[] = [];
/** The row the operator last clicked or right-clicked, for the keyboard shortcuts. */
let selected: Finding | null = null;

export function initScanner(): void {
  const section = $("#scanner");
  if (!section) return;
  section.innerHTML = `
    ${liveAuditCardHtml("scan")}
    <div class="command-bar">
      <span id="scan-counts"></span>
      <span class="grow"></span>
      <label>Audit exchange <input id="scan-audit-id" placeholder="ID" class="control-short" /></label>
      <button class="go" id="scan-audit-run">Run audit</button>
    </div>
    <div class="page-actions">
      <span class="hint">Right-click a finding to open or send its first occurrence.</span>
      <span class="grow"></span><span class="hint">Export</span>
      <a class="text-action" href="/api/report/html" download>HTML</a>
      <a class="text-action" href="/api/report/json" download>JSON</a>
      <a class="text-action" href="/api/report/sarif" download>SARIF</a>
    </div>
    <div id="scan-hint" class="hint"></div>
    <div id="scan-audit-out"></div>
    <div class="scanner-workspace">
      <div class="table-panel"><div class="panel-head"><div><div class="eyebrow">Results</div><div class="panel-title">Findings</div></div></div><div class="table-scroll"><table>
        <thead><tr><th>Sev</th><th>Conf</th><th>Check</th><th>Issue</th><th>Host</th><th>Seen</th><th>Detail</th></tr></thead>
        <tbody id="scan-body"></tbody>
      </table></div></div>
      <div id="scan-detail" class="scanner-detail"><div class="empty-state"><b>Select a finding</b><span>Its evidence, remediation, and occurrences will appear here.</span></div></div>
    </div>
  `;
  $("#scan-audit-run")!.addEventListener("click", () => void runAudit());
  // Same control as the Dashboard's, same state, same endpoint — liveaudit.ts owns all three, so the
  // two panes cannot show different answers. The operator who came here looking for "scan on/off"
  // and found nothing is the reason it is drawn twice.
  mountLiveAudit("scan");
  attachRowContextMenu<Finding>({
    container: "#scan-body",
    rowSelector: "tr[data-id]",
    resolve: (tr) => rendered.find((f) => f.id === Number(tr.dataset["id"])) ?? null,
    heading: (f) => f.issue_name ?? f.check_name,
    select: (f) => markSelected(f),
    items: (f) => findingMenuItems(f),
  });
  registerRowTarget("scanner", () => {
    if (!selected) return null;
    const first = selected.occurrences[0];
    return {
      label: `finding "${selected.issue_name ?? selected.check_name}"`,
      ...(first ? { exchangeId: first.exchange_id } : {}),
      note: "this finding has no recorded occurrence, so there is no request to send",
    };
  });
  // Passive findings arrive while the operator browses, which is the whole point of passive scanning —
  // so the pane follows them instead of waiting to be asked.
  live({ kinds: ["issues"], section: "scanner", refresh: () => void load() });
  void load();
}

function markSelected(f: Finding): void {
  selected = f;
  $all("#scan-body tr").forEach((tr) => tr.classList.toggle("on", Number(tr.dataset["id"]) === f.id));
}

/** A finding is not a request, so the send-to actions act on its first recorded occurrence — stated in
 * the labels, because "Send to Repeater" on a finding with fourteen occurrences must not leave the
 * operator guessing which one went. */
function findingMenuItems(f: Finding): MenuItem[] {
  const first = f.occurrences[0];
  const items: MenuItem[] = [
    { label: "Copy finding as text", run: () => void copyText(findingAsText(f), "the finding") },
    { separator: true },
  ];
  if (!first) {
    items.push({ label: "no occurrence recorded — nothing to send", disabled: true });
    return items;
  }
  items.push({ label: `First occurrence: #${first.exchange_id} ${first.path}`, disabled: true });
  items.push(...exchangeIdMenuItems(first.exchange_id, undefined, { showInHistory: true }));
  return items;
}

function findingAsText(f: Finding): string {
  return [
    `${f.severity} / ${f.confidence} confidence — ${f.issue_name ?? f.check_name}`,
    `check: ${f.check_name}`,
    `host: ${f.host}`,
    `seen: ${f.times_seen} time(s)`,
    `occurrences: ${f.occurrences.map((o) => `#${o.exchange_id} ${o.path}`).join(", ") || "none recorded"}`,
    "",
    `detail: ${f.detail ?? "none recorded"}`,
    `remediation: ${f.remediation ?? "none recorded"}`,
  ].join("\n");
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
    body.innerHTML = `<tr><td colspan="7" class="empty-cell">${esc(resp.hint ?? "Passive scanning is not enabled.")}</td></tr>`;
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
      .join("") || `<tr><td colspan="7" class="empty-cell">No findings yet. Passive and active results will appear here.</td></tr>`;
  // A refresh may change ids/contents underneath an open panel, so close it rather than show stale data.
  openFindingId = null;
  $("#scan-detail")!.innerHTML = emptyFindingHtml();
  wireRows(resp.findings);
}

function wireRows(findings: Finding[]): void {
  rendered = findings;
  const byId = new Map(findings.map((f) => [f.id, f]));
  // A reload may have removed the selected finding entirely; drop the selection rather than let a
  // shortcut act on a row that is no longer on screen.
  if (selected && !byId.has(selected.id)) selected = null;
  $all("#scan-body tr").forEach((tr) => {
    const id = Number(tr.dataset["id"]);
    const f = byId.get(id);
    if (!f) return;
    if (selected && selected.id === id) {
      selected = f;
      tr.classList.add("on");
    }
    tr.addEventListener("click", () => {
      markSelected(f);
      toggleDetail(f);
    });
  });
}

function toggleDetail(f: Finding): void {
  const out = $("#scan-detail")!;
  if (openFindingId === f.id) {
    openFindingId = null;
    out.innerHTML = emptyFindingHtml();
    return;
  }
  openFindingId = f.id;
  out.innerHTML = findingDetailHtml(f);
  $("#scan-detail-close")!.addEventListener("click", () => {
    openFindingId = null;
    out.innerHTML = emptyFindingHtml();
  });
  $all("button[data-exchange-id]", out).forEach((btn) => {
    btn.addEventListener("click", () => {
      const exchangeId = Number(btn.dataset["exchangeId"]);
      emit(EVT_SHOW_EXCHANGE, { exchangeId });
      switchTab("history");
    });
  });
}

function emptyFindingHtml(): string {
  return `<div class="empty-state"><b>Select a finding</b><span>Its evidence, remediation, and occurrences will appear here.</span></div>`;
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
