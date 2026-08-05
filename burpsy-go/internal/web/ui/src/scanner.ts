// Scanner/Issues tab: passive findings, an operator-triggered active audit on one exchange, and
// report downloads. Every request mirrors the API's own "not configured" convention (a plain 200
// with enabled:false, never a broken-looking empty panel).

import { $, $all, esc, getJSON, postJSON, emit, switchTab, toast, makeSortable, createSorter, renderEmptyState } from "./common";
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
    <div class="row">
      <span id="scan-counts"></span>
      <span class="hint">right-click a finding to open or send its first occurrence  ? for shortcuts</span>
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
  
  // Initialize table sorting
  makeSortable('scan-body', 'severity');
  
  // Handle sort events
  $('#scan-body')?.addEventListener('sort', (e: CustomEvent) => {
    const { field, ascending } = e.detail;
    if (rendered.length > 0) {
      rendered.sort(createSorter<Finding>(field as keyof Finding, ascending));
      renderBody();
    }
  });
  
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

function renderSeverity(sev: string): string {
  const classes = {
    "High": "sev-high",
    "Medium": "sev-medium",
    "Low": "sev-low",
    "Information": "sev-info",
  };
  return `<span class="${classes[sev] || "sev-info"}">${esc(sev)}</span>`;
}

function renderConfidence(conf: string): string {
  const classes = {
    "Certain": "ok",
    "Firm": "ok",
    "Tentative": "dim",
  };
  return `<span class="${classes[conf] || "dim"}">${esc(conf)}</span>`;
}

function renderRow(f: Finding): string {
  const sev = renderSeverity(f.severity);
  const conf = renderConfidence(f.confidence);
  const issue = esc(f.issue_name || f.check_name);
  const check = esc(f.check_name);
  const host = esc(f.host);
  const seen = f.times_seen.toLocaleString();
  const detail = f.detail ? `<button class="ghost small" onclick="toggleDetail(${f.id})">Show</button>` : "-";

  return `
    <tr data-id="${f.id}" ${selected?.id === f.id ? 'class="on"' : ''}>
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

function renderDetail(f: Finding): string {
  return `
    <div class="card" style="margin-top:10px">
      <div class="card-title">Finding Details</div>
      <div class="detail-text">${esc(f.detail || "No detail available")}</div>
      ${f.remediation ? `<div style="margin-top:8px"><b>Remediation:</b><div class="detail-text">${esc(f.remediation)}</div></div>` : ''}
      ${f.occurrences.length > 0 ? `
        <div style="margin-top:8px"><b>Occurrences:</b>
        <ul style="margin:4px 0;padding-left:20px">
          ${f.occurrences.map(o => `<li>Exchange #${o.exchange_id} - ${esc(o.path)}</li>`).join('')}
        </ul>
        </div>
      ` : ''}
    </div>
  `;
}

// Global function for detail toggle
window.toggleDetail = function(id: number): void {
  const detailEl = $("#scan-detail")!;
  const finding = rendered.find(f => f.id === id);
  
  if (!finding) return;
  
  if (openFindingId === id) {
    openFindingId = null;
    detailEl.innerHTML = "";
  } else {
    openFindingId = id;
    detailEl.innerHTML = renderDetail(finding);
  }
};

function renderCounts(counts: { high: number; medium: number; low: number; info: number } | undefined): string {
  if (!counts) return "";
  const total = counts.high + counts.medium + counts.low + counts.info;
  return `
    <span class="pill sev-high">${counts.high}</span>
    <span class="pill sev-medium">${counts.medium}</span>
    <span class="pill sev-low">${counts.low}</span>
    <span class="pill sev-info">${counts.info}</span>
    <span style="margin-left:8px">Total: ${total.toLocaleString()}</span>
  `;
}

async function load(): Promise<void> {
  const body = $("#scan-body")!;
  const counts = $("#scan-counts")!;
  const hint = $("#scan-hint")!;
  
  // Show loading state
  body.innerHTML = `<tr><td colspan="7" class="loading-state"><span class="spinner spinner-medium"></span> Loading findings...</td></tr>`;
  
  let resp: IssuesResp;
  try {
    resp = await getJSON<IssuesResp>("/api/issues");
  } catch (e) {
    body.innerHTML = `<tr><td colspan="7" class="err">${esc((e as Error).message)}</td></tr>`;
    return;
  }
  
  if (!resp.enabled) {
    body.innerHTML = renderEmptyState(
      "Passive scanning not enabled",
      resp.hint || "Enable passive scanning to see findings here",
      "🔍",
      7
    );
    counts.innerHTML = "";
    hint.textContent = resp.hint || "";
    return;
  }

  rendered = resp.findings;
  
  if (rendered.length === 0) {
    body.innerHTML = renderEmptyState(
      "No findings yet",
      "Passive findings will appear here as traffic is captured",
      "✅",
      7
    );
    counts.innerHTML = "";
    hint.textContent = "No issues detected";
    return;
  }

  counts.innerHTML = renderCounts(resp.counts);
  hint.textContent = "";
  body.innerHTML = rendered.map(renderRow).join("");
}

async function runAudit(): Promise<void> {
  const input = $<HTMLInputElement>("#scan-audit-id")!;
  const id = parseInt(input.value, 10);
  
  if (isNaN(id)) {
    toast("Please enter a valid exchange ID", "error");
    return;
  }

  const button = $("#scan-audit-run")!;
  const originalText = button.textContent;
  
  try {
    // Show loading state on button
    button.classList.add('loading');
    button.textContent = "Auditing...";
    
    const out = $("#scan-audit-out")!;
    out.innerHTML = '<div class="hint"><span class="spinner spinner-small"></span> Starting audit...</div>';
    
    const result = await postJSON<{ task_id: number; message: string }>(`/api/scanner/audit/${id}`, {});
    
    out.innerHTML = `<div class="hint ok">Audit started: Task #${result.task_id} - ${esc(result.message)}</div>`;
    input.value = "";
    
    toast(`Audit started for exchange #${id}`, "success");
  } catch (e) {
    toast((e as Error).message, "error");
  } finally {
    button.classList.remove('loading');
    button.textContent = originalText;
  }
}
