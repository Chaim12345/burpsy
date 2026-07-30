// Dashboard tab: session overview. Every number here is real — no placeholder data — so a tab
// with nothing captured yet honestly shows zeroes and "not enabled" hints rather than a mockup.

import { $, esc, getJSON, postJSON } from "./common";

interface Stats {
  exchanges: number;
  messages: number;
  stored_bytes: number;
}
interface ScopeInfo {
  allow_all: boolean;
  rules: unknown[];
}
interface IssuesResp {
  enabled: boolean;
  counts?: { high: number; medium: number; low: number; info: number };
}
interface LogEntry {
  id: number;
  tool: string;
  host: string;
  port: number;
  method: string;
  path: string;
  status: number | null;
  duration_ms: number;
  started_ms: number;
  error: string | null;
}
interface LogResp {
  entries: LogEntry[];
}
interface LiveAuditResp {
  wired: boolean;
  enabled: boolean;
  hint?: string;
  swept?: number;
  findings?: number;
}

export function initDashboard(): void {
  const section = $("#dashboard");
  if (!section) return;
  section.innerHTML = `
    <div class="four">
      <div class="stat-tile"><div class="label">Exchanges captured</div><div class="value" id="dash-exchanges">–</div></div>
      <div class="stat-tile"><div class="label">Findings</div><div class="value" id="dash-findings">–</div></div>
      <div class="stat-tile"><div class="label">Storage used</div><div class="value" id="dash-storage">–</div></div>
      <div class="stat-tile"><div class="label">Scope rules</div><div class="value" id="dash-scope">–</div></div>
    </div>
    <div class="two">
      <div class="card">
        <div class="card-title">Live activity</div>
        <table>
          <thead><tr><th>Time</th><th>Source</th><th>Event</th></tr></thead>
          <tbody id="dash-activity"></tbody>
        </table>
      </div>
      <div class="card">
        <div class="row" style="justify-content:space-between;margin-bottom:4px">
          <div class="card-title" style="margin:0">Live active audit</div>
          <label class="switch"><input type="checkbox" id="dash-audit-toggle" /><span class="slider"></span></label>
        </div>
        <p class="hint">Auditing new in-scope traffic. Active checks are never sent automatically
          while this is off.</p>
        <div id="dash-audit-hint" class="hint"></div>
        <div class="row">
          <div class="stat-tile grow"><div class="label">Exchanges swept</div><div class="value" id="dash-audit-swept">0</div></div>
          <div class="stat-tile grow"><div class="label">Findings</div><div class="value" id="dash-audit-findings">0</div></div>
        </div>
      </div>
    </div>
  `;
  $<HTMLInputElement>("#dash-audit-toggle")!.addEventListener("change", (e) =>
    void setAudit((e.target as HTMLInputElement).checked),
  );
  void refresh();
  setInterval(() => void refresh(), 4000);
}

async function refresh(): Promise<void> {
  await Promise.all([refreshStats(), refreshScope(), refreshIssues(), refreshActivity(), refreshAudit()]);
}

async function refreshStats(): Promise<void> {
  try {
    const s = await getJSON<Stats>("/api/stats");
    $("#dash-exchanges")!.textContent = s.exchanges.toLocaleString();
    $("#dash-storage")!.textContent = `${(s.stored_bytes / 1048576).toFixed(1)} MB`;
  } catch {
    // best-effort, matches the header's own polling
  }
}

async function refreshScope(): Promise<void> {
  try {
    const s = await getJSON<ScopeInfo>("/api/scope");
    $("#dash-scope")!.textContent = s.allow_all ? "everything" : `${s.rules.length}`;
  } catch {
    // best-effort
  }
}

async function refreshIssues(): Promise<void> {
  const el = $("#dash-findings")!;
  try {
    const r = await getJSON<IssuesResp>("/api/issues");
    if (!r.enabled || !r.counts) {
      el.innerHTML = `<span class="hint" style="font-size:11px">--bchecks disabled</span>`;
      return;
    }
    const c = r.counts;
    el.innerHTML =
      `<span class="sev-high">${c.high}</span> <span class="sev-medium">${c.medium}</span> ` +
      `<span class="sev-low">${c.low}</span> <span class="sev-info">${c.info}</span>`;
  } catch {
    // best-effort
  }
}

async function refreshActivity(): Promise<void> {
  const body = $("#dash-activity")!;
  try {
    const r = await getJSON<LogResp>("/api/tools/log?limit=20");
    body.innerHTML = r.entries.length
      ? r.entries
          .map(
            (e) => `<tr>
          <td>${relTime(e.started_ms)}</td>
          <td><span class="tag tag-${esc(e.tool)}">${esc(e.tool)}</span></td>
          <td>${esc(e.method)} ${esc(e.path)} ${
            e.error
              ? `<span class="err">${esc(e.error)}</span>`
              : e.status !== null
                ? `→ ${e.status}`
                : ""
          }</td>
        </tr>`,
          )
          .join("")
      : `<tr><td colspan="3" class="hint">nothing yet — use Repeater to see activity here</td></tr>`;
  } catch (e) {
    body.innerHTML = `<tr><td colspan="3" class="err">${esc((e as Error).message)}</td></tr>`;
  }
}

function relTime(startedMs: number): string {
  const diffS = Math.max(0, Math.round((Date.now() - startedMs) / 1000));
  if (diffS < 60) return `${diffS}s ago`;
  if (diffS < 3600) return `${Math.round(diffS / 60)}m ago`;
  return `${Math.round(diffS / 3600)}h ago`;
}

async function refreshAudit(): Promise<void> {
  const toggle = $<HTMLInputElement>("#dash-audit-toggle")!;
  const hint = $("#dash-audit-hint")!;
  try {
    const r = await getJSON<LiveAuditResp>("/api/scanner/live");
    toggle.disabled = !r.wired;
    if (!r.wired) {
      hint.textContent = r.hint ?? "not available";
      return;
    }
    toggle.checked = r.enabled;
    hint.textContent = r.enabled ? "sweeping new in-scope traffic" : "off";
    $("#dash-audit-swept")!.textContent = String(r.swept ?? 0);
    $("#dash-audit-findings")!.textContent = String(r.findings ?? 0);
  } catch {
    // best-effort
  }
}

async function setAudit(enabled: boolean): Promise<void> {
  try {
    await postJSON("/api/scanner/live", { enabled });
  } finally {
    void refreshAudit();
  }
}
