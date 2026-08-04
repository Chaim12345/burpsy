// Dashboard tab: what is running, what the tool did, and what every count on this screen does not
// account for. Every number here is real — no placeholder data — so a tab with nothing captured yet
// honestly shows zeroes and "not enabled" hints rather than a mockup.
//
// The pane reads one endpoint, /api/dashboard, rather than stitching four together. That matters for
// more than the request count: the old pane read a findings total from /api/issues and a check count
// from nowhere at all, so "12 issues" arrived with no way to say whether anything had been skipped.
// Every count now arrives as a Summary carrying its own found/skipped/errored/gated breakdown, and
// renderSummary refuses to draw the number without them.

import { $, esc, getJSON, postJSON } from "./common";
import type { LogEntry } from "./toollog";

interface ScopeInfo {
  allow_all: boolean;
  rules: unknown[];
}
// Breakdown mirrors Go's dash.Breakdown wire shape. Every field is always present — the Go
// marshaller writes all four buckets even when they are zero — so this has no optional members and
// the renderer never has to guess at a missing caveat.
interface Breakdown {
  found: number;
  skipped: number;
  errored: number;
  gated: number;
  unaccounted: number;
  complete: boolean;
  summary: string;
}
interface Reason {
  bucket: string;
  detail: string;
  count: number;
}
interface Summary {
  label: string;
  unit: string;
  work_unit: string;
  breakdown: Breakdown;
  reasons: Reason[];
}
interface Task {
  id: number;
  kind: string;
  target: string;
  state: string;
  done: number;
  total: number;
  started_ms: number;
  ended_ms: number;
  note?: string;
  result: Breakdown;
  elapsed_ms: number;
  fraction: number;
  fraction_known: boolean;
  progress: string;
  complete: boolean;
}
// Event mirrors Go's dash.Event. Deliberately a separate list from `activity`: that one is requests the
// tool *sent* (host, method, status), this one is things the tool *did* — a task started, the scope was
// edited, the live audit was switched on. Neither shape fits the other, and the sweep completing used to
// be crammed into the request log as a row with the invented method "LIVE".
interface ToolEvent {
  id: number;
  kind: string;
  severity: "info" | "warn" | "error";
  detail: string;
  task_id?: number;
  at_ms: number;
}
interface DashboardResp {
  summaries: Summary[];
  tasks: Task[];
  tasks_running: number;
  tasks_dropped: number;
  activity: LogEntry[];
  activity_shown: number;
  activity_total: number;
  activity_dropped: number;
  events: ToolEvent[];
  events_shown: number;
  events_total: number;
  events_dropped: number;
  exchanges: number;
  messages: number;
  stored_bytes: number;
  sources: Record<string, number>;
}
interface LiveAuditResp {
  wired: boolean;
  enabled: boolean;
  hint?: string;
  swept?: number;
  findings?: number;
  // Carried beside `swept`, never added to it: an exchange the sweep gave up waiting on is not one
  // that came back clean. `stalled_at` is the exchange id the cursor is currently waiting on.
  skipped?: number;
  stalled_at?: number;
  // Not optional: a zero backlog is the most useful thing this field says ("the sweep is caught up"),
  // and omitting it would make caught-up indistinguishable from a build that never reported it.
  behind: number;
  collapsed: number;
  ledger_resets: number;
  query?: string;
}

export function initDashboard(): void {
  const section = $("#dashboard");
  if (!section) return;
  section.innerHTML = `
    <div class="four">
      <div class="stat-tile"><div class="label">Exchanges captured</div><div class="value" id="dash-exchanges">–</div></div>
      <div class="stat-tile"><div class="label">Storage used</div><div class="value" id="dash-storage">–</div></div>
      <div class="stat-tile"><div class="label">Scope rules</div><div class="value" id="dash-scope">–</div></div>
      <div class="stat-tile"><div class="label">Tasks running</div><div class="value" id="dash-running">–</div></div>
    </div>
    <div class="card">
      <div class="card-title">Counts, and what they do not account for</div>
      <p class="hint">A count with a caveat is a floor, not a total. Nothing here reports a number
        without reporting the work that produced no verdict.</p>
      <div class="four" id="dash-summaries"></div>
    </div>
    <div class="card">
      <div class="card-title">Tasks</div>
      <table>
        <thead><tr><th>Kind</th><th>Target</th><th>State</th><th>Progress</th><th>Result</th><th>Elapsed</th></tr></thead>
        <tbody id="dash-tasks"></tbody>
      </table>
      <div id="dash-tasks-meta" class="hint"></div>
    </div>
    <div class="two">
      <div class="card">
        <div class="card-title">Requests sent</div>
        <p class="hint">Every request burpsy's own tools sent. Proxy traffic lives in History.</p>
        <table>
          <thead><tr><th>Time</th><th>Tool</th><th>Request</th></tr></thead>
          <tbody id="dash-activity"></tbody>
        </table>
        <div id="dash-activity-meta" class="hint"></div>
      </div>
      <div class="card">
        <div class="card-title">What the tool did</div>
        <p class="hint">Tasks starting and finishing, scope edits, bounds hit — the things that are not
          requests, so they are not in the list beside this one.</p>
        <table>
          <thead><tr><th>Time</th><th>Kind</th><th>Detail</th></tr></thead>
          <tbody id="dash-events"></tbody>
        </table>
        <div id="dash-events-meta" class="hint"></div>
      </div>
    </div>
    <div class="two">
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
  await Promise.all([refreshDashboard(), refreshScope(), refreshAudit()]);
}

async function refreshDashboard(): Promise<void> {
  try {
    const d = await getJSON<DashboardResp>("/api/dashboard");
    $("#dash-exchanges")!.textContent = d.exchanges.toLocaleString();
    $("#dash-storage")!.textContent = `${(d.stored_bytes / 1048576).toFixed(1)} MB`;
    $("#dash-running")!.textContent = String(d.tasks_running);
    $("#dash-summaries")!.innerHTML = d.summaries.map(renderSummary).join("");
    renderTasks(d);
    renderActivity(d);
    renderEvents(d);
  } catch (e) {
    $("#dash-summaries")!.innerHTML = `<div class="err">${esc((e as Error).message)}</div>`;
  }
}

// renderSummary draws the count and its four buckets together. The caveat chips are drawn whenever
// they are non-zero and the "complete" line is drawn when they are not, so there is no code path
// here that emits the found number on its own.
function renderSummary(s: Summary): string {
  const b = s.breakdown;
  const chips = [
    b.skipped > 0 ? `<span class="pill pill-outline sev-low">${b.skipped} skipped</span>` : "",
    b.errored > 0 ? `<span class="pill pill-outline sev-high">${b.errored} errored</span>` : "",
    b.gated > 0 ? `<span class="pill pill-outline sev-medium">${b.gated} gated</span>` : "",
  ]
    .filter(Boolean)
    .join(" ");
  const verdict = b.complete
    ? `<div class="hint ok">complete — nothing skipped, errored or gated</div>`
    : `<div class="hint err">a floor, not a total: ${b.unaccounted} ${esc(s.work_unit)} produced no verdict</div>`;
  const reasons = b.complete
    ? ""
    : `<ul class="hint">${s.reasons
        .map((r) => `<li>${r.count} — ${esc(r.detail)}</li>`)
        .join("")}</ul>`;
  return `<div class="stat-tile">
    <div class="label">${esc(s.label)}</div>
    <div class="value">${b.found.toLocaleString()}</div>
    <div class="hint">${esc(s.unit)}</div>
    <div class="row">${chips}</div>
    ${verdict}
    ${reasons}
  </div>`;
}

function renderTasks(d: DashboardResp): void {
  const body = $("#dash-tasks")!;
  body.innerHTML = d.tasks.length
    ? d.tasks
        .map(
          (t) => `<tr>
        <td><span class="tag">${esc(t.kind)}</span></td>
        <td>${esc(t.target)}</td>
        <td>${stateBadge(t)}</td>
        <td>${progressCell(t)}</td>
        <td>${resultCell(t)}</td>
        <td>${(t.elapsed_ms / 1000).toFixed(1)}s</td>
      </tr>`,
        )
        .join("")
    : `<tr><td colspan="6" class="hint">nothing has run yet — start an audit, an attack or a crawl</td></tr>`;
  $("#dash-tasks-meta")!.textContent =
    `${d.tasks.length} shown, ${d.tasks_running} running` +
    (d.tasks_dropped ? ` · ${d.tasks_dropped} older finished tasks dropped at the capacity bound` : "");
}

function stateBadge(t: Task): string {
  const cls =
    t.state === "failed" ? "sev-high" : t.state === "stopped" ? "sev-medium" : t.state === "done" ? "ok" : "";
  return `<span class="pill pill-outline ${cls}">${esc(t.state)}</span>`;
}

// progressCell draws a bar only when the total is known. A task whose frontier is still growing gets
// its count and an explicit "total not yet known" instead of a bar at some arbitrary width — a
// progress bar that cannot know its end must not draw one.
function progressCell(t: Task): string {
  if (!t.fraction_known) {
    return `<span class="hint">${esc(t.progress)}</span>`;
  }
  return `<div class="seq-bar-track" title="${esc(t.progress)}">
      <span class="seq-bar-fill" style="width:${(t.fraction * 100).toFixed(1)}%"></span>
    </div><span class="hint">${esc(t.progress)}</span>`;
}

function resultCell(t: Task): string {
  if (t.state === "running") return `<span class="hint">pending</span>`;
  const cls = t.complete ? "ok" : "err";
  const note = t.note ? `<div class="hint">${esc(t.note)}</div>` : "";
  return `<span class="${cls}">${esc(t.result.summary)}</span>${note}`;
}

function renderActivity(d: DashboardResp): void {
  const body = $("#dash-activity")!;
  body.innerHTML = d.activity.length
    ? d.activity
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
  $("#dash-activity-meta")!.textContent =
    `newest ${d.activity_shown} of ${d.activity_total}` +
    (d.activity_dropped ? ` · ${d.activity_dropped} dropped at the log's capacity bound` : "");
}

// renderEvents draws the event log. Severity picks the row's emphasis, so a bounded run does not scroll
// past at the same weight as a clean one.
function renderEvents(d: DashboardResp): void {
  const body = $("#dash-events")!;
  body.innerHTML = d.events.length
    ? d.events
        .map(
          (e) => `<tr>
          <td>${relTime(e.at_ms)}</td>
          <td><span class="pill pill-outline ${severityClass(e.severity)}">${esc(e.kind)}</span></td>
          <td class="${severityClass(e.severity)}">${esc(e.detail)}</td>
        </tr>`,
        )
        .join("")
    : `<tr><td colspan="3" class="hint">nothing yet — start an audit, a crawl or an attack</td></tr>`;
  $("#dash-events-meta")!.textContent =
    `newest ${d.events_shown} of ${d.events_total}` +
    (d.events_dropped ? ` · ${d.events_dropped} dropped at the log's capacity bound` : "");
}

function severityClass(sev: ToolEvent["severity"]): string {
  return sev === "error" ? "err" : sev === "warn" ? "sev-medium" : "";
}

async function refreshScope(): Promise<void> {
  try {
    const s = await getJSON<ScopeInfo>("/api/scope");
    $("#dash-scope")!.textContent = s.allow_all ? "everything" : `${s.rules.length}`;
  } catch {
    // best-effort
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
    // The backlog and what the sweep gave up on are stated next to the state, never folded into
    // "sweeping": a sweep 9,000 exchanges behind is not caught up, and an operator reading only
    // "sweeping new in-scope traffic" would think it was.
    const notes: string[] = [r.enabled ? "sweeping new in-scope traffic" : "off"];
    if (r.query) notes.push(`filtered to ${r.query}`);
    if (r.behind > 0) notes.push(`${r.behind} exchange(s) not reached yet`);
    if (r.skipped) notes.push(`${r.skipped} given up on (no response)`);
    if (r.stalled_at !== undefined) notes.push(`waiting on exchange ${r.stalled_at}`);
    if (r.ledger_resets) notes.push(`${r.ledger_resets} ledger reset(s)`);
    hint.textContent = notes.join(" · ");
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
