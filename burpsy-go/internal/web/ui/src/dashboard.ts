// Dashboard tab: what is running, what the tool did, and what every count on this screen does not
// account for. Every number here is real — no placeholder data — so a tab with nothing captured yet
// honestly shows zeroes and "not enabled" hints rather than a mockup.
//
// The pane reads one endpoint, /api/dashboard, rather than stitching four together. That matters for
// more than the request count: the old pane read a findings total from /api/issues and a check count
// from nowhere at all, so "12 issues" arrived with no way to say whether anything had been skipped.
// Every count now arrives as a Summary carrying its own found/skipped/errored/gated breakdown, and
// renderSummary refuses to draw the number without them.

import { $, $all, esc, getJSON, switchTab } from "./common";
import type { LogEntry } from "./toollog";
import { liveAuditCardHtml, mountLiveAudit } from "./liveaudit";
import { live } from "./live";

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

export function initDashboard(): void {
  const section = $("#dashboard");
  if (!section) return;
  section.innerHTML = `
    <div class="dashboard-head">
    <div class="metric-grid">
      <div class="stat-tile"><div class="label">Exchanges captured</div><div class="value" id="dash-exchanges">–</div></div>
      <div class="stat-tile"><div class="label">Storage used</div><div class="value" id="dash-storage">–</div></div>
      <div class="stat-tile"><div class="label">Scope rules</div><div class="value" id="dash-scope">–</div></div>
      <div class="stat-tile"><div class="label">Tasks running</div><div class="value" id="dash-running">–</div></div>
    </div>
    <div class="quick-launch panel"><div class="eyebrow">Quick launch</div><div class="panel-title">Start working</div>
      <button class="launch-action" data-jump="history"><b>Inspect traffic</b><span>Open HTTP history</span></button>
      <button class="launch-action" data-jump="repeater"><b>Send a request</b><span>Open Repeater</span></button>
      <button class="launch-action" data-jump="scanner"><b>Review findings</b><span>Open Scanner</span></button>
    </div></div>
    <div class="section-block">
      <div class="section-heading"><div><div class="eyebrow">Coverage ledger</div><div class="panel-title">Counts and incomplete work</div></div><p class="hint">Every result stays attached to skipped, errored, and gated work.</p></div>
      <div class="metric-grid" id="dash-summaries"></div>
    </div>
    <div class="table-panel">
      <div class="panel-head"><div><div class="eyebrow">Work in progress</div><div class="panel-title">Tasks</div></div><div id="dash-tasks-meta" class="hint"></div></div><div class="table-scroll"><table>
        <thead><tr><th>Kind</th><th>Target</th><th>State</th><th>Progress</th><th>Result</th><th>Elapsed</th></tr></thead>
        <tbody id="dash-tasks"></tbody>
      </table></div>
    </div>
    <div class="activity-grid">
      <div class="table-panel"><div class="panel-head"><div><div class="eyebrow">Network activity</div><div class="panel-title">Requests sent</div></div><div id="dash-activity-meta" class="hint"></div></div><div class="table-scroll"><table>
          <thead><tr><th>Time</th><th>Tool</th><th>Request</th></tr></thead>
          <tbody id="dash-activity"></tbody>
        </table></div></div>
      <div class="table-panel"><div class="panel-head"><div><div class="eyebrow">System activity</div><div class="panel-title">What burpsy did</div></div><div id="dash-events-meta" class="hint"></div></div><div class="table-scroll"><table>
          <thead><tr><th>Time</th><th>Kind</th><th>Detail</th></tr></thead>
          <tbody id="dash-events"></tbody>
        </table></div></div>
    </div>
    <div class="audit-row">
      ${liveAuditCardHtml("dash")}
    </div>
  `;
  $all<HTMLButtonElement>("#dashboard [data-jump]").forEach((button) => {
    button.addEventListener("click", () => switchTab(button.dataset["jump"]!));
  });
  // The switch, its counters and its POST all live in liveaudit.ts, because the Scanner tab draws the
  // same control: two panes each with their own copy of this state is how a UI ends up claiming the
  // sweep is on in one place and off in another.
  mountLiveAudit("dash");
  // Four kinds, because this pane is a view of all of them: traffic feeds the counts, findings feed the
  // issue summary, the tool log is the activity table and the event log is the task table. One endpoint
  // reads all four, so one refresh answers any of them.
  //
  // A longer minimum gap than the other panes: /api/dashboard walks every store to build its summaries,
  // and re-reading it six times a second during a crawl would spend more on rendering the numbers than
  // on capturing what they count. Once a second is live enough for a progress bar.
  live({
    kinds: ["history", "issues", "toollog", "dashboard"],
    section: "dashboard",
    refresh: () => void refresh(),
    minGapMs: 1000,
    fallbackMs: 4000,
  });
  void refresh();
}

async function refresh(): Promise<void> {
  await Promise.all([refreshDashboard(), refreshScope()]);
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
