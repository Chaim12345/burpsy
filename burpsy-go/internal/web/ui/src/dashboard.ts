// Dashboard tab: what is running, what the tool did, and what every count on this screen does not
// account for. Every number here is real — no placeholder data — so a tab with nothing captured yet
// honestly shows zeroes and "not enabled" hints rather than a mockup.
//
// The pane reads one endpoint, /api/dashboard, rather than stitching four together. That matters for
// more than the request count: the old pane read a findings total from /api/issues and a check count
// from nowhere at all, so "12 issues" arrived with no way to say whether anything had been skipped.
// Every count now arrives as a Summary carrying its own found/skipped/errored/gated breakdown, and
// renderSummary refuses to draw the number without them.

import { $, esc, getJSON, makeSortable, createSorter, renderEmptyState } from "./common";
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
    <div class="four">
      <div class="stat-tile"><div class="label">Exchanges captured</div><div class="value" id="dash-exchanges"></div></div>
      <div class="stat-tile"><div class="label">Storage used</div><div class="value" id="dash-storage"></div></div>
      <div class="stat-tile"><div class="label">Scope rules</div><div class="value" id="dash-scope"></div></div>
      <div class="stat-tile"><div class="label">Tasks running</div><div class="value" id="dash-running"></div></div>
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
        <thead><tr><th data-sort="kind">Kind</th><th data-sort="target">Target</th><th data-sort="state">State</th><th>Progress</th><th>Result</th><th data-sort="elapsed_ms">Elapsed</th></tr></thead>
        <tbody id="dash-tasks"></tbody>
      </table>
      <div id="dash-tasks-meta" class="hint"></div>
    </div>
    <div class="two">
      <div class="card">
        <div class="card-title">Requests sent</div>
        <p class="hint">Every request burpsy's own tools sent. Proxy traffic lives in History.</p>
        <table>
          <thead><tr><th data-sort="at_ms">Time</th><th data-sort="tool">Tool</th><th>Request</th></tr></thead>
          <tbody id="dash-activity"></tbody>
        </table>
        <div id="dash-activity-meta" class="hint"></div>
      </div>
      <div class="card">
        <div class="card-title">What the tool did</div>
        <p class="hint">Tasks starting and finishing, scope edits, bounds hit — the things that are not
          requests, so they are not in the list beside this one.</p>
        <table>
          <thead><tr><th data-sort="at_ms">Time</th><th data-sort="kind">Kind</th><th>Detail</th></tr></thead>
          <tbody id="dash-events"></tbody>
        </table>
        <div id="dash-events-meta" class="hint"></div>
      </div>
    </div>
    <div class="two">
      ${liveAuditCardHtml("dash")}
    </div>
  `;
  
  // Initialize table sorting
  makeSortable('dash-tasks', 'started_ms');
  makeSortable('dash-activity', 'at_ms');
  makeSortable('dash-events', 'at_ms');
  
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
  // on the crawl itself.
  live({ kinds: ["history", "issues", "toollog", "dashboard"], section: "dashboard", refresh: () => void load(), minGapMs: 500 });
  void load();
}

function renderSummary(s: Summary): string {
  const b = s.breakdown;
  const total = b.found + b.skipped + b.errored + b.gated;
  const caveats: string[] = [];
  if (b.skipped > 0) caveats.push(`${b.skipped} skipped`);
  if (b.errored > 0) caveats.push(`${b.errored} errored`);
  if (b.gated > 0) caveats.push(`${b.gated} gated`);
  if (b.unaccounted > 0) caveats.push(`${b.unaccounted} unaccounted`);

  const caveat = caveats.length > 0 ? ` (${caveats.join(", ")})` : "";
  const complete = b.complete ? "complete" : "incomplete";

  return `
    <div class="stat-tile">
      <div class="label">${esc(s.label)}</div>
      <div class="value">${total.toLocaleString()}${esc(caveat)}</div>
      <div class="hint" style="font-size:11px;margin-top:4px">${esc(s.summary)}</div>
    </div>
  `;
}

function renderTask(t: Task): string {
  const progress = t.progress || (t.fraction_known ? `${Math.round(t.fraction * 100)}%` : "");
  const elapsed = t.elapsed_ms > 0 ? `${(t.elapsed_ms / 1000).toFixed(1)}s` : "";
  const result = renderBreakdown(t.result);

  return `
    <tr>
      <td>${esc(t.kind)}</td>
      <td>${esc(t.target)}</td>
      <td>${esc(t.state)}</td>
      <td>${esc(progress)}</td>
      <td>${result}</td>
      <td>${elapsed}</td>
    </tr>
  `;
}

function renderBreakdown(b: Breakdown): string {
  const parts: string[] = [];
  if (b.found > 0) parts.push(`${b.found} found`);
  if (b.skipped > 0) parts.push(`${b.skipped} skipped`);
  if (b.errored > 0) parts.push(`${b.errored} errors`);
  if (b.gated > 0) parts.push(`${b.gated} gated`);
  if (parts.length === 0) return "-";
  return parts.join(", ");
}

function renderActivity(e: LogEntry): string {
  const time = new Date(e.at_ms).toLocaleTimeString();
  return `
    <tr>
      <td>${esc(time)}</td>
      <td><span class="tag tag-${esc(e.tool)}">${esc(e.tool)}</span></td>
      <td>${esc(e.request)}</td>
    </tr>
  `;
}

function renderEvent(e: ToolEvent): string {
  const time = new Date(e.at_ms).toLocaleTimeString();
  const sevClass = e.severity === "error" ? "err" : e.severity === "warn" ? "sev-medium" : "dim";
  return `
    <tr>
      <td>${esc(time)}</td>
      <td><span class="${sevClass}">${esc(e.kind)}</span></td>
      <td>${esc(e.detail)}</td>
    </tr>
  `;
}

async function load(): Promise<void> {
  const summariesEl = $("#dash-summaries")!;
  const tasksEl = $("#dash-tasks")!;
  const tasksMetaEl = $("#dash-tasks-meta")!;
  const activityEl = $("#dash-activity")!;
  const activityMetaEl = $("#dash-activity-meta")!;
  const eventsEl = $("#dash-events")!;
  const eventsMetaEl = $("#dash-events-meta")!;

  // Show loading state
  summariesEl.innerHTML = '<div class="loading-state"><span class="spinner spinner-medium"></span> Loading...</div>';
  tasksEl.innerHTML = renderEmptyState("Loading tasks...", "", "⏳", 6);
  activityEl.innerHTML = renderEmptyState("Loading activity...", "", "⏳", 3);
  eventsEl.innerHTML = renderEmptyState("Loading events...", "", "⏳", 3);

  let resp: DashboardResp;
  try {
    resp = await getJSON<DashboardResp>("/api/dashboard");
  } catch (e) {
    summariesEl.innerHTML = `<div class="err">${esc((e as Error).message)}</div>`;
    return;
  }

  // Update header stats
  $("#dash-exchanges")!.textContent = resp.exchanges.toLocaleString();
  $("#dash-storage")!.textContent = `${(resp.stored_bytes / 1048576).toFixed(2)} MB`;
  $("#dash-scope")!.textContent = resp.sources?.scope ? resp.sources.scope.toLocaleString() : "0";
  $("#dash-running")!.textContent = resp.tasks_running.toLocaleString();

  // Render summaries
  if (resp.summaries.length > 0) {
    summariesEl.innerHTML = resp.summaries.map(renderSummary).join("");
  } else {
    summariesEl.innerHTML = renderEmptyState("No summaries available", "", "📊", 4);
  }

  // Render tasks
  if (resp.tasks.length > 0) {
    tasksEl.innerHTML = resp.tasks.map(renderTask).join("");
    tasksMetaEl.textContent = `Showing ${resp.tasks.length} of ${resp.tasks.length + resp.tasks_dropped} tasks`;
  } else {
    tasksEl.innerHTML = renderEmptyState("No tasks running", "Start a scan or crawl to see tasks here", "🛠️", 6);
    tasksMetaEl.textContent = "No tasks";
  }

  // Render activity
  if (resp.activity.length > 0) {
    activityEl.innerHTML = resp.activity.map(renderActivity).join("");
    activityMetaEl.textContent = `Showing ${resp.activity_shown} of ${resp.activity_total} (${resp.activity_dropped} dropped)`;
  } else {
    activityEl.innerHTML = renderEmptyState("No activity yet", "Requests sent by burpsy will appear here", "📤", 3);
    activityMetaEl.textContent = "No activity";
  }

  // Render events
  if (resp.events.length > 0) {
    eventsEl.innerHTML = resp.events.map(renderEvent).join("");
    eventsMetaEl.textContent = `Showing ${resp.events_shown} of ${resp.events_total} (${resp.events_dropped} dropped)`;
  } else {
    eventsEl.innerHTML = renderEmptyState("No events yet", "Tool actions will appear here", "📝", 3);
    eventsMetaEl.textContent = "No events";
  }
}
