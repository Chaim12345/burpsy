import { taskActivityFindings } from "../lib/task-activity";
import { useMemo, useRef, useState } from "react";
import { parseSeeds } from "../lib/parse-seeds";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Copy, FolderTree, MoreVertical, Pause, Play, Plus, Radar, Search, Square } from "lucide-react";
import { toast } from "sonner";
import { api, copyToClipboard, formatCount, formatDuration, json, relativeTime, statusTone } from "../lib/api";
import { useDashboard, useInvalidate, useIssues } from "../lib/data";
import { useIssuesDetailedWithIsolated, useScannerConfigs, useScannerLive, useSetScannerLive } from "../lib/data.attack";
import { usePools } from "../lib/data.pools";
import type { FindingDetail } from "../lib/types.attack";
import type { CrawlLoginReport } from "../lib/types.observe";
import {
 useAPIScanCheck,
 useAPIScanReviewCheck,
 useAuditSelected,
 useCrawlRun,
 useCrawls,
 useStartAPIScan,
 useStartCrawl,
} from "../lib/data.observe";
import { crawlOutcome, crawlStopLabel, crawlStops, isPolicyPause } from "../lib/crawl-stops";
import { useApp } from "../lib/store";
import type { ActivityRow, CoverageSummary, TaskRow, ToolEvent } from "../lib/types";
import { PageHeader, RefreshButton, SectionHeading, SplitPane } from "../ui/layout";
import {
 Badge,
 Button,
 Card,
 Empty,
 ErrorNotice,
 Field,
 IconButton,
 Input,
 Metric,
 Modal,
 NeedsValueButton,
 Select,
 Switch,
 Tabs,
 TabsContent,
 TabsList,
 TabsTrigger,
 Textarea,
 Toolbar,
} from "../ui/primitives";
import { APIScanFetchFromURL, APIScanReview } from "../ui/apiscan-review";
import {
 buildReview,
 discardStale,
 emptyReview,
 fetchedCaption,
 fetchedWarning,
 reviewChangesRequest,
 type ReviewState,
} from "../lib/apiscan-review";
import { DetailList } from "../ui/json";
import { DropdownMenu, type MenuGroup } from "../ui/menu";
import { MenuRow, SimpleTable } from "../ui/table";
import { RecordedLoginPicker } from "../ui/recorded-logins";
import { CrawlLiveView } from "../ui/crawl-live";
import { useDeleteTask, useScanTaskAgain } from "../lib/data.attack";
import { severityTone } from "../lib/severity";
import {
 EVENT_SEVERITY_OPTIONS,
 eventSource,
 filterEvents,
 isFiltered,
 severityCounts,
 type EventLogFilter,
 type EventSeverityFilter,
} from "../lib/event-log-filter";

function taskTone(state: string): "good" | "bad" | "warn" | "info" {
 const value = state.toLowerCase();
 if (value === "failed" || value === "error") return "bad";
 if (value === "done" || value === "complete" || value === "completed") return "good";
 if (value === "cancelled" || value === "stopped") return "warn";
 return "info";
}

/**
 * Agrees a server-supplied work unit with its count.
 *
 * The server names its units in the plural — "exchanges", "passive check sets", "tasks" — and the
 * count was interpolated straight in front, so a single one read "1 EXCHANGES WITHOUT A VERDICT".
 *
 * Trailing-`s` removal only, and only at exactly one. That is enough for every unit this API emits
 * and, importantly, it leaves the mass noun alone: "passive scanning work" does not end in `s`, so
 * it is returned unchanged rather than mangled into "wor". A unit with an irregular plural would
 * need a real inflector; none exists today, and inventing one for a case that has not arrived would
 * be the more fragile choice.
 */
function unitFor(count: number, unit: string): string {
 if (count !== 1 || !unit.endsWith("s") || unit.endsWith("ss")) return unit;
 return unit.slice(0, -1);
}

/**
 * Coverage is reported as a floor, never as a total: a check that was skipped,
 * errored or gated is accounted for separately so a low finding count is not
 * mistaken for a clean result.
 */
function CoverageCard({ summary }: { summary: CoverageSummary }): JSX.Element {
 const { breakdown } = summary;
 return (
  <div className="summary-card">
   <span>{summary.label}</span>
   <strong>{formatCount(breakdown.found)}</strong>
   <small>{summary.unit}</small>
   <div className="chip-row">
    {breakdown.skipped ? <Badge tone="warn">{breakdown.skipped} skipped</Badge> : null}
    {breakdown.errored ? <Badge tone="bad">{breakdown.errored} errored</Badge> : null}
    {breakdown.gated ? <Badge tone="info">{breakdown.gated} gated</Badge> : null}
   </div>
   <p className={breakdown.complete ? "summary-verdict good-text" : "summary-verdict warn-text"}>
    {breakdown.complete
     ? "complete"
     : `${formatCount(breakdown.unaccounted)} ${unitFor(breakdown.unaccounted, summary.work_unit)} without a verdict`}
   </p>
  </div>
 );
}

/**
 * Burp's "Clear event log" (burp.Zbuz). DELETE /api/dashboard/events clears the EventLog the
 * dashboard reads — the source, not a view of it — so after this the feed is genuinely empty for
 * every browser watching, not just the one that clicked.
 */
function useClearEventLog() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: () => api<{ cleared: boolean }>("/api/dashboard/events", { method: "DELETE" }),
  onSuccess: () => {
   toast.success("Event log cleared");
   invalidate([["dashboard"]]);
  },
  onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Clearing the event log failed"),
 });
}

// Burp's per-task Pause / Resume (burpsy-react-ui-g0ba), shown only on a running task whose loop
// stops at the pause gate. The server answers 409 for any other, so the button never promises more.
function TaskPauseButton({ task }: { task: TaskRow }): JSX.Element | null {
 const invalidate = useInvalidate();
 const toggle = useMutation({
  mutationFn: (pause: boolean) => api<{ id: number; paused: boolean }>(`/api/tasks/${task.id}/${pause ? "pause" : "resume"}`, json("POST")),
  onSuccess: (out) => {
   toast.success(out.paused ? `Task ${task.id} paused at its next step` : `Task ${task.id} resumed`);
   invalidate([["dashboard"]]);
  },
  onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Pausing the task failed"),
 });
 if (task.id === -1 || !task.pausable || task.state !== "running") return null;
 return (
  <IconButton
   label={`${task.paused ? "Resume" : "Pause"} ${task.kind} task on ${task.target}`}
   size="small"
   disabled={toggle.isPending}
   onClick={() => toggle.mutate(!task.paused)}
  >
   {task.paused ? <Play size={12} /> : <Pause size={12} />}
  </IconButton>
 );
}

function useCancelTask() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (id: number) => api<{ cancelled: number }>(`/api/tasks/${id}/cancel`, json("POST")),
  onSuccess: () => {
   toast.success("Task cancelled");
   invalidate([["dashboard"]]);
  },
  onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Cancelling the task failed"),
 });
}

/**
 * The leading "N found" of a result summary, for the tile badge. Summaries that do not match
 * (there are none today, but the server owns the phrasing) show a dash rather than a zero —
 * zero found is a claim, and only the server may make it.
 */
function foundCount(summary?: string): string {
 return /([\d,]+)\s+found/.exec(summary ?? "")?.[1] ?? "—";
}

/**
 * The standing live-audit entry. While live auditing is enabled Burp keeps its live task
 * permanently visible even between sweep batches; the registry only records a row per bounded
 * batch (:577 in liveaudit.go), so the standing entry is synthesised here from /api/scanner/live
 * state instead of faking registry data.
 */
function withStandingLiveTask(tasks: TaskRow[], liveEnabled: boolean): TaskRow[] {
 const batchRunning = tasks.some((task) => task.kind === "live audit" && task.state === "running");
 const standing: TaskRow | null =
  liveEnabled && !batchRunning
   ? {
      id: -1,
      kind: "live audit",
      target: "proxied traffic",
      state: "running",
      done: 0,
      total: 0,
      fraction: 0,
      fraction_known: false,
      cancellable: true,
      progress: "waiting for in-scope traffic",
      elapsed_ms: 0,
      result: { summary: "" },
     }
   : null;
 return standing ? [standing, ...tasks] : tasks;
}

/** Burp's dashboard is two panes: a Tasks list on the left, the selected task's detail on the
 * right. The findings column and the kind/target/state/progress columns of the old table were the
 * same facts a tile carries — the table form was the only part that differed from Burp, and the
 * detail pane replaces its per-row controls. */
function TaskTile({
 task,
 ordinal,
 selected,
 onSelect,
 liveFindings,
 liveEnabled,
}: {
 task: TaskRow;
 ordinal: number;
 selected: boolean;
 onSelect: () => void;
 liveFindings?: number;
 liveEnabled: boolean;
}): JSX.Element {
 const cancel = useCancelTask();
 const setLive = useSetScannerLive();
 const again = useScanTaskAgain();
 const remove = useDeleteTask();
 // A crawl task's retained run (j5j7). The shell already keeps this list warm, so a tile costs no
 // request: a finished crawl that hit a bound reads "incomplete" / "paused by policy", never "done".
 const crawls = useCrawls();
 const crawlRun = crawls.data?.crawls.find((run) => run.task_id === task.id);
 const tileStops = crawlStops(crawlRun);
 const tileState = crawlRun && task.state.toLowerCase() === "done" ? crawlOutcome(crawlRun) : null;
 // The task row's options menu (burpsy-react-ui-r6q): Burp's taskListEntryOptionsMenu, minus the
 // pieces that are their own tracked issues (pause/resume is 8gw; settings live on the detail
 // pane). Scan again re-runs a crawl at its target; Delete removes a finished row — the server
 // refuses a running one with 409, and the toast passes that reason through.
 const menu: MenuGroup[] =
  task.id === -1
   ? []
   : [
      {
       id: "task-options",
       actions: [
        {
         id: "scan-again",
         label: "Scan again",
         onSelect: () =>
          again.mutate(task.id, {
           onSuccess: () => toast.success(`Scan started again on ${task.target}`),
           onError: (cause: unknown) => toast.error(cause instanceof Error ? cause.message : String(cause)),
          }),
        },
        {
         id: "delete-task",
         label: "Delete task",
         danger: true,
         onSelect: () =>
          remove.mutate(task.id, {
           onSuccess: () => toast.success(`Task ${task.id} removed from the list`),
           onError: (cause: unknown) => toast.error(cause instanceof Error ? cause.message : String(cause)),
          }),
        },
       ],
      },
     ];
 // The tile is a div, not a button: it owns an IconButton and a Switch, and a button wrapping
 // either is invalid HTML, fails the axe nested-interactive rule, and selects the tile when the
 // operator only meant to flip the switch. Only the title selects.
 return (
  <div className={selected ? "task-tile task-tile-selected" : "task-tile"}>
   <div className="task-tile-head">
    <button type="button" className="task-tile-select" aria-pressed={selected} onClick={onSelect}>
     <strong>
      {ordinal}. {task.kind === "live audit" ? "Live audit from Proxy (all traffic)" : `${task.kind} (${task.target})`}
     </strong>
    </button>
    {task.paused ? <Badge tone="warn">paused</Badge> : null}
    <TaskPauseButton task={task} />
    {task.id !== -1 && task.cancellable && task.state === "running" ? (
     <IconButton
      label={`Cancel ${task.kind} task on ${task.target}`}
      size="small"
      disabled={cancel.isPending}
      onClick={() => cancel.mutate(task.id)}
     >
      <Square size={12} />
     </IconButton>
    ) : null}
    {menu.length > 0 ? (
     <DropdownMenu
      groups={menu}
      trigger={
       <IconButton label={`Options for task ${task.id} on ${task.target}`} size="small">
        <MoreVertical size={12} />
       </IconButton>
      }
     />
    ) : null}
   </div>
   <div className="task-tile-state">
    {tileState ? (
     <Badge tone={tileState.tone} title={tileStops.map(crawlStopLabel).join("\n") || undefined}>
      {tileState.label}
     </Badge>
    ) : (
     <Badge tone={taskTone(task.state)}>{task.state}</Badge>
    )}
    <span className="cell-dim">{task.progress}</span>
   </div>
   {task.kind === "live audit" ? (
    <div className="task-tile-row">
     <span>Capturing</span>
     <Switch
      checked={liveEnabled}
      label={`Capturing for live audit task ${ordinal}`}
      onCheckedChange={(next) => {
       setLive.mutate(
        { enabled: next },
        {
         onSuccess: () => toast.success(next ? "Live audit started" : "Live audit stopped"),
         onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Toggling the live sweep failed"),
        },
       );
      }}
     />
    </div>
   ) : null}
   <div className="task-tile-row">
    <span>Issues:</span>
    {task.kind === "live audit" ? (
     <Badge tone={liveFindings ? "bad" : "neutral"}>{liveFindings ?? 0}</Badge>
    ) : (
     // The badge carries the found count; the full summary sits beside it as plain text.
     // A severity ladder would be the fabrication the advisory caught: the summary counts
     // findings without splitting them, so the split lives on the Issues page, which has
     // the real findings.
     <>
      <Badge tone={task.result?.summary ? "warn" : "neutral"}>{foundCount(task.result?.summary)}</Badge>
      <span className="cell-dim">{task.result?.summary || "no summary"}</span>
     </>
    )}
   </div>
  </div>
 );
}

/** The suite-wide pause (burpsy-react-ui-8gw): Burp's "Pause all tasks" / "Resume task
 * processing". One mutation per verb — the answer carries the running count, and the toast says
 * that count, because "paused" on an empty dashboard is a different report than "paused 3
 * tasks". */
function usePauseAllTasks(paused: boolean) {
 const queryClient = useQueryClient();
 return useMutation<{ paused: boolean; running: number }, Error, void>({
  // The literals named, not one interpolated path: the route-reachability test scans ui/src for
  // each manifest pattern verbatim, and an interpolated `${paused ? ... : ...}` hides both.
  mutationFn: () => api(paused ? "/api/tasks/resume" : "/api/tasks/pause", json("POST", {})),
  onSuccess: (result) => {
   toast.success(result.paused ? `Tasks paused (${result.running} running)` : "Tasks resumed");
   void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  },
  onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : String(failure)),
 });
}

/**
 * Burp's left Tasks pane: a filter over the tiles, then one tile per task, newest first. The
 * selection lives in the parent so the detail pane can follow it, and so a poll that reorders
 * nothing does not reset what the operator clicked.
 */
function TaskSidebar({
 tasks,
 liveFindings,
 liveEnabled,
 pausedState,
 selectedId,
 onSelect,
 onNewScan,
 onNewLive,
}: {
 tasks: TaskRow[];
 liveFindings?: number;
 liveEnabled: boolean;
 pausedState?: boolean;
 selectedId: number | null;
 onSelect: (id: number) => void;
 onNewScan: () => void;
 onNewLive: () => void;
}): JSX.Element {
 const [filter, setFilter] = useState("");
 const rows = withStandingLiveTask(tasks, liveEnabled);
 const needle = filter.trim().toLowerCase();
 const shown = needle ? rows.filter((task) => `${task.kind} ${task.target}`.toLowerCase().includes(needle)) : rows;
 // The suite-wide pause (burpsy-react-ui-8gw). The state lives on the dashboard query (paused
 // arrives beside tasks), so the button reflects what the server last said; the mutation flips
 // it and invalidates the same query.
 const paused = pausedState === true;
 const pauseAll = usePauseAllTasks(paused);

 return (
  <div className="task-sidebar">
   {paused ? <div className="notice notice-warn">Task execution is paused</div> : null}
   <div className="task-sidebar-head">
    <strong>Tasks</strong>
    <div className="task-sidebar-actions">
     <Button size="small" variant="outline" onClick={() => pauseAll.mutate()} disabled={pauseAll.isPending}>
      {paused ? <Play size={13} /> : <Pause size={13} />}
      {paused ? "Resume tasks" : "Pause all tasks"}
     </Button>
     <Button size="small" onClick={onNewScan}>
      <Plus size={13} />
      New scan
     </Button>
     <Button size="small" variant="outline" onClick={onNewLive}>
      <Radar size={13} />
      New live task
     </Button>
    </div>
   </div>
   <div className="task-sidebar-filter">
    <Input aria-label="Filter tasks" placeholder="Filter tasks" value={filter} onChange={(event) => setFilter(event.target.value)} />
    <Search size={13} className="task-sidebar-filter-icon" />
   </div>
   {shown.length ? (
    <div className="task-tile-list">
     {shown.map((task) => (
      <TaskTile
       key={task.id}
       task={task}
       ordinal={rows.length - rows.indexOf(task)}
       selected={selectedId === task.id}
       onSelect={() => onSelect(task.id)}
       liveFindings={liveFindings}
       liveEnabled={liveEnabled}
      />
     ))}
    </div>
   ) : (
    <Empty
     title={needle ? "No matching tasks" : "No tasks"}
     detail={
      needle
       ? "No task matches this filter."
       : "Real-time information on your scans and live tasks is displayed here. Start a new scan or live task to populate this page."
     }
    />
   )}
  </div>
 );
}

function ActivityTable({ rows }: { rows: ActivityRow[] }): JSX.Element {
 const setHistoryQuery = useApp((state) => state.setHistoryQuery);
 const setRoute = useApp((state) => state.setRoute);

 /**
  * The dashboard's recent-activity menu.
  *
  * These rows are the same tool-log entries the Logger page shows, and they carry the same
  * limitation: the log records that one of burpsy's own tools sent a request, not the request's
  * bytes. There is no message id on an `ActivityRow`, so there is nothing to send to Repeater or
  * Intruder from here — offering it would mean fabricating a request. What is offered is the two
  * things the row can honestly do: jump to the traffic it describes, and copy it. Noted on
  * burpsy-react-ui-3fr.
  */
 const menuFor = (row: ActivityRow): MenuGroup[] => [
  {
   id: "history",
   actions: [
    ...(row.host
     ? [
        {
         id: "host",
         label: `Show ${row.host} in HTTP history`,
         icon: FolderTree,
         onSelect: () => {
          setHistoryQuery(`host = ${row.host}`);
          setRoute("history");
         },
        },
       ]
     : []),
    {
     id: "path",
     label: `Show ${row.path} in HTTP history`,
     icon: FolderTree,
     onSelect: () => {
      setHistoryQuery(`path ~ "${row.path.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`);
      setRoute("history");
     },
    },
   ],
  },
  {
   id: "copy",
   actions: [
    {
     id: "request-line",
     label: "Copy request line",
     icon: Copy,
     onSelect: () => {
      void copyToClipboard(`${row.method} ${row.path}`);
      toast.success("Request line copied");
     },
    },
    ...(row.host
     ? [
        {
         id: "url",
         label: "Copy URL (as logged)",
         icon: Copy,
         onSelect: () => {
          // The log carries no TLS flag, so the scheme is inferred from the port — the same
          // honest guess logger.tsx makes, and the same reason this says "as logged".
          const scheme = row.port === 443 ? "https" : "http";
          const authority = row.port === undefined || row.port === 80 || row.port === 443 ? row.host : `${row.host}:${row.port}`;
          void copyToClipboard(`${scheme}://${authority ?? ""}${row.path}`);
          toast.success("URL copied");
         },
        },
       ]
     : []),
   ],
  },
 ];

 if (!rows.length) {
  return <Empty title="No tool traffic" detail="Requests that burpsy itself sends — Repeater, Intruder, Scanner — are logged here." />;
 }
 return (
  <SimpleTable headers={["Age", "Tool", "Request", "Status"]}>
   {rows.map((row, index) => (
    <MenuRow key={`${row.tool}-${row.started_ms}-${index}`} groups={menuFor(row)}>
     <td>
      <span className="cell-dim">{relativeTime(row.started_ms)}</span>
     </td>
     <td>
      <Badge>{row.tool}</Badge>
     </td>
     <td title={`${row.method} ${row.path}`}>
      <code>
       {row.method} {row.path}
      </code>
     </td>
     <td>{row.status === null ? <Badge>pending</Badge> : <Badge tone={statusTone(row.status)}>{row.status}</Badge>}</td>
    </MenuRow>
   ))}
  </SimpleTable>
 );
}

// Two entry points, matching Burp's dashboard header: "New scan" starts bounded work against a
// seed, "New live task" flips the always-on sweep. The scan-type cards mirror the New scan dialog's
// first page — all four of its options (Zhw0 in the 2026.7.1 teardown): Crawl and audit, Crawl,
// Audit selected items and API-only scan. The kinds burpsy cannot run render as disabled cards that
// name *what is missing* rather than disappearing, because a missing capability silently hidden is
// the defect this UI exists to avoid — and "not built yet" is a reason no operator can act on.
//
// Two fields describe a card, because the four kinds reach the server through two different doors and
// neither field can cover both:
//
//   * `launch` is which door the card posts to at all — "crawl" for the two that seed a crawl through
//     /api/crawl, "audit" for the selection-driven one, which takes exchange ids rather than seeds and
//     posts them to /api/audit/selected, "api" for the definition-driven one, which takes a document
//     rather than seeds and posts it to /api/apiscan, and "none" for one that cannot run.
//   * `wire` is the scan kind /api/crawl is told to run, for the two that go through it.
//
// A card cannot be marked ready without a launch, so a missing capability is never a click that does
// nothing. See the Go side's scanKind, which refuses an unknown kind rather than running a plain crawl
// — the two lists therefore have to agree, and a mismatch fails loudly at the launch instead of
// producing a scan that does something else.
const SCAN_TYPES = [
 {
  id: "crawl-audit",
  title: "Crawl and audit",
  detail: "Maps the attack surface and audits what it finds.",
  ready: true,
  launch: "crawl",
  wire: "crawl-audit",
  missing: "",
 },
 {
  id: "crawl",
  title: "Crawl",
  detail: "Maps the attack surface of the web application.",
  ready: true,
  launch: "crawl",
  wire: "crawl",
  missing: "",
 },
 {
  id: "audit-selected",
  title: "Audit selected items",
  detail: "Identifies vulnerabilities in the selected items",
  ready: true,
  launch: "audit",
  wire: "",
  missing: "",
 },
 {
  id: "api",
  title: "API-only scan",
  detail: "Offers additional configuration options",
  ready: true,
  launch: "api",
  wire: "",
  missing: "",
 },
] as const;

// selectedScanType resolves the card the operator picked. A lookup rather than an index, so the
// submit button's enablement and the kind that goes on the wire come from the one description of the
// card instead of two conditions that can disagree.
function selectedScanType(id: string) {
 return SCAN_TYPES.find((scan) => scan.id === id) ?? SCAN_TYPES[0];
}

// The recorded login's account of a crawl (burpsy-react-ui-xhtk): whether it was authenticated at
// all, every replay, and what the replay's scope gate refused. A failed login is the first thing on
// it, because an unauthenticated crawl of an application behind a login maps the login page.
function CrawlLoginCard({ login }: { login: CrawlLoginReport }): JSX.Element {
 return (
  <Card>
   <SectionHeading
    title={
     !login.authenticated
      ? `The recorded login “${login.label}” failed`
      : login.verified
        ? `Logged in with “${login.label}”`
        : `“${login.label}” ran — the login was not verified`
    }
    detail={
     !login.authenticated
      ? "The replay before the first request did not log in, so this crawl ran logged out."
      : login.verified
        ? "The recorded login was replayed in an isolated browser before the first request, confirmed by its status check, and its session was carried on every request."
        : "Every step ran, but the sequence has no status check, so nothing confirmed the session was real. A rejected password looks the same."
    }
   />
   <div className="metric-grid wide">
    <Metric
     label="Replays"
     value={login.attempts}
     detail={`${login.succeeded} logged in, ${login.failed} failed`}
     tone={login.failed > 0 ? "warn" : undefined}
    />
    <Metric label="Re-logins" value={login.relogins} detail="replays run because the session was detected as lost" />
    <Metric label="Requests with the session" value={login.requests_with_session} />
    <Metric
     label="Pages found after login"
     value={login.pages_found_after_login}
     tone={login.authenticated && login.pages_found_after_login === 0 ? "warn" : undefined}
    />
   </div>
   <DetailList
    rows={[
     ...(login.last_failure ? [{ label: "Last failure", value: <span className="warn-text">{login.last_failure}</span> }] : []),
     { label: "Ended on", value: login.final_url ? <code>{login.final_url}</code> : "—" },
     { label: "Cookies earned", value: login.cookie_names.length ? login.cookie_names.join(", ") : "none" },
     {
      label: "Refused by scope",
      value: login.blocked.length ? (
       <ul className="replay-blocked">
        {login.blocked.map((line) => (
         <li key={line}>
          <code>{line}</code>
         </li>
        ))}
       </ul>
      ) : (
       "nothing"
      ),
     },
     {
      label: "Refused while rendering",
      value: login.render_blocked.length ? (
       <ul className="replay-blocked">
        {login.render_blocked.map((line) => (
         <li key={line}>
          <code>{line}</code>
         </li>
        ))}
       </ul>
      ) : (
       "nothing"
      ),
     },
    ]}
   />
  </Card>
 );
}

function NewScanModal({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }): JSX.Element {
 const startCrawl = useStartCrawl();
 const auditSelected = useAuditSelected();
 const startAPIScan = useStartAPIScan();
 // The selection the audit kind works on. It is the same store value the history table's tick column
 // writes, which is what makes "the selected items" one notion rather than two: Burp's wizard reads
 // the selection from whichever table made it, and so does this dialog.
 const checked = useApp((state) => state.checkedExchanges);
 const setRoute = useApp((state) => state.setRoute);
 // Burp's dialog opens on "Crawl and audit" — its primary workflow and the one it defaults to.
 const [kind, setKind] = useState<string>("crawl-audit");
 const [seed, setSeed] = useState("");
 // f3k: the New scan dialog takes Burp's "URLs to scan" shape — many seeds, one box
 // (Burp: "Define the URLs to scan. Burp will begin crawling from these URLs"). The wire has
 // taken an array all along; only the input was single.
 const seeds = parseSeeds(seed);
 // Burp's Protocol settings (in8j): "Scan using HTTP & HTTPS" is its default, and is what lets a seed
 // be written as a bare host.
 const [protocols, setProtocols] = useState<"both" | "specified">("both");
 // Burp's crawl scope (501u): by default "restricted to the configured URLs, ending with the final
 // directory"; the detailed configuration takes URL prefixes. Always inside the engagement scope.
 const [scopeMode, setScopeMode] = useState<"seed_directories" | "engagement" | "prefixes">("seed_directories");
 const [scopeInclude, setScopeInclude] = useState("");
 // Burp's "Run isolated scan" (13uw): results stay out of the site map and All issues.
 const [isolated, setIsolated] = useState(false);
 const [scopeExclude, setScopeExclude] = useState("");
 const [maxRequests, setMaxRequests] = useState("50");
 const [maxDepth, setMaxDepth] = useState("5");
 const [maxDuration, setMaxDuration] = useState("");
 // The recorded login the crawl logs in with (burpsy-react-ui-xhtk); "" is none.
 const [recordedLogin, setRecordedLogin] = useState("");
 // The API-only scan's own inputs. `definitionName` is only ever a label — it is what the operator
 // picked or pasted from, shown so a pasted document and an uploaded one are distinguishable after
 // the fact — and never travels to the server, which reads the bytes and not the filename.
 const [definition, setDefinition] = useState("");
 const [definitionName, setDefinitionName] = useState("");
 // Upload from URL (fu4l): whether the URL panel is open, and what the dialog has to say about a
 // fetched document the scan cannot read (WSDL, an HTML login page) — null for a readable one.
 const [fromUrlOpen, setFromUrlOpen] = useState(false);
 const [fetchedNote, setFetchedNote] = useState<string | null>(null);
 const [baseUrl, setBaseUrl] = useState("");
 // Its own cap, empty by default. Sharing the crawl card's "50" would cap a definition sweep at fifty
 // endpoints without the operator asking, and the server's default for this card is the document's own
 // count — the honest reading of "scan these endpoints".
 const [apiMaxRequests, setApiMaxRequests] = useState("");
 // On by default, because this card is "API-only *scan*": the sweep is the seed and the audit is the
 // scan. Turning it off is the operator asking for the endpoint sweep alone, which is a real thing to
 // want ("what does my API do with its own documented requests") and not the default.
 const [auditEndpoints, setAuditEndpoints] = useState(true);
 const definitionFileRef = useRef<HTMLInputElement>(null);
 // The server reads the document, decides the host and resolves every operation before answering, so
 // what this renders is the same parse the launch will use. See useAPIScanCheck for why it is a POST
 // behind a query hook rather than a second validate route.
 const scanCheck = useAPIScanCheck(definition, baseUrl);
 // The API-details review step (burpsy-react-ui-vuw7). Built against the unreviewed parse, so a
 // removed endpoint stays listed and a parameter's document value stays beside its override; the
 // reviewed dry run below is the server's verdict on the review itself.
 const [review, setReview] = useState<ReviewState>(emptyReview);
 const operations = scanCheck.data?.definition.operations ?? [];
 const builtReview = buildReview(operations, review);
 const reviewChanges = reviewChangesRequest(builtReview.fields);
 const reviewCheck = useAPIScanReviewCheck(
  definition,
  baseUrl,
  builtReview.fields,
  scanCheck.data !== undefined && reviewChanges && builtReview.missing === null,
 );
 const reviewedPaths =
  reviewChanges && reviewCheck.check.data ? new Map(reviewCheck.check.data.definition.operations.map((op) => [op.key, op.path])) : null;
 const reviewedCount = operations.length - (builtReview.fields.exclude_endpoints?.length ?? 0);
 // Why the API launch cannot go yet, in the operator's terms; null when it can.
 const apiMissing =
  definition.trim() === ""
   ? "Paste or load an API definition first."
   : scanCheck.data === undefined
     ? scanCheck.error
      ? "The definition was refused; see the message above."
      : "Reading the definition…"
     : (builtReview.missing ??
       (reviewChanges && reviewCheck.check.error
        ? "The review was refused; see the message above."
        : reviewChanges && (!reviewCheck.settled || reviewCheck.check.data === undefined)
          ? "Checking the review…"
          : startAPIScan.isPending
            ? "Starting…"
            : null));

 const chosen = selectedScanType(kind);
 const close = () => onOpenChange(false);
 const auditing = chosen.launch === "audit";
 const apiScan = chosen.launch === "api";
 const canSubmit = auditing
  ? checked.length > 0 && !auditSelected.isPending
  : apiScan
    ? apiMissing === null
    : chosen.ready && seed.trim() !== "" && !startCrawl.isPending;
 const submit = () => {
  if (apiScan) {
   // The check already passed on this exact text and this exact review, so the launch cannot be
   // refused for a reason the operator was not shown — every call runs the server's one
   // prepareAPIScan. The dialog stays open until the server accepts, so a refusal that does happen
   // (the scope changed in between) is read beside the review that caused it, not in a toast alone.
   startAPIScan.mutate(
    {
     definition,
     base_url: baseUrl.trim() || undefined,
     audit: auditEndpoints,
     max_requests: Number(apiMaxRequests) || undefined,
     ...builtReview.fields,
    },
    {
     onSuccess: (accepted) => {
      const endpoints = accepted.definition.operations.length;
      toast.success(
       `${accepted.audit ? "API scan" : "API sweep"} started over ${endpoints} endpoint${endpoints === 1 ? "" : "s"}` +
        (accepted.definition.placeholder_values > 0 ? ` (${accepted.definition.placeholder_note})` : ""),
      );
      // The credential is not kept past the launch that needed it; the endpoint and parameter
      // choices are, so a second scan of the same document starts from the same review.
      setReview((current) => ({ ...current, auth: { type: "none" } }));
      close();
     },
     onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Starting the API scan failed"),
    },
   );
   return;
  }
  // The selection kind takes ids, not seeds, so it goes to /api/audit/selected and there is no crawl
  // to message about. The count in the toast is the reply's own — the server drops repeated ids and
  // says so — rather than the tick count, which is what the operator sees rather than what ran.
  if (auditing) {
   auditSelected.mutate(
    { exchange_ids: [...checked] },
    {
     onSuccess: (reply) =>
      toast.success(
       reply.duplicates_dropped > 0
        ? `Audit started over ${reply.count} selected item${reply.count === 1 ? "" : "s"} (${reply.duplicates_dropped} repeated id${reply.duplicates_dropped === 1 ? "" : "s"} dropped)`
        : `Audit started over ${reply.count} selected item${reply.count === 1 ? "" : "s"}`,
      ),
     onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Starting the audit failed"),
    },
   );
   close();
   return;
  }
  // The kind travels with the seeds, so the server runs what the card said it would. The success
  // message names the scan that started rather than always "Crawl": a crawl-and-audit's audit phase
  // produces findings minutes after the crawl task finishes, and a toast that called it a crawl
  // would leave the operator with nothing to connect them to.
  const verb = chosen.id === "crawl-audit" ? "Crawl and audit" : "Crawl";
  startCrawl.mutate(
   {
    seeds,
    kind: chosen.wire,
    protocols,
    isolated: isolated || undefined,
    scope: {
     mode: scopeMode,
     include: scopeMode === "prefixes" ? parseSeeds(scopeInclude) : undefined,
     exclude: scopeMode !== "engagement" ? parseSeeds(scopeExclude) : undefined,
    },
    max_requests: Number(maxRequests) || undefined,
    max_depth: Number(maxDepth) || undefined,
    max_duration_secs: Number(maxDuration) || undefined,
    recorded_login: recordedLogin || undefined,
   },
   {
    onSuccess: (started) => {
     // Seeds the scope refused (us6r.3): the crawl runs from the rest, and the operator is told which
     // were left out and why, instead of the run silently being smaller than what was typed.
     const refused = started.out_of_scope_seeds ?? [];
     if (refused.length) {
      toast.warning(
       `${verb} started without ${refused.length} out-of-scope URL(s): ${refused.map((r) => `${r.url} — ${r.reason}`).join("; ")}`,
      );
     } else {
      toast.success(`${verb} started on ${seed.trim()}`);
     }
    },
    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : `Starting the ${verb.toLowerCase()} failed`),
   },
  );
  close();
 };

 return (
  <Modal
   open={open}
   onOpenChange={onOpenChange}
   title="New scan"
   wide
   description="Select the type of scan to run. It registers as a task below, with progress and a cancel button."
  >
   <div className="stack">
    <h3 className="subheading">Scan type</h3>
    <div className="scan-type-grid">
     {SCAN_TYPES.map((scan) => (
      <button
       key={scan.id}
       type="button"
       className={`scan-type-card ${kind === scan.id ? "scan-type-selected" : ""}`}
       disabled={!scan.ready}
       onClick={() => setKind(scan.id)}
      >
       <strong>{scan.title}</strong>
       <span>{scan.detail}</span>
       {!scan.ready ? <small className="cell-dim">{scan.missing}</small> : null}
      </button>
     ))}
    </div>
    {auditing ? (
     <>
      <p className="cell-dim" style={{ margin: 0 }}>
       Scans the items ticked in HTTP history, as one task. Burp takes its selection from the table you are looking at, and so does this —
       the ticks are the selection, and the scan is over exactly those rows.
      </p>
      <div className="metric-grid wide">
       <Metric
        label="Selected items"
        value={checked.length}
        tone={checked.length === 0 ? "warn" : undefined}
        detail={
         checked.length === 0
          ? "Nothing is ticked. Tick the rows you mean in HTTP history, then reopen this dialog — a launch with no selection is refused, because an audit of nothing is not a scan."
          : `Exactly these ${checked.length} exchange${checked.length === 1 ? "" : "s"} will be audited, and nothing else in the capture.`
        }
       />
      </div>
      {checked.length === 0 ? (
       <Button
        variant="outline"
        size="small"
        onClick={() => {
         // Leaves the dialog open: the operator is being sent somewhere to make a selection, and
         // closing behind them would lose the scan type they picked.
         setRoute("history");
         close();
        }}
       >
        Go to HTTP history
       </Button>
      ) : null}
     </>
    ) : apiScan ? (
     <>
      <p className="cell-dim" style={{ margin: 0 }}>
       Sends the endpoints an API definition describes, instead of discovering them by crawling. The document's own examples, defaults and
       enums become the parameter values where it supplies them; where it does not, this build invents visible placeholders and says how
       many below.
      </p>
      <Field
       label="API definition"
       hint="OpenAPI 3.x, Swagger 2.0 or a Postman Collection (v2.x), in JSON or YAML. Paste it here, load the file, or fetch it from a URL."
      >
       {(id) => (
        <Textarea
         id={id}
         value={definition}
         onChange={(event) => {
          setDefinition(event.target.value);
          // Cleared rather than kept: the box no longer holds the file, and a label naming a file
          // whose contents have since been edited would be a caption that disagrees with the box.
          setDefinitionName("");
          setFetchedNote(null);
         }}
         rows={7}
         placeholder={
          'openapi: "3.0.3"\ninfo: {title: Petstore, version: "1.0.2"}\nservers: [{url: https://api.example.com/v1}]\npaths:\n  /pets:\n    get:\n      responses: {"200": {description: ok}}'
         }
         aria-label="API definition"
        />
       )}
      </Field>
      <div className="toolbar">
       <Button variant="outline" size="small" onClick={() => definitionFileRef.current?.click()}>
        Load from file
       </Button>
       <Button variant="outline" size="small" aria-expanded={fromUrlOpen} onClick={() => setFromUrlOpen((open) => !open)}>
        Load from URL
       </Button>
       {definitionName ? <span className="cell-dim">{definitionName}</span> : null}
       {definition ? (
        <Button
         variant="outline"
         size="small"
         onClick={() => {
          setDefinition("");
          setDefinitionName("");
          setFetchedNote(null);
          setReview(emptyReview);
         }}
        >
         Clear
        </Button>
       ) : null}
       <input
        ref={definitionFileRef}
        type="file"
        accept=".json,.yaml,.yml,text/yaml,application/json"
        className="sr-only"
        aria-hidden="true"
        tabIndex={-1}
        onChange={(event) => {
         const file = event.target.files?.[0];
         // Cleared so re-picking the same file fires change again: an edited document saved over the
         // same path is an ordinary way to fix a line the check refused.
         event.target.value = "";
         if (!file) return;
         void file.text().then((text) => {
          setDefinition(text);
          setDefinitionName(file.name);
          setFetchedNote(null);
         });
        }}
       />
      </div>
      {fromUrlOpen ? (
       <APIScanFetchFromURL
        onLoaded={(fetched) => {
         setDefinition(fetched.definition);
         setDefinitionName(fetchedCaption(fetched));
         setFetchedNote(fetchedWarning(fetched));
         setFromUrlOpen(false);
        }}
       />
      ) : null}
      {fetchedNote ? (
       <div className="notice notice-warn" role="status">
        {fetchedNote}
       </div>
      ) : null}
      <Field
       label="Base URL (optional)"
       hint="Overrides the document's own servers[0]. Required when the document declares no server, or a relative one — a pasted document has no host of its own to be relative to."
      >
       {(id) => (
        <Input id={id} value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://api.example.com/v1" />
       )}
      </Field>
      {definition.trim() === "" ? (
       <p className="cell-dim" style={{ margin: 0 }}>
        Nothing to scan yet. As soon as the document is in the box above, it is read here — endpoint count, the host the paths resolve
        against, and how many of its values this build would have to invent.
       </p>
      ) : scanCheck.error ? (
       // Rendered as advice rather than as a query failure: while someone is editing a document, a
       // refusal is the expected state, and the server's message names what the file actually is.
       <ErrorNotice error={scanCheck.error} title="This document cannot be read" />
      ) : scanCheck.data ? (
       <>
        <div className="metric-grid wide">
         <Metric
          label="Endpoints"
          value={scanCheck.data.definition.operations.length}
          detail={
           scanCheck.data.definition.title
            ? `${scanCheck.data.definition.title}${scanCheck.data.definition.version ? ` ${scanCheck.data.definition.version}` : ""}, ${scanCheck.data.definition.format} ${scanCheck.data.definition.spec_version}`
            : `${scanCheck.data.definition.format} ${scanCheck.data.definition.spec_version}`
          }
         />
         <Metric
          label="Values invented"
          value={`${scanCheck.data.definition.placeholder_values} / ${scanCheck.data.definition.declared_values}`}
          tone={scanCheck.data.definition.placeholder_values > 0 ? "warn" : undefined}
          detail={scanCheck.data.definition.placeholder_note}
         />
        </div>
        <p className="cell-dim" style={{ margin: 0 }}>
         Base URL <code>{scanCheck.data.definition.base_url}</code>. Every request is re-authorised against the current scope before it is
         sent, exactly as a crawl's is.
        </p>
        <APIScanReview
         operations={operations}
         format={scanCheck.data.definition.format}
         state={review}
         onChange={setReview}
         reviewedPaths={reviewedPaths}
        />
        {builtReview.stale.length > 0 ? (
         <div className="warn-text" role="status">
          <p style={{ margin: 0 }}>
           {builtReview.stale.length === 1 ? "1 review row no longer matches" : `${builtReview.stale.length} review rows no longer match`}{" "}
           the edited definition and will not be sent: {builtReview.stale.join("; ")}.
          </p>
          <Button variant="outline" size="small" onClick={() => setReview(discardStale(operations, review))}>
           Discard them
          </Button>
         </div>
        ) : null}
        {reviewChanges && reviewCheck.check.error ? (
         <ErrorNotice error={reviewCheck.check.error} title="The server refused this review" />
        ) : null}
       </>
      ) : (
       <p className="cell-dim" style={{ margin: 0 }}>
        Reading the document…
       </p>
      )}
      <div className="metric-grid wide">
       <Field
        label="Max requests (empty = one per endpoint)"
        hint="A cap below the document's endpoint count sends a prefix of the list, and the report says how many were never sent."
       >
        {(id) => (
         <Input
          id={id}
          type="number"
          min={1}
          value={apiMaxRequests}
          onChange={(event) => setApiMaxRequests(event.target.value)}
          placeholder={scanCheck.data ? String(reviewedCount) : ""}
         />
        )}
       </Field>
      </div>
      <div className="task-tile-row">
       <span>Audit the endpoints once they have been fetched</span>
       <Switch checked={auditEndpoints} label="Audit the API scan's endpoints" onCheckedChange={setAuditEndpoints} />
      </div>
      <p className="cell-dim" style={{ margin: 0 }}>
       {auditEndpoints
        ? "Two tasks appear below: the sweep, then a separate audit of the exchanges it fetched — the same audit half a crawl-and-audit runs."
        : "One task appears below: the endpoints are sent and captured, and nothing is audited. The traffic still lands in HTTP history and is still scanned passively."}
      </p>
     </>
    ) : chosen.ready ? (
     <>
      <Field label="URLs to scan" hint="One per line, or comma separated — Burp's own field is many URLs in one box.">
       {(id) => (
        <Input
         id={id}
         value={seed}
         onChange={(event) => setSeed(event.target.value)}
         placeholder={"https://demo.local/\nhttps://api.demo.local/"}
        />
       )}
      </Field>
      <div role="radiogroup" aria-label="Crawl scope">
       {(
        [
         ["seed_directories", "Restrict to the URLs' directories", "Burp's default: each URL's final directory"],
         ["engagement", "Use the engagement scope", "everything the project scope allows"],
         ["prefixes", "Detailed scope configuration", "URL prefixes to include and exclude"],
        ] as const
       ).map(([value, label, hint]) => (
        <label key={value} style={{ display: "flex", alignItems: "center", gap: "var(--s1)", margin: "var(--s1) 0" }}>
         <input type="radio" name="crawl-scope" checked={scopeMode === value} onChange={() => setScopeMode(value)} />
         <span>
          {label} <span className="field-hint">— {hint}</span>
         </span>
        </label>
       ))}
      </div>
      {scopeMode === "prefixes" ? (
       <Field label="Include URL prefixes" hint="One per line; the crawl stays under these.">
        {(id) => (
         <Input
          id={id}
          value={scopeInclude}
          onChange={(event) => setScopeInclude(event.target.value)}
          placeholder="https://demo.local/app/"
         />
        )}
       </Field>
      ) : null}
      {scopeMode !== "engagement" ? (
       <Field label="Exclude URL prefixes" hint="Optional; never requested even when included.">
        {(id) => (
         <Input
          id={id}
          value={scopeExclude}
          onChange={(event) => setScopeExclude(event.target.value)}
          placeholder="https://demo.local/app/logout"
         />
        )}
       </Field>
      ) : null}
      <label style={{ display: "flex", alignItems: "center", gap: "var(--s1)", margin: "var(--s1) 0" }}>
       <input type="checkbox" checked={isolated} onChange={(event) => setIsolated(event.target.checked)} />
       <span>
        Run isolated scan{" "}
        <span className="field-hint">— its locations and issues stay out of the site map and All issues; the task still shows them</span>
       </span>
      </label>
      <div role="radiogroup" aria-label="Protocol settings">
       {(
        [
         ["both", "Scan using HTTP & HTTPS", "each URL is crawled over both schemes; a URL may be written as a bare host"],
         ["specified", "Scan using my specified protocols", "each URL over the scheme it names"],
        ] as const
       ).map(([value, label, hint]) => (
        <label key={value} style={{ display: "flex", alignItems: "center", gap: "var(--s1)", margin: "var(--s1) 0" }}>
         <input type="radio" name="scan-protocols" checked={protocols === value} onChange={() => setProtocols(value)} />
         <span>
          {label} <span className="field-hint">— {hint}</span>
         </span>
        </label>
       ))}
      </div>
      {chosen.id === "crawl-audit" ? (
       <p className="cell-dim" style={{ margin: 0 }}>
        Two tasks appear below: the crawl, then a separate audit of the exchanges it fetched. The audit starts when the crawl finishes, and
        its own row reports the checks it could not run — a bounded sweep is never shown as a clean one.
       </p>
      ) : null}
      <div className="metric-grid wide">
       <Field label="Max requests (empty = uncapped)">
        {(id) => <Input id={id} type="number" min={1} value={maxRequests} onChange={(event) => setMaxRequests(event.target.value)} />}
       </Field>
       <Field label="Max depth">
        {(id) => <Input id={id} type="number" min={1} value={maxDepth} onChange={(event) => setMaxDepth(event.target.value)} />}
       </Field>
       <Field label="Max duration (seconds)">
        {(id) => (
         <Input
          id={id}
          type="number"
          min={1}
          value={maxDuration}
          onChange={(event) => setMaxDuration(event.target.value)}
          placeholder="uncapped"
         />
        )}
       </Field>
      </div>
      <RecordedLoginPicker value={recordedLogin} onChange={setRecordedLogin} />
     </>
    ) : null}
    {apiScan && startAPIScan.error ? <ErrorNotice error={startAPIScan.error} title="The API scan was not started" /> : null}
    <div className="toolbar-end">
     <Button variant="outline" size="small" onClick={close}>
      Cancel
     </Button>
     {apiScan ? (
      <NeedsValueButton size="small" missing={apiMissing} onClick={submit}>
       {`Scan ${reviewedCount} endpoint${reviewedCount === 1 ? "" : "s"}`}
      </NeedsValueButton>
     ) : (
      <Button size="small" disabled={!canSubmit} onClick={submit}>
       {auditing ? "Audit selected items" : "Start"}
      </Button>
     )}
    </div>
   </div>
  </Modal>
 );
}

// The live task's own dialog: one Capturing switch and the optional scope filter, mirroring Burp's
// "Live audit from Proxy (all traffic)" task configuration panel. Family switches are global —
// they live in Settings → Audit checks — so this panel points there instead of pretending to
// carry a per-task check set burpsy does not have.
function NewLiveTaskModal({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }): JSX.Element {
 const setLive = useSetScannerLive();
 const [query, setQuery] = useState("");
 // Burp's live task Scan configuration and Resource pool tabs (chct).
 const configs = useScannerConfigs();
 const pools = usePools();
 const [config, setConfig] = useState("");
 const [poolName, setPoolName] = useState("");
 const close = () => onOpenChange(false);

 return (
  <Modal
   open={open}
   onOpenChange={onOpenChange}
   title="New live task"
   description="Audit proxied traffic as it arrives. The sweep registers as a task below."
  >
   <div className="stack">
    <Field label="Scope filter query (optional)">
     {(id) => <Input id={id} value={query} onChange={(event) => setQuery(event.target.value)} placeholder='host == "demo.local"' />}
    </Field>
    <Field label="Scan configuration">
     {(id) => (
      <Select id={id} value={config} onChange={(event) => setConfig(event.target.value)}>
       <option value="">Server default (Settings → Audit checks)</option>
       {(configs.data?.configs ?? []).map((c) => (
        <option key={c.name} value={c.name}>
         {c.name}
        </option>
       ))}
      </Select>
     )}
    </Field>
    <Field label="Resource pool">
     {(id) => (
      <Select id={id} value={poolName} onChange={(event) => setPoolName(event.target.value)}>
       <option value="">Global pace</option>
       {(pools.data?.pools ?? []).map((p) => (
        <option key={p.name} value={p.name}>
         {p.name}
        </option>
       ))}
      </Select>
     )}
    </Field>
    <div className="toolbar-end">
     <Button variant="outline" size="small" onClick={close}>
      Cancel
     </Button>
     <Button
      size="small"
      disabled={setLive.isPending}
      onClick={() => {
       setLive.mutate(
        { enabled: true, query: query.trim() || undefined, config, pool: poolName },
        {
         onSuccess: () => toast.success("Live audit sweep enabled"),
         onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Enabling the live sweep failed"),
        },
       );
       close();
      }}
     >
      Start
     </Button>
    </div>
   </div>
  </Modal>
 );
}

export function DashboardPage(): JSX.Element {
 const { data, error, isFetching, refetch } = useDashboard();
 const issues = useIssues();
 const live = useScannerLive();
 const setRoute = useApp((state) => state.setRoute);
 const setHistoryQuery = useApp((state) => state.setHistoryQuery);
 const [scanOpen, setScanOpen] = useState(false);
 const [liveOpen, setLiveOpen] = useState(false);
 // Which task tile is open in the right pane. Null means "first tile" — the same default Burp
 // applies, where the newest task is selected without a click.
 const [selectedId, setSelectedId] = useState<number | null>(null);

 const sources = useMemo(() => Object.entries(data?.sources ?? {}).sort((a, b) => b[1] - a[1]), [data?.sources]);
 const liveEnabled = live.data?.enabled === true;
 const liveFindings = live.data?.findings;
 const tasks = withStandingLiveTask(data?.tasks ?? [], liveEnabled);
 const selected = tasks.find((task) => task.id === selectedId) ?? tasks[0] ?? null;

 if (error) {
  return (
   <div className="page">
    <PageHeader title="Dashboard" />
    <ErrorNotice error={error} onRetry={() => void refetch()} />
   </div>
  );
 }

 return (
  <div className="page page-flush">
   <PageHeader
    title="Dashboard"
    description="Running work on the left; the selected task's outcome and coverage on the right."
    actions={<RefreshButton onClick={() => void refetch()} loading={isFetching} />}
   />

   <SplitPane
    storageId="dashboard-tasks"
    orientation="horizontal"
    defaultMasterSize="34"
    minMasterSize="22"
    master={
     <TaskSidebar
      tasks={data?.tasks ?? []}
      liveFindings={liveFindings}
      liveEnabled={liveEnabled}
      pausedState={data?.paused}
      selectedId={selected?.id ?? null}
      onSelect={setSelectedId}
      onNewScan={() => setScanOpen(true)}
      onNewLive={() => setLiveOpen(true)}
     />
    }
    detail={
     selected ? (
      <TaskDetail
       task={selected}
       tasks={data?.tasks ?? []}
       liveFindings={liveFindings}
       liveEnabled={liveEnabled}
       issuesEnabled={issues.data?.enabled === true}
       summaries={data?.summaries ?? []}
       sources={sources}
       events={data?.events ?? []}
       eventWindow={{
        shown: data?.events_shown ?? data?.events?.length ?? 0,
        total: data?.events_total ?? data?.events?.length ?? 0,
        dropped: data?.events_dropped ?? 0,
       }}
       activity={data?.activity ?? []}
       onFilterHistory={(query) => {
        setHistoryQuery(query);
        setRoute("history");
       }}
      />
     ) : (
      <Empty
       title="No tasks"
       detail="Real-time information on your scans and live tasks is displayed here. Start a new scan or live task to populate this page."
      />
     )
    }
   />

   <NewScanModal open={scanOpen} onOpenChange={setScanOpen} />
   <NewLiveTaskModal open={liveOpen} onOpenChange={setLiveOpen} />
  </div>
 );
}

/**
 * The event log, filterable by severity, searchable, and with a Source column (burpsy-react-ui-lxqq).
 *
 * It sits in a task's pane but holds the whole log — scope edits and live-audit switches belong to
 * no task, and hiding them under whichever task happens to be selected would lose them. So Source
 * is a filter as well as a column: "This task" narrows to the selected task's own events, and the
 * column is dropped then, because every row would say the same thing.
 */
function EventLogPanel({
 events,
 tasks,
 task,
 eventWindow,
}: {
 events: ToolEvent[];
 tasks: TaskRow[];
 task: TaskRow;
 eventWindow: { shown: number; total: number; dropped: number };
}): JSX.Element {
 const clearEvents = useClearEventLog();
 const [severity, setSeverity] = useState<EventSeverityFilter>("all");
 const [search, setSearch] = useState("");
 // "task" rather than the id itself, so selecting another task re-targets the filter instead of
 // leaving it pinned to a task that is no longer the one on screen. The synthetic live-audit row
 // (id -1) owns no events — the sweep records with no task id — so it is not offered there.
 const [sourceScope, setSourceScope] = useState<"all" | "task">("all");
 const taskScoped = sourceScope === "task" && task.id > 0;
 const filter: EventLogFilter = { severity, search, source: taskScoped ? task.id : "all" };
 const visible = filterEvents(events, filter, tasks);
 const counts = severityCounts(events);
 const showSource = !taskScoped;
 return (
  <>
   {/*
    * The feed used to render events.slice(0, 20): rows 21 and beyond were dropped on the floor
    * with nothing saying so, which is the half of burpsy-react-ui-voc that made the log unable
    * to answer "what happened". Every row the server sends is now rendered, and the window is
    * stated from the server's own counters rather than re-derived here. The real bound is the
    * EventLog's, which already counts what it discarded — a second, silent cap in the browser
    * could only disagree with it. The filters below narrow what is shown, and say so.
    */}
   <SectionHeading
    title="Event log"
    detail={
     eventWindow.dropped > 0
      ? `State changes that are not requests. Showing all ${eventWindow.shown} the log holds; ${eventWindow.dropped} older event(s) have been discarded as it filled.`
      : "State changes that are not requests. The log shows key task events, such as start times, alerts, and progress updates."
    }
    actions={
     <Button variant="outline" disabled={!events.length || clearEvents.isPending} onClick={() => clearEvents.mutate()}>
      {clearEvents.isPending ? "Clearing…" : "Clear event log"}
     </Button>
    }
   />
   {events.length ? (
    <Toolbar className="event-filters">
     <Field label="Severity" className="field-inline">
      {(id) => (
       <Select id={id} value={severity} onChange={(event) => setSeverity(event.target.value as EventSeverityFilter)}>
        {EVENT_SEVERITY_OPTIONS.map((option) => (
         <option key={option.value} value={option.value}>
          {option.value === "all" ? `${option.label} (${events.length})` : `${option.label} (${counts[option.value]})`}
         </option>
        ))}
       </Select>
      )}
     </Field>
     <Field label="Source" className="field-inline">
      {(id) => (
       <Select id={id} value={taskScoped ? "task" : "all"} onChange={(event) => setSourceScope(event.target.value as "all" | "task")}>
        <option value="all">All sources</option>
        {task.id > 0 ? <option value="task">This task (Task {task.id})</option> : null}
       </Select>
      )}
     </Field>
     <Field label="Search" className="field-inline">
      {(id) => (
       <Input
        id={id}
        type="search"
        value={search}
        onChange={(event) => setSearch(event.target.value)}
        placeholder="kind, detail or source…"
        style={{ maxWidth: "var(--w-md)" }}
       />
      )}
     </Field>
     {isFiltered(filter) ? (
      <span className="cell-dim" role="status">
       {visible.length} of {events.length} shown
      </span>
     ) : null}
    </Toolbar>
   ) : null}
   {!events.length ? (
    <Empty
     title="No event log items to show"
     detail="The event log shows key task events, such as start times, alerts, and progress updates."
    />
   ) : !visible.length ? (
    // Distinct from the empty log: the events are still there, the filters are narrower than them.
    <Empty
     title="No event matches these filters"
     detail={`All ${events.length} events are still in the log. Widen or clear the severity, source or search to see them.`}
     action={
      <Button
       variant="outline"
       size="small"
       onClick={() => {
        setSeverity("all");
        setSearch("");
        setSourceScope("all");
       }}
      >
       Clear filters
      </Button>
     }
    />
   ) : (
    <div className="event-list event-list-scroll">
     {visible.map((event, index) => (
      <div className={showSource ? "event-row event-row-sourced" : "event-row"} key={event.id ?? `${event.kind}-${event.at_ms}-${index}`}>
       <span className={`event-dot event-${event.severity}`} title={event.severity} />
       <div>
        <strong>{event.kind}</strong>
        <p>{event.detail}</p>
       </div>
       {showSource ? <span className="event-source">{eventSource(event, tasks)}</span> : null}
       <time title={new Date(event.at_ms).toLocaleString()}>{relativeTime(event.at_ms)}</time>
      </div>
     ))}
    </div>
   )}
  </>
 );
}

/** One task's detail pane: header, Summary / Event log tabs, then the tab's content. Burp keeps
 * the task's own facts (configuration, progress) on Summary and everything the task produced
 * (issues, events) on the later tabs; the same split, with burpsy's equivalents in each. */
function TaskDetail({
 task,
 tasks,
 liveFindings,
 liveEnabled,
 issuesEnabled,
 summaries,
 sources,
 events,
 eventWindow,
 activity,
 onFilterHistory,
}: {
 task: TaskRow;
 tasks: TaskRow[];
 liveFindings?: number;
 liveEnabled: boolean;
 issuesEnabled: boolean;
 summaries: CoverageSummary[];
 sources: [string, number][];
 events: ToolEvent[];
 eventWindow: { shown: number; total: number; dropped: number };
 activity: ActivityRow[];
 onFilterHistory: (query: string) => void;
}): JSX.Element {
 const cancel = useCancelTask();
 const setLive = useSetScannerLive();
 // The same cache key the Issues page reads, so a finding that arrives mid-scan is here on the
 // next render without a second request. Reverse-chronological by id: the store is a dense counter
 // from zero, so higher id == raised later — the feed's whole point (burpsy-react-ui-i18).
 // With isolated scans' findings (13uw): a task's own view shows what it found even when the run
 // was isolated from All issues and the site map.
 const issuesDetailed = useIssuesDetailedWithIsolated();
 // The retained run behind this task, when there is one. Only an API scan's row carries anything the
 // detail pane does not already have (its definition), and the request is made for every kind anyway
 // because which kinds have a run is not something the console should have to predict — a crawl
 // answers with its own run, and the card simply does not render for it.
 const run = useCrawlRun(task.id > 0 ? task.id : null);
 const focusIssue = useApp((state) => state.focusIssue);
 const setRoute = useApp((state) => state.setRoute);
 // Scoped to THIS task, through the tested module rather than a filter inline here
 // (burpsy-react-ui-xwxd). The tab sits beside a task's name and answers "what did that scan
 // find?"; it was the project-wide feed sorted and capped, which fails in two directions at once —
 // a task that found nothing showing other runs' findings under its own name, and a busy task
 // dropping its own older findings to the 20-cap while showing newer ones it never raised.
 const { shown: activityFindings, hidden: activityHidden } = taskActivityFindings(issuesDetailed.data?.findings ?? [], task.id);
 const openAdvisory = (finding: FindingDetail) => {
  // The Issues page is where an advisory opens; landing there with the finding selected is the
  // "way in" this feed exists to provide — the same focus mechanism History's focusExchange uses.
  focusIssue(finding.id);
  setRoute("scanner");
 };
 const title = task.kind === "live audit" ? "Live audit from Proxy (all traffic)" : `${task.kind} (${task.target})`;
 // Burp's "Live crawl view" tab, on a crawl's own detail (burpsy-react-ui-1l3x). An API-only scan
 // shares the run registry but does not crawl, so it gets no tab.
 const isCrawlRun = run.data !== undefined && run.data.kind !== "api-scan";

 return (
  <div className="task-detail">
   <div className="task-detail-head">
    <h2>{title}</h2>
    <div className="task-detail-actions">
     <TaskPauseButton task={task} />
     {task.id !== -1 && task.cancellable && task.state === "running" ? (
      <IconButton
       label={`Cancel ${task.kind} task on ${task.target}`}
       size="small"
       disabled={cancel.isPending}
       onClick={() => cancel.mutate(task.id)}
      >
       <Square size={12} />
      </IconButton>
     ) : null}
    </div>
   </div>

   <Tabs defaultValue="summary">
    <TabsList>
     <TabsTrigger value="summary">Summary</TabsTrigger>
     <TabsTrigger value="issue-activity">Issue activity</TabsTrigger>
     <TabsTrigger value="events">Event log</TabsTrigger>
     <TabsTrigger value="activity">Activity</TabsTrigger>
     {isCrawlRun ? <TabsTrigger value="live-crawl">Live crawl view</TabsTrigger> : null}
    </TabsList>
    {isCrawlRun ? (
     <TabsContent value="live-crawl">
      <CrawlLiveView taskId={task.id} />
     </TabsContent>
    ) : null}

    <TabsContent value="issue-activity">
     <Card>
      <SectionHeading
       title="Issue activity"
       detail="Findings THIS task raised, newest first. Each opens its advisory on the Issues page."
      />
      {/* The fourth column shows the finding id — order in a dense counter, not a timestamp
          (FindingDetail carries no time), so the header must not say "Age". */}
      {activityFindings.length ? (
       <SimpleTable headers={["Severity", "Issue", "Host", "ID", ""]}>
        {activityFindings.map((finding) => (
         <MenuRow
          key={finding.id}
          groups={[
           {
            id: "open",
            actions: [
             {
              id: "open-advisory",
              label: "Open advisory",
              onSelect: () => openAdvisory(finding),
             },
            ],
           },
          ]}
         >
          <td>
           <Badge tone={severityTone(finding.severity)}>{finding.severity}</Badge>
          </td>
          <td title={finding.detail ?? undefined}>
           {finding.issue_name ?? finding.check_name ?? "Unnamed finding"}
           {finding.times_seen > 1 ? <span className="cell-dim"> ×{finding.times_seen}</span> : null}
          </td>
          <td>{finding.host}</td>
          <td className="cell-dim">#{finding.id}</td>
          <td>
           <Button variant="outline" size="small" onClick={() => openAdvisory(finding)}>
            Open
           </Button>
          </td>
         </MenuRow>
        ))}
       </SimpleTable>
      ) : (
       /* Task-scoped, and it says so. This used to fall back to the project feed, so a scan that
          found nothing displayed other runs' findings under its own name — the tab's whole
          question is "what did THIS task find", and answering it with the project's answer is the
          attribution failure this bead is about. An empty state scoped to the task is a fact. */
       <Empty
        title="This task recorded no issues"
        detail={
         issuesEnabled
          ? "Nothing was raised against this run. The Issues page carries every finding in the project, including the ones this task did not raise."
          : "Nothing was raised against this run, and the scanner is disabled — so findings elsewhere are historical and none of them are this task's."
        }
       />
      )}
      {/* A cap that reads as a total is the same defect one level up, so the pane says which it is. */}
      {activityHidden > 0 ? (
       <p className="field-hint">
        Showing the {activityFindings.length} newest of {activityFindings.length + activityHidden} this task raised. The rest are on the
        Issues page.
       </p>
      ) : null}
     </Card>
    </TabsContent>

    <TabsContent value="summary">
     <div className="task-detail-grid">
      <Card>
       <SectionHeading
        title="Findings"
        detail={
         issuesEnabled
          ? "What this task and the live sweep have reported so far."
          : "The scanner is disabled; findings below are historical."
        }
       />
       <div className="metric-grid wide">
        <Metric
         accent
         label="Findings"
         value={
          task.kind === "live audit"
           ? (liveFindings ?? 0)
           : Number(/([\d,]+)/.exec(task.result?.summary ?? "")?.[1]?.replace(/,/g, "") ?? 0) || 0
         }
         detail={task.kind === "live audit" ? "live audit sweep" : "recorded by this task"}
        />
        {/* burpsy-react-ui-uxi, the derivable half: requests done and the average rate are both
            facts the task row already carries — done over elapsed seconds — so neither is invented.
            The rate is a whole-task average, not a live window; saying so keeps it from reading as
            an instantaneous measurement. Byte transfer is deliberately absent: nothing on any egress
            path accounts bytes per task, and a metric nobody measures is a number somebody made up. */}
        <Metric label="Requests" value={task.done.toLocaleString()} detail="sent by this task" />
        <Metric label="Elapsed" value={formatDuration(task.elapsed_ms)} detail={task.state === "running" ? "still running" : undefined} />
        <Metric
         label="Avg throughput"
         value={task.elapsed_ms > 0 ? `${(task.done / (task.elapsed_ms / 1000)).toFixed(1)} req/s` : "—"}
         detail="whole-task average"
        />
       </div>
       {/* Burp's "Most serious vulnerabilities found" table. The per-task result does not
                  carry the findings themselves — the Issues page does — so the honest equivalent is
                  the summary line plus the link, not a table of invented rows. */}
       <div className="task-detail-note">
        <p className="cell-dim">{task.result?.summary || "No issues recorded for this task."}</p>
        <Button
         size="small"
         variant="outline"
         onClick={() => onFilterHistory(`host ~ "${task.target.replace(/^https?:\/\//, "").split("/")[0] ?? task.target}"`)}
        >
         <FolderTree size={13} />
         Show in HTTP history
        </Button>
       </div>
      </Card>

      {crawlStops(run.data).length ? (
       <Card>
        <SectionHeading
         title={
          crawlStops(run.data).some(isPolicyPause) ? "Paused by policy — the crawl stopped itself" : "Incomplete — the crawl hit a bound"
         }
         detail="This crawl did not cover the application. Everything counted here is what it reached before it stopped."
        />
        <ul className="crawl-stops">
         {crawlStops(run.data).map((stop) => (
          <li key={stop} className={isPolicyPause(stop) ? "crawl-stop crawl-stop-policy" : "crawl-stop"}>
           {crawlStopLabel(stop)}
          </li>
         ))}
        </ul>
       </Card>
      ) : null}

      {run.data?.report?.login ? <CrawlLoginCard login={run.data.report.login} /> : null}

      {run.data?.definition ? (
       <Card>
        <SectionHeading
         title="API definition"
         detail="The document this scan read, and how much of the traffic it sent actually came from the document."
        />
        <div className="metric-grid wide">
         <Metric
          label="Endpoints sent"
          value={run.data.definition.operations.length}
          detail={
           run.data.definition.title
            ? `${run.data.definition.title}${run.data.definition.version ? ` ${run.data.definition.version}` : ""}, ${run.data.definition.format} ${run.data.definition.spec_version}`
            : `${run.data.definition.format} ${run.data.definition.spec_version}`
          }
         />
         {/* The number that decides how the run should be read. "0 of 5" and "5 of 5" are the same
             endpoint count and different scans, so it is shown with the server's own sentence rather
             than as a ratio an operator has to interpret. */}
         <Metric
          label="Values invented"
          value={`${run.data.definition.placeholder_values} / ${run.data.definition.declared_values}`}
          tone={run.data.definition.placeholder_values > 0 ? "warn" : undefined}
          detail={run.data.definition.placeholder_note}
         />
        </div>
        <DetailList
         rows={[
          { label: "Base URL", value: <code>{run.data.definition.base_url}</code> },
          {
           label: "Endpoints",
           value: (
            <div className="stack">
             <SimpleTable headers={["Method", "Document path", "Request"]}>
              {run.data.definition.operations.slice(0, 12).map((op) => (
               <tr key={`${op.method} ${op.template} ${op.path}`}>
                <td>
                 <Badge tone={op.method === "GET" ? "info" : op.method === "DELETE" ? "bad" : "warn"}>{op.method}</Badge>
                </td>
                <td>
                 <code>{op.template}</code>
                </td>
                <td className="cell-dim">
                 <code>{op.path}</code>
                </td>
               </tr>
              ))}
             </SimpleTable>
             {run.data.definition.operations.length > 12 ? (
              <span className="cell-dim">
               …and {run.data.definition.operations.length - 12} more endpoint(s); the run's record lists every one.
              </span>
             ) : null}
            </div>
           ),
          },
         ]}
        />
       </Card>
      ) : null}

      <Card>
       <SectionHeading title="Task configuration" />
       <DetailList
        rows={[
         { label: "Task type", value: task.kind === "live audit" ? "Live audit" : task.kind },
         { label: "Target", value: task.target },
         {
          label: "Capturing",
          value:
           task.kind === "live audit" ? (
            <Switch
             checked={liveEnabled}
             label="Capturing for this live audit task"
             onCheckedChange={(next) => {
              setLive.mutate(
               { enabled: next },
               {
                onSuccess: () => toast.success(next ? "Live audit started" : "Live audit stopped"),
                onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Toggling the live sweep failed"),
               },
              );
             }}
            />
           ) : run.data && task.state.toLowerCase() === "done" ? (
            <Badge tone={crawlOutcome(run.data).tone}>{crawlOutcome(run.data).label}</Badge>
           ) : (
            <Badge tone={taskTone(task.state)}>{task.state}</Badge>
           ),
         },
         { label: "Progress", value: task.progress },
        ]}
       />
      </Card>

      <Card className="task-detail-wide">
       {/* Project-wide, and the most misleading of the three without saying so (burpsy-react-ui-xwxd).
          CoverageSummary carries no task id — the shape is {label, unit, work_unit, breakdown} — so
          this roll-up cannot be attributed to the selected run, and a card reading "audit: 412
          loaded" beside one task's name reads as that task's number. The honest half of the original
          detail is kept: findings are a floor, not a total. */}
       <SectionHeading
        title="Coverage"
        detail="Project-wide: every run's accounting, not this task's. Findings are a floor, not a total — skipped, errored and gated work is counted separately."
       />
       {summaries.length ? (
        <div className="summary-grid">
         {summaries.map((summary) => (
          <CoverageCard key={summary.label} summary={summary} />
         ))}
        </div>
       ) : (
        <Empty title="No coverage reported" detail="Run a crawl or an audit to produce coverage accounting." />
       )}
      </Card>

      <Card className="task-detail-wide">
       {/* Project-wide, and now labelled as such (burpsy-react-ui-xwxd). The Sources histogram is
          a dashboard-level roll-up with no task dimension at all (api_dashboard.go's Sources), so
          it cannot be scoped to this task without the server building a per-task histogram it does
          not keep. Labelling it is the honest option the bead names, and it costs a heading. */}
       <SectionHeading title="Traffic sources" detail="Project-wide: where every captured exchange came from, not only this task's." />
       {sources.length ? (
        <div className="metric-grid wide">
         {sources.map(([name, count]) => (
          <Metric key={name} label={name} value={formatCount(count)} detail="exchanges" />
         ))}
        </div>
       ) : (
        <Empty title="No traffic yet" detail="Configure a client to use the proxy, then install the CA certificate to capture HTTPS." />
       )}
      </Card>
     </div>
    </TabsContent>

    <TabsContent value="events">
     <Card>
      {/*
       * The feed used to render events.slice(0, 20): rows 21 and beyond were dropped on the floor
       * with nothing saying so, which is the half of burpsy-react-ui-voc that made the log unable
       * to answer "what happened". Every row the server sends is now rendered, and the window is
       * stated from the server's own counters rather than re-derived here. The real bound is the
       * EventLog's, which already counts what it discarded — a second, silent cap in the browser
       * could only disagree with it.
       */}
      <EventLogPanel events={events} tasks={tasks} task={task} eventWindow={eventWindow} />
     </Card>
    </TabsContent>

    <TabsContent value="activity">
     <Card>
      {/* Project-wide for the same reason, and for a second one: ToolLogRow carries no task_id, so
          the rows cannot be attributed to a run at all (types.workbench.ts). An Intruder payload's
          row in a crawl's pane is a misattribution the operator cannot see through. */}
      <SectionHeading
       title="Recent traffic"
       detail="Project-wide: what burpsy sent and what it relayed across every tool, newest first. The full log is on the Logger page."
      />
      <ActivityTable rows={activity.slice(0, 20)} />
     </Card>
    </TabsContent>
   </Tabs>
  </div>
 );
}
