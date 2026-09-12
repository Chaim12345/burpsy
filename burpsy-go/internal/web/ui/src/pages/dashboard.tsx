import { useMemo, useState } from "react";
import { parseSeeds } from "../lib/parse-seeds";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Copy, FolderTree, MoreVertical, Pause, Play, Plus, Radar, Search, Square } from "lucide-react";
import { toast } from "sonner";
import { api, copyToClipboard, formatCount, formatDuration, json, relativeTime, statusTone } from "../lib/api";
import { useDashboard, useInvalidate, useIssues } from "../lib/data";
import { useIssuesDetailed, useScannerLive, useSetScannerLive } from "../lib/data.attack";
import type { FindingDetail } from "../lib/types.attack";
import { useStartCrawl } from "../lib/data.observe";
import { useApp } from "../lib/store";
import type { ActivityRow, CoverageSummary, TaskRow, ToolEvent } from "../lib/types";
import { PageHeader, RefreshButton, SectionHeading, SplitPane } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Field, IconButton, Input, Metric, Modal, Switch, Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/primitives";
import { DetailList } from "../ui/json";
import { DropdownMenu, type MenuGroup } from "../ui/menu";
import { MenuRow, SimpleTable } from "../ui/table";
import { useDeleteTask, useScanTaskAgain } from "../lib/data.attack";

function taskTone(state: string): "good" | "bad" | "warn" | "info" {
 const value = state.toLowerCase();
 if (value === "failed" || value === "error") return "bad";
 if (value === "done" || value === "complete" || value === "completed") return "good";
 if (value === "cancelled" || value === "stopped") return "warn";
 return "info";
}

/** Burp's severity colours for the activity feed, the same mapping sitemap.tsx's findingTone uses —
 * copied rather than imported because both are tiny and a shared home would invent a module for one
 * switch statement. If a third copy appears, that is the signal to move it. */
function findingTone(severity: string): "bad" | "warn" | "info" | "neutral" {
 switch (severity) {
  case "Critical":
  case "High":
   return "bad";
  case "Medium":
   return "warn";
  case "Low":
   return "info";
  default:
   return "neutral";
 }
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
 const standing: TaskRow | null = liveEnabled && !batchRunning
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
 // The task row's options menu (burpsy-react-ui-r6q): Burp's taskListEntryOptionsMenu, minus the
 // pieces that are their own tracked issues (pause/resume is 8gw; settings live on the detail
 // pane). Scan again re-runs a crawl at its target; Delete removes a finished row — the server
 // refuses a running one with 409, and the toast passes that reason through.
 const menu: MenuGroup[] = task.id === -1 ? [] : [
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
    <Badge tone={taskTone(task.state)}>{task.state}</Badge>
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
         onError: (failure: unknown) =>
          toast.error(failure instanceof Error ? failure.message : "Toggling the live sweep failed"),
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
  mutationFn: () => api(`/api/tasks/${paused ? "resume" : "pause"}`, json("POST", {})),
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
    <Input
     aria-label="Filter tasks"
     placeholder="Filter tasks"
     value={filter}
     onChange={(event) => setFilter(event.target.value)}
    />
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
// first page; the two kinds burpsy cannot run yet render as disabled cards that say so rather than
// disappearing, because a missing capability silently hidden is the defect this UI exists to avoid.
const SCAN_TYPES = [
 { id: "crawl-audit", title: "Crawl and audit", detail: "Maps the attack surface and audits what it finds.", ready: false },
 { id: "crawl", title: "Crawl", detail: "Maps the attack surface of the web application.", ready: true },
 { id: "api", title: "API-only scan", detail: "Scans detected API definitions.", ready: false },
] as const;

function NewScanModal({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }): JSX.Element {
 const startCrawl = useStartCrawl();
 const [kind, setKind] = useState<string>("crawl");
 const [seed, setSeed] = useState("");
 // f3k: the New scan dialog takes Burp's "URLs to scan" shape — many seeds, one box
 // (Burp: "Define the URLs to scan. Burp will begin crawling from these URLs"). The wire has
 // taken an array all along; only the input was single.
 const seeds = parseSeeds(seed);
 const [maxRequests, setMaxRequests] = useState("50");
 const [maxDepth, setMaxDepth] = useState("5");
 const [maxDuration, setMaxDuration] = useState("");

 const close = () => onOpenChange(false);
 const submit = () => {
  startCrawl.mutate(
   {
    seeds,
    max_requests: Number(maxRequests) || undefined,
    max_depth: Number(maxDepth) || undefined,
    max_duration_secs: Number(maxDuration) || undefined,
   },
   {
    onSuccess: () => toast.success(`Crawl started on ${seed.trim()}`),
    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Starting the crawl failed"),
   },
  );
  close();
 };

 return (
  <Modal open={open} onOpenChange={onOpenChange} title="New scan" wide description="Select the type of scan to run. It registers as a task below, with progress and a cancel button.">
   <div className="stack">
    <h4>Scan type</h4>
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
       {!scan.ready ? <small className="cell-dim">not built yet</small> : null}
      </button>
     ))}
    </div>
    {kind === "crawl" ? (
     <>
      <Field
       label="URLs to scan"
       hint="One per line, or comma separated — Burp's own field is many URLs in one box."
      >
       {(id) => (
        <Input
         id={id}
         value={seed}
         onChange={(event) => setSeed(event.target.value)}
         placeholder={"https://demo.local/\nhttps://api.demo.local/"}
        />
       )}
      </Field>
      <div className="metric-grid wide">
       <Field label="Max requests (empty = uncapped)">
        {(id) => <Input id={id} type="number" min={1} value={maxRequests} onChange={(event) => setMaxRequests(event.target.value)} />}
       </Field>
       <Field label="Max depth">
        {(id) => <Input id={id} type="number" min={1} value={maxDepth} onChange={(event) => setMaxDepth(event.target.value)} />}
       </Field>
       <Field label="Max duration (seconds)">
        {(id) => <Input id={id} type="number" min={1} value={maxDuration} onChange={(event) => setMaxDuration(event.target.value)} placeholder="uncapped" />}
       </Field>
      </div>
     </>
    ) : null}
    <div className="toolbar-end">
     <Button variant="outline" size="small" onClick={close}>
      Cancel
     </Button>
     <Button size="small" disabled={kind !== "crawl" || !seed.trim() || startCrawl.isPending} onClick={submit}>
      Start
     </Button>
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
 const close = () => onOpenChange(false);

 return (
  <Modal open={open} onOpenChange={onOpenChange} title="New live task" description="Audit proxied traffic as it arrives. The sweep registers as a task below.">
   <div className="stack">
    <Field label="Scope filter query (optional)">
     {(id) => <Input id={id} value={query} onChange={(event) => setQuery(event.target.value)} placeholder='host == "demo.local"' />}
    </Field>
    <p className="cell-dim" style={{ margin: 0 }}>
     Which checks run is global — set it under Settings → Audit checks.
    </p>
    <div className="toolbar-end">
     <Button variant="outline" size="small" onClick={close}>
      Cancel
     </Button>
     <Button
      size="small"
      disabled={setLive.isPending}
      onClick={() => {
       setLive.mutate(
        { enabled: true, query: query.trim() || undefined },
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
       liveFindings={liveFindings}
       liveEnabled={liveEnabled}
       issuesEnabled={issues.data?.enabled === true}
       summaries={data?.summaries ?? []}
       sources={sources}
       events={data?.events ?? []}
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

/** One task's detail pane: header, Summary / Event log tabs, then the tab's content. Burp keeps
 * the task's own facts (configuration, progress) on Summary and everything the task produced
 * (issues, events) on the later tabs; the same split, with burpsy's equivalents in each. */
function TaskDetail({
 task,
 liveFindings,
 liveEnabled,
 issuesEnabled,
 summaries,
 sources,
 events,
 activity,
 onFilterHistory,
}: {
 task: TaskRow;
 liveFindings?: number;
 liveEnabled: boolean;
 issuesEnabled: boolean;
 summaries: CoverageSummary[];
 sources: [string, number][];
 events: ToolEvent[];
 activity: ActivityRow[];
 onFilterHistory: (query: string) => void;
}): JSX.Element {
 const cancel = useCancelTask();
 const setLive = useSetScannerLive();
 // The same cache key the Issues page reads, so a finding that arrives mid-scan is here on the
 // next render without a second request. Reverse-chronological by id: the store is a dense counter
 // from zero, so higher id == raised later — the feed's whole point (burpsy-react-ui-i18).
 const issuesDetailed = useIssuesDetailed();
 const focusIssue = useApp((state) => state.focusIssue);
 const setRoute = useApp((state) => state.setRoute);
 const activityFindings = useMemo(
  () => [...(issuesDetailed.data?.findings ?? [])].sort((a, b) => b.id - a.id).slice(0, 20),
  [issuesDetailed.data?.findings],
 );
 const openAdvisory = (finding: FindingDetail) => {
  // The Issues page is where an advisory opens; landing there with the finding selected is the
  // "way in" this feed exists to provide — the same focus mechanism History's focusExchange uses.
  focusIssue(finding.id);
  setRoute("scanner");
 };
 const title = task.kind === "live audit" ? "Live audit from Proxy (all traffic)" : `${task.kind} (${task.target})`;

 return (
  <div className="task-detail">
   <div className="task-detail-head">
    <h2>{title}</h2>
    <div className="task-detail-actions">
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
    </TabsList>

    <TabsContent value="issue-activity">
     <Card>
      <SectionHeading
       title="Issue activity"
       detail="Findings as they were raised, newest first. Each opens its advisory on the Issues page."
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
           <Badge tone={findingTone(finding.severity)}>{finding.severity}</Badge>
          </td>
          <td title={finding.detail ?? undefined}>
           {finding.issue_name ?? finding.check_name ?? "Unnamed finding"}
           {finding.times_seen > 1 ? (
            <span className="cell-dim"> ×{finding.times_seen}</span>
           ) : null}
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
       <Empty
        title="No issues recorded"
        detail={
         issuesEnabled
          ? "Findings appear here as the audit and the live sweep raise them."
          : "The scanner is disabled; findings below are historical — and there are none yet."
        }
       />
      )}
     </Card>
    </TabsContent>

    <TabsContent value="summary">
     <div className="task-detail-grid">
      <Card>
       <SectionHeading title="Findings" detail={issuesEnabled ? "What this task and the live sweep have reported so far." : "The scanner is disabled; findings below are historical."} />
       <div className="metric-grid wide">
        <Metric
         accent
         label="Findings"
         value={task.kind === "live audit" ? (liveFindings ?? 0) : Number(/([\d,]+)/.exec(task.result?.summary ?? "")?.[1]?.replace(/,/g, "") ?? 0) || 0}
         detail={task.kind === "live audit" ? "live audit sweep" : "recorded by this task"}
        />
        {/* burpsy-react-ui-uxi, the derivable half: requests done and the average rate are both
            facts the task row already carries — done over elapsed seconds — so neither is invented.
            The rate is a whole-task average, not a live window; saying so keeps it from reading as
            an instantaneous measurement. Byte transfer is deliberately absent: nothing on any egress
            path accounts bytes per task, and a metric nobody measures is a number somebody made up. */}
        <Metric label="Requests" value={task.done.toLocaleString()} detail="sent by this task" />
        <Metric
         label="Elapsed"
         value={formatDuration(task.elapsed_ms)}
         detail={task.state === "running" ? "still running" : undefined}
        />
        <Metric
         label="Avg throughput"
         value={
          task.elapsed_ms > 0
           ? `${(task.done / (task.elapsed_ms / 1000)).toFixed(1)} req/s`
           : "—"
         }
         detail="whole-task average"
        />
       </div>
       {/* Burp's "Most serious vulnerabilities found" table. The per-task result does not
                  carry the findings themselves — the Issues page does — so the honest equivalent is
                  the summary line plus the link, not a table of invented rows. */}
       <div className="task-detail-note">
        <p className="cell-dim">{task.result?.summary || "No issues recorded for this task."}</p>
        <Button size="small" variant="outline" onClick={() => onFilterHistory(`host ~ "${task.target.replace(/^https?:\/\//, "").split("/")[0] ?? task.target}"`)}>
         <FolderTree size={13} />
         Show in HTTP history
        </Button>
       </div>
      </Card>

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
                onError: (failure: unknown) =>
                 toast.error(failure instanceof Error ? failure.message : "Toggling the live sweep failed"),
               },
              );
             }}
            />
           ) : (
            <Badge tone={taskTone(task.state)}>{task.state}</Badge>
           ),
         },
         { label: "Progress", value: task.progress },
        ]}
       />
      </Card>

      <Card className="task-detail-wide">
       <SectionHeading title="Coverage" detail="Findings are a floor, not a total. Skipped, errored and gated work is counted separately." />
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
       <SectionHeading title="Traffic sources" detail="Where captured exchanges came from." />
       {sources.length ? (
        <div className="metric-grid wide">
         {sources.map(([name, count]) => (
          <Metric key={name} label={name} value={formatCount(count)} detail="exchanges" />
         ))}
        </div>
       ) : (
        <Empty
         title="No traffic yet"
         detail="Configure a client to use the proxy, then install the CA certificate to capture HTTPS."
        />
       )}
      </Card>
     </div>
    </TabsContent>

    <TabsContent value="events">
     <Card>
      <SectionHeading title="Event log" detail="State changes that are not requests." />
      {events.length ? (
       <div className="event-list">
        {events.slice(0, 20).map((event, index) => (
         <div className="event-row" key={`${event.kind}-${event.at_ms}-${index}`}>
          <span className={`event-dot event-${event.severity}`} />
          <div>
           <strong>{event.kind}</strong>
           <p>{event.detail}</p>
          </div>
          <time title={new Date(event.at_ms).toLocaleString()}>{relativeTime(event.at_ms)}</time>
         </div>
        ))}
       </div>
      ) : (
       <Empty title="No events" detail="Start an audit, a crawl or an attack to populate this feed." />
      )}
     </Card>
    </TabsContent>

    <TabsContent value="activity">
     <Card>
      <SectionHeading title="Requests sent by burpsy" detail="Tool traffic, kept separate from proxy history." />
      <ActivityTable rows={activity.slice(0, 20)} />
     </Card>
    </TabsContent>
   </Tabs>
  </div >
 );
}
