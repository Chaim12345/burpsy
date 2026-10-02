import { taskActivityFindings } from "../lib/task-activity";
import { useMemo, useRef, useState } from "react";
import { parseSeeds } from "../lib/parse-seeds";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Copy, FolderTree, MoreVertical, Pause, Play, Plus, Radar, Search, Square } from "lucide-react";
import { toast } from "sonner";
import { api, copyToClipboard, formatCount, formatDuration, json, relativeTime, statusTone } from "../lib/api";
import { useDashboard, useInvalidate, useIssues } from "../lib/data";
import { useIssuesDetailed, useScannerLive, useSetScannerLive } from "../lib/data.attack";
import type { FindingDetail } from "../lib/types.attack";
import { useAPIScanCheck, useAuditSelected, useCrawlRun, useStartAPIScan, useStartCrawl } from "../lib/data.observe";
import { useApp } from "../lib/store";
import type { ActivityRow, CoverageSummary, TaskRow, ToolEvent } from "../lib/types";
import { PageHeader, RefreshButton, SectionHeading, SplitPane } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Field, IconButton, Input, Metric, Modal, Switch, Tabs, TabsContent, TabsList, TabsTrigger, Textarea } from "../ui/primitives";
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
 const [maxRequests, setMaxRequests] = useState("50");
 const [maxDepth, setMaxDepth] = useState("5");
 const [maxDuration, setMaxDuration] = useState("");
 // The API-only scan's own inputs. `definitionName` is only ever a label — it is what the operator
 // picked or pasted from, shown so a pasted document and an uploaded one are distinguishable after
 // the fact — and never travels to the server, which reads the bytes and not the filename.
 const [definition, setDefinition] = useState("");
 const [definitionName, setDefinitionName] = useState("");
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

 const chosen = selectedScanType(kind);
 const close = () => onOpenChange(false);
 const auditing = chosen.launch === "audit";
 const apiScan = chosen.launch === "api";
 const canSubmit = auditing
  ? checked.length > 0 && !auditSelected.isPending
  : apiScan
   ? definition.trim() !== "" && scanCheck.data !== undefined && !startAPIScan.isPending
   : chosen.ready && seed.trim() !== "" && !startCrawl.isPending;
 const submit = () => {
  if (apiScan) {
   // The check already passed on this exact text, so the launch cannot be refused for a reason the
   // operator was not shown — both calls run the server's one prepareAPIScan.
   startAPIScan.mutate(
    {
     definition,
     base_url: baseUrl.trim() || undefined,
     audit: auditEndpoints,
     max_requests: Number(apiMaxRequests) || undefined,
    },
    {
     onSuccess: (accepted) => {
      const endpoints = accepted.definition.operations.length;
      toast.success(
       `${accepted.audit ? "API scan" : "API sweep"} started over ${endpoints} endpoint${endpoints === 1 ? "" : "s"}` +
        (accepted.definition.placeholder_values > 0 ? ` (${accepted.definition.placeholder_note})` : ""),
      );
     },
     onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Starting the API scan failed"),
    },
   );
   close();
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
    max_requests: Number(maxRequests) || undefined,
    max_depth: Number(maxDepth) || undefined,
    max_duration_secs: Number(maxDuration) || undefined,
   },
   {
    onSuccess: () => toast.success(`${verb} started on ${seed.trim()}`),
    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : `Starting the ${verb.toLowerCase()} failed`),
   },
  );
  close();
 };

 return (
  <Modal open={open} onOpenChange={onOpenChange} title="New scan" wide description="Select the type of scan to run. It registers as a task below, with progress and a cancel button.">
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
       Scans the items ticked in HTTP history, as one task. Burp takes its selection from the table you are looking at, and so
       does this — the ticks are the selection, and the scan is over exactly those rows.
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
       Sends the endpoints an API definition describes, instead of discovering them by crawling. The document's own examples,
       defaults and enums become the parameter values where it supplies them; where it does not, this build invents visible
       placeholders and says how many below.
      </p>
      <Field
       label="API definition"
       hint="OpenAPI 3.x or Swagger 2.0, in JSON or YAML. Paste it here, or load the file."
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
         }}
         rows={7}
         placeholder={'openapi: "3.0.3"\ninfo: {title: Petstore, version: "1.0.2"}\nservers: [{url: https://api.example.com/v1}]\npaths:\n  /pets:\n    get:\n      responses: {"200": {description: ok}}'}
         aria-label="API definition"
        />
       )}
      </Field>
      <div className="toolbar">
       <Button variant="outline" size="small" onClick={() => definitionFileRef.current?.click()}>
        Load from file
       </Button>
       {definitionName ? <span className="cell-dim">{definitionName}</span> : null}
       {definition ? (
        <Button
         variant="outline"
         size="small"
         onClick={() => {
          setDefinition("");
          setDefinitionName("");
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
         });
        }}
       />
      </div>
      <Field
       label="Base URL (optional)"
       hint="Overrides the document's own servers[0]. Required when the document declares no server, or a relative one — a pasted document has no host of its own to be relative to."
      >
       {(id) => (
        <Input
         id={id}
         value={baseUrl}
         onChange={(event) => setBaseUrl(event.target.value)}
         placeholder="https://api.example.com/v1"
        />
       )}
      </Field>
      {definition.trim() === "" ? (
       <p className="cell-dim" style={{ margin: 0 }}>
        Nothing to scan yet. As soon as the document is in the box above, it is read here — endpoint count, the host the paths
        resolve against, and how many of its values this build would have to invent.
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
         Base URL <code>{scanCheck.data.definition.base_url}</code>. Every request is re-authorised against the current scope
         before it is sent, exactly as a crawl's is.
        </p>
        {/* Capped at twelve rows, with the remainder counted rather than dropped: a document can
            describe hundreds of endpoints, and a list that silently stopped at twelve would read as
            the whole list. The full record is on the run, which keeps every operation. */}
        <SimpleTable headers={["Method", "Document path", "Request"]}>
         {scanCheck.data.definition.operations.slice(0, 12).map((op) => (
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
        {scanCheck.data.definition.operations.length > 12 ? (
         <p className="cell-dim" style={{ margin: 0 }}>
          …and {scanCheck.data.definition.operations.length - 12} more endpoint(s); the run's record lists every one.
         </p>
        ) : null}
       </>
      ) : (
       <p className="cell-dim" style={{ margin: 0 }}>
        Reading the document…
       </p>
      )}
      <div className="metric-grid wide">
       <Field label="Max requests (empty = one per endpoint)" hint="A cap below the document's endpoint count sends a prefix of the list, and the report says how many were never sent.">
        {(id) => <Input id={id} type="number" min={1} value={apiMaxRequests} onChange={(event) => setApiMaxRequests(event.target.value)} placeholder={String(scanCheck.data?.definition.operations.length ?? "")} />}
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
      {chosen.id === "crawl-audit" ? (
       <p className="cell-dim" style={{ margin: 0 }}>
        Two tasks appear below: the crawl, then a separate audit of the exchanges it fetched. The audit starts when the
        crawl finishes, and its own row reports the checks it could not run — a bounded sweep is never shown as a clean one.
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
        {(id) => <Input id={id} type="number" min={1} value={maxDuration} onChange={(event) => setMaxDuration(event.target.value)} placeholder="uncapped" />}
       </Field>
      </div>
     </>
    ) : null}
    <div className="toolbar-end">
     <Button variant="outline" size="small" onClick={close}>
      Cancel
     </Button>
     <Button size="small" disabled={!canSubmit} onClick={submit}>
      {auditing ? "Audit selected items" : apiScan ? `Scan ${scanCheck.data?.definition.operations.length ?? 0} endpoint${scanCheck.data?.definition.operations.length === 1 ? "" : "s"}` : "Start"}
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
 eventWindow,
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
 eventWindow: { shown: number; total: number; dropped: number };
 activity: ActivityRow[];
 onFilterHistory: (query: string) => void;
}): JSX.Element {
 const cancel = useCancelTask();
 const clearEvents = useClearEventLog();
 const setLive = useSetScannerLive();
 // The same cache key the Issues page reads, so a finding that arrives mid-scan is here on the
 // next render without a second request. Reverse-chronological by id: the store is a dense counter
 // from zero, so higher id == raised later — the feed's whole point (burpsy-react-ui-i18).
 const issuesDetailed = useIssuesDetailed();
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
 const { shown: activityFindings, hidden: activityHidden } = taskActivityFindings(
  issuesDetailed.data?.findings ?? [],
  task.id,
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
        Showing the {activityFindings.length} newest of {activityFindings.length + activityHidden} this task
        raised. The rest are on the Issues page.
       </p>
      ) : null}
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
      <SectionHeading
       title="Traffic sources"
       detail="Project-wide: where every captured exchange came from, not only this task's."
      />
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
      {/*
        * The feed used to render events.slice(0, 20): rows 21 and beyond were dropped on the floor
        * with nothing saying so, which is the half of burpsy-react-ui-voc that made the log unable
        * to answer "what happened". Every row the server sends is now rendered, and the window is
        * stated from the server's own counters rather than re-derived here. The real bound is the
        * EventLog's, which already counts what it discarded — a second, silent cap in the browser
        * could only disagree with it.
        */}
      <SectionHeading
       title="Event log"
       detail={
        eventWindow.dropped > 0
         ? `State changes that are not requests. Showing all ${eventWindow.shown} the log holds; ${eventWindow.dropped} older event(s) have been discarded as it filled.`
         : "State changes that are not requests. The log shows key task events, such as start times, alerts, and progress updates."
       }
       actions={
        <Button
         variant="outline"
         disabled={!events.length || clearEvents.isPending}
         onClick={() => clearEvents.mutate()}
        >
         {clearEvents.isPending ? "Clearing…" : "Clear event log"}
        </Button>
       }
      />
      {events.length ? (
       <div className="event-list event-list-scroll">
        {events.map((event, index) => (
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
       <Empty
        title="No event log items to show"
        detail="The event log shows key task events, such as start times, alerts, and progress updates."
       />
      )}
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
  </div >
 );
}
