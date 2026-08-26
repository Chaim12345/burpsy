import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Activity, CircleAlert, Gauge, Play, Plus, Radar, Square } from "lucide-react";
import { toast } from "sonner";
import { api, formatBytes, formatCount, formatDuration, json, relativeTime, statusTone } from "../lib/api";
import { useDashboard, useInvalidate, useIssues } from "../lib/data";
import { useScannerLive, useSetScannerLive } from "../lib/data.attack";
import { useStartCrawl } from "../lib/data.observe";
import { useApp } from "../lib/store";
import type { ActivityRow, CoverageSummary, TaskRow } from "../lib/types";
import { PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Field, IconButton, Input, Metric, Modal } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

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

function TaskTable({ tasks, liveFindings, liveEnabled }: { tasks: TaskRow[]; liveFindings?: number; liveEnabled: boolean }): JSX.Element {
  const cancel = useCancelTask();
  const setLive = useSetScannerLive();

  // While live auditing is enabled Burp keeps its live task permanently visible even between
  // sweep batches; the registry only records a row per bounded batch (:577 in liveaudit.go), so
  // the standing entry is rendered here from /api/scanner/live state instead of faking registry data.
  const batchRunning = tasks.some((task) => task.kind === "live audit" && task.state === "running");
  const standing: TaskRow | null = liveEnabled && !batchRunning ? {
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
  } : null;
  const rows = standing ? [standing, ...tasks] : tasks;

  if (!rows.length) {
    return <Empty title="No tasks" detail="Crawls, audits and attacks appear here with their progress and bounded results." />;
  }
  return (
    <SimpleTable headers={["Kind", "Target", "State", "Progress", "Issues", "Elapsed", ""]}>
      {rows.map((task) => (
        <tr key={task.id}>
          <td>
            <Badge>{task.kind}</Badge>
          </td>
          <td title={task.note || task.target}>{task.target}</td>
          <td>
            <Badge tone={taskTone(task.state)}>{task.state}</Badge>
          </td>
          <td style={{ minWidth: "9rem" }}>
            <div className="progress-track" title={task.progress}>
              {task.fraction_known ? (
                <div className={`progress-fill ${task.state === "running" ? "progress-live" : ""}`} style={{ width: `${Math.round(task.fraction * 100)}%` }} />
              ) : (
                <div className="progress-fill progress-unknown" />
              )}
            </div>
            <span className="cell-dim">{task.progress}</span>
          </td>
          <td>
            {task.kind === "live audit" ? (
              liveFindings === undefined ? (
                <span className="cell-dim">—</span>
              ) : (
                <Badge tone={liveFindings > 0 ? "bad" : undefined}>{liveFindings}</Badge>
              )
            ) : (
              <span className="cell-dim" title={task.result?.summary}>
                {task.result?.summary || "—"}
              </span>
            )}
          </td>
          <td>
            <span className="cell-num">{formatDuration(task.elapsed_ms)}</span>
          </td>
          <td>
            {task.id === -1 ? (
              <IconButton
                label="Stop live auditing"
                size="small"
                disabled={setLive.isPending}
                onClick={() =>
                  setLive.mutate(
                    { enabled: false },
                    {
                      onSuccess: () => toast.success("Live audit stopped"),
                      onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Stopping the live audit failed"),
                    },
                  )
                }
              >
                <Square size={12} />
              </IconButton>
            ) : task.cancellable && task.state === "running" ? (
              <IconButton
                label={`Cancel ${task.kind} task on ${task.target}`}
                size="small"
                disabled={cancel.isPending}
                onClick={() => cancel.mutate(task.id)}
              >
                <Square size={12} />
              </IconButton>
            ) : null}
          </td>
        </tr>
      ))}
    </SimpleTable>
  );
}

function ActivityTable({ rows }: { rows: ActivityRow[] }): JSX.Element {
  if (!rows.length) {
    return <Empty title="No tool traffic" detail="Requests that burpsy itself sends — Repeater, Intruder, Scanner — are logged here." />;
  }
  return (
    <SimpleTable headers={["Age", "Tool", "Request", "Status"]}>
      {rows.map((row, index) => (
        <tr key={`${row.tool}-${row.started_ms}-${index}`}>
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
        </tr>
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
  const [maxRequests, setMaxRequests] = useState("50");
  const [maxDepth, setMaxDepth] = useState("5");
  const [maxDuration, setMaxDuration] = useState("");

  const close = () => onOpenChange(false);
  const submit = () => {
    startCrawl.mutate(
      {
        seeds: [seed.trim()],
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
            <Field label="Seed URL">
              {(id) => <Input id={id} value={seed} onChange={(event) => setSeed(event.target.value)} placeholder="https://demo.local/" />}
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
  const [scanOpen, setScanOpen] = useState(false);
  const [liveOpen, setLiveOpen] = useState(false);

  const sources = useMemo(() => Object.entries(data?.sources ?? {}).sort((a, b) => b[1] - a[1]), [data?.sources]);
  const incomplete = useMemo(() => (data?.summaries ?? []).filter((item) => !item.breakdown.complete).length, [data?.summaries]);

  if (error) {
    return (
      <div className="page">
        <PageHeader title="Dashboard" />
        <ErrorNotice error={error} onRetry={() => void refetch()} />
      </div>
    );
  }

  return (
    <div className="page">
      <PageHeader
        title="Dashboard"
        description="Capture totals, honest coverage accounting, and the work currently in flight."
        actions={<RefreshButton onClick={() => void refetch()} loading={isFetching} />}
      />

      <div className="metric-grid">
        <Metric
          accent
          label="Exchanges"
          value={formatCount(data?.exchanges)}
          detail={`${formatCount(data?.messages)} stored messages`}
        />
        <Metric label="Capture store" value={data ? formatBytes(data.stored_bytes) : "—"} detail="on-disk message bytes" />
        <Metric
          label="Running tasks"
          value={formatCount(data?.tasks_running)}
          detail={`${formatCount(data?.tasks.length)} tracked`}
          tone={data?.tasks_running ? "info" : undefined}
        />
        <Metric
          label="Coverage gaps"
          value={formatCount(incomplete)}
          detail={incomplete ? "summaries without a full verdict" : "every summary is complete"}
          tone={incomplete ? "warn" : "good"}
        />
      </div>

      {issues.data ? (
        <div className="metric-grid wide">
          {/* Critical was missing from this row while core.Severity has had it all along, so a
              critical finding was counted by the API and shown by nothing. The tiles now mirror
              the severity ladder rather than a subset of it. */}
          {(["critical", "high", "medium", "low", "info"] as const).map((severity) => (
            <Metric
              key={severity}
              label={`${severity} findings`}
              value={formatCount(issues.data!.counts?.[severity] ?? 0)}
              tone={
                (severity === "critical" || severity === "high") && (issues.data!.counts?.[severity] ?? 0) > 0
                  ? "bad"
                  : severity === "medium" && (issues.data!.counts?.medium ?? 0) > 0
                    ? "warn"
                    : undefined
              }
            />
          ))}
          {/* A severity the API did not recognise is surfaced rather than left out of the row: the
              defect this replaced was exactly a class of finding that no tile accounted for. */}
          {issues.data.counts?.unrecognised ? (
            <Metric
              label="unrecognised severity"
              value={formatCount(issues.data.counts.unrecognised)}
              tone="warn"
              detail="reported by the API under a name this row does not know"
            />
          ) : null}
        </div>
      ) : null}

      <div className="dashboard-grid">
        <Card className="dashboard-wide">
          <SectionHeading
            title="Coverage"
            detail="Findings are a floor, not a total. Skipped, errored and gated work is counted separately."
          />
          {data?.summaries.length ? (
            <div className="summary-grid">
              {data.summaries.map((summary) => (
                <CoverageCard key={summary.label} summary={summary} />
              ))}
            </div>
          ) : (
            <Empty title="No coverage reported" detail="Run a crawl or an audit to produce coverage accounting." />
          )}
        </Card>

        <Card>
          <SectionHeading title="Requests sent by burpsy" detail="Tool traffic, kept separate from proxy history." />
          <ActivityTable rows={data?.activity.slice(0, 10) ?? []} />
        </Card>

        <Card>
          <SectionHeading title="Tool events" detail="State changes that are not requests." />
          {data?.events.length ? (
            <div className="event-list">
              {data.events.slice(0, 12).map((event, index) => (
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

        <Card className="dashboard-wide">
          <SectionHeading
            title="Tasks"
            detail="Progress and bounded results for active and recent work."
            actions={
              <>
                <Button size="small" onClick={() => setScanOpen(true)}>
                  <Plus size={13} />
                  New scan
                </Button>
                <Button variant="outline" size="small" onClick={() => setLiveOpen(true)}>
                  <Radar size={13} />
                  New live task
                </Button>
              </>
            }
          />
          <TaskTable tasks={data?.tasks ?? []} liveFindings={live.data?.findings} liveEnabled={live.data?.enabled === true} />
        </Card>

        <Card className="dashboard-wide">
          <SectionHeading
            title="Traffic sources"
            detail="Where captured exchanges came from."
            actions={
              <button type="button" className="button button-outline button-sm" onClick={() => setRoute("history")}>
                <Activity size={13} />
                Open HTTP history
              </button>
            }
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

      {data && !data.exchanges ? (
        <div className="notice">
          <Gauge size={15} />
          <div>
            <strong>Nothing captured yet.</strong> Point a browser or client at the proxy listener, install the CA
            certificate from the sidebar, then reload this page. Use <Play size={11} /> Intercept to hold traffic, or
            Repeater to craft a request by hand.
          </div>
        </div>
      ) : null}

      {incomplete ? (
        <div className="notice notice-warn">
          <CircleAlert size={15} />
          <div>
            {incomplete} coverage {incomplete === 1 ? "summary reports" : "summaries report"} work without a verdict.
            Treat the finding counts above as a lower bound, not a clean result.
          </div>
        </div>
      ) : null}

      <NewScanModal open={scanOpen} onOpenChange={setScanOpen} />
      <NewLiveTaskModal open={liveOpen} onOpenChange={setLiveOpen} />
    </div>
  );
}
