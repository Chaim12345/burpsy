import { useMemo } from "react";
import { Activity, CircleAlert, Gauge, Play } from "lucide-react";
import { formatBytes, formatCount, formatDuration, relativeTime, statusTone } from "../lib/api";
import { useDashboard } from "../lib/data";
import { useApp } from "../lib/store";
import type { ActivityRow, CoverageSummary, TaskRow } from "../lib/types";
import { PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Card, Empty, ErrorNotice, Metric } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

function taskTone(state: string): "good" | "bad" | "warn" | "info" {
  const value = state.toLowerCase();
  if (value === "failed" || value === "error") return "bad";
  if (value === "done" || value === "complete" || value === "completed") return "good";
  if (value === "cancelled" || value === "stopped") return "warn";
  return "info";
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
          : `${formatCount(breakdown.unaccounted)} ${summary.work_unit} without a verdict`}
      </p>
    </div>
  );
}

function TaskTable({ tasks }: { tasks: TaskRow[] }): JSX.Element {
  if (!tasks.length) {
    return <Empty title="No tasks" detail="Crawls, audits and attacks appear here with their progress and bounded results." />;
  }
  return (
    <SimpleTable headers={["Kind", "Target", "State", "Progress", "Result", "Elapsed"]}>
      {tasks.map((task) => (
        <tr key={task.id}>
          <td>
            <Badge>{task.kind}</Badge>
          </td>
          <td title={task.target}>{task.target}</td>
          <td>
            <Badge tone={taskTone(task.state)}>{task.state}</Badge>
          </td>
          <td>{task.progress}</td>
          <td title={task.result?.summary}>{task.result?.summary ?? "—"}</td>
          <td>
            <span className="cell-num">{formatDuration(task.elapsed_ms)}</span>
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

export function DashboardPage(): JSX.Element {
  const { data, error, isFetching, refetch } = useDashboard();
  const setRoute = useApp((state) => state.setRoute);

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
          <SectionHeading title="Tasks" detail="Progress and bounded results for active and recent work." />
          <TaskTable tasks={data?.tasks ?? []} />
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
    </div>
  );
}
