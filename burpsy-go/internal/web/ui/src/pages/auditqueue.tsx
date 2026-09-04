/**
 * The audit queue: what the active audit decided about every exchange it was
 * handed, in Burp's SCANNER-tab shape. The server's view already carries the
 * honest machinery — per-state counts, the Burp-status parity statement, a
 * reason when nothing has been queued — so this page renders that rather than
 * deriving a friendlier summary. A row that was skipped says why in its note;
 * a queue that never ran says so instead of looking clean.
 */
import { Fragment, useState } from "react";
import { Badge, Button, Card, Empty, ErrorNotice, Metric } from "../ui/primitives";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { SimpleTable } from "../ui/table";
import { useAuditItemAgain, useAuditItems } from "../lib/data.auditqueue";
import { toast } from "sonner";

function stateTone(state: string): "good" | "bad" | "warn" | "info" {
  const value = state.toLowerCase();
  if (value.includes("complete") || value.includes("audited")) return "good";
  if (value.includes("fail") || value.includes("abandon")) return "bad";
  if (value.includes("bound") || value.includes("pause") || value.includes("cancel") || value.includes("skip")) return "warn";
  if (value.includes("pending") || value.includes("audit")) return "info";
  return "info";
}

export function AuditQueuePage(): JSX.Element {
  const queue = useAuditItems();
  const again = useAuditItemAgain();
  const [expanded, setExpanded] = useState<number | null>(null);

  if (queue.isLoading) return <LoadingPanel label="Loading the audit queue" />;
  if (queue.error || !queue.data)
    return <ErrorNotice error={queue.error ?? new Error("Audit queue unavailable")} onRetry={() => void queue.refetch()} />;

  const d = queue.data;

  return (
    <div className="stack">
      <PageHeader
        title="Audit queue"
        description="What the active audit did with every exchange it was handed — bounded work is reported, never dropped."
        actions={<RefreshButton onClick={() => void queue.refetch()} loading={queue.isFetching} />}
      />
      {queue.data.reason ? (
        <Empty title="Nothing queued yet" detail={d.reason ?? "No audit has been queued yet."} />
      ) : (
        <>
          <div className="metric-grid wide">
            <Metric label="Pending" value={d.totals.items_pending} />
            <Metric label="Auditing" value={d.totals.items_auditing} />
            <Metric label="Completed" value={d.totals.items_completed_audit} tone={d.totals.items_completed_audit > 0 ? "good" : undefined} />
            <Metric label="Bounded" value={d.totals.items_bounded} tone={d.totals.items_bounded > 0 ? "warn" : undefined} detail="hit a budget or breaker" />
            <Metric label="Failed" value={d.totals.items_failed} tone={d.totals.items_failed > 0 ? "bad" : undefined} />
            <Metric label="Out of scope" value={d.totals.items_out_of_scope} />
          </div>
          <Card>
            <SectionHeading
              title="Queue"
              detail={`${d.returned} row(s)${d.truncated ? ` of ${d.queue.retained} retained` : ""} · Burp status parity: ${d.parity.burp_statuses_modelled}/${d.parity.burp_statuses_declared} modelled${
                d.parity.burp_statuses_not_modelled?.length
                  ? ` (not modelled: ${d.parity.burp_statuses_not_modelled.map((gap) => gap.label || gap.status).filter(Boolean).join(", ")})`
                  : ""
              }`}
            />
            <SimpleTable headers={["Seq", "Request", "State", "Attempts", "Note", ""]}>
              {d.items.map((item) => (
                <Fragment key={item.seq}>
                  <tr key={item.seq}>
                    <td className="cell-num">{item.seq}</td>
                    <td className="mono">
                      {item.method ? (
                        <>
                          {item.method} {item.tls ? "https" : "http"}://{item.host}
                          {item.port && item.port !== (item.tls ? 443 : 80) ? `:${item.port}` : ""} {item.path}
                        </>
                      ) : (
                        <span className="cell-dim">exchange #{item.exchange_id} — not yet resolved</span>
                      )}
                    </td>
                    <td>
                      <Badge tone={stateTone(item.state)}>{item.status_label || item.state}</Badge>
                      {item.burp_status ? <span className="cell-dim"> {item.burp_status}</span> : null}
                    </td>
                    <td className="cell-num">{item.attempts}</td>
                    <td className="cell-dim">{item.note ?? "—"}</td>
                    <td>
                      {/* Per row, because the control used to be one page-level button that only ever
                          expanded d.items[0] — on every other row it appeared to do nothing, and an
                          operator read "no insertion points" where the truth was "this control cannot
                          show you them" (burpsy-react-ui-d0n).

                          Disabled with its count when a row recorded none, rather than hidden: an
                          absent button is indistinguishable from a row that has points and a broken
                          toggle, which is the confusion this issue was about. */}
                      <Button
                        variant="quiet"
                        size="small"
                        disabled={!item.insertion_points?.length}
                        aria-expanded={expanded === item.seq}
                        title={
                          item.insertion_points?.length
                            ? `${expanded === item.seq ? "Hide" : "Show"} the ${item.insertion_points.length} insertion point(s) recorded for this item`
                            : "No insertion points were recorded for this item"
                        }
                        onClick={() => setExpanded(expanded === item.seq ? null : item.seq)}
                      >
                        {item.insertion_points?.length
                          ? `${expanded === item.seq ? "Hide" : "Points"} (${item.insertion_points.length})`
                          : "Points (0)"}
                      </Button>
                      <Button
                        variant="outline"
                        size="small"
                        disabled={again.isPending}
                        onClick={() =>
                          again.mutate(item.exchange_id, {
                            onSuccess: () => toast.success(`Re-auditing exchange #${item.exchange_id}`),
                            onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Re-audit failed"),
                          })
                        }
                      >
                        Audit again
                      </Button>
                    </td>
                  </tr>
                  {expanded === item.seq && item.insertion_points?.length ? (
                    <tr key={`${item.seq}-points`}>
                      <td colSpan={6}>
                        <div className="stack">
                          <span className="cell-dim">
                            {item.insertion_points.length} insertion point(s) recorded for seq {item.seq}
                          </span>
                          {item.insertion_points.map((point, index) => (
                            <div key={index} className="cell-dim mono">
                              {point.kind}/{point.name}: {point.status}
                              {point.detail ? ` — ${point.detail}` : ""}
                            </div>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              ))}
            </SimpleTable>
          </Card>
        </>
      )}
    </div>
  );
}
