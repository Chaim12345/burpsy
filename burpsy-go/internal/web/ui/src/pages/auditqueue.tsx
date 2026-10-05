/**
 * The audit queue: what the active audit decided about every exchange it was
 * handed, in Burp's SCANNER-tab shape. The server's view already carries the
 * honest machinery — per-state counts, the Burp-status parity statement, a
 * reason when nothing has been queued — so this page renders that rather than
 * deriving a friendlier summary. A row that was skipped says why in its note;
 * a queue that never ran says so instead of looking clean.
 *
 * Selecting a row also shows the exchange it names — Burp's audit-items view is
 * a table over a request/response viewer (map_root.tsv, class burp.Zr_7:
 * auditItemsTable beside auditItemsTableRequestResponseViewer), because the
 * note column gives the engine's reason and the base bytes are what make that
 * reason legible: a 500 on the base response, or an expired session cookie,
 * is invisible until the request itself is on screen. The byte fetch reuses the
 * history row → message-id → /api/message shape scanner.tsx already uses, so
 * no second read path exists.
 */
import { Fragment, useMemo, useState } from "react";
import { Badge, Button, Card, Empty, ErrorNotice, Metric, Tabs, TabsContent, TabsList, TabsTrigger } from "../ui/primitives";
import { HttpEditor } from "../ui/editor";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { SimpleTable } from "../ui/table";
import { useAuditItemAgain, useAuditItemCancel, useAuditItems } from "../lib/data.auditqueue";
import { itemProgress, itemTiming } from "../lib/audit-queue-item";
import { useHistory, useMessage } from "../lib/data";
import { usePluginExchangeActions } from "../lib/plugin-exchange-actions";
import { useApp } from "../lib/store";
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
 const cancel = useAuditItemCancel();
 const [expanded, setExpanded] = useState<number | null>(null);
 /** Selection is the queue row's seq: a refetch reorders nothing (seq is stable), ids survive it. */
 const [selectedSeq, setSelectedSeq] = useState<number | null>(null);

 const focusExchange = useApp((state) => state.focusExchange);
 const setRoute = useApp((state) => state.setRoute);
 const actions = usePluginExchangeActions();

 // The same history cache key the history tab uses: the row carries the exchange id, the
 // ExchangeView carries the message ids, and the bytes come from /api/message only when this
 // row is selected — a 500-row queue never pulls a body until asked.
 const { data: history } = useHistory("", 1000);
 const items = useMemo(() => queue.data?.items ?? [], [queue.data]);
 const selected = useMemo(() => items.find((item) => item.seq === selectedSeq) ?? null, [items, selectedSeq]);
 const exchange = useMemo(() => {
  if (!selected) return null;
  return (history ?? []).find((ex) => ex.id === selected.exchange_id) ?? null;
 }, [history, selected]);
 const request = useMessage(exchange?.request);
 const response = useMessage(exchange?.response ?? null);

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
       detail={`${d.returned} row(s)${d.truncated ? ` of ${d.queue.retained} retained` : ""} · Burp status parity: ${d.parity.burp_statuses_modelled}/${d.parity.burp_statuses_declared} modelled${d.parity.burp_statuses_not_modelled?.length
        ? ` (not modelled: ${d.parity.burp_statuses_not_modelled.map((gap) => gap.label || gap.status).filter(Boolean).join(", ")})`
        : ""
        }`}
      />
      {/* Progress and evidence are columns rather than a row's expansion because a partial audit is
          diagnosed FROM THE TABLE: the question is "which items stopped early, and how far did they
          get", and answering it needs every row's number visible at once. The data was already on
          the wire — the endpoint hands out scanner.AuditItem wholesale (burpsy-react-ui-xdtx). */}
      <SimpleTable headers={["Seq", "Request", "State", "Progress", "Points", "Timing", "Attempts", "Note", ""]}>
       {d.items.map((item) => (
        <Fragment key={item.seq}>
         <tr
          key={item.seq}
          className={selectedSeq === item.seq ? "data-row clickable selected-row" : "data-row clickable"}
          onClick={() => setSelectedSeq(selectedSeq === item.seq ? null : item.seq)}
         >
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
           {item.url_disposition ? (
            <div style={{ marginTop: 2 }}>
             <Badge
              tone={item.url_disposition === "NETWORK_ERROR" ? "bad" : "good"}
              title={item.url_disposition === "NETWORK_ERROR" ? "This URL's probes failed below HTTP — it never answered" : "This URL was reached and audited"}
             >
              {item.url_disposition}
             </Badge>
            </div>
           ) : null}
          </td>
          <td title="Steps that reached a disposition, out of the steps this item planned">
           {itemProgress(item)}
          </td>
          <td
           className="cell-num"
           title={
            item.point_kinds?.length
             ? `Enumerated for: ${item.point_kinds.join(", ")}` +
             (item.points_skipped ? ` · ${item.points_skipped} dropped at the per-request ceiling` : "") +
             (item.points_declined_places ? ` · ${item.points_declined_places} places the enumerator refused` : "")
             : "No insertion points were recorded for this item"
           }
          >
           {item.points_enumerated ?? 0}
           {item.points_skipped ? (
            <span className="cell-dim"> +{item.points_skipped} at limit</span>
           ) : null}
          </td>
          <td className="cell-dim">{itemTiming(item) || "—"}</td>
          <td className="cell-num">{item.attempts}</td>
          <td className="cell-dim">{item.note ?? "—"}</td>
          <td>
           {/* Per row, because the control used to be one page-level button that only ever
                          expanded d.items[0] — on every other row it appeared to do nothing, and an
                          operator read "no insertion points" where the truth was "this control cannot
                          show you them" (burpsy-react-ui-d0n).

                          Disabled with its count when a row recorded none, rather than hidden: an
                          absent button is indistinguishable from a row that has points and a broken
                          toggle, which is the confusion this issue was about. Both buttons stop
                          propagation so clicking one does not toggle the row's viewer selection. */}
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
            onClick={(event) => {
             event.stopPropagation();
             setExpanded(expanded === item.seq ? null : item.seq);
            }}
           >
            {item.insertion_points?.length
             ? `${expanded === item.seq ? "Hide" : "Points"} (${item.insertion_points.length})`
             : "Points (0)"}
           </Button>
           <Button
            variant="outline"
            size="small"
            disabled={again.isPending}
            onClick={(event) => {
             event.stopPropagation();
             again.mutate(item.exchange_id, {
              onSuccess: () => toast.success(`Re-auditing exchange #${item.exchange_id}`),
              onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Re-audit failed"),
             });
            }}
           >
            Audit again
           </Button>
           {/* Cancel (burpsy-react-ui-exiu). Enabled only while the item is still queued, because that
               is the only state the server will move it from — the button is present and disabled
               with its reason rather than hidden, so a row that cannot be cancelled says so instead
               of looking like a row whose control is missing. */}
           <Button
            variant="outline"
            size="small"
            disabled={cancel.isPending || item.state !== "pending"}
            title={
             item.state === "pending"
              ? `Stop auditing exchange #${item.exchange_id} and nothing else`
              : `This item is ${item.status_label || item.state}, so it cannot be cancelled`
            }
            onClick={(event) => {
             event.stopPropagation();
             cancel.mutate(item.exchange_id, {
              onSuccess: (result) => toast.success(`Cancelled exchange #${item.exchange_id}: ${result.reason}`),
              onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Cancel failed"),
             });
            }}
           >
            Cancel
           </Button>
          </td>
         </tr>
         {expanded === item.seq && item.insertion_points?.length ? (
          <tr key={`${item.seq}-points`}>
           <td colSpan={9}>
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

     {selected ? (
      <Card>
       <SectionHeading
        title={`Seq ${selected.seq} — exchange #${selected.exchange_id}`}
        detail="The base request the audit decided about. Its state is the row above; the bytes are the context the state is about."
        actions={
         exchange ? (
          <Button
           variant="outline"
           size="small"
           onClick={() => {
            focusExchange(selected.exchange_id);
            setRoute("history");
           }}
          >
           In history
          </Button>
         ) : undefined
        }
       />
       {exchange === null ? (
        <Empty
         title="Exchange not in the loaded history"
         detail={`The queue names exchange #${selected.exchange_id}, which is outside the last 1000 captured — its bytes cannot be shown from here.`}
        />
       ) : (
        <Tabs defaultValue="request" className="tabs-fill">
         <TabsList aria-label="Audit item messages">
          <TabsTrigger value="request">Request</TabsTrigger>
          <TabsTrigger value="response">Response</TabsTrigger>
         </TabsList>
         <TabsContent value="request">
          <HttpEditor
           label="Request"
           readOnly
           value={request.data?.text ?? (request.isFetching ? "Loading request bytes…" : "No request bytes captured.")}
           filename={`audit-${selected.seq}-request.txt`}
           menuGroups={actions.menu(exchange)}
          />
         </TabsContent>
         <TabsContent value="response">
          <HttpEditor
           label="Response"
           readOnly
           value={
            exchange.response === null
             ? "No response was captured for this exchange."
             : (response.data?.text ?? (response.isFetching ? "Loading response bytes…" : "No response bytes captured."))
           }
           bodyBase64={response.data?.body_base64}
           filename={`audit-${selected.seq}-response.txt`}
           menuGroups={actions.menu(exchange)}
          />
         </TabsContent>
        </Tabs>
       )}
      </Card>
     ) : null}
    </>
   )}
  </div>
 );
}
