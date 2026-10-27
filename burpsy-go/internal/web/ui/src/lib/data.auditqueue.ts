/**
 * Query hooks for the audit-items queue — the SCANNER-tab data. The server's
 * view carries its own honesty machinery (parity counts, caveats, a reason when
 * nothing has been queued), so the hooks stay thin: fetch, expose, let the page
 * render what the engine said rather than derive a rosier summary.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys } from "./data";

export interface AuditItemRow {
 exchange_id: number;
 seq: number;
 method: string;
 host: string;
 port: number;
 tls: boolean;
 path: string;
 state: string;
 status_label: string;
 burp_status: string;
 /** The URL-level verdict (burpsy-react-ui-87fq): AUDITABLE, NETWORK_ERROR, or absent. Distinct from
  *  the per-check dispositions in `outcome`. */
 url_disposition?: string;
 note?: string;
 attempts: number;
 insertion_points?: { kind: string; name: string; status: number; detail?: string }[];

 /**
  * The evidence the engine retained per item, which the page now renders (burpsy-react-ui-xdtx).
  *
  * Every one of these was already on the wire — the endpoint hands out `scanner.AuditItem`
  * wholesale — and none of it was declared here, so the page reduced a diagnosable audit to six
  * state totals. Burp's audit-item page exposes phase, requests, errors, insertion points scanned
  * and start/end time precisely so a PARTIAL audit can be diagnosed; an item that stopped after
  * two of five steps is finished and 40% audited, and both facts are needed at once.
  *
  * A missing field is absent rather than zero. `steps_planned` is zero for an item refused before
  * planning, which is not the same as a plan of length zero that finished — a percentage over a
  * zero denominator is undefined, and this type does not invite computing one.
  */
 /** How many (unit, check) steps this item planned, and how many reached a disposition. */
 steps_planned?: number;
 steps_done?: number;
 /** The plan's shape: how many dispatch units the item was broken into. */
 units_planned?: number;
 /** The size of the enabled check set this item was measured against. */
 checks?: number;
 /** How many insertion points were enumerated, dropped at the per-request ceiling, and refused
  *  outright — three counts that must never be collapsed into one. */
 points_enumerated?: number;
 points_skipped?: number;
 points_declined_places?: number;
 /** Which insertion-point kinds the points were enumerated for. "9 insertion points" is a claim
  *  about these kinds, not about every place a payload could go. */
 point_kinds?: string[];
 /** When the item was queued and when its row last changed — the two timestamps Burp shows, and
  *  the only way to tell a slow item from a stalled one. */
 queued_unix_ms?: number;
 updated_unix_ms?: number;
}

export interface AuditItemsResponse {
 items: AuditItemRow[];
 returned: number;
 truncated: boolean;
 queue: { retained: number; enqueued: number; evicted: number; cap: number };
 states: { state: string; status_label: string; burp_status: string; count: number; completed_audit: boolean }[];
 totals: {
  items_retained: number;
  items_completed_audit: number;
  items_bounded: number;
  items_failed: number;
  items_paused: number;
  items_out_of_scope: number;
  items_unauditable: number;
  items_pending: number;
  items_auditing: number;
  checks_considered: number;
  checks_ran: number;
  checks_not_admitted: number;
  findings: number;
 };
 parity: {
  burp_statuses_declared: number;
  burp_statuses_modelled: number;
  burp_statuses_not_modelled?: { status: string; label: string; why: string }[];
 };
 caveats: Record<string, unknown>;
 reason?: string;
}

export function useAuditItems(): ReturnType<typeof useQuery<AuditItemsResponse>> {
 return useQuery({
  queryKey: keys.auditItems,
  queryFn: ({ signal }) => api<AuditItemsResponse>("/api/scanner/audit-items", { signal }),
  refetchInterval: 3_000,
 });
}

/** Burp's auditItemContextMenuAuditAgain: re-run the whole check set against a live target. */
/**
 * Burp's `auditItemContextMenuCancel` (running-scans/results/audit-items/index.html:102-115).
 *
 * Stops ONE queued item and nothing else (burpsy-react-ui-exiu). The alternatives were waiting for
 * a slow or heavily-guarded URL to exhaust its own bounds, or disabling the enclosing live task,
 * which stops every item including the ones that were fine.
 *
 * A refusal surfaces rather than being swallowed: the server answers 409 with the reason — the item
 * already finished, or the queue does not hold it — and a cancel that appeared to work while the
 * item kept auditing is worse than a control nobody had.
 */
export function useAuditItemCancel() {
 const client = useQueryClient();
 return useMutation<{ status: string; reason: string }, Error, number>({
  mutationFn: (exchangeId) => api<{ status: string; reason: string }>(`/api/scanner/audit-items/${exchangeId}/cancel`, json("POST", {})),
  onSuccess: () => void client.invalidateQueries({ queryKey: keys.auditItems }),
 });
}

export function useAuditItemAgain() {
 const client = useQueryClient();
 return useMutation<unknown, Error, number>({
  mutationFn: (exchangeId) => api<unknown>(`/api/scanner/audit-items/${exchangeId}/again`, json("POST", {})),
  onSuccess: () => void client.invalidateQueries({ queryKey: keys.auditItems }),
 });
}
