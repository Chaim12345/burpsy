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
  note?: string;
  attempts: number;
  insertion_points?: { kind: string; name: string; status: number; detail?: string }[];
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
  parity: { burp_statuses_declared: number; burp_statuses_modelled: number; burp_statuses_not_modelled?: { status: string; label: string; why: string }[] };
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
export function useAuditItemAgain() {
  const client = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: (exchangeId) =>
      api<unknown>(`/api/scanner/audit-items/${exchangeId}/again`, json("POST", {})),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.auditItems }),
  });
}
