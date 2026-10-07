// Issue consolidation (burpsy-react-ui-oorl): what the finding store does when a new finding is the
// same issue at the same place as an existing one — and what it has done so far.
//
// Served by internal/web/api_issue_consolidation.go at /api/issues/consolidation (GET/PUT, riskLocal).

import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json } from "./api";

export type ConsolidationAction = "keep_existing" | "keep_both" | "keep_new";

export interface ConsolidationTally {
 collisions: number;
 merged: number;
 replaced: number;
 kept_both: number;
}

export interface ConsolidationView {
 default: ConsolidationAction;
 per_row: Record<string, ConsolidationAction>;
 tally: ConsolidationTally;
 by_task: (ConsolidationTally & { task_id: number })[];
 /** Rows the store never merges whatever the action; an override on one would be inert. */
 never_merge: string[];
}

export interface ConsolidationPolicy {
 default: ConsolidationAction;
 per_row: Record<string, ConsolidationAction>;
}

export const CONSOLIDATION_ACTIONS: { value: ConsolidationAction; label: string; hint: string }[] = [
 {
  value: "keep_existing",
  label: "Keep existing (merge)",
  hint: "fold the duplicate into the issue already reported — occurrences added, severity raised",
 },
 {
  value: "keep_both",
  label: "Keep both",
  hint: "report the duplicate as its own issue; a host-wide passive check then files one per response",
 },
 {
  value: "keep_new",
  label: "Keep new",
  hint: "replace the reported issue's detail with the newer observation, severity included",
 },
];

// Under the "issues" prefix on purpose: every finding change invalidates ["issues"], and the tallies
// change with exactly those events.
const consolidationKey = ["issues", "consolidation"] as const;

export function useIssueConsolidation(): UseQueryResult<ConsolidationView> {
 return useQuery({
  queryKey: consolidationKey,
  queryFn: ({ signal }) => api<ConsolidationView>("/api/issues/consolidation", { signal }),
 });
}

export function useSetIssueConsolidation() {
 const client = useQueryClient();
 return useMutation<ConsolidationView, Error, ConsolidationPolicy>({
  mutationFn: (policy) => api<ConsolidationView>("/api/issues/consolidation", json("PUT", policy)),
  onSuccess: (view) => client.setQueryData(consolidationKey, view),
 });
}
