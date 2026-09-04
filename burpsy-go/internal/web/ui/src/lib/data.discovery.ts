/**
 * Wire shapes and hooks for content discovery — `/api/discovery`, ffuf behind
 * `extscan`.
 *
 * The engine has been complete and tested since it was written; what did not
 * exist was any way to reach it from the console, so an operator's only route to
 * it was `burpsy extscan` on the command line. That is the whole of issue 519.
 *
 * # The fields that must not be dropped on the way to the screen
 *
 * This endpoint is unusually careful about the difference between "swept and
 * found nothing" and "never swept", and a UI that renders only `discoveries`
 * would throw exactly that distinction away. Three fields carry it:
 *
 *   - `looked` — whether ffuf actually examined the target. An empty
 *     `discoveries` may be read as "nothing is there" only when this is true.
 *   - `outcome` — extscan's own six-state verdict, not derivable from the list
 *     length, which is why the server puts it on the wire.
 *   - `counts.out_of_scope` — reported paths the engagement scope refused. A
 *     sweep that matched forty paths and discarded thirty-nine must not render
 *     identically to one that matched one.
 *
 * `summary` is the server's own one-line statement of all three. The page shows
 * it verbatim rather than composing its own sentence, so there is one wording of
 * the caveat and it lives next to the logic that knows it.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys } from "./data";

/** One path ffuf reported and scope allowed. Mirrors extscan.Discovery. */
export interface Discovery {
  url: string;
  path: string;
  word?: string;
  status: number;
  length: number;
  words: number;
  lines: number;
  content_type?: string;
  /** ffuf's redirectlocation. A 301 to /admin/ and a 301 to /login are different discoveries. */
  redirect?: string;
  host: string;
}

export interface DiscoveryStatusCount {
  status: number;
  count: number;
}

export interface DiscoveryCounts {
  discovered: number;
  out_of_scope: number;
  by_status: DiscoveryStatusCount[];
}

export interface DiscoveryRun {
  task_id: number;
  target: string;
  wordlist: string;
  extensions?: string;
  match_codes?: string;
  /** running | done | stopped | failed. */
  state: string;
  started: string;
  finished?: string;
  outcome: string;
  looked: boolean;
  error?: string;
  /** The argv that ran, so a reader can see what was executed against the target. */
  command?: string[];
  exit_code: number;
  discoveries: Discovery[];
  counts: DiscoveryCounts;
  summary: string;
}

/**
 * Whether this server could run a sweep at all.
 *
 * `reason` is empty exactly when `available` is true. The server refuses rather
 * than answering 200 with an empty list, because an empty list reads as "content
 * discovery found nothing here" — so the console must show the reason with the
 * same weight it would show a result.
 */
export interface DiscoveryToolState {
  name: string;
  allowlisted: boolean;
  available: boolean;
  reason?: string;
}

export interface DiscoveryIndex {
  tool: DiscoveryToolState;
  runs: DiscoveryRun[];
  /** How many runs the server retains; older ones are gone, not hidden. */
  retained: number;
}

export interface StartDiscoveryRequest {
  target: string;
  wordlist: string;
  extensions?: string;
  match_codes?: string;
  threads?: number;
  rate?: number;
}

export interface StartDiscoveryResponse {
  task_id: number;
  target: string;
  state: string;
}

/**
 * The run list and the tool state together, because they are one answer: a list
 * of zero runs means something different when the tool is missing.
 *
 * Polled while anything is running, and otherwise left alone. The server also
 * emits a dashboard event when a run finishes — see INVALIDATION in data.ts —
 * so the poll is a backstop for a dropped event rather than the only path.
 */
export function useDiscoveryRuns(): ReturnType<typeof useQuery<DiscoveryIndex>> {
  return useQuery({
    queryKey: keys.discovery,
    queryFn: ({ signal }) => api<DiscoveryIndex>("/api/discovery", { signal }),
    refetchInterval: (query) =>
      (query.state.data?.runs ?? []).some((run) => run.state === "running") ? 2_000 : false,
  });
}

export function useStartDiscovery() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: StartDiscoveryRequest) =>
      api<StartDiscoveryResponse>("/api/discovery", json("POST", request)),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: keys.discovery });
      // The dashboard gains a task row for the run, and it is the same identity —
      // the task id keys both — so refresh it rather than leave the two disagreeing.
      void client.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}
