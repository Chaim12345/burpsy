/**
 * Wire shapes and hooks for hidden-input guessing — `/api/hidden-inputs`, Burp's Param Miner
 * "Guess params" built in (burpsy-react-ui-wlz8).
 *
 * # The fields that must not be dropped on the way to the screen
 *
 * A run that confirmed nothing is only a clean result when every name was actually tested. The
 * server keeps the difference on the wire and the dialog shows it:
 *
 *   - `state` — `unstable` (the page varies on its own, nothing was guessed), `budget` (the request
 *     budget ran out), `stopped`, `failed` and `done` are five different statements about the target.
 *   - per kind, `untested` and `unresolved` — names never sent, and names in a batch that changed
 *     the response without bisection isolating one. Non-zero means "found nothing" is a floor.
 *   - `summary` — the server's own one line with every caveat in it, shown verbatim.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys } from "./data";

export type HiddenInputKind = "query" | "cookie" | "header";

export const HIDDEN_INPUT_KINDS: { kind: HiddenInputKind; label: string; hint: string }[] = [
 { kind: "query", label: "Guess query parameters", hint: 'Burp\'s "Guess GET parameters"' },
 { kind: "cookie", label: "Guess cookies", hint: 'Burp\'s "Guess cookie parameters"' },
 { kind: "header", label: "Guess headers", hint: 'Burp\'s "Guess headers"' },
];

/** One confirmed input. Mirrors scanner.HiddenInput. */
export interface HiddenInput {
 kind: HiddenInputKind;
 name: string;
 issue: string;
 confidence: string;
 reflected: boolean;
 evidence: string;
}

/** One kind's accounting: candidates = present + settled + unresolved + untested. */
export interface HiddenKindResult {
 kind: HiddenInputKind;
 state: string;
 reason?: string;
 candidates: number;
 present: number;
 settled: number;
 unresolved: number;
 untested: number;
 unconfirmed: string[];
 found: HiddenInput[];
}

export interface HiddenInputResult {
 exchange_id: number;
 state: string;
 reason?: string;
 requests_sent: number;
 request_budget: number;
 kinds: HiddenKindResult[];
 inputs: HiddenInput[];
 summary: string;
}

export interface HiddenInputRun {
 task_id: number;
 exchange_id: number;
 target: string;
 kinds: HiddenInputKind[];
 /** running, then the engine's terminal state. */
 state: string;
 started: string;
 finished?: string;
 /** Null while running: no result yet is not an empty result. */
 result: HiddenInputResult | null;
 finding_ids: number[];
 summary: string;
}

export interface StartHiddenInputsRequest {
 exchange_id: number;
 kinds: HiddenInputKind[];
 max_requests?: number;
 cache_buster?: boolean;
}

export interface StartHiddenInputsResponse {
 task_id: number;
 exchange_id: number;
 target: string;
 kinds: HiddenInputKind[];
 budget: number;
 state: string;
}

export const hiddenInputsKey = (taskId: number) => [...keys.hiddenInputs, taskId] as const;

/**
 * One run, by task id. Polled while it runs as a backstop; the server's dashboard and issues
 * events also invalidate the ["hidden-inputs"] prefix when it finishes (INVALIDATION in data.ts).
 */
export function useHiddenInputRun(taskId: number | null): ReturnType<typeof useQuery<HiddenInputRun>> {
 return useQuery({
  queryKey: hiddenInputsKey(taskId ?? -1),
  enabled: taskId !== null,
  queryFn: ({ signal }) => api<HiddenInputRun>(`/api/hidden-inputs?task=${taskId}`, { signal }),
  refetchInterval: (query) => (query.state.data?.state === "running" ? 1_500 : false),
 });
}

export function useStartHiddenInputs() {
 const client = useQueryClient();
 return useMutation({
  mutationFn: (request: StartHiddenInputsRequest) => api<StartHiddenInputsResponse>("/api/hidden-inputs", json("POST", request)),
  onSuccess: () => {
   void client.invalidateQueries({ queryKey: keys.hiddenInputs });
   void client.invalidateQueries({ queryKey: keys.dashboard });
  },
 });
}
