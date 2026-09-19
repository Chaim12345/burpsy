/**
 * Query hooks for the attack-area pages (Intercept, Scanner). Built on the same `useResource`/`keys`
 * the shared hooks in `data.ts` use, so where an endpoint is already read there the cache entry is
 * the same entry the event stream invalidates — only the static type of what comes back differs.
 * Endpoints with no shared hook at all (intercept rules, scanner live/coverage/configs, audit) live
 * here in full.
 */
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys, useInvalidate, useResource } from "./data";
import type { InterceptTarget } from "./intercept-target";
import type { IssueTriagePatch } from "./issue-triage";
import type {
 AuditResult,
 InterceptListState,
 InterceptStateDetail,
 IssuesDetail,
 LiveAuditState,
 ScannerConfigsResponse,
 ScannerCoverage,
} from "./types.attack";

/**
 * The four directions the proxy can hold, named exactly as the backend's
 * `interceptDirectionNames` table spells them — these strings are the URL suffix for
 * `/api/intercept/rules/{dir}` and the keys inside an exported config bundle, so a typo here is a
 * 404 rather than a type error.
 *
 * The WebSocket pair arrived with 626ac5f, which made `internal/proxy/ws.go` actually hold frames.
 * Before that the backend could describe a WebSocket hold but never performed one, so shipping
 * these two as UI would have produced controls that render, accept input, return 200 and change
 * nothing — the single decorative control the parity audit went looking for.
 */
export type InterceptDirection =
 | "requests"
 | "responses"
 | "websocket_to_server"
 | "websocket_to_client";

/**
 * Keys for the attack-area resources. The intercept-rules key keeps the "intercept" prefix the event
 * stream already invalidates (see INVALIDATION in data.ts), so a server-side rule change still
 * refreshes these views.
 */
export const attackKeys = {
 interceptRules: (dir: InterceptDirection) => ["intercept", "rules", dir] as const,
};

/* --- intercept ------------------------------------------------------------ */

/**
 * Same endpoint and cache key as the shared `useIntercept`, typed to the full held-message shape
 * (port, tls, status, held_ms, len) the queue table needs.
 *
 * Still polls: a held message blocks its connection with an operator sitting there waiting for the
 * row to appear, so this is the one surface where "as it happens" and "within a beat" differ.
 */
export function useInterceptDetailed(pollMs = 1_500): UseQueryResult<InterceptStateDetail> {
 return useQuery({
  queryKey: keys.intercept,
  queryFn: ({ signal }) => api<InterceptStateDetail>("/api/intercept", { signal }),
  refetchInterval: pollMs,
  staleTime: 0,
 });
}

/** Annotate one held message (burpsy-react-ui-5q8u): POST {comment, highlight} to
 * /api/intercept/annotate/{id} — "annotate" in the first segment cannot be an id, so it
 * cannot collide with the queue's /{id}/forward|drop paths. Empty highlight clears; the
 * queue re-renders from the poll it already runs. */
export function useAnnotateHeld() {
 const client = useQueryClient();
 return useMutation<unknown, Error, { id: number; comment: string; highlight: string }>({
  mutationFn: ({ id, comment, highlight }) =>
   api(`/api/intercept/annotate/${id}`, json("POST", { comment, highlight })),
  onSuccess: () => void client.invalidateQueries({ queryKey: keys.intercept }),
 });
}

export const useInterceptRules = (dir: InterceptDirection) =>
 useResource<InterceptListState>(attackKeys.interceptRules(dir), `/api/intercept/rules/${dir}`);

/**
 * Save one direction's rule list. The server compiles every pattern and refuses the whole list on a
 * bad one, so a rejected save leaves both the proxy's list and the operator's on-screen edit
 * untouched rather than half-applying rows — a bad pattern is something to fix, not to retype.
 */
export function useSaveInterceptRules(dir: InterceptDirection) {
 const client = useQueryClient();
 return useMutation<InterceptListState, Error, Pick<InterceptListState, "active" | "rules">>({
  mutationFn: (state) => api<InterceptListState>(`/api/intercept/rules/${dir}`, json("PUT", state)),
  onSuccess: () => {
   void client.invalidateQueries({ queryKey: attackKeys.interceptRules(dir) });
   void client.invalidateQueries({ queryKey: keys.intercept });
  },
 });
}

/**
 * Forward a held message with the operator's edited bytes.
 *
 * Distinct from the shared `useInterceptControls().forward`, which hard-codes `fix_content_length`
 * to true: rewriting a body and having the length silently corrected is usually what an operator
 * wants, but testing how a server handles a mismatched Content-Length is a real thing to do, so the
 * flag is a parameter here rather than a decision made for them.
 *
 * `target` is Burp's "Edit target" pencil (burpsy-react-ui-akv): the destination this one request goes
 * to, when the operator pointed it somewhere other than where the client asked. It is sent as all
 * three fields or none at all — the server refuses a partial destination rather than inheriting the
 * fields it left out, because an inherited port is a destination nobody typed. `undefined` is the
 * ordinary forward and the only shape every other caller needs.
 */
export function useForwardHeld() {
 const client = useQueryClient();
 return useMutation<
  unknown,
  Error,
  { id: number; raw: string; fixContentLength: boolean; holdResponse?: boolean; target?: InterceptTarget }
 >({
  mutationFn: ({ id, raw, fixContentLength, holdResponse, target }) =>
   api<unknown>(
    `/api/intercept/${id}/forward`,
    json("POST", {
     raw,
     fix_content_length: fixContentLength,
     hold_response: holdResponse ?? false,
     ...(target ? { host: target.host, port: target.port, tls: target.tls } : {}),
    }),
   ),
  onSuccess: () => void client.invalidateQueries({ queryKey: keys.intercept }),
 });
}

/* --- scanner -------------------------------------------------------------- */

/** Same endpoint and cache key as the shared `useIssues`, typed to the full finding shape (`id`, and
 * nullable detail/remediation) that stable row selection and honest empty text need. */
export const useIssuesDetailed = () => useResource<IssuesDetail>(keys.issues, "/api/issues");

/**
 * The triage writes (burpsy-react-ui-pwd): PUT /api/issues/{id} for severity, confidence,
 * false-positive and comment decisions, DELETE /api/issues/{id} to remove the finding. The PUT body
 * semantics are the backend's total-replacement contract: a present `severity` sets an override and
 * an *empty string* clears it, so "no override" is expressible — a partial protocol would turn a
 * cleared override into a ghost that survives restarts. Success invalidates the issues cache the
 * same server-pushed `issues` events do, plus the dashboard, whose severity counts triage moves.
 */
export function useIssueTriage() {
 const client = useQueryClient();
 const done = () => {
  void client.invalidateQueries({ queryKey: keys.issues });
  void client.invalidateQueries({ queryKey: keys.dashboard });
 };
 return {
  triage: useMutation<unknown, Error, { id: number; patch: IssueTriagePatch }>({
   mutationFn: ({ id, patch }) => api<unknown>(`/api/issues/${id}`, json("PUT", patch)),
   onSuccess: done,
  }),
  remove: useMutation<unknown, Error, number>({
   mutationFn: (id) => api<unknown>(`/api/issues/${id}`, { method: "DELETE" }),
   onSuccess: done,
  }),
 };
}

/** POST /api/tasks/{id}/again — Burp's "Scan again" on a dashboard task row
 * (burpsy-react-ui-r6q). Only crawl tasks re-run: the re-run goes through the same start path the
 * New scan dialog uses, and the server answers 409 naming the refusal for any other kind, which
 * the toast passes through rather than flattening into a generic failure. */
export function useScanTaskAgain() {
 const invalidate = useInvalidate();
 return useMutation<unknown, Error, number>({
  mutationFn: (id) => api<unknown>(`/api/tasks/${id}/again`, { method: "POST" }),
  onSuccess: () => invalidate([keys.dashboard, keys.crawls]),
 });
}

/** DELETE /api/tasks/{id} — remove a finished task's row from the list. The row is burpsy's own
 * state about past work, so no confirmation: the findings, exchanges and coverage the row pointed
 * at live elsewhere and survive it. A running task answers 409 and the toast says to cancel first. */
export function useDeleteTask() {
 const invalidate = useInvalidate();
 return useMutation<unknown, Error, number>({
  mutationFn: (id) => api<unknown>(`/api/tasks/${id}`, { method: "DELETE" }),
  onSuccess: () => invalidate([keys.dashboard]),
 });
}

export const useScannerConfigs = () => useResource<ScannerConfigsResponse>(keys.scannerConfigs, "/api/scanner/configs");

/**
 * Burp's Configuration library (burpsy-react-ui-uxcs): save, clone, rename and delete a named scan
 * configuration. One mutation for all four because they share a route, a refusal vocabulary and an
 * invalidation — a shipped name is refused with 409 whichever verb asks.
 */
export function useScanConfigLibrary() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (body: { action: "save" | "clone" | "rename" | "delete"; name: string; from?: string }) =>
   api<Record<string, unknown>>("/api/scanner/configs", json(body.action === "delete" ? "DELETE" : "POST", body)),
  onSuccess: () => invalidate([keys.scannerConfigs]),
 });
}

export const useScannerCoverage = () => useResource<ScannerCoverage>(keys.scannerCoverage, "/api/scanner/coverage");

/** Polls like Intercept: the sweep's swept/behind counters move as traffic is captured, and an
 * operator watching progress should see it advance between event-stream bursts. */
export function useScannerLive(pollMs = 2_000): UseQueryResult<LiveAuditState> {
 return useQuery({
  queryKey: keys.scannerLive,
  queryFn: ({ signal }) => api<LiveAuditState>("/api/scanner/live", { signal }),
  refetchInterval: pollMs,
  staleTime: 0,
 });
}

/**
 * Flips the live-audit switch. The server's answer is the new state, so a refused POST cannot leave
 * the switch showing a state the sweep is not in. `query` is omitted rather than sent empty when the
 * caller only means to toggle: an empty string is the explicit way to clear an installed filter, and
 * collapsing the two would silently widen every toggle back to the whole engagement scope.
 */
export function useSetScannerLive() {
 const client = useQueryClient();
 return useMutation<LiveAuditState, Error, { enabled: boolean; query?: string; retry_stalled?: boolean; traffic_source?: string }>({
  mutationFn: (body) => api<LiveAuditState>("/api/scanner/live", json("POST", body)),
  onSuccess: () => void client.invalidateQueries({ queryKey: keys.scannerLive }),
 });
}

/**
 * Runs the active audit against one exchange, optionally under a named built-in configuration.
 *
 * The result is returned to the caller rather than cached: this sends real traffic, and re-running
 * the same id can legitimately produce a different outcome, so there is nothing here a later reader
 * should be handed as if it were current state.
 */
export function useRunAudit() {
 const client = useQueryClient();
 return useMutation<AuditResult, Error, { exchangeId: number; config?: string }>({
  mutationFn: ({ exchangeId, config }) =>
   api<AuditResult>(`/api/audit/${exchangeId}`, json("POST", config ? { config } : {})),
  onSuccess: () => {
   void client.invalidateQueries({ queryKey: keys.issues });
   void client.invalidateQueries({ queryKey: keys.dashboard });
  },
 });
}
