/**
 * Query hooks for the attack-area pages (Intercept, Scanner). Built on the same `useResource`/`keys`
 * the shared hooks in `data.ts` use, so where an endpoint is already read there the cache entry is
 * the same entry the event stream invalidates — only the static type of what comes back differs.
 * Endpoints with no shared hook at all (intercept rules, scanner live/coverage/configs, audit) live
 * here in full.
 */
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys, useResource } from "./data";
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
 */
export function useForwardHeld() {
  const client = useQueryClient();
  return useMutation<unknown, Error, { id: number; raw: string; fixContentLength: boolean }>({
    mutationFn: ({ id, raw, fixContentLength }) =>
      api<unknown>(`/api/intercept/${id}/forward`, json("POST", { raw, fix_content_length: fixContentLength })),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.intercept }),
  });
}

/* --- scanner -------------------------------------------------------------- */

/** Same endpoint and cache key as the shared `useIssues`, typed to the full finding shape (`id`, and
 * nullable detail/remediation) that stable row selection and honest empty text need. */
export const useIssuesDetailed = () => useResource<IssuesDetail>(keys.issues, "/api/issues");

export const useScannerConfigs = () => useResource<ScannerConfigsResponse>(keys.scannerConfigs, "/api/scanner/configs");

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
  return useMutation<LiveAuditState, Error, { enabled: boolean; query?: string }>({
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
