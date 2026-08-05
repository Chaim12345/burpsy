import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys, useResource } from "./data";
import type {
  EventHubStats,
  FrameProgramRequest,
  FrameProgramResponse,
  MatchReplaceTestRequest,
  MatchReplaceTestResponse,
  ProtocolReport,
  ScopeUpdate,
  ScopeView,
  SessionCookiesResponse,
  SessionLoginResponse,
  SessionMacroStep,
  SessionRulesResponse,
} from "./types.policy";

/** Keys not already declared in data.ts. Prefix-compatible with the event-stream invalidation map. */
export const policyKeys = {
  eventStats: ["events", "stats"] as const,
  caCert: ["ca-cert"] as const,
};

export interface CaCertState {
  available: boolean;
  /** The server's own reason when there is no certificate to import. */
  detail: string;
}

/* --- reads --------------------------------------------------------------- */

/**
 * /api/scope in the shape the Go handler actually serves ({kind, host} plus `empty`),
 * which is not what types.ts's `Scope` describes. Shares the ["scope"] key so a
 * scope change invalidates both readers.
 */
export const useScopeView = (): UseQueryResult<ScopeView> => useResource<ScopeView>(keys.scope, "/api/scope");

/** The full session rule shape: steps, extractions, validity, scope, max_attempts. */
export const useSessionRulesFull = (): UseQueryResult<SessionRulesResponse> =>
  useResource<SessionRulesResponse>(keys.sessionRules, "/api/session/rules");

export const useSessionCookies = (): UseQueryResult<SessionCookiesResponse> =>
  useResource<SessionCookiesResponse>(keys.sessionCookies, "/api/session/cookies");

export const useProtocols = (): UseQueryResult<ProtocolReport> =>
  useResource<ProtocolReport>(keys.protocols, "/api/protocols");

export const useEventHubStats = (): UseQueryResult<EventHubStats> =>
  useResource<EventHubStats>(policyKeys.eventStats, "/api/events/stats");

/**
 * Whether there is a CA to import. /ca.crt is not JSON and answers 404 when TLS
 * interception is off, which is exactly the case the operator needs told — so it is
 * probed with HEAD and the failure text is kept.
 */
export function useCaCert(): UseQueryResult<CaCertState> {
  return useQuery({
    queryKey: policyKeys.caCert,
    queryFn: async ({ signal }): Promise<CaCertState> => {
      const response = await fetch("/ca.crt", { method: "HEAD", signal });
      if (response.ok) return { available: true, detail: "" };
      return {
        available: false,
        detail:
          response.status === 404
            ? "TLS interception is not enabled, so there is no CA to trust. Start burpsy with -intercept-tls."
            : `The proxy answered ${response.status} for /ca.crt.`,
      };
    },
  });
}

/* --- writes -------------------------------------------------------------- */

function useInvalidate(): (prefixes: readonly (readonly unknown[])[]) => void {
  const client = useQueryClient();
  return (prefixes) => {
    for (const prefix of prefixes) void client.invalidateQueries({ queryKey: prefix });
  };
}

/**
 * Dry-run the draft rule set. Nothing is persisted: the server compiles `draft_rules`
 * into a throwaway rule set, so a half-typed rule can never reach live traffic.
 */
export function useTestMatchReplace() {
  return useMutation({
    mutationFn: (request: MatchReplaceTestRequest) =>
      api<MatchReplaceTestResponse>("/api/tools/rules/test", json("POST", request)),
  });
}

/** POST /api/session/login with a probe step; the reply names one of eight outcomes. */
export function useSessionLogin() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (probe: SessionMacroStep) =>
      api<SessionLoginResponse>("/api/session/login", json("POST", { probe })),
    onSuccess: () => invalidate([["session"]]),
  });
}

/**
 * Promote what the last login run actually sent onto the rule's stored macro.
 * Answers 409 when nothing was observed, so it is only offered after a `recovered` run.
 */
export function useUpdateSessionMacro() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (id: number) =>
      api<{ steps: SessionMacroStep[] }>(`/api/session/rules/${id}/update-macro`, json("POST", {})),
    onSuccess: () => invalidate([["session"]]),
  });
}

/**
 * Send a frame program to one authority. With no frames it is a preface-and-listen
 * probe: it reports what ALPN negotiated and what the peer sent back.
 */
export function useSendFrameProgram() {
  return useMutation({
    mutationFn: (request: FrameProgramRequest) =>
      api<FrameProgramResponse>("/api/http2/program", json("POST", request)),
  });
}

/** POST /api/scope. One action per call — the handler has no batch arm. */
export function useUpdateScope() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (update: ScopeUpdate) => api<unknown>("/api/scope", json("POST", update)),
    onSuccess: () => invalidate([keys.scope]),
  });
}
