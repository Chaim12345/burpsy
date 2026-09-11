import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys, useResource } from "./data";
import type {
 EventHubStats,
 FrameProgramRequest,
 FrameProgramResponse,
 MatchReplaceTestRequest,
 MatchReplaceTestResponse,
 PassthroughView,
 ProtocolReport,
 ScopeUpdate,
 ScopeView,
 SessionCookiesResponse,
 SessionLoginResponse,
 SessionMacroStep,
 SessionRulesResponse,
 SessionTestResponse,
} from "./types.policy";

/** Keys not already declared in data.ts. Prefix-compatible with the event-stream invalidation map. */
export const policyKeys = {
 eventStats: ["events", "stats"] as const,
 caCert: ["ca-cert"] as const,
 caStatus: ["ca-status"] as const,
 passthrough: ["tls-passthrough"] as const,
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

/** One cookie-jar write (dkb): Burp's "edit cookies manually, remove cookies from the jar, or
 *  empty the jar altogether". The response reports what changed, so the caller can toast the
 *  difference between "done" and "it was not there". */
export interface CookieJarWriteResult {
 action: "set" | "remove" | "clear";
 host?: string;
 name?: string;
 ok?: boolean;
 removed?: boolean;
 cleared?: boolean;
}

export function useCookieJarWrite() {
 const client = useQueryClient();
 return useMutation<CookieJarWriteResult, Error, { action: "set" | "remove" | "clear"; host: string; port: number; tls: boolean; name?: string; value?: string }>({
  mutationFn: (vars) => api<CookieJarWriteResult>("/api/session/cookies", json("POST", vars)),
  onSuccess: () => void client.invalidateQueries({ queryKey: keys.sessionCookies }),
 });
}

export const useProtocols = (): UseQueryResult<ProtocolReport> =>
 useResource<ProtocolReport>(keys.protocols, "/api/protocols");

export const useEventHubStats = (): UseQueryResult<EventHubStats> =>
 useResource<EventHubStats>(policyKeys.eventStats, "/api/events/stats");

/** The live TLS passthrough list. Edits through the mutations below take effect immediately. */
export const usePassthrough = (): UseQueryResult<PassthroughView> =>
 useResource<PassthroughView>(policyKeys.passthrough, "/api/proxy/passthrough");

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

/** Which CA is signing intercepted TLS right now. Subject and expiry only — never the key. */
export interface CaStatus {
 configured: boolean;
 subject?: string;
 not_after?: string;
 persisted: boolean;
 persist_error?: string;
 hint?: string;
}

export const useCaStatus = (): UseQueryResult<CaStatus> =>
 useResource<CaStatus>(policyKeys.caStatus, "/api/proxy/ca");

/**
 * Import the operator's own CA — Burp's `configPanelCustomCACertificates`.
 *
 * Before this the capability was filesystem-only: `LoadOrGenerateCA` reads `ca.crt`/`ca.key` from
 * `-ca-dir` at startup, so bringing your own CA meant stopping burpsy, placing two files and
 * starting again — losing every exchange captured so far.
 *
 * The server validates the pair before replacing anything, so a refusal leaves the running CA
 * signing exactly as it was; a certificate that could not sign would otherwise take HTTPS
 * interception down completely. On success it also empties the per-host leaf cache, because every
 * cached leaf was signed by the CA just replaced.
 *
 * Invalidates the `/ca.crt` probe as well as the status: the download link must now serve the new
 * certificate, and an operator installing the old one would be trusting a CA that signs nothing.
 */
export function useImportCaCert() {
 const client = useQueryClient();
 return useMutation<CaStatus, Error, { cert_pem: string; key_pem: string }>({
  mutationFn: (body) => api<CaStatus>("/api/proxy/ca/import", json("POST", body)),
  onSuccess: () => {
   void client.invalidateQueries({ queryKey: policyKeys.caStatus });
   void client.invalidateQueries({ queryKey: policyKeys.caCert });
  },
 });
}

/** What a project backup reports. Mirrors internal/web/api_backup.go's backupResult. */
export interface BackupResult {
 path: string;
 bytes: number;
 pruned: number;
 kept: number;
 /**
  * A partial success — most often that the snapshot landed beside the live database, where a disk
  * failure loses both. Surfaced rather than swallowed: a backup with a caveat is not a clean backup.
  */
 warning?: string;
}

/**
 * Snapshot the project database now — Burp's `configPanelAutomaticProjectBackup` (W6 #2), which had
 * no counterpart here: persistence existed and nothing ever copied it, so losing the machine lost
 * the engagement.
 *
 * The snapshot is taken with SQLite's `VACUUM INTO`, not a file copy. This store runs in WAL mode, so
 * the main database file alone is not a database anyone can open — a `cp`-style backup produces a
 * file of plausible size that opens to a corrupt schema.
 *
 * Beware the retention parameter: snapshots beyond the count are deleted, oldest first. Pass -1 to
 * keep everything.
 */
export function useBackupNow() {
 return useMutation<BackupResult, Error, { dir?: string; retention?: number }>({
  mutationFn: (body) => api<BackupResult>("/api/backup", json("POST", body)),
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
 * Move one rule within the evaluation order by a signed offset (-1 = up, +1 = down).
 * MatchingRule runs the *first* enabled rule whose scope covers a host, so position is
 * precedence; the server refuses a move past either end with a 400 naming the edge
 * (ErrRuleAtEdge) rather than silently clamping, and an unknown id with a 404.
 */
export function useMoveSessionRule() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: ({ id, offset }: { id: number; offset: number }) =>
   api<{ position: number }>(`/api/session/rules/${id}/move`, json("POST", { offset })),
  onSuccess: () => invalidate([["session"]]),
 });
}

/**
 * POST /api/session/rules/{id}/test — Burp's "Test macro" (burpsy-react-ui-7zdm): a dry-run of the
 * rule's steps. Deliberately no cache invalidation: the dry-run is read-only by contract (it writes
 * nothing to the login-run memory), and the cookie jar DOES move — which the report shows per step,
 * so re-rendering the page from a shifted jar mid-read would misstate what the run did.
 */
export function useTestSessionRule() {
 return useMutation({
  mutationFn: (id: number) =>
   api<SessionTestResponse>(`/api/session/rules/${id}/test`, json("POST", {})),
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

/**
 * POST /api/scope. One action per call — the handler has no batch arm. "toggle" is the
 * per-rule enable/disable switch (burpsy-react-ui-1xb): the tuple names the row, `enabled`
 * is the target state, and a 404 means the row moved on under a stale render.
 */
export function useUpdateScope() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (update: ScopeUpdate) => api<unknown>("/api/scope", json("POST", update)),
  onSuccess: () => invalidate([keys.scope]),
 });
}

/** POST /api/proxy/passthrough — append one host pattern; the reply is the confirmed list. */
export function useAddPassthrough() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (pattern: string) => api<PassthroughView>("/api/proxy/passthrough", json("POST", { pattern })),
  onSuccess: () => invalidate([policyKeys.passthrough]),
 });
}

/**
 * DELETE /api/proxy/passthrough?pattern=… — take back exactly the named rule.
 * The server answers 404 for a pattern that is not there, so a stale row's
 * remove surfaces as an error toast instead of silently "succeeding".
 */
export function useRemovePassthrough() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (pattern: string) =>
   api<PassthroughView>(`/api/proxy/passthrough?pattern=${encodeURIComponent(pattern)}`, json("DELETE")),
  onSuccess: () => invalidate([policyKeys.passthrough]),
 });
}
