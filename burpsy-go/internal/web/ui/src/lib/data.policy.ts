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
 SessionAnalyzeResponse,
 SessionTraceResponse,
 SessionTraceEnableResponse,
 SessionApplyExtractionsResponse,
} from "./types.policy";

/** Keys not already declared in data.ts. Prefix-compatible with the event-stream invalidation map. */
export const policyKeys = {
 eventStats: ["events", "stats"] as const,
 caCert: ["ca-cert"] as const,
 caStatus: ["ca-status"] as const,
 passthrough: ["tls-passthrough"] as const,
 sessionTrace: ["session", "trace"] as const,
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
export const useScopeView = (): UseQueryResult<ScopeViewWithLibraries> =>
 useResource<ScopeViewWithLibraries>(keys.scope, "/api/scope");

/** The full session rule shape: steps, extractions, validity, scope, max_attempts. */
export const useSessionRulesFull = (): UseQueryResult<SessionRulesResponse> =>
 useResource<SessionRulesResponse>(keys.sessionRules, "/api/session/rules");

export const useSessionCookies = (): UseQueryResult<SessionCookiesResponse> =>
 useResource<SessionCookiesResponse>(keys.sessionCookies, "/api/session/cookies");

/** One cookie-jar write (dkb): Burp's "edit cookies manually, remove cookies from the jar, or
 *  empty the jar altogether". The response reports what changed, so the caller can toast the
 *  difference between "done" and "it was not there". */
export interface CookieJarWriteResult {
 action: "set" | "remove" | "clear" | "monitor";
 host?: string;
 name?: string;
 ok?: boolean;
 removed?: boolean;
 cleared?: boolean;
 /** For the monitor action (sn3j): the set in force, echoed from the coordinator. */
 monitoring?: string[];
}

export function useCookieJarWrite() {
 const client = useQueryClient();
 return useMutation<CookieJarWriteResult, Error, { action: "set" | "remove" | "clear" | "monitor"; host?: string; port?: number; tls?: boolean; name?: string; value?: string; tools?: string[] }>({
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

/**
 * Regenerate the signing CA — Burp's "Regenerate CA certificate" (BurpClass9617), beside
 * import/export.
 *
 * Where import brings the operator's own pair, this mints a fresh self-signed CA server-side and
 * installs it as the signing CA. It takes no body: the new private key is generated inside burpsy and
 * never crosses the wire — the response describes the new certificate, never its key.
 *
 * It is destructive and, once persisted, irreversible: the previous CA stops signing, every per-host
 * leaf is discarded, and the old key is overwritten on disk. Every client that trusted the old CA
 * must be re-given the new one, so like import this invalidates the `/ca.crt` probe as well as the
 * status — the download link must now serve the new certificate.
 */
export function useRegenerateCaCert() {
 const client = useQueryClient();
 return useMutation<CaStatus, Error, void>({
  mutationFn: () => api<CaStatus>("/api/proxy/ca/regenerate", json("POST", {})),
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
 * POST /api/session/macro-steps — the macro recorder (burpsy-react-ui-escl). Burp's Macro Recorder is
 * "select the items you need from the Proxy history list", so the request is a list of exchange ids
 * and the answer is one step per row that could be converted.
 *
 * `skipped` is not an error channel to be discarded: it names each selected row that could not become
 * a step and why, and the caller must show it. A recorder that silently returns fewer steps than the
 * operator selected is how a login macro ends up one request short, failing at login time with
 * nothing to point at.
 *
 * Deliberately no invalidation: reading the history does not change a rule, and invalidating
 * ["session"] here would refetch and re-render the rule list while the operator is still picking
 * rows from the recorder.
 */
export interface RecordedMacro {
 steps: SessionMacroStep[];
 skipped: { exchange: number; reason: string }[];
}

export function useRecordMacroSteps() {
 return useMutation<RecordedMacro, Error, { exchanges: number[]; variant?: "edited" | "original" | "auto-modified" }>({
  mutationFn: (vars) => api<RecordedMacro>("/api/session/macro-steps", json("POST", vars)),
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
 * POST /api/session/rules/{id}/analyze — Burp's "Re-analyze macro" (e23c): the same dry-run
 * /test runs, plus the parameter-relationship analysis over its responses (hidden form
 * fields, Set-Cookie names, query strings in links). Read-only like /test; the apply is a
 * separate call so the operator picks from what they were shown.
 */
/** GET /api/session/trace — the session-handling tracer (n29): the recorded entries and
 * whether it is recording. No refetch interval: the tracer's entries are the operator's
 * troubleshooting evidence and the page refreshes them on demand, like the jar. */
export function useSessionTrace() {
 return useResource<SessionTraceResponse>(policyKeys.sessionTrace, "/api/session/trace");
}

/** POST /api/session/trace/enable — turn the tracer on or off. Off is the default; the
 * overhead Burp warns about is why, and the Session page says so at the toggle. */
export function useSessionTraceEnable() {
 const client = useQueryClient();
 return useMutation({
  mutationFn: (enabled: boolean) =>
   api<SessionTraceEnableResponse>("/api/session/trace/enable", json("POST", { enabled })),
  onSuccess: () => void client.invalidateQueries({ queryKey: policyKeys.sessionTrace }),
 });
}

export function useAnalyzeSessionRule() {
 return useMutation({
  mutationFn: (id: number) =>
   api<SessionAnalyzeResponse>(`/api/session/rules/${id}/analyze`, json("POST", {})),
 });
}

/**
 * POST /api/session/rules/{id}/apply-extractions — the apply half of Re-analyze (e23c). The
 * body names suggestions by name only; the server rebuilds each extraction from its own
 * analysis, so what lands in the rule is a working extraction, not whatever shape arrived.
 */
export function useApplySessionExtractions() {
 return useMutation({
  mutationFn: (vars: { id: number; names: string[] }) =>
   api<SessionApplyExtractionsResponse>(`/api/session/rules/${vars.id}/apply-extractions`, json("POST", { names: vars.names })),
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

/* --- scope libraries (burpsy-react-ui-e365) ------------------------------- */

/**
 * One saved rule set as GET /api/scope lists it: what it is called, how many rules it holds and when
 * it was written. The rules themselves are deliberately not here — the list feeds a picker, and a
 * library's rules are only ever wanted by the one load that installs them.
 */
export interface ScopeLibraryEntry {
 name: string;
 /**
  * The rule count, or -1 for a library whose stored document cannot be read. -1 rather than 0
  * because 0 is a real, loadable rule set and "unreadable" is not: an empty scope is default-allow,
  * so the two must never render the same. The picker shows such a row as damaged and refuses to
  * offer it for loading.
  */
 rules: number;
 /** Unix milliseconds. */
 saved_at: number;
}

/**
 * The scope resource as this page reads it: everything ScopeView describes, plus the saved libraries
 * the same GET carries. Declared here rather than in types.policy.ts because the libraries are what
 * this change added to the response, and one widened type beside the hook that reads it is easier to
 * keep true than a second declaration two files away.
 */
export interface ScopeViewWithLibraries extends ScopeView {
 libraries?: ScopeLibraryEntry[];
 /** Present only when the saved libraries could not be read. An empty list would say "nothing is
  *  saved", which is a different and misleading claim. */
 libraries_error?: string;
}

/** POST /api/scope. One action per call, like every other arm of that endpoint. */
export interface ScopeLibraryUpdate {
 action: "library_save" | "library_load" | "library_delete";
 name: string;
}

/** What the three actions report back, so a toast can state what actually happened. */
export interface ScopeLibraryResult {
 name?: string;
 saved?: boolean;
 /** True when a save overwrote a library that already carried that name. */
 replaced?: boolean;
 loaded?: boolean;
 deleted?: boolean;
 /** On save, how many rules were stored; on load, how many are now in force. */
 rules?: number;
}

/**
 * Save, load or delete a named rule set.
 *
 * It posts to /api/scope, not to a library route of its own: a library is a saved copy of the scope
 * resource's state. The scope key is invalidated on success, and `library_load` is the reason — it
 * rewrites the live rule list, so a mutation that refreshed nothing would leave the rules table
 * showing the scope the operator had *before* the load, on the one screen where a stale render is a
 * statement about what traffic is authorised.
 */
export function useUpdateScopeLibrary() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (update: ScopeLibraryUpdate) =>
   api<ScopeLibraryResult>("/api/scope", json("POST", update)),
  onSuccess: () => invalidate([keys.scope]),
 });
}
