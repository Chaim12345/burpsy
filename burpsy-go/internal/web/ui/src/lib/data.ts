import { QueryClient, useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { create } from "zustand";
import { api, json, query } from "./api";
import { useApp, type RepeaterTab } from "./store";
import type {
 Dashboard,
 Exchange,
 InterceptState,
 Issues,
 MatchReplaceConfig,
 MatchReplaceResponse,
 MessageView,
 OrganizerCollection,
 OrganizerEdit,
 OrganizerItem,
 ProjectInfo,
 ProjectList,
 WorkflowStatus,
 Scope,
 ScannerConfig,
 SessionRule,
 SessionRules,
 SiteMap,
 Stats,
 ToolLog,
 WsConnection,
 WsHistory,
 WsMessage,
} from "./types";

export const queryClient = new QueryClient({
 defaultOptions: {
  queries: {
   // The API is on localhost: retries mostly hide real errors, and window-focus
   // refetching fights the SSE stream that already tells us what changed.
   retry: false,
   refetchOnWindowFocus: false,
   staleTime: 2_000,
   gcTime: 5 * 60_000,
  },
 },
});

export const keys = {
 stats: ["stats"] as const,
 scope: ["scope"] as const,
 project: ["project"] as const,
 projects: ["projects"] as const,
 dashboard: ["dashboard"] as const,
 history: (q: string, limit: number, search?: HistorySearch) =>
  [
   "history",
   q,
   limit,
   ...(search && search.term !== "" ? [search.term, search.caseSensitive ?? false, search.regex ?? false, search.negate ?? false] : []),
  ] as const,
 message: (id: number) => ["message", id] as const,
 exchange: (id: number) => ["exchange", id] as const,
 issues: ["issues"] as const,
 intercept: ["intercept"] as const,
 sitemap: ["sitemap"] as const,
 crawls: ["crawls"] as const,
 discovery: ["discovery"] as const,
 hiddenInputs: ["hidden-inputs"] as const,
 wsConnections: ["ws", "connections"] as const,
 /** The trailing filter axes keep one cache entry per distinct view (burpsy-react-ui-5k4):
  * a page fetched under one payload substring must not be served for another. */
 wsHistory: (exchange: number, direction: string, opcode: string, payload: string) =>
  ["ws", "history", exchange, direction, opcode, payload] as const,
 wsMessage: (id: number) => ["ws", "message", id] as const,
 toolLog: (filter: string, search: string) => ["toollog", filter, search] as const,
 organizer: ["organizer"] as const,
 rules: ["rules"] as const,
 sessionRules: ["session", "rules"] as const,
 sessionCookies: ["session", "cookies"] as const,
 protocols: ["protocols"] as const,
 scannerConfigs: ["scanner", "configs"] as const,
 scannerIssueTypes: ["scanner", "issue-types"] as const,
 scannerConfig: ["scanner", "config"] as const,
 scannerCoverage: ["scanner", "coverage"] as const,
 scannerChecks: ["scanner", "checks"] as const,
 scannerLive: ["scanner", "live"] as const,
 auditItems: ["scanner", "audit-items"] as const,
 collaborator: ["collaborator"] as const,
 collaboratorInteractions: ["collaborator", "interactions"] as const,
 blindxss: ["blindxss"] as const,
 proxyOptions: ["proxy", "options"] as const,
 proxyListener: ["proxy", "listener"] as const,
 networkSettings: ["network", "settings"] as const,
 pools: ["pools"] as const,
 schedules: ["schedules"] as const,
 // Extender. The console key is parameterised by plugin and by line limit, and shares the
 // ["extensions"] prefix so a load or an unload invalidates the row and the console together.
 extensions: ["extensions"] as const,
 extensionConsole: (name: string, limit: number) => ["extensions", "console", name, limit] as const,
 extensionApis: ["extensions", "apis"] as const,
 networkProxy: ["network", "proxy"] as const,
 networkAuth: ["network", "auth"] as const,
 networkClientCerts: ["network", "client-certs"] as const,
};

/**
 * Which caches a server event invalidates. Keys are prefixes, so one entry
 * covers every parameterised variant of a resource.
 */
const INVALIDATION: Record<string, string[][]> = {
 history: [["history"], ["stats"], ["sitemap"], ["dashboard"]],
 capture: [["history"], ["stats"], ["sitemap"], ["dashboard"]],
 // A finished hidden-input run files its findings and notifies issues and dashboard; both refresh
 // the run record so the dialog's result does not wait for its own poll.
 issues: [["issues"], ["dashboard"], ["scanner"], ["hidden-inputs"]],
 scanner: [["issues"], ["dashboard"], ["scanner"]],
 toollog: [["toollog"], ["dashboard"]],
 // A finished content-discovery run notifies changeDashboard and nothing else — it fetched
 // nothing through burpsy, so no history row, site-map node or finding moved. That makes this
 // entry the only event that can tell the console a sweep has results.
 dashboard: [["dashboard"], ["discovery"], ["hidden-inputs"]],
 task: [["dashboard"]],
 tasks: [["dashboard"]],
 ws: [["ws"], ["stats"], ["dashboard"]],
 intercept: [["intercept"]],
 scope: [["scope"]],
 session: [["session"]],
 sitemap: [["sitemap"], ["dashboard"]],
 organizer: [["organizer"]],
 rules: [["rules"]],
 // A DOM-auditor hit the operator's browser just reported (burpsy-react-ui-wl94), so the auditor
 // view refetches without a poll.
 dominvader: [["dominvader"]],
};

const FALLBACK: string[][] = [["dashboard"], ["stats"]];

interface ConnectionState {
 live: boolean;
 lastEventAt: number | null;
 eventCount: number;
 setLive: (live: boolean) => void;
 noteEvent: () => void;
}

export const useConnection = create<ConnectionState>((set) => ({
 live: false,
 lastEventAt: null,
 eventCount: 0,
 setLive: (live) => set({ live }),
 noteEvent: () => set((state) => ({ lastEventAt: Date.now(), eventCount: state.eventCount + 1 })),
}));

/**
 * Single server-sent-events subscription for the whole console.
 *
 * Bursts are coalesced into one invalidation pass: a crawl can emit hundreds of
 * frames a second, and invalidating per frame turned the stream into a request
 * storm in the previous implementation.
 */
export function useEventStream(): void {
 const client = useQueryClient();
 const setLive = useConnection((state) => state.setLive);
 const noteEvent = useConnection((state) => state.noteEvent);

 useEffect(() => {
  let stream: EventSource | null = null;
  let flushTimer: number | null = null;
  let retryTimer: number | null = null;
  let closed = false;
  const pending = new Set<string>();

  const flush = () => {
   flushTimer = null;
   const kinds = [...pending];
   pending.clear();
   const prefixes = new Set<string>();
   for (const kind of kinds) {
    for (const key of INVALIDATION[kind] ?? FALLBACK) prefixes.add(JSON.stringify(key));
   }
   for (const prefix of prefixes) {
    void client.invalidateQueries({ queryKey: JSON.parse(prefix) as string[] });
   }
  };

  const connect = () => {
   if (closed) return;
   stream = new EventSource("/api/events");

   stream.onopen = () => setLive(true);

   stream.onmessage = (event) => {
    setLive(true);
    let kind = "";
    try {
     const frame = JSON.parse(event.data) as { kind?: string };
     kind = frame.kind ?? "";
    } catch {
     // A malformed frame still proves the stream is alive; treat it as a
     // generic change rather than dropping it silently.
    }
    if (kind === "hello" || kind === "ping") return;
    noteEvent();
    pending.add(kind);
    if (flushTimer === null) flushTimer = window.setTimeout(flush, 350);
   };

   stream.onerror = () => {
    setLive(false);
    stream?.close();
    stream = null;
    // EventSource retries on its own only for some failures; an explicit
    // backoff keeps the badge honest and recovers after a server restart.
    if (!closed && retryTimer === null) {
     retryTimer = window.setTimeout(() => {
      retryTimer = null;
      connect();
     }, 3_000);
    }
   };
  };

  connect();

  return () => {
   closed = true;
   if (flushTimer !== null) window.clearTimeout(flushTimer);
   if (retryTimer !== null) window.clearTimeout(retryTimer);
   stream?.close();
   setLive(false);
  };
 }, [client, setLive, noteEvent]);
}

/** Debounce a fast-changing value (search boxes) so we do not fetch per keystroke. */
export function useDebounced<T>(value: T, delayMs = 250): T {
 const [settled, setSettled] = useState(value);
 useEffect(() => {
  const timer = window.setTimeout(() => setSettled(value), delayMs);
  return () => window.clearTimeout(timer);
 }, [value, delayMs]);
 return settled;
}

/**
 * Shared read hook. Area-specific modules (data.observe.ts, data.attack.ts, …)
 * build on this so concurrent work does not all land in one file.
 */
export function useResource<T>(key: readonly unknown[], url: string, enabled = true): UseQueryResult<T> {
 return useQuery({
  queryKey: key,
  // The signal makes an in-flight request abort when the key changes, so a
  // slow earlier response can never overwrite a newer one.
  queryFn: ({ signal }) => api<T>(url, { signal }),
  enabled,
 });
}

/* --- reads --------------------------------------------------------------- */

export const useStats = () => useResource<Stats>(keys.stats, "/api/stats");
export const useScannerConfig = () => useResource<ScannerConfig>(keys.scannerConfig, "/api/scanner/config");

/** GET /api/project — the Project menu's readout: which project this instance is. */
export const useProject = () => useResource<ProjectInfo>(keys.project, "/api/project");

/** GET /api/projects — the .db files beside the active project, the active one marked. Fetched
 *  only while the switcher is open (`enabled`): the server peeks into every file for its stored
 *  name, which is not a read the shell should repeat on every render. */
export const useProjects = (enabled: boolean) => useResource<ProjectList>(keys.projects, "/api/projects", enabled);

/**
 * Bumped once per completed project switch. The shell keys the routed page on it, so every page's
 * own component state — a selected row, an expanded node, a draft filter — is discarded with the
 * project it belonged to. Exchange and finding ids restart per database, so a selection that
 * survived the switch would silently point at a different request in the new project.
 */
export const useProjectEpoch = create<{ epoch: number; bump: () => void }>((set) => ({
 epoch: 0,
 bump: () => set((state) => ({ epoch: state.epoch + 1 })),
}));

/**
 * POST /api/project/open — switch this process to another project file (burpsy-react-ui-dlw2).
 *
 * riskDestructive, so it goes through the confirmation gate: the caller has already asked the
 * operator, and only then is a token minted at /api/project/open/confirm and spent on the call. A
 * path that does not exist yet creates the project.
 *
 * On success EVERY store on the server has been replaced, so nothing cached may survive: the
 * confirmed project view goes into the readout, every query is reset (not invalidated — an
 * invalidated query keeps showing the old project's rows until its refetch lands, and an inactive
 * one would show them on the next navigation), and the caller's `onSwitched` clears the
 * browser-side pointers into the old project and remounts the page.
 */
export function useOpenProject() {
 return useMutation<ProjectInfo, Error, string>({
  mutationFn: (path: string) => api<ProjectInfo>("/api/project/open", json("POST", { path })),
  onSuccess: (confirmed) => {
   void queryClient.resetQueries();
   queryClient.setQueryData(keys.project, confirmed);
   forgetOutgoingProjectPointers();
   useProjectEpoch.getState().bump();
  },
 });
}

/**
 * Clear the session state that names rows of the project being left: the focused exchange and
 * issue, the checked rows, the history filter (one that hid every row of the new project would
 * make it read as empty) and the Comparer lists (copies of the old project's messages).
 *
 * The drafts that are kept — Repeater tabs' request text and the Intruder payloads, settings and
 * last report — are persisted per browser rather than per project, and discarding them would be
 * losing work nobody asked to lose. But the ids INSIDE them are references into the project being
 * left, and ids restart per database: so a Repeater tab's `fromExchange` (sent as the resend's
 * parent) is dropped, and Intruder's base message id and the insertion points measured on that
 * message are cleared — kept, the next attack would silently run against whatever request has
 * that id in the new project. The switcher's confirmation says all of this.
 */
export function forgetOutgoingProjectPointers(): void {
 const app = useApp.getState();
 app.focusExchange(null);
 app.focusIssue(null);
 app.setCheckedExchanges([]);
 app.setHistoryQuery("");
 app.clearComparerItems("a");
 app.clearComparerItems("b");
 app.setIntruder((current) => ({ ...current, msgId: "", points: [], selected: [], manualSpans: [] }));
 const dropLineage = (tabs: RepeaterTab[]) => tabs.map(({ fromExchange: _left, ...tab }) => tab);
 useApp.setState((state) => ({
  repeaterTabs: dropLineage(state.repeaterTabs),
  closedRepeaterTabs: dropLineage(state.closedRepeaterTabs),
 }));
}

/** PUT /api/project/name — rename the project. The name is stored with the database file, so a
 *  restart keeps it; the confirmed response is what the cache gets. */
export function useRenameProject() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (name: string) => api<ProjectInfo>("/api/project/name", json("PUT", { name })),
  onSuccess: (confirmed) => {
   queryClient.setQueryData(keys.project, confirmed);
   invalidate([keys.project]);
  },
 });
}

/** PUT /api/scanner/config — apply a partial patch of audit-family switches and knobs. The server
 *  answers with the whole confirmed state and persists it for the next start, so the confirmed
 *  response is what the cache gets, never the optimistic draft. */
export function useSaveScannerConfig() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (patch: Partial<ScannerConfig>) => api<ScannerConfig>("/api/scanner/config", json("PUT", patch)),
  onSuccess: (confirmed) => {
   queryClient.setQueryData(keys.scannerConfig, confirmed);
   invalidate([keys.scannerCoverage]);
  },
 });
}
export const useScope = () => useResource<Scope>(keys.scope, "/api/scope");
export const useDashboard = () => useResource<Dashboard>(keys.dashboard, "/api/dashboard");
export const useIssues = () => useResource<Issues>(keys.issues, "/api/issues");
export const useSitemap = () => useResource<SiteMap>(keys.sitemap, "/api/sitemap");
export const useOrganizer = () =>
 useResource<{ items: OrganizerItem[]; collections: OrganizerCollection[] }>(keys.organizer, "/api/tools/organizer");
export const useMatchReplace = () => useResource<MatchReplaceResponse>(keys.rules, "/api/tools/rules");
export const useSessionRules = () => useResource<SessionRules>(keys.sessionRules, "/api/session/rules");
export const useWsConnections = () => useResource<WsConnection[]>(keys.wsConnections, "/api/ws/connections");

/** The Search box's server-side modifiers (ngcj). Same names and truthy spellings as the
 * endpoint's query string, so a search a test replays through the API and one an operator types
 * in the box cannot diverge in what they mean.
 *
 * `term` blank means no search is active, whatever the modifiers hold — the same contract
 * compileHistorySearch documents, kept because the endpoint answers the same way. */
export interface HistorySearch {
 term: string;
 caseSensitive?: boolean;
 regex?: boolean;
 negate?: boolean;
}

export const useHistory = (q: string, limit = 500, search?: HistorySearch) =>
 useResource<Exchange[]>(
  keys.history(q, limit, search),
  `/api/history${query({ limit, q, ...(search && search.term !== "" ? { search: search.term, search_case: search.caseSensitive ?? false, search_regex: search.regex ?? false, search_negate: search.negate ?? false } : {}) })}`,
 );

// `id >= 0`, not `id > 0`: the stores are position-is-the-id counters from zero, so message 0,
// exchange 0 and ws message 0 are all real rows. Guarding on `> 0` disabled the fetch for the
// first thing ever captured, and the editor rendered "No request bytes captured" for a message
// the server would have served — visible on the very first exchange of a fresh session.
export const useMessage = (id: number | null | undefined) =>
 useResource<MessageView>(keys.message(id ?? -1), `/api/message/${id ?? 0}`, typeof id === "number" && id >= 0);

/** The frame-list filter (burpsy-react-ui-5k4): server-side on /api/ws/history, because a frame's
 * payload bytes are not on the row. `filter` with an empty payload box reads as no payload
 * constraint, so direction/opcode can narrow without the substring axis; the query key carries all
 * three so a change to any re-fetches rather than reusing the page another filter produced. */
export const useWsHistory = (
 exchange: number | null | undefined,
 filter?: { direction?: string; opcode?: string; payload?: string },
 limit = 500,
) =>
 useResource<WsHistory>(
  keys.wsHistory(exchange ?? -1, filter?.direction ?? "", filter?.opcode ?? "", filter?.payload ?? ""),
  `/api/ws/history${query({ exchange: exchange ?? 0, limit, direction: filter?.direction, opcode: filter?.opcode, payload: filter?.payload })}`,
  typeof exchange === "number",
 );

export const useWsMessage = (id: number | null | undefined) =>
 useResource<WsMessage>(keys.wsMessage(id ?? -1), `/api/ws/message/${id ?? 0}`, typeof id === "number" && id >= 0);

export const useToolLog = (filter: string, search: string, limit = 300) =>
 useResource<ToolLog>(keys.toolLog(filter, search), `/api/tools/log${query({ limit, filter, search })}`);

/**
 * Intercept is the one resource that still polls: held messages must appear
 * within a beat of being trapped even if the event stream is unavailable.
 */
export function useIntercept(pollMs = 1_500): UseQueryResult<InterceptState> {
 return useQuery({
  queryKey: keys.intercept,
  queryFn: ({ signal }) => api<InterceptState>("/api/intercept", { signal }),
  refetchInterval: pollMs,
  staleTime: 0,
 });
}

/* --- writes -------------------------------------------------------------- */

/** Invalidate by key prefix after a mutation lands. */
export function useInvalidate(): (prefixes: readonly (readonly unknown[])[]) => void {
 const client = useQueryClient();
 return (prefixes) => {
  for (const prefix of prefixes) void client.invalidateQueries({ queryKey: prefix });
 };
}

export function useSaveMatchReplace() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (config: MatchReplaceConfig) => api<unknown>("/api/tools/rules", json("PUT", config)),
  onSuccess: () => invalidate([keys.rules]),
 });
}

export function useSaveSessionRule() {
 const invalidate = useInvalidate();
 return useMutation({
  // riskCredential: api() mints at the /api/session/rules pair's one /confirm on this Save click
  // (burpsy-react-ui-p1uz), for the create and the edit alike.
  mutationFn: (rule: SessionRule) =>
   rule.id === undefined
    ? api<{ rule: SessionRule }>("/api/session/rules", json("POST", rule))
    : api<{ rule: SessionRule }>(`/api/session/rules/${rule.id}`, json("PUT", rule)),
  onSuccess: () => invalidate([["session"]]),
 });
}

export function useDeleteSessionRule() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (id: number) => api<unknown>(`/api/session/rules/${id}`, { method: "DELETE" }),
  onSuccess: () => invalidate([["session"]]),
 });
}

export function useOrganizerMutations() {
 const invalidate = useInvalidate();
 const done = () => invalidate([keys.organizer]);
 return {
  add: useMutation({
   mutationFn: (exchange: number) => api<OrganizerItem>("/api/tools/organizer", json("POST", { exchange })),
   onSuccess: done,
  }),
  save: useMutation({
   mutationFn: (item: OrganizerEdit) => api<unknown>(`/api/tools/organizer/${item.id}`, json("POST", item)),
   onSuccess: done,
  }),
  remove: useMutation({
   mutationFn: (id: number) => api<unknown>(`/api/tools/organizer/${id}`, { method: "DELETE" }),
   onSuccess: done,
  }),
  /**
   * PUT .../status sets the workflow status — one deliberate operator decision, kept off the
   * title/note save above the same way the Go store keeps SetStatus apart from Update.
   * Refusals: 400 names the five valid values, 404 is an unknown item.
   */
  setStatus: useMutation({
   mutationFn: ({ id, status }: { id: number; status: WorkflowStatus }) =>
    api<unknown>(`/api/tools/organizer/${id}/status`, json("PUT", { status })),
   onSuccess: done,
  }),
  /** Create a collection. 400 when the name is taken — the server refuses, not the UI. */
  createCollection: useMutation({
   mutationFn: (name: string) => api<OrganizerCollection>("/api/tools/organizer/collections", json("POST", { name })),
   onSuccess: done,
  }),
  /** Rename and/or set the About note on one collection. */
  updateCollection: useMutation({
   mutationFn: ({ id, name, note }: { id: number; name?: string; note?: string }) =>
    api<unknown>(`/api/tools/organizer/collections/${id}`, json("PUT", { name, note })),
   onSuccess: done,
  }),
  /** Delete one collection; disposition unlinks its items to the inbox (default) or deletes them. */
  deleteCollection: useMutation({
   mutationFn: ({ id, items }: { id: number; items?: "inbox" | "delete" }) =>
    api<{ unlinked: number }>(`/api/tools/organizer/collections/${id}${items ? `?items=${items}` : ""}`, { method: "DELETE" }),
   onSuccess: done,
  }),
  /** Duplicate a collection with every item in it, under a non-colliding "(copy)" name. */
  duplicateCollection: useMutation({
   mutationFn: (id: number) =>
    api<{ collection: OrganizerCollection; items_copied: number }>(`/api/tools/organizer/collections/${id}/duplicate`, json("POST", {})),
   onSuccess: done,
  }),
  /** Move (or, with copy, duplicate) items into a collection; the inbox takes the literal id "inbox". */
  moveItems: useMutation({
   mutationFn: ({ collection, itemIds, copy }: { collection: number | "inbox"; itemIds: number[]; copy?: boolean }) =>
    api<{ moved: number }>(
     collection === "inbox" ? "/api/tools/organizer/collections/inbox" : `/api/tools/organizer/collections/${collection}/items`,
     json("PUT", { item_ids: itemIds, copy: copy === true }),
    ),
   onSuccess: done,
  }),
 };
}

/**
 * PATCH /api/exchange/:id (UX-15). `notes: undefined` leaves notes untouched, matching the Go
 * handler's "omitted field is unchanged" contract; pass `notes: null` explicitly to clear it.
 * Invalidates `keys.history` so every open history query (any filter/limit) refetches and picks up
 * the new highlight/notes on its next render, the same prefix-invalidation shape `useOrganizerMutations`
 * uses for `keys.organizer`.
 */
export function useAnnotateExchange() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: ({ id, notes, highlight }: { id: number; notes?: string | null; highlight?: string }) =>
   api<Exchange>(`/api/exchange/${id}`, json("PATCH", { notes, highlight })),
  // ["history"] is a prefix: it matches keys.history(q, limit) for every q/limit combination in
  // the cache, the same pattern the server-push INVALIDATION map above already uses.
  onSuccess: () => invalidate([["history"]]),
 });
}

/** DELETE /api/history/rows — Burp's "Delete items" / "Clear (tool)" (burpsy-react-ui-r6li). With ids
 *  those rows leave the operator's view; with none the whole capture clears. The server answers
 *  {removed, requested} so a caller naming a row already gone can say so — a bare 200 would read
 *  as success for a request that removed nothing. The route is riskDestructive (gf68), so api()
 *  mints the confirmation; the history page's "Delete the selected items?" / "Clear the capture?"
 *  modal is the operator's act that confirmation records. */
export function useDeleteHistory() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (ids: number[] | null) =>
   api<{ removed: number; requested: number }>("/api/history/rows", json("DELETE", ids === null ? undefined : { ids })),
  // Same prefixes the server-push map gives history (INVALIDATION.history), inlined: that
  // Record's value type is string[][] and invalidate() needs tuple literals.
  onSuccess: () => invalidate([["history"], ["stats"], ["sitemap"], ["dashboard"]]),
 });
}

/** POST /api/history/import/har — Burp's "Import HAR" (burpsy-react-ui-eyi1). The raw HAR file bytes
 *  are the request body — the handler reads the body and json-parses it, so there is no JSON envelope —
 *  and the File is handed straight to fetch rather than through json(), so a capture of up to
 *  maxHARImportBytes (64 MB in api_har_import.go) is never copied into a JS string. The imported entries
 *  become ordinary history rows (Source "import"), so the same prefixes the delete hook refreshes are
 *  invalidated and the new rows appear without a manual reload. */
export function useImportHar() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (file: File) =>
   api<{ imported: number; skipped: number; errors?: string[] }>("/api/history/import/har", { method: "POST", body: file }),
  onSuccess: () => invalidate([["history"], ["stats"], ["sitemap"], ["dashboard"]]),
 });
}

export function useClearToolLog() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: () => api<unknown>("/api/tools/log", { method: "DELETE" }),
  onSuccess: () => invalidate([["toollog"], keys.dashboard]),
 });
}

export function useInterceptControls() {
 const invalidate = useInvalidate();
 const done = () => invalidate([keys.intercept]);
 return {
  setEnabled: useMutation({
   mutationFn: (enabled: boolean) => api<unknown>("/api/intercept/enable", json("POST", { enabled })),
   onSuccess: done,
  }),
  /** Burp's "Only intercept in-scope messages" (burpsy-react-ui-cz1). Its own route, not a second
   * field on /enable: two independent switches, and an endpoint named "enable" carrying a filter
   * would make a caller setting one have to restate the other. */
  setInScopeOnly: useMutation({
   mutationFn: (inScopeOnly: boolean) =>
    api<{ in_scope_only: boolean; scope_attached: boolean }>("/api/intercept/in-scope-only", json("POST", { in_scope_only: inScopeOnly })),
   onSuccess: done,
  }),
  forward: useMutation({
   mutationFn: ({ id, raw }: { id: number; raw: string }) =>
    api<unknown>(`/api/intercept/${id}/forward`, json("POST", { raw, fix_content_length: true })),
   onSuccess: done,
  }),
  drop: useMutation({
   mutationFn: (id: number) => api<unknown>(`/api/intercept/${id}/drop`, json("POST", { reason: "dropped by operator" })),
   onSuccess: done,
  }),
  /**
   * Drop every held message in one round trip (burpsy-react-ui-t6f).
   *
   * The route answers the count it ACTUALLY dropped, which is the useful part and the reason this
   * is not just a loop over the visible rows: a message resolved elsewhere between the page's last
   * poll and this request is not counted, so the number cannot overstate. The caller shows it, and
   * says so when it differs from what was on screen — that difference is how an operator learns
   * the queue moved under them rather than assuming the button half-worked.
   */
  /**
   * Forward every held message in one round trip (burpsy-react-ui-4v3) — the safe half of the
   * pair dropAll is the destructive half of, and Burp ships both from one dropdown. The route
   * takes no body on purpose: a bulk forward applies no edits and no content-length rewrite,
   * because nobody has looked at what it sends. The count it answers is what the engine
   * actually forwarded — a message resolved elsewhere between the page's last poll and this
   * request is not counted, so the number cannot overstate.
   */
  forwardAll: useMutation({
   mutationFn: () => api<{ forwarded: number }>("/api/intercept/forward-all", json("POST", {})),
   onSuccess: done,
  }),
  dropAll: useMutation({
   mutationFn: () => api<{ dropped: number }>("/api/intercept/drop-all", json("POST", { reason: "dropped by operator" })),
   onSuccess: done,
  }),
 };
}

/** Burp's "Default Proxy interception state" (burpsy-react-ui-7vy): what the intercept
 * switch reads when a server starts — on, off, or restored-from-last-session. A preference
 * about the NEXT start, distinct from /api/intercept/enable, the live switch. */
export function useInterceptStartup(): UseQueryResult<{ mode: string }> {
 return useQuery({
  queryKey: ["intercept", "startup"],
  queryFn: ({ signal }) => api<{ mode: string }>("/api/intercept/startup", { signal }),
 });
}

/** Burp's "Proxy history logging" (burpsy-react-ui-z80e): what Add to scope does about
 * out-of-scope proxy logging — stop, ask, or nothing. */
export function useProxyHistoryLogging(): UseQueryResult<{ mode: string }> {
 return useQuery({
  queryKey: ["proxy", "history-logging"],
  queryFn: ({ signal }) => api<{ mode: string }>("/api/proxy/history-logging", { signal }),
 });
}

export function useSaveProxyHistoryLogging() {
 const invalidate = useInvalidate();
 return useMutation<{ mode: string }, Error, string>({
  mutationFn: (mode) => api<{ mode: string }>("/api/proxy/history-logging", json("POST", { mode })),
  onSuccess: () => invalidate([["proxy", "history-logging"]]),
 });
}

export function useSaveInterceptStartup() {
 const invalidate = useInvalidate();
 return useMutation<{ mode: string }, Error, string>({
  mutationFn: (mode) => api<{ mode: string }>("/api/intercept/startup", json("POST", { mode })),
  onSuccess: () => invalidate([["intercept", "startup"]]),
 });
}
