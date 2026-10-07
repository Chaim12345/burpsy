/**
 * Query hooks for the observe-area pages (WS history, site map) that need a richer wire shape than
 * the shared, trimmed hooks in `data.ts` provide. Built on the same `useResource`/`keys` the shared
 * hooks use, so the cache entries are the same entries the rest of the app invalidates — only the
 * static type of what comes back differs.
 */
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys, useDebounced, useInvalidate, useResource } from "./data";
import type { Exchange } from "./types";
import type { APIScanAccepted, APIScanCheck, CrawlRun, SiteMapDetail, WsMessageDetail } from "./types.observe";
import type { SitemapDiffResponse } from "./sitemap-diff";

/** Full Exchange record for one id — used where a page only started with an exchange id (a WS
 * connection, a site-map node) and needs the whole row to offer the full send-to menu. */
// `id >= 0`, not `id > 0`: the stores are position-is-the-id counters from zero, so message 0,
// exchange 0 and ws message 0 are all real rows. Guarding on `> 0` disabled the fetch for the
// first thing ever captured, and the editor rendered "No request bytes captured" for a message
// the server would have served — visible on the very first exchange of a fresh session.
export const useExchange = (id: number | null | undefined) =>
 useResource<Exchange>(keys.exchange(id ?? -1), `/api/exchange/${id ?? 0}`, typeof id === "number" && id >= 0);

/** Same endpoint and cache key as the shared `useSitemap`, typed to the full node shape (id, segment)
 * that a real expand/collapse tree needs. */
export const useSitemapDetailed = () => useResource<SiteMapDetail>(keys.sitemap, "/api/sitemap");

/** DELETE /api/sitemap — Burp's "Delete host"/"Delete branch"/"Delete item"
 * (burpsy-react-ui-10e). Suppression, not deletion: the server keeps every exchange, so history,
 * findings and audit references stay whole; the branch leaves the map and stays out across
 * rebuilds and re-captures. The fields are the row's own (SiteNodeDetail carries port/tls), so
 * nothing parses the composed key back into parts. */
export function useDeleteSitemap() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (req: { host: string; port: number; tls: boolean; path: string; kind: "host" | "branch" | "item" }) =>
   api<{ suppressed: string; kind: string }>("/api/sitemap", json("DELETE", req)),
  onSuccess: () => invalidate([keys.sitemap]),
 });
}

/** Same endpoint and cache key as the shared `useWsMessage`, typed to the full frame shape (opcode,
 * dropped, truncated) needed to render text/hex/close payloads distinctly. */
export const useWsMessageDetailed = (id: number | null | undefined) =>
 useResource<WsMessageDetail>(keys.wsMessage(id ?? -1), `/api/ws/message/${id ?? 0}`, typeof id === "number" && id >= 0);

/** Retained crawl reports, newest first. Polls while any crawl is running: a crawl is asynchronous by
 * design (it outlives the request that started it), so the list is the only way its progress and its
 * final coverage report reach the page. */
export const useCrawls = () => {
 const q = useResource<{ crawls: CrawlRun[]; default_limits?: CrawlRun["limits"] }>(keys.crawls, "/api/crawl");
 const running = (q.data?.crawls ?? []).some((c) => c.state === "running");
 return { ...q, running };
};

/** Compare site maps (k3a7): the path-set diff between two runs, as the server computed it. */
export function useCompareSitemaps() {
 return useMutation<SitemapDiffResponse, Error, { taskA: number; taskB: number }>({
  // camelCase at the hook boundary, snake_case on the wire the same mutation body spells.
  mutationFn: ({ taskA, taskB }) =>
   api<SitemapDiffResponse>("/api/tools/compare-sitemaps", json("POST", { task_a: taskA, task_b: taskB })),
 });
}

/**
 * The outcome of a passive re-scan of one site-map branch (burpsy-react-ui-p09).
 *
 * The counts are a partition, not a summary: `scanned + skipped_out_of_scope + skipped_no_response`
 * equals `matched`, always. A caller can therefore answer "what happened to the other ones", which
 * is what makes this readable as coverage rather than a highlight reel.
 *
 * `loaded` is the check count. Zero means the sweep ran and could not have found anything, which is
 * NOT a clean branch, and a surface must not render the two alike.
 */
export interface PassiveBranchResult {
 host: string;
 path_prefix?: string;
 port?: number;
 matched: number;
 scanned: number;
 /** In the branch, refused by the CURRENT scope — they may have been captured under a wider one. */
 skipped_out_of_scope: number;
 /** No response to scan. A request in flight is neither a failure nor a clean result. */
 skipped_no_response: number;
 /** In the branch and removed by the operator's pre-scan filter before the sweep's own gates (a13). */
 filtered: number;
 /** The filter the sweep actually applied, echoed so a caller can state which rule shaped it. */
 exclude?: string;
 findings: number;
 loaded: number;
 /** The server's own one-line statement of the counts and their caveats. Shown verbatim. */
 summary: string;
}

/**
 * Passively re-scan one branch's already-captured exchanges.
 *
 * Sends nothing to the target — this re-reads what the store holds — which is why it needs no
 * confirmation step of the kind an audit does.
 */
export function usePassiveScanBranch() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (body: { host: string; path_prefix?: string; port?: number; exclude?: string }) =>
   api<PassiveBranchResult>("/api/scanner/passive-branch", json("POST", body)),
  // Findings and the dashboard both move; the site map does not, because no traffic was captured.
  onSuccess: () => invalidate([["issues"], ["dashboard"], ["scanner"]]),
 });
}

/** Audit a selection of captured exchanges as one run — Burp's "Audit selected items".
 *
 *  Resolves when the server has accepted it and registered the task, not when the scan finishes, for
 *  the same reason useStartCrawl does: a selection has no bound on its size, so the work is followed
 *  through the task row rather than through a held-open request. The reply's `count` is the number of
 *  items actually taken on and `duplicates_dropped` says how many were repeated, so the toast can
 *  state the work rather than the length of the list that was sent. */
export function useAuditSelected() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (body: { exchange_ids: number[]; config?: string; pool?: string }) =>
   api<{ task_id: number; kind: string; count: number; duplicates_dropped: number; target: string }>(
    "/api/audit/selected",
    json("POST", body),
   ),
  // The audit's own row is the progress; findings and the dashboard's counters move when it lands.
  // The same three key prefixes the passive-branch audit invalidates, and by their literals for the
  // same reason it uses literals: `keys` has no "scanner" entry, and inventing one here would make
  // this the only hook invalidating a key the rest of the app spells differently.
  onSuccess: () => invalidate([["issues"], ["dashboard"], ["scanner"]]),
 });
}

/**
 * One retained run by its task id, or nothing while there is no such run.
 *
 * The run record is where an API scan's definition lives — the task row carries a target and a
 * progress count and nothing about the document — so the task detail pane asks for it here rather than
 * for the whole list, and only once a task is actually selected.
 *
 * Polls while the run is still going, because a run's report and its endpoint list only exist once it
 * has finished and the selected tile does not re-render on its own. Keyed by task id, so the drawer
 * following a click from one task to another cannot show the previous one's document while the new one
 * is in flight.
 */
export function useCrawlRun(taskId: number | null) {
 return useQuery({
  queryKey: ["crawl-run", taskId],
  queryFn: ({ signal }) => api<CrawlRun>(`/api/crawl?task=${taskId}`, { signal }),
  enabled: typeof taskId === "number" && taskId > 0,
  refetchInterval: (query) => (query.state.data?.state === "running" ? 1500 : false),
  // A task that has been evicted from the run registry is answered with a 404 and will stay a 404;
  // retrying it would be a request per keystroke of the operator's attention for no change.
  retry: false,
 });
}

/**
 * What a definition would resolve to, asked before anything is sent.
 *
 * A POST behind a query hook, which is unusual and deliberate: the server's dry run is the same parse,
 * the same resolution and the same refusals the launch runs, so the endpoint count the operator
 * approves in the dialog and the count the sweep sends come from one code path. A separate GET
 * "validate" route would be a second parser to keep in step with the first.
 *
 * Keyed on the definition and base URL after `useDebounced`, so typing in the pasted document does not
 * send a request per keystroke. The definition is part of the key, which is also what makes switching
 * between two documents show the right answer rather than the last one's while the new one is in
 * flight.
 *
 * `enabled: false` while the box is empty is not an optimisation: an empty definition is a 400, and a
 * dialog that opened showing "no API definition was given" before the operator had typed anything
 * would be reporting their next action as a mistake.
 */
export function useAPIScanCheck(definition: string, baseUrl: string) {
 const debouncedDefinition = useDebounced(definition, 420);
 const debouncedBase = useDebounced(baseUrl, 420);
 return useQuery({
  queryKey: ["apiscan-check", debouncedDefinition, debouncedBase],
  queryFn: ({ signal }) =>
   api<APIScanCheck>("/api/apiscan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
     definition: debouncedDefinition,
     base_url: debouncedBase.trim() || undefined,
     dry_run: true,
    }),
    signal,
   }),
  enabled: debouncedDefinition.trim() !== "",
  // A refused document is the normal case while someone is still editing, so a failure is data the
  // dialog renders as advice rather than a broken query. Retrying a 400 would send the same 400 again.
  retry: false,
 });
}

/**
 * Start an API-only scan — Burp's fourth scan kind.
 *
 * Resolves as soon as the server has read the document and registered the task, for the same reason
 * useStartCrawl does: the sweep outlives the request. The reply's `definition.operations` is the list
 * the server actually built, so a toast can name the work rather than the document that was sent.
 */
export function useStartAPIScan() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (body: {
   definition: string;
   base_url?: string;
   audit?: boolean;
   max_requests?: number;
   requests_per_second?: number;
   pool?: string;
  }) => api<APIScanAccepted>("/api/apiscan", json("POST", body)),
  // The same three keys a crawl-and-audit invalidates: the sweep writes history, its audit half writes
  // findings, and both move the dashboard's counters and the site map.
  onSuccess: () => invalidate([keys.crawls, keys.dashboard, keys.sitemap, ["issues"]]),
 });
}

/** Start a crawl. Resolves as soon as the server has accepted it and registered the task — not when
 * the crawl finishes — so the caller gets a task id to follow rather than a blocked promise. */
export function useStartCrawl() {
 const invalidate = useInvalidate();
 return useMutation({
  // `kind` is which Burp scan kind to run: "crawl", or "crawl-audit" for the crawl followed by an
  // audit of the exchanges it fetched. Omitted means a plain crawl, which is what every caller
  // predating the field sends. The server refuses a kind it does not recognise rather than treating
  // it as a crawl — see its scanKind — so a typo here is a visible error and not a silent downgrade.
  mutationFn: (body: {
   seeds: string[];
   kind?: string;
   max_requests?: number;
   max_depth?: number;
   max_duration_secs?: number;
    /**
     * The eight bounds the engine had but the wire did not (burpsy-react-ui-qzzy).
     *
     * Omitted means the engine's documented default. A 0 is sent as 0 and means the operator's answer
     * — zero locations, zero links per page — which is why the console omits a BLANK field rather than
     * sending 0 for it. That distinction is the server's pointer-typed fields; here it is `undefined`
     * versus 0, which `Number(x) || undefined` cannot express.
     */
    max_locations?: number;
    max_frontier?: number;
    max_links_per_page?: number;
    max_parse_bytes?: number;
    max_template_visits?: number;
    max_capture_bytes?: number;
    max_fingerprints?: number;
    max_relogins?: number;
   requests_per_second?: number;
   submit_forms?: boolean;
   /** Burp's "Reuse the site map" (burpsy-react-ui-z8qf): requests the site map already holds for the
    *  seeds' origins are not fetched again. Opt-in; omitted means off. */
   seed_from_site_map?: boolean;
   /**
    * Burp's crawler.error_handling, under Burp's names (burpsy-react-ui-o0c5). Same blank-versus-0
    * rule as the bounds above: blank is omitted (the engine default), a typed 0 is sent as 0 and
    * means "never" / "off" / "no retries".
    */
   pause_task_requests_timed_out_count?: number;
   pause_task_requests_timed_out_percentage?: number;
   consecutive_authentication_failures_before_pausing_task?: number;
   number_of_follow_up_passes?: number;
   query?: string;
   retention_query?: string;
  // riskAttack: api() mints the gate's confirmation on the operator's Start click (p1uz).
  }) => api<{ task_id: number; seeds: string[]; state: string; kind: string }>("/api/crawl", json("POST", body)),
  onSuccess: () => invalidate([keys.crawls, keys.dashboard, keys.sitemap]),
 });
}
