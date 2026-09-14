/**
 * Query hooks for the observe-area pages (WS history, site map) that need a richer wire shape than
 * the shared, trimmed hooks in `data.ts` provide. Built on the same `useResource`/`keys` the shared
 * hooks use, so the cache entries are the same entries the rest of the app invalidates — only the
 * static type of what comes back differs.
 */
import { useMutation } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys, useInvalidate, useResource } from "./data";
import type { Exchange } from "./types";
import type { CrawlRun, SiteMapDetail, WsMessageDetail } from "./types.observe";

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
 const q = useResource<{ crawls: CrawlRun[] }>(keys.crawls, "/api/crawl");
 const running = (q.data?.crawls ?? []).some((c) => c.state === "running");
 return { ...q, running };
};

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
  mutationFn: (body: { host: string; path_prefix?: string; port?: number }) =>
   api<PassiveBranchResult>("/api/scanner/passive-branch", json("POST", body)),
  // Findings and the dashboard both move; the site map does not, because no traffic was captured.
  onSuccess: () => invalidate([["issues"], ["dashboard"], ["scanner"]]),
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
   requests_per_second?: number;
   submit_forms?: boolean;
   query?: string;
   retention_query?: string;
  }) => api<{ task_id: number; seeds: string[]; state: string; kind: string }>("/api/crawl", json("POST", body)),
  onSuccess: () => invalidate([keys.crawls, keys.dashboard, keys.sitemap]),
 });
}
