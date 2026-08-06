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

/** Start a crawl. Resolves as soon as the server has accepted it and registered the task — not when
 * the crawl finishes — so the caller gets a task id to follow rather than a blocked promise. */
export function useStartCrawl() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (body: {
      seeds: string[];
      max_requests?: number;
      max_depth?: number;
      max_duration_secs?: number;
      requests_per_second?: number;
      submit_forms?: boolean;
      query?: string;
      retention_query?: string;
    }) => api<{ task_id: number; seeds: string[]; state: string }>("/api/crawl", json("POST", body)),
    onSuccess: () => invalidate([keys.crawls, keys.dashboard, keys.sitemap]),
  });
}
