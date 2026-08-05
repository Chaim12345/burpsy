/**
 * Query hooks for the observe-area pages (WS history, site map) that need a richer wire shape than
 * the shared, trimmed hooks in `data.ts` provide. Built on the same `useResource`/`keys` the shared
 * hooks use, so the cache entries are the same entries the rest of the app invalidates — only the
 * static type of what comes back differs.
 */
import { keys, useResource } from "./data";
import type { Exchange } from "./types";
import type { SiteMapDetail, WsMessageDetail } from "./types.observe";

/** Full Exchange record for one id — used where a page only started with an exchange id (a WS
 * connection, a site-map node) and needs the whole row to offer the full send-to menu. */
export const useExchange = (id: number | null | undefined) =>
  useResource<Exchange>(keys.exchange(id ?? -1), `/api/exchange/${id ?? 0}`, typeof id === "number" && id > 0);

/** Same endpoint and cache key as the shared `useSitemap`, typed to the full node shape (id, segment)
 * that a real expand/collapse tree needs. */
export const useSitemapDetailed = () => useResource<SiteMapDetail>(keys.sitemap, "/api/sitemap");

/** Same endpoint and cache key as the shared `useWsMessage`, typed to the full frame shape (opcode,
 * dropped, truncated) needed to render text/hex/close payloads distinctly. */
export const useWsMessageDetailed = (id: number | null | undefined) =>
  useResource<WsMessageDetail>(keys.wsMessage(id ?? -1), `/api/ws/message/${id ?? 0}`, typeof id === "number" && id > 0);
