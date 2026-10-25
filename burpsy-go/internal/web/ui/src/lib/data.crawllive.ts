import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

/**
 * The live crawl view (burpsy-react-ui-1l3x): GET /api/crawl/live?task=N. Mirrors crawlLiveView in
 * internal/web/crawl_live.go. `frame` is null with `frame_note` saying why — no browser, logging in, not
 * rendered yet, or finished — so an absent picture never reads as a blank page.
 */
export interface CrawlLiveFetch {
 at: string;
 method: string;
 url: string;
 status: number;
 depth: number;
 exchange_id: number;
 found_by_render?: boolean;
}

export interface CrawlLiveView {
 task_id: number;
 state: "running" | "done" | "failed";
 phase: "starting" | "logging-in" | "fetching" | "rendering" | "rendered-audit" | "finished";
 current: { method?: string; url: string; since: string } | null;
 fetched: number;
 /** Newest first, at most fifty. */
 recent: CrawlLiveFetch[];
 browser: boolean;
 frame: { url: string; captured_at: string; image: string } | null;
 frame_note?: string;
 /** The most recent HTML page fetched — what the no-browser preview shows. */
 last_page: CrawlLiveFetch | null;
}

/** Polled once a second while the crawl runs, then left alone: a finished crawl's view does not move. */
export function useCrawlLive(taskId: number | null) {
 return useQuery({
  queryKey: ["crawl-live", taskId],
  queryFn: ({ signal }) => api<CrawlLiveView>(`/api/crawl/live?task=${taskId}`, { signal }),
  enabled: typeof taskId === "number" && taskId > 0,
  refetchInterval: (query) => (query.state.data?.state === "running" || query.state.data === undefined ? 1000 : false),
  retry: false,
 });
}

/**
 * The wire HTML of a page, made safe to show in the console: a Content-Security-Policy that forbids
 * every load and every script goes first, so the operator's browser sends nothing to the target on the
 * crawler's behalf — the crawl's requests are scope-checked, a preview's would not be.
 */
export const PREVIEW_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:";

export function lockedPreview(html: string): string {
 return `<meta http-equiv="Content-Security-Policy" content="${PREVIEW_CSP}">` + html;
}
