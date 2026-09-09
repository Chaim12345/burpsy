/**
 * Observe-area wire types that are richer than the shared trimmed views in `types.ts`.
 * Kept in their own module so this page's work doesn't collide with concurrent edits to the
 * shared `types.ts` file. Field names mirror the Go json tags exactly.
 */

/** Full payload view for one WS frame; the Go handler embeds wsRowView's fields at the top level,
 * so `opcode` here is what decides whether `text` or `hex` is the payload to show. */
export interface WsMessageDetail {
 id: number;
 exchange: number;
 direction: string;
 opcode: string;
 len: number;
 dropped: number;
 truncated: boolean;
 at_ms: number;
 text: string;
 hex: string;
 close?: { code: number; reason: string };
}

/** Site-map node, including the fields the trimmed shared `SiteNode` omits (`id`, `segment`) that
 * this page needs for a stable expand/collapse key and a display label independent of the full path. */
export interface SiteNodeDetail {
 /** Exact identity: the host for a host node, host + NUL + path for a path node. Replaced a numeric
  *  `id` that was a string hash — it could collide and could not be looked up, so this page already
  *  re-derived host+path itself rather than trusting it. */
 key: string;
 segment: string;
 path: string;
 exchanges: number;
 subtree_exchanges: number;
 methods: string[];
 statuses: number[];
 /** Distinct media-type words (mimeLabel's vocabulary) in the subtree; empty for a clean folder. */
 mimes?: string[];
 /** False for a folder synthesised to hold children — nothing requested the path itself. */
 requested: boolean;
 /** Findings recorded at this exact path. */
 issues: number;
 /** Findings at this path and everything under it, so a collapsed branch still says what is inside. */
 subtree_issues: number;
 /** Worst severity in the subtree, or "" when it is clean — never a zero-valued severity. */
 worst_severity?: string;
 /**
  * Whether the tools are allowed to touch this node. The map records every host the proxy saw,
  * including third parties nobody authorised, so out-of-scope nodes are dimmed rather than hidden:
  * the traffic is still evidence, it just is not a target.
  */
 in_scope: boolean;
 /** Distinct query-parameter names seen on this path; null when the server has none to report. */
 params: string[] | null;
 /** Omitted entirely by the server for leaf nodes, so it must be treated as optional. */
 children?: SiteNodeDetail[];
}

export interface SiteMapDetail {
 exchanges: number;
 nodes: number;
 synced: number;
 in_flight: number;
 tree: SiteNodeDetail[];
}

/**
 * One crawl's coverage story. Every count is a partition of something rather than a highlight:
 * fetched + refused + failed is every request the loop attempted, and the skip counts account for
 * every URL that was discovered and not attempted — so a report always answers "what happened to the
 * other ones", which is what makes it readable as coverage instead of as a highlight reel.
 */
export interface CrawlSkipCount {
 reason: number;
 name: string;
 count: number;
}

export interface CrawlSkipRecord {
 reason: number;
 url: string;
 method: string;
 detail: string;
}

/**
 * One request the crawl made, and how it got there.
 *
 * `found_at` is the crawl-paths edge: the URL of the page this one was discovered on, absent for a
 * seed. Absent means *seed*, not "unknown" — a seed genuinely has no referring page, and a renderer
 * must not label it as unattributed.
 *
 * `depth` says how far from a seed this is; `found_at` says which way. Two pages at depth 2 can be
 * reached through entirely different parents, which is why depth alone could not produce a
 * reachability view.
 */
export interface CrawlFetch {
 url: string;
 method: string;
 /** 0 when the response could not be parsed — not a real status. */
 status: number;
 exchange_id: number;
 depth: number;
 fingerprint?: string;
 /** Set when this response's contents had already been seen at another URL, so its links were not requeued. */
 duplicate_of?: string;
 /** Captured and scanned, but not traversed: the retention query did not match. */
 retention_excluded?: boolean;
 /** The page this was found on. Absent for a seed. */
 found_at?: string;
 /** The link text or form label followed to get here. Absent for a seed, or an untitled link. */
 link_text?: string;
}

export interface CrawlReport {
 seeds: string[];
 query?: string;
 retention_query?: string;
 form_submission: boolean;
 robots_policy: string;
 fetched: number;
 refused: number;
 failed: number;
 not_captured: number;
 links_found: number;
 forms_found: number;
 forms_submitted: number;
 locations: number;
 duplicate_locations: number;
 elapsed: number;
 skips?: { counts?: CrawlSkipCount[]; records?: CrawlSkipRecord[] };
 /** Every request the crawl attempted, carrying the crawl-paths edge. Absent on an empty crawl. */
 fetches?: CrawlFetch[];
}

export interface CrawlRun {
 /** The dashboard task id that produced this crawl — one identity, not two numbers to correlate. */
 task_id: number;
 seeds: string[];
 state: "running" | "done" | "failed";
 started: string;
 finished?: string;
 error?: string;
 report?: CrawlReport;
}
