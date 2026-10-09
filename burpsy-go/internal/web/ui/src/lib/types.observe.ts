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
 /** The host-node identity repeated per node, so a row can name its exact connection tuple
   *  without parsing `key` (DELETE /api/sitemap, burpsy-react-ui-10e). */
 port: number;
 tls: boolean;
 exchanges: number;
 subtree_exchanges: number;
 methods: string[];
 statuses: number[];
 /** Distinct media-type words (mimeLabel's vocabulary) in the subtree; empty for a clean folder. */
 mimes?: string[];
 /** False for a folder synthesised to hold children — nothing requested the path itself. */
 requested: boolean;
 /**
  * True for a node an operator added to the map themselves (amu), as against one traffic was
  * observed on. The two are kept apart because the map's counts are all zero on an inserted node
  * precisely because nothing was requested there, and a zero that reads as a clean observation
  * would be a lie about coverage.
  */
 inserted?: boolean;
 /**
  * True for a URL the live passive crawl saw linked from proxied traffic that nothing has requested
  * (burpsy-react-ui-t3zk), Burp's grey "unrequested item". linked_from is the page that linked to it.
  */
 unrequested?: boolean;
 linked_from?: string;
 /** When the operator added it, in Unix milliseconds. Absent on an observed node. */
 added_at?: number;
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
 /** Requests not made because the site map already held them (burpsy-react-ui-z8qf) — only when the
  *  run was launched with seed_from_site_map. */
 sitemap_seeded?: number;
 /** Requests a follow-up pass retried successfully (burpsy-react-ui-o0c5). Omitted when 0. */
 follow_up_recovered?: number;
 /**
  * What bounded the crawl (internal/crawler/limits.go's LimitReport). `stops` names every bound
  * that was hit, in the order first hit; a crawl with any stop did not cover the application
  * (burpsy-react-ui-j5j7). Read through lib/crawl-stops.ts.
  */
 limits?: CrawlLimitReport;
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

/**
 * One crawl's effective bound set, as the run record publishes it.
 *
 * A named type rather than an inline shape because the server publishes the SAME eleven fields twice
 * — once as each run's effective bounds, once as the engine defaults — and a console that compares
 * the two needs one type for both. The index signature is what lets a row say "name every bound that
 * differs from the default" without a hand-written switch over eleven fields.
 */
export interface CrawlLimits {
 max_requests?: number;
 max_depth?: number;
 max_duration_secs?: number;
 max_locations?: number;
 max_frontier?: number;
 max_links_per_page?: number;
 max_parse_bytes?: number;
 max_template_visits?: number;
 max_capture_bytes?: number;
 max_fingerprints?: number;
 max_relogins?: number;
 [bound: string]: number | undefined;
}

/** A finished crawl's limit report. Only the fields the console reads are declared. */
export interface CrawlLimitReport {
 /** Stable stop names ("request-budget", "paused-timeouts", …); absent when nothing was hit. */
 stops?: string[];
 requests?: number;
 locations?: number;
 deepest_depth?: number;
 frontier_remaining?: number;
}

export interface CrawlRun {
 /** The dashboard task id that produced this crawl — one identity, not two numbers to correlate. */
 task_id: number;
 seeds: string[];
 state: "running" | "done" | "failed";
 /** "crawl", "crawl-audit" or "api-scan". Carried on the run rather than only in the launch request
  *  so a run read back tomorrow still says which of the three it was. */
 kind?: string;
 started: string;
 finished?: string;
 error?: string;
 report?: CrawlReport;
 /** Present only for an API-only scan: the document it was built from and what it sent. */
 definition?: APIScanDefinition;
 /**
  * The effective bound set this run was launched with, after defaults were filled in and any named
  * configuration overlaid (burpsy-react-ui-qzzy).
  *
  * On the run rather than only inside the finished report, because a crawl that is still running — or
  * one that found nothing and reported no report — is exactly when an operator asks "what was this
  * bounded by", and the answer has to exist then. Every field is a count or a length and every one of
  * them is optional here because the engine fills in its documented default for anything unset.
  */
 limits?: CrawlLimits;
}

/**
 * One endpoint an API scan sent, as the run record reports it.
 *
 * `template` is the path as the document wrote it (`/pets/{petId}`) and `path` is what went on the
 * wire (`/pets/1`). Both, because the first is what an operator checks against their document and the
 * second is the only one that names the request — and a run record carrying only the template could
 * not say which value the scan chose.
 */
export interface APIScanOperation {
 method: string;
 template: string;
 path: string;
}

/**
 * What a definition resolved to, in the terms the operator asked about.
 *
 * The two value counts are the honest-reporting half: a document that supplies examples for every
 * parameter drives a scan of the API as its authors documented it, and one that supplies none drives a
 * scan of placeholders this build invented. Same endpoint count, different scans — so both numbers and
 * `placeholder_note` travel with the run.
 *
 * Note what the counts cover: path, query and header parameters. A request body synthesised from a
 * schema is counted by neither, which is why the note spells out the three places rather than saying
 * "values".
 */
export interface APIScanDefinition {
 format: string;
 title?: string;
 version?: string;
 spec_version: string;
 servers?: string[];
 /** The host the paths were resolved against — the caller's override, or the document's first server. */
 base_url: string;
 operations: APIScanOperation[];
 declared_values: number;
 placeholder_values: number;
 placeholder_note: string;
}

/** The reply to a dry run: what a launch would send, with nothing started. */
export interface APIScanCheck {
 dry_run: true;
 definition: APIScanDefinition;
}

/** The reply to a launch: a task id to follow, not a finished scan. */
export interface APIScanAccepted {
 task_id: number;
 state: string;
 kind: string;
 /** Whether the audit half was accepted. Echoed so the toast can say what was actually started. */
 audit: boolean;
 definition: APIScanDefinition;
}
