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
