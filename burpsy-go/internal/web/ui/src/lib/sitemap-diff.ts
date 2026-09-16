// The Compare-site-maps surface (burpsy-react-ui-k3a7): which runs a comparison can be drawn
// from, and how the rows render their verdicts.
//
// The DOM half (the pickers, the table, the jump-to-history link) needs a mounted console; the
// rules here decide whether a control exists at all, which is the failure class this bead was
// filed on — the capability existed in Burp and nothing surfaced it.
import type { CrawlRun } from "./types.observe";

/**
 * The runs a site-map comparison can be drawn from.
 *
 * Only finished runs, because a running crawl's path set is still growing: a diff against it
 * would report paths the run simply has not reached yet as absent — the exact false finding an
 * access-control comparison must not make. Failed runs ARE offered: what a crawl reached before
 * failing is a real path set, and "the authenticated crawl died at /admin but had already seen
 * it" is worth comparing.
 *
 * Order is the served order (the run registry answers newest-first), so the two most recent
 * runs are the first two a picker offers — the comparison an operator just ran the crawls for.
 */
export function comparableRuns(runs: CrawlRun[] | undefined): CrawlRun[] {
 return (runs ?? []).filter((run) => run.state !== "running");
}

/** The human label for one row's side verdict. The wire carries "a" | "b" | "both". */
export function sideLabel(side: string, taskA: number, taskB: number): string {
 if (side === "a") return `only in run ${taskA}`;
 if (side === "b") return `only in run ${taskB}`;
 return "both runs";
}

/** One row of the path-set diff, mirroring sitemapPathDiffRow on the Go side. */
export interface SitemapDiffRow {
 host: string;
 port: number;
 tls: boolean;
 path: string;
 side: "a" | "b" | "both";
 status_a?: number;
 status_b?: number;
}

/** The wire answer of POST /api/tools/compare-sitemaps. */
export interface SitemapDiffResponse {
 task_a: number;
 task_b: number;
 rows: SitemapDiffRow[];
 only_a: number;
 only_b: number;
 both: number;
}
