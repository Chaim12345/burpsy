/**
 * Why a crawl stopped short (burpsy-react-ui-j5j7): the console's labels for the stop names the
 * engine reports in `report.limits.stops` (internal/crawler/limits.go, CrawlStop.String — stable
 * names, one per bound that was hit). A crawl with any stop did NOT cover the application, and it
 * must never read as a plain "done · N fetched".
 */
import type { CrawlRun } from "./types.observe";

export const CRAWL_STOP_LABELS: Readonly<Record<string, string>> = {
 "request-budget": "Request budget spent with URLs still queued",
 duration: "Time budget spent with URLs still queued",
 "location-budget": "Location budget spent",
 depth: "Links past the depth limit were not followed",
 "frontier-capacity": "Frontier full — links were dropped",
 "speculative-links": "Speculative-link cap spent",
 "links-per-page": "A page had more links than the per-page bound",
 "parse-bytes": "A body's tail was not examined for links",
 cancelled: "Cancelled before the frontier emptied",
 "template-quota": "A URL template was sampled to its quota",
 "capture-bytes": "A response was too large to store or scan",
 "fingerprint-budget": "Request-identity table full — unseen URLs refused",
 "relogin-budget": "Re-login budget spent — the rest was crawled logged out",
 "paused-timeouts": "Paused by policy: too many requests timed out in a row",
 "paused-timeout-percentage": "Paused by policy: too large a share of requests timed out",
 "paused-auth-failures": "Paused by policy: re-logins kept failing",
 "follow-up-budget": "Failed requests not retried — the request budget was spent",
 "follow-up-cancelled": "Cancelled during the follow-up pass — some failures not retried",
};

/** A stop the console has no label for still shows, under its own name. */
export function crawlStopLabel(name: string): string {
 return CRAWL_STOP_LABELS[name] ?? `Stopped: ${name}`;
}

export function isPolicyPause(name: string): boolean {
 return name.startsWith("paused-");
}

export function crawlStops(run: Pick<CrawlRun, "report"> | undefined): string[] {
 return run?.report?.limits?.stops ?? [];
}

/**
 * The one word a run's badge shows. "done" is reserved for a crawl that exhausted its frontier; a
 * finished crawl that hit any bound is "incomplete", and one that stopped itself on an
 * error-handling threshold is "paused by policy" — the operator has something to look at.
 */
export function crawlOutcome(run: Pick<CrawlRun, "state" | "report">): { label: string; tone: "good" | "warn" | "bad" | "info" } {
 if (run.state === "failed") return { label: "failed", tone: "bad" };
 if (run.state === "running") return { label: "running", tone: "info" };
 const stops = crawlStops(run);
 if (stops.some(isPolicyPause)) return { label: "paused by policy", tone: "warn" };
 if (stops.length > 0) return { label: "incomplete", tone: "warn" };
 return { label: "done", tone: "good" };
}
