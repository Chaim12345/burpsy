import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CRAWL_STOP_LABELS, crawlOutcome, crawlStopLabel } from "./crawl-stops";
import type { CrawlRun } from "./types.observe";

function run(state: CrawlRun["state"], stops?: string[]): Pick<CrawlRun, "state" | "report"> {
 return {
  state,
  report: {
   seeds: [], form_submission: false, robots_policy: "", fetched: 4, refused: 0, failed: 0, not_captured: 0,
   links_found: 0, forms_found: 0, forms_submitted: 0, locations: 0, duplicate_locations: 0, elapsed: 0,
   ...(stops ? { limits: { stops } } : {}),
  },
 };
}

describe("crawlOutcome", () => {
 test("a crawl with no stop is done", () => {
  expect(crawlOutcome(run("done"))).toEqual({ label: "done", tone: "good" });
 });
 test("a crawl that hit a bound is not done", () => {
  expect(crawlOutcome(run("done", ["request-budget"])).label).toBe("incomplete");
 });
 test("a policy pause wins over any other stop", () => {
  expect(crawlOutcome(run("done", ["depth", "paused-auth-failures"])).label).toBe("paused by policy");
 });
 test("running and failed are their own states", () => {
  expect(crawlOutcome(run("running", ["depth"])).label).toBe("running");
  expect(crawlOutcome(run("failed")).label).toBe("failed");
 });
});

describe("labels", () => {
 test("an unknown stop name still renders, by name", () => {
  expect(crawlStopLabel("new-stop")).toBe("Stopped: new-stop");
 });
 test("every stop the engine names has a label", () => {
  // The engine's names, read from CrawlStop.String in internal/crawler/limits.go.
  const go = readFileSync(join(import.meta.dir, "..", "..", "..", "..", "crawler", "limits.go"), "utf8");
  const fn = /func \(s CrawlStop\) String\(\) string \{([\s\S]*?)\n\}/.exec(go)?.[1] ?? "";
  const names = [...fn.matchAll(/return "([^"]+)"/g)].map((m) => m[1]).filter((n) => n !== "unknown");
  expect(names.length).toBeGreaterThanOrEqual(18);
  expect(names.filter((n) => !(n! in CRAWL_STOP_LABELS))).toEqual([]);
 });
});
