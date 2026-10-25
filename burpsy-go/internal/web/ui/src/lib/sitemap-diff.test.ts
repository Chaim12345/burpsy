// The Compare-site-maps surface (burpsy-react-ui-k3a7) — the part worth testing without a DOM:
// which runs a comparison can be drawn from, and how the rows render their verdicts.
//
// The DOM half (the pickers, the table, the jump-to-history link) needs a mounted console; the
// rules here decide whether a control exists at all, which is the failure class this bead was
// filed on — the capability existed in Burp and nothing surfaced it.
import { describe, expect, test } from "bun:test";
import { comparableRuns, sideLabel } from "./sitemap-diff";

/** A CrawlRun, minimal: the fields comparableRuns reads. */
function run(taskId: number, state: "running" | "done" | "failed", seeds: string[] = []) {
 return { task_id: taskId, seeds, state, started: "2026-09-16T00:00:00Z" };
}

describe("which runs a site-map comparison can be drawn from", () => {
 test("only finished runs are offered, because a running crawl's path set is still growing", () => {
  const runs = [run(1, "done"), run(2, "running"), run(3, "failed")];
  expect(
   comparableRuns(runs).map((r) => r.task_id),
   "a diff against a running crawl would report paths the run has not reached yet as absent — the exact false finding an access-control check must not make",
  ).toEqual([1, 3]);
 });

 test("a failed run is offered, because what it reached before failing is still a real path set", () => {
  const runs = [run(1, "failed"), run(2, "done")];
  expect(
   comparableRuns(runs).map((r) => r.task_id),
   "excluding failed runs would hide a half-finished crawl whose partial map is exactly the thing worth comparing",
  ).toEqual([1, 2]);
 });

 test("the module lists what it holds; the page decides whether two exist — a picker needs the truth, not a pre-clamped list", () => {
  expect(comparableRuns([run(1, "done")]).map((r) => r.task_id)).toEqual([1]);
  expect(comparableRuns([])).toEqual([]);
 });
});

describe("the row verdict a site-map diff renders", () => {
 test("side labels name the run, not a bare letter", () => {
  // The rows carry side: "a" | "b" | "both" on the wire (a compact enumerable); the render
  // must not leak the wire token to the operator. This pins the mapping rather than the DOM.
  expect(sideLabel("a", 3, 7)).toBe("only in run 3");
  expect(sideLabel("b", 3, 7)).toBe("only in run 7");
  expect(sideLabel("both", 3, 7)).toBe("both runs");
 });
});
