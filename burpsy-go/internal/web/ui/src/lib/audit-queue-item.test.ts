import { describe, expect, test } from "bun:test";
import { itemProgress, itemTiming } from "./audit-queue-item";

/**
 * What one audit item's progress and timing say (burpsy-react-ui-xdtx).
 *
 * The engine retained all of this — the endpoint hands out `scanner.AuditItem` wholesale — and the
 * page reduced a diagnosable audit to six state totals. An item that stopped after two of five
 * steps is FINISHED and 40% audited, and an operator diagnosing a partial audit needs both at once:
 * a progress bar that snapped to 100 the moment the item left the queue would report exactly the
 * completeness the engine refused to claim.
 */

function item(over: Partial<Parameters<typeof itemProgress>[0]> = {}) {
 return { seq: 1, steps_planned: 5, steps_done: 5, ...over } as Parameters<typeof itemProgress>[0];
}

describe("an item's progress", () => {
 test("is the steps done out of planned, as a percentage", () => {
  expect(itemProgress(item({ steps_planned: 10, steps_done: 2 }))).toBe("2/10 steps (20%)");
 });

 test("is a finished item at 100%, not a finished item reported as partial", () => {
  // The rounding that would be wrong: 7/8 is 87.5% and must not read as 88% of something.
  expect(itemProgress(item({ steps_planned: 8, steps_done: 7 }))).toBe("7/8 steps (88%)");
  expect(itemProgress(item({ steps_planned: 4, steps_done: 4 }))).toBe("4/4 steps (100%)");
 });

 test("says NOT PLANNED rather than 0% when the plan is empty", () => {
  // The distinction the engine's own comment insists on: StepsPlanned is zero for an item refused
  // BEFORE planning, which is a different fact from a plan of length zero that ran to completion.
  // Reporting either as "0%" says the item did nothing, when it may never have been given work.
  expect(itemProgress(item({ steps_planned: 0, steps_done: 0 }))).toBe("not planned");
 });

 test("reports 0% for a real plan where nothing reached a disposition", () => {
  // The case the row above must not swallow: a planned item that reached nothing IS at 0%.
  expect(itemProgress(item({ steps_planned: 5, steps_done: 0 }))).toBe("0/5 steps (0%)");
 });

 test("treats missing fields as no progress rather than crashing", () => {
  // An older server, or a row that has not been resolved yet. The panel must still render.
  expect(itemProgress({ seq: 1 } as Parameters<typeof itemProgress>[0])).toBe("not planned");
 });

 test("reports more done than planned as itself rather than clamping to 100", () => {
  // A plan can grow — a breaker opening adds work. Clamping would hide that the denominator
  // moved, which is the number an operator needs when an item's accounting does not add up.
  expect(itemProgress(item({ steps_planned: 5, steps_done: 7 }))).toBe("7/5 steps (140%)");
 });
});

describe("an item's timing", () => {
 test("is the queue time alone when the row has not moved since", () => {
  const ms = Date.UTC(2026, 8, 26, 10, 0, 0);
  expect(itemTiming({ seq: 1, queued_unix_ms: ms, updated_unix_ms: ms } as never)).toBe(new Date(ms).toLocaleTimeString());
 });

 test("is a range when the row moved after it was queued", () => {
  // The only way to tell a slow item from a stalled one, which is the question a partial audit
  // raises: did the work take a long time, or did it stop changing?
  const q = Date.UTC(2026, 8, 26, 10, 0, 0);
  const u = Date.UTC(2026, 8, 26, 10, 5, 0);
  expect(itemTiming({ seq: 1, queued_unix_ms: q, updated_unix_ms: u } as never)).toBe(
   `${new Date(q).toLocaleTimeString()} → ${new Date(u).toLocaleTimeString()}`,
  );
 });

 test("is empty for a row that was never queued, so the cell can render an em dash", () => {
  expect(itemTiming({ seq: 1 } as never)).toBe("");
 });

 test("shows the queue time when the update timestamp is absent", () => {
  // A partial record beats a blank cell: the queue time is still a fact.
  const q = Date.UTC(2026, 8, 26, 10, 0, 0);
  expect(itemTiming({ seq: 1, queued_unix_ms: q } as never)).toBe(new Date(q).toLocaleTimeString());
 });
});
