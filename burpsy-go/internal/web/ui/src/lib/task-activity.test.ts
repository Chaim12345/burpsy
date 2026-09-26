import { describe, expect, test } from "bun:test";
import { taskActivityFindings } from "./task-activity";

/**
 * Which findings a task's detail pane may show (burpsy-react-ui-xwxd).
 *
 * The tab sits beside ONE task and answers "what did that scan find?". It was the project-wide
 * feed sorted by id and capped at 20, which fails in two directions at once:
 *
 *   1. A task that found nothing displays OTHER tasks' findings under its own name — a clean scan
 *      that reports findings, which is the failure this project treats as worse than an absent panel.
 *   2. A busy task has its own older findings dropped by the 20-cap while showing newer ones it
 *      never raised, so it is under-reported in favour of somebody else's work.
 */

/** A finding as the API returns one, with the fields this module reads. */
function finding(id: number, taskID?: number): { id: number; task_id?: number; issue_name: string } {
 return { id, task_id: taskID, issue_name: `finding ${id}` };
}

describe("a task's own issue activity", () => {
 test("is only the findings that task raised", () => {
  // The core property. Without it, a scan's pane reports another scan's results.
  const all = [finding(1, 7), finding(2, 8), finding(3, 7), finding(4, undefined)];
  expect(taskActivityFindings(all, 7).shown.map((f) => f.id)).toEqual([3, 1]);
 });

 test("is EMPTY for a task that found nothing, rather than falling back to the project feed", () => {
  // The clean-scan failure. An empty state scoped to the task is a fact; a project feed under a
  // task's name is not, and the pane must not quietly substitute one for the other.
  const all = [finding(1, 8), finding(2, 9), finding(3, 8)];
  expect(taskActivityFindings(all, 7).shown).toEqual([]);
 });

 test("excludes a finding with no task at all, however recent it is", () => {
  // A manual recording, or a collaborator result imported from elsewhere, belongs to no run. It is
  // a real loss from this tab — but attributing it to a task the scanner did not produce is worse
  // than not showing it, and the Issues page still carries every finding including these.
  const all = [finding(9, undefined), finding(1, 7)];
  expect(taskActivityFindings(all, 7).shown.map((f) => f.id)).toEqual([1]);
 });

 test("is ordered newest first, by the id the order IS", () => {
  // FindingDetail carries no time, so id order is the feed's whole basis (burpsy-react-ui-i18) and
  // a stable secondary ordering is needed for the equal case rather than leaving it to sort.
  const all = [finding(1, 7), finding(3, 7), finding(2, 7)];
  expect(taskActivityFindings(all, 7).shown.map((f) => f.id)).toEqual([3, 2, 1]);
 });

 test("caps the list, and reports how many it left out", () => {
  // A cap that reads as a total is the same defect one level up: a task with 40 findings would
  // show 20 and let the row count imply those were all of them.
  const all = Array.from({ length: 40 }, (_, i) => finding(i + 1, 7));
  const result = taskActivityFindings(all, 7, 20);
  expect(result.shown).toHaveLength(20);
  expect(result.shown[0]?.id).toBe(40);
  expect(result.hidden).toBe(20);
 });

 test("reports nothing hidden when the list fits under the cap", () => {
  // A "showing 20 of 20" line on a complete list is noise that trains the operator to ignore the
  // one time it matters.
  const all = [finding(1, 7), finding(2, 7)];
  expect(taskActivityFindings(all, 7, 20).hidden).toBe(0);
 });

 test("scopes before capping, so the cap cannot drop this task's own findings in favour of others'", () => {
  // The second failure mode. 30 findings from another task must not consume the budget and push
  // this task's older findings out of the pane entirely.
  const others = Array.from({ length: 30 }, (_, i) => finding(100 + i, 8));
  const mine = [finding(1, 7), finding(2, 7)];
  const result = taskActivityFindings([...others, ...mine], 7, 20);
  expect(result.shown.map((f) => f.id)).toEqual([2, 1]);
  expect(result.hidden).toBe(0);
 });

 test("is empty for a project with no findings at all", () => {
  const result = taskActivityFindings([], 7);
  expect(result.shown).toEqual([]);
  expect(result.hidden).toBe(0);
 });
});
