/**
 * Which findings a task's detail pane may show (burpsy-react-ui-xwxd).
 *
 * Extracted so the scoping rule is testable on its own. In the component it was a one-line filter
 * over the project feed — which is exactly why nobody could see it was wrong: a filter that
 * returns the input unchanged looks identical to one that scopes it.
 *
 * A finding with no `task_id` belongs to no run. Excluding it from every task's pane is a real
 * loss, and it is the right one: attributing an untracked manual recording to the scan the operator
 * is looking at is the failure this module exists to prevent, and the Issues page still carries
 * every finding including those.
 */
export interface TaskActivityFinding {
 id: number;
 task_id?: number;
}

/** The default cap, matching the pane's original 20-row limit. */
export const DEFAULT_TASK_ACTIVITY_LIMIT = 20;

export interface TaskActivityResult<T extends TaskActivityFinding> {
 /** This task's findings, newest first, at most `limit` of them. */
 shown: T[];
 /** How many of this task's findings the cap left out — 0 when the list fit. */
 hidden: number;
}

/**
 * The findings raised by `taskID`, newest first, with the number the cap dropped.
 *
 * Scoping happens BEFORE the cap, which is the ordering that matters: capping first would let a
 * busy neighbouring task consume the budget and push this task's own older findings out of its
 * pane entirely — the second of the two failure modes, and the one a reader is least likely to
 * notice, because the pane still shows findings.
 */
export function taskActivityFindings<T extends TaskActivityFinding>(
 findings: readonly T[],
 taskID: number,
 limit: number = DEFAULT_TASK_ACTIVITY_LIMIT,
): TaskActivityResult<T> {
 const mine = findings.filter((f) => f.task_id === taskID);
 // A copy before sorting: the caller's array is the query cache's, and sorting it in place would
 // reorder what every other view of the same data sees.
 const ordered = [...mine].sort((a, b) => b.id - a.id);
 const shown = limit >= ordered.length ? ordered : ordered.slice(0, Math.max(0, limit));
 return { shown, hidden: ordered.length - shown.length };
}
