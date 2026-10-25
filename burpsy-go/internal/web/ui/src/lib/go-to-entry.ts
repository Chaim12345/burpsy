/**
 * Burp's TABLE_GO_TO_ENTRY (Zipf.java) for HTTP history (vfu2): "see entry 1843" in a ticket is
 * one action, not a query.
 *
 * The entry number is History's # column — the exchange id — so "go to 1843" has four honest
 * outcomes, and the point of naming them is that the operator is told which:
 *   - shown: the row is in the table now; select it and scroll to it.
 *   - filtered: the exchange exists, the table's filter hides it; offer to clear the filter.
 *   - beyond-limit: it exists, nothing filters it, and it is older than the rows loaded (History
 *     loads the newest N); offer it in a detail window rather than pretending it is not there.
 *   - missing: the store has no such exchange (deleted, or never captured).
 */

/** "1843", "#1843", " 1843 " → 1843. Anything else, including 0 and negatives, is null. */
export function parseEntryNumber(raw: string): number | null {
  const match = /^\s*#?\s*(\d{1,12})\s*$/.exec(raw);
  if (!match) return null;
  const n = Number(match[1]);
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

export type GoToOutcome = "shown" | "filtered" | "beyond-limit" | "missing";

export function classifyEntry(input: {
  id: number;
  /** Ids of the rows the table is displaying now. */
  displayed: ReadonlySet<number>;
  /** Whether the store answered for this id. */
  exists: boolean;
  /** Whether any filter (not the row limit) is narrowing the table. */
  filtered: boolean;
}): GoToOutcome {
  if (input.displayed.has(input.id)) return "shown";
  if (!input.exists) return "missing";
  return input.filtered ? "filtered" : "beyond-limit";
}
