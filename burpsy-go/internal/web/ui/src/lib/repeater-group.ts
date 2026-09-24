import type { RepeaterGroupSendResult, RepeaterHistoryEntry, RepeaterWsHistoryEntry } from "./types";

/**
 * Fold a group send's results into the per-tab Repeater history (burpsy-react-ui-03z).
 *
 * Extracted from the page rather than written inline because it is the part of a group send that can
 * be wrong quietly. Three rules it has to get right at once, and each of them has already been the
 * shape of a real defect in this panel:
 *
 *  1. Each result goes into *its own tab's* history. A group send is N answers and only one of them
 *     belongs to the tab on screen; putting them all on the active tab is the bug that looks like it
 *     works until the operator clicks tab 2.
 *  2. Each entry pairs the response with the request that produced it — the RepeaterHistoryEntry
 *     contract. `sentRequests` is captured before the send, so an entry records what was sent rather
 *     than what that tab's draft says by the time the answers arrive.
 *  3. An item with no result appends nothing. There is no response to pair a request with, and a
 *     fabricated entry would put a request in the history beside a response that never existed.
 *
 * The whole fold is one new object, so a caller can hand it straight to a setState updater: N
 * separate updates in a loop would each close over the same snapshot and only the last would survive.
 */
export function appendGroupResultsToHistory(
  current: Record<string, (RepeaterHistoryEntry | RepeaterWsHistoryEntry)[]>,
  result: RepeaterGroupSendResult,
  sentRequests: Map<string, string>,
): Record<string, (RepeaterHistoryEntry | RepeaterWsHistoryEntry)[]> {
  const next = { ...current };
  for (const item of result.items) {
    const sentRequest = sentRequests.get(item.tab_id);
    if (!item.result || sentRequest == null) continue;
    next[item.tab_id] = [
      ...(next[item.tab_id] ?? []),
      {
        ...item.result,
        request: sentRequest,
        // How it was sent, kept on the entry because an entry that rode a shared socket is not
        // comparable with one that dialled fresh, and that difference is the subject of the test.
        group_mode: result.mode,
        duration_measured: item.duration_measured,
        ...(item.framing ? { framing: item.framing } : {}),
        ...(item.response_complete != null ? { response_complete: item.response_complete } : {}),
      },
    ];
  }
  return next;
}

/**
 * Return every tab that just got an answer to following its newest entry.
 *
 * Same rule a single send follows: an operator who had paged back to compare is still asking "what
 * did this one do", so a landed result snaps that tab forward. Only tabs that actually got a result
 * move — a tab whose request failed has no new entry to snap to, and moving it would point it at an
 * older send it did not ask to see.
 */
export function followNewestAfterGroupSend(
  current: Record<string, number | null>,
  result: RepeaterGroupSendResult,
): Record<string, number | null> {
  const next = { ...current };
  for (const item of result.items) {
    if (item.result) next[item.tab_id] = null;
  }
  return next;
}
