import { highlightName } from "./types";
/**
 * The slice of a Repeater tab this module reads. Declared here rather than imported from the store:
 * every function below is a decision about a list of tabs, and taking the shape structurally keeps
 * them testable with a literal and keeps the store's churn (the 6ex tab kind) out of their types.
 */
export interface TabLike {
 id: string;
 name: string;
 groupId?: string;
 color?: string;
}

/**
 * The Repeater tab strip's three view affordances (burpsy-react-ui-fkj), as pure functions over a
 * tab list. The page owns the DOM and the drag events; every decision about what those events MEAN
 * lives here, where a test can pin it with no browser — the same split the rest of the UI's
 * interaction logic uses, and the only reason a reorder can be mutation-checked at all.
 */

/**
 * Burp's tab-view toggle: one scrollable row, or tabs wrapped onto several rows.
 *
 * Burp's scrolling view is "a single, scrollable row" with "a drop-down list of open tabs" beside
 * it, so a strip of forty tabs costs one row of height and one dropdown to find the other thirty-
 * nine. Wrapped view trades the row for visibility. Both are here because the choice is per-operator
 * and per-engagement, not a default one side can pick for everyone.
 */
export type TabView = "scrolling" | "wrapped";

/** The columns a dropdown lists a tab under, in the order a reader scans them. */
export function tabDropdownGroups(
 tabs: TabLike[],
 named: { id: string; name: string }[] = [],
): { id: string; title: string; tabs: TabLike[] }[] {
 const byGroup = new Map<string, TabLike[]>();
 for (const tab of tabs) {
  const key = tab.groupId ?? "";
  const bucket = byGroup.get(key);
  if (bucket) {
   bucket.push(tab);
  } else {
   byGroup.set(key, [tab]);
  }
 }
 return [...byGroup.entries()].map(([id, members]) => ({
  id,
  title: id === "" ? "Ungrouped" : (named.find((group) => group.id === id)?.name ?? id),
  tabs: members,
 }));
}

/**
 * Move a tab to a new position in the strip, returning a new list.
 *
 * The tab is REMOVED first and then inserted at the target index, which is what makes "drag the
 * first tab to the end" move one tab rather than landing it on its neighbour: with the target
 * computed against the original indices, removing first would shift every later index down by one
 * and the drop would land one place short. That off-by-one is the whole bug this shape exists to
 * avoid, so the index is recomputed after the removal and clamped to the shortened list.
 */
export function reorderTabs<T>(tabs: T[], from: number, to: number): T[] {
 if (from < 0 || from >= tabs.length) return tabs;
 // A drop on a tab's own place is a no-op, and returns the SAME array so a caller can skip the
 // setState entirely rather than replacing a list with an identical copy.
 const same = Math.max(0, Math.min(to, tabs.length - 1)) === from;
 if (same && to >= 0 && to < tabs.length) return tabs;
 const next = [...tabs];
 const [moved] = next.splice(from, 1);
 if (moved === undefined) return tabs;
 // Clamp against the list AFTER the removal, which is one shorter. Clamping against the original
 // length would let a drop past the end insert at originalLength - 1 and land on the wrong tab —
 // moving the first tab of three "to the end" would put it between the last two, which is a bug a
 // test pins because an operator cannot see it as anything but "the drag did not go where I dropped
 // it".
 next.splice(Math.max(0, Math.min(to, next.length)), 0, moved);
 return next;
}

/**
 * Move a tab to sit at `to` within the tabs of its own group, keeping group membership.
 *
 * Burp lets a tab be dragged between groups too; that changes the tab's group, which is
 * `setRepeaterTabGroup` and not a move, so this function deliberately only reorders. A drag onto
 * another group's header is a different gesture with a different result, and conflating the two
 * would make an accidental drop change which group a request belongs to.
 */
export function reorderTabWithinGroup(tabs: TabLike[], tabId: string, to: number): TabLike[] {
 const index = tabs.findIndex((tab) => tab.id === tabId);
 if (index < 0) return tabs;
 const groupId = tabs[index]?.groupId;
 // The target is an index in the whole strip; translate it into the group-local one, or -1 when the
 // drop landed outside this tab's group (a no-op rather than a move into a group it never joined).
 const local = tabs.slice(0, index + 1).filter((tab) => tab.groupId === groupId).length - 1;
 if (local < 0) return tabs;
 const groupMembers = tabs.filter((tab) => tab.groupId === groupId);
 // `to` is a strip index; translate it into this tab's own group, and refuse a drop that landed
 // past the group rather than treating it as "last in the group". A drag that crosses a group
 // boundary is a different gesture with a different meaning (move the tab INTO the group), and
 // silently reinterpreting it as an in-group reorder would move a request between orders the
 // operator did not choose.
 if (to < 0 || to >= tabs.length) return tabs;
 // The drop landed ON a row. If that row is not in this tab's group, the drag crossed a boundary,
 // which is a different gesture (move the tab INTO that group) and must not be reinterpreted as an
 // in-group reorder.
 const landed = tabs[to];
 if (landed === undefined || landed.groupId !== groupId) return tabs;
 const targetLocal = tabs.slice(0, to + 1).filter((tab) => tab.groupId === groupId).length;
 const moved = reorderTabs(groupMembers, local, targetLocal);
 if (moved === groupMembers) return tabs;
 const next = [...tabs];
 let cursor = 0;
 return next.map((tab) => (tab.groupId === groupId ? (moved[cursor++] ?? tab) : tab));
}

/**
 * The colour a tab is drawn with, and why.
 *
 * A tab's own colour wins over its group's: Burp colours by group, but an operator marking ONE tab
 * (the one to attack next, the one whose response is still open) is saying something the group's
 * colour cannot, and burying it under the group would make the mark invisible exactly where it
 * was made. A grouped tab with no colour of its own inherits the group's, which is Burp's rule and
 * the reason a group's colour is still visible on its members.
 */
export function tabColour(
 // A structural type rather than Pick<RepeaterTab, ...>: the rule reads two fields and nothing
 // else, and naming the fields here keeps the test able to pass a literal without building a tab.
 tab: { color?: string; groupId?: string },
 groups: { id: string; color: string }[],
): { color: string; from: "tab" | "group" | undefined } {
 // "none" (any case) is no colour, the same as "" — see highlightName (burpsy-react-ui-iqwb).
 const own = highlightName(tab.color);
 if (own) {
  return { color: own, from: "tab" };
 }
 if (!tab.groupId) {
  return { color: "", from: undefined };
 }
 const group = groups.find((entry) => entry.id === tab.groupId);
 const inherited = highlightName(group?.color);
 return inherited ? { color: inherited, from: "group" } : { color: "", from: undefined };
}

/**
 * Burp's "Open tab search" over Repeater tabs (burpsy-react-ui-qqcn): the tabs whose name or target
 * contains every word of the query, case-insensitively, in strip order.
 *
 * Every word, not the phrase: "login staging" finds the tab named "login" whose target is the
 * staging host, which is how an operator with forty tabs remembers one — by two facts about it,
 * neither of which is the whole name. An empty query matches every tab rather than none, so
 * opening the search shows the full list to narrow rather than a blank box that reads as "no tabs".
 */
export function filterTabs<T extends { name: string; target?: string }>(tabs: T[], query: string): T[] {
 const words = query
  .toLowerCase()
  .split(/\s+/)
  .filter((word) => word !== "");
 if (words.length === 0) return tabs;
 return tabs.filter((tab) => {
  const haystack = `${tab.name}\n${tab.target ?? ""}`.toLowerCase();
  return words.every((word) => haystack.includes(word));
 });
}
