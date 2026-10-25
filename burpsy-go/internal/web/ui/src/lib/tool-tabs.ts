/**
 * Which top-level tool tabs the operator has hidden (burpsy-react-ui-lje3).
 *
 * Burp's View menu carries one checkable entry per top-level tab plus "Restore default tab layout":
 * hiding a tab is how a Burp user narrows the chrome to the tools they actually use, and the hidden
 * tab keeps working — it is still reachable by hotkey, by the command palette and by a link into one
 * of its routes.
 *
 * localStorage, matching `burpsy.split.*`, `burpsy.logger.columns` and the keymap overrides: this is
 * a per-browser preference, not server state, and it must survive a reload without a round trip.
 * Every access is wrapped, because a private window, cleared site data or a browser set to block
 * storage all throw on access — and a tab strip is not worth a blank page.
 *
 * Stored as an array of tool ids rather than a map of booleans so an unknown id (a tab removed in a
 * later release) costs nothing and never resurrects itself.
 */
export const TOOL_TABS_STORAGE_KEY = "burpsy.tooltabs.hidden";

/**
 * The ids currently hidden. Anything that is not an array of non-empty strings reads as "nothing is
 * hidden" — the state that shows every tab — because a corrupted preference must not be able to
 * hide a tool the operator cannot then find.
 */
export function readHiddenToolTabs(): string[] {
 try {
  const raw = window.localStorage.getItem(TOOL_TABS_STORAGE_KEY);
  if (!raw) return [];
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) return [];
  const ids = parsed.filter((id): id is string => typeof id === "string" && id !== "");
  return [...new Set(ids)];
 } catch {
  return [];
 }
}

/** Persists the hidden set. A failed write still applies for this session. */
export function writeHiddenToolTabs(ids: string[]): void {
 try {
  window.localStorage.setItem(TOOL_TABS_STORAGE_KEY, JSON.stringify(ids));
 } catch {
  // Storage unavailable (private mode, quota): the choice holds until the page is reloaded.
 }
}

/** Forgets the preference entirely — Burp's "Restore default tab layout". */
export function clearHiddenToolTabs(): void {
 try {
  window.localStorage.removeItem(TOOL_TABS_STORAGE_KEY);
 } catch {
  // Nothing to do: the caller resets its own state, which is what the operator sees.
 }
}

/*
 * Tab order (burpsy-react-ui-sk29). Burp: "click a tab and drag it along the tab bar … Burp
 * remembers your preferences". Same storage posture as the hidden set above: localStorage, every
 * access guarded, and a value that cannot be read means the default order, never a lost tab.
 */
export const TOOL_TAB_ORDER_STORAGE_KEY = "burpsy.tooltabs.order";

/** The saved order: ids, first occurrence wins. Anything unreadable is the default order (empty). */
export function readToolTabOrder(): string[] {
 try {
  const raw = window.localStorage.getItem(TOOL_TAB_ORDER_STORAGE_KEY);
  if (!raw) return [];
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) return [];
  return [...new Set(parsed.filter((id): id is string => typeof id === "string" && id !== ""))];
 } catch {
  return [];
 }
}

export function writeToolTabOrder(ids: string[]): void {
 try {
  window.localStorage.setItem(TOOL_TAB_ORDER_STORAGE_KEY, JSON.stringify(ids));
 } catch {
  // Storage unavailable: the order holds until the page is reloaded.
 }
}

export function clearToolTabOrder(): void {
 try {
  window.localStorage.removeItem(TOOL_TAB_ORDER_STORAGE_KEY);
 } catch {
  // The caller resets its own state.
 }
}

/**
 * `tabs` in the saved order. Saved ids that name no tab are skipped; a tab the saved order does not
 * mention (one added in a later release) keeps its default relative place after the saved ones, so
 * the result is always exactly the tabs given, each once.
 */
export function orderToolTabs<T extends { id: string }>(tabs: readonly T[], order: readonly string[]): T[] {
 const byId = new Map(tabs.map((tab) => [tab.id, tab]));
 const out: T[] = [];
 for (const id of order) {
  const tab = byId.get(id);
  if (tab) {
   out.push(tab);
   byId.delete(id);
  }
 }
 return [...out, ...tabs.filter((tab) => byId.has(tab.id))];
}

/** `order` after dragging `from` onto `to`: it lands where `to` was (after it going forward, before it going back). */
export function moveToolTab(order: readonly string[], from: string, to: string): string[] {
 const fromAt = order.indexOf(from);
 const toAt = order.indexOf(to);
 if (fromAt < 0 || toAt < 0 || fromAt === toAt) return [...order];
 const rest = order.filter((id) => id !== from);
 rest.splice(rest.indexOf(to) + (fromAt < toAt ? 1 : 0), 0, from);
 return rest;
}
