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
