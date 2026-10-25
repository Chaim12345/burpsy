import type { ScopeLibraryEntry, ScopeLibraryResult } from "./data.policy";

/**
 * The sentences the scope page says about a saved rule set (burpsy-react-ui-e365).
 *
 * They live here, apart from the page, because every one of them is a statement about what traffic
 * will be authorised a moment from now, and the page is the one place where that statement is
 * hardest to test. A load REPLACES the live rule list — it does not merge into it — and the operator
 * has to be told that in a sentence carrying the two numbers before they click, not by a button
 * labelled "Load" and a surprise afterwards. The wording is what the issue asked to be stated
 * rather than left to the implementation, so it is the thing under test.
 */

/** The count a library reports when its stored document cannot be parsed. See ScopeLibraryEntry. */
export const SCOPE_LIBRARY_DAMAGED = -1;

/** True when the server could not read this library's rules. Such a row must never be loadable:
 *  the server refuses it anyway (500), and offering the button would be an invitation to an error. */
export const isScopeLibraryDamaged = (entry: ScopeLibraryEntry): boolean =>
 entry.rules === SCOPE_LIBRARY_DAMAGED || entry.rules < 0;

/** "1 rule" / "4 rules", so the sentences below read as English rather than as "1 rules". */
export const scopeRuleCount = (n: number): string => `${n} ${n === 1 ? "rule" : "rules"}`;

/**
 * What loading this library will do to the scope that is in force now, in one sentence, before it
 * happens. Both numbers are real — the library's count from the listing, the live count from the
 * rules table — because "replaces your rules" without them leaves the operator to guess whether
 * they are about to lose four rules or forty.
 */
export function describeScopeLibraryLoad(entry: ScopeLibraryEntry, liveRules: number): string {
 if (isScopeLibraryDamaged(entry)) {
  return `“${entry.name}” cannot be read, so it cannot be loaded. Your current scope is untouched.`;
 }
 if (liveRules === 0) {
  return `Loads ${scopeRuleCount(entry.rules)} from “${entry.name}”. Your scope is empty right now, and an empty scope allows every host.`;
 }
 return `Replaces the ${scopeRuleCount(liveRules)} in your scope now with the ${scopeRuleCount(entry.rules)} saved in “${entry.name}”. Rules that are not in the library are removed.`;
}

/** The confirmation a delete asks for. A library is the only copy of a rule set, so the sentence
 *  says that rather than asking "are you sure?" about an unnamed thing. */
export const describeScopeLibraryDelete = (entry: ScopeLibraryEntry): string =>
 `Delete the scope library “${entry.name}”? The ${isScopeLibraryDamaged(entry) ? "rules it holds" : scopeRuleCount(entry.rules)} saved under that name cannot be recovered. Your current scope is not changed.`;

/**
 * The toast after a save. An overwrite is reported as an overwrite: a save that quietly replaced
 * yesterday's rule set and said "Saved" is how a scope is lost without anyone noticing.
 */
export function describeScopeLibrarySaved(name: string, result: ScopeLibraryResult): string {
 const rules = scopeRuleCount(result.rules ?? 0);
 return result.replaced
  ? `Replaced the scope library “${name}” with the ${rules} in scope now`
  : `Saved ${rules} to the scope library “${name}”`;
}

/** The toast after a load, stating what is now in force rather than that a button worked. */
export const describeScopeLibraryLoaded = (name: string, result: ScopeLibraryResult): string =>
 `Loaded “${name}”: ${scopeRuleCount(result.rules ?? 0)} now in scope`;

/**
 * When a library was written, as a row in a picker shows it. Relative for anything inside a day —
 * "which of these two is the one I saved after lunch" is the question the picker is actually asked —
 * and an absolute date beyond that, where "9 days ago" stops being easier to read than the date.
 */
export function describeScopeLibraryAge(savedAtMs: number, now: number = Date.now()): string {
 if (!Number.isFinite(savedAtMs) || savedAtMs <= 0) return "saved at an unknown time";
 const seconds = Math.round((now - savedAtMs) / 1000);
 if (seconds < 0) return new Date(savedAtMs).toLocaleString();
 if (seconds < 60) return "just now";
 const minutes = Math.round(seconds / 60);
 if (minutes < 60) return `${minutes} min ago`;
 const hours = Math.round(minutes / 60);
 if (hours < 24) return `${hours} h ago`;
 return new Date(savedAtMs).toLocaleDateString();
}
