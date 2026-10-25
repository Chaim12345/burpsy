// The pre-scan filter step (burpsy-react-ui-a13), as data.
//
// Burp's scan wizard puts four filters in front of a scan — remove duplicate items, remove items
// with no parameters, remove out-of-scope items, remove items with the extensions js,gif,jpg,png,ico,
// css,woff,woff2,ttf,svg — each with a live count of what it removes. burpsy's ACTIVE scan is a crawl
// from seeds, so there is no item set to filter: the URLs are discovered during the crawl, and a
// crawl visits each unique URL once, so "remove duplicates" has nothing to remove. The passive branch
// sweep is the surface that does hold an item set (every captured exchange under a host/path) and
// that an operator is spending a budget on, so the filters landed there.
//
// The composition is a query rather than four booleans, for the reason the server takes a query: the
// filters and this package's filter grammar stay one thing, an operator can narrow past the presets,
// and the applied rule is a string the response echoes back. What the operator checks here and what
// the server removes cannot drift, because it is the same string.

/** Burp's shipped default list, verbatim from the wizard. */
export const BURP_DEFAULT_HIDDEN_EXTENSIONS = [
 "js", "gif", "jpg", "png", "ico", "css", "woff", "woff2", "ttf", "svg",
] as const;

/** The four filters the wizard offers, in its order. */
export interface PrescanFilters {
 /** Burp's own checkbox, always on here: the sweep already refuses out-of-scope exchanges and
  *  reports how many, so there is no second switch for a decision the server already makes. */
 removeNoParameters: boolean;
 /** The extension list, the one the bead calls worth building first. */
 hiddenExtensions: string[];
 /** Duplicates. Kept as a switch with its own explanation rather than dropped: a reader comparing
  *  this dialog with Burp's must be able to see it is absent and why, not find it missing. */
 removeDuplicates: boolean;
}

export const DEFAULT_PRESCAN_FILTERS: PrescanFilters = {
 removeNoParameters: false,
 hiddenExtensions: [...BURP_DEFAULT_HIDDEN_EXTENSIONS],
 removeDuplicates: false,
};

/** One extension as the grammar's `extension` field spells it: lower-case, no dot, no wildcard. */
export function normaliseExtension(raw: string): string {
 return raw.trim().toLowerCase().replace(/^\./, "");
}

/** The parseable extensions, de-duplicated. An entry that cannot be a field value is dropped rather
 *  than quoted into a query the server would refuse. */
export function parseExtensions(raw: string): string[] {
 const out = new Set<string>();
 for (const part of raw.split(/[\s,]+/)) {
  const ext = normaliseExtension(part);
  if (/^[a-z0-9][a-z0-9+.-]*$/.test(ext)) out.add(ext);
 }
 return [...out];
}

/**
 * The `exclude` query for a set of filters. Empty string means no filter at all, which is what the
 * server treats as "keep everything" — not a query that matches nothing.
 *
 * Every clause MATCHES the items to drop, the opposite polarity from the History filter box. The
 * grammar gives `extension` only =, != and ~ (no `in`), so a list of extensions is a disjunction of
 * `=`, parenthesised so the outer `not` cannot swallow the other clauses.
 */
export function prescanExclude(filters: PrescanFilters): string {
 const clauses: string[] = [];
 if (filters.removeNoParameters) clauses.push('params = 0');
 const extensions = filters.hiddenExtensions.map(normaliseExtension).filter((e) => e !== "");
 if (extensions.length > 0) {
  const one = extensions.map((ext) => `extension = "${ext}"`).join(" or ");
  clauses.push(`(${one})`);
 }
 if (clauses.length === 0) return "";
 // `not` binds tighter than `and` in this grammar, so more than one clause needs the whole group
 // parenthesised: `not params = 0 and extension = "png"` would drop every parameterless item and
 // KEEP every .png — the opposite of both filters at once.
 if (clauses.length === 1) return `not ${clauses[0]}`;
 return `not (${clauses.join(" and ")})`;
}

/**
 * What each filter would remove from a set of items, counted the way the wizard counts.
 *
 * A client-side prediction for the dialog's live counts only: the sweep's own numbers come back from
 * the server, and those are the ones reported. A prediction that drifted would be a wrong number on
 * a dialog, never a wrong sweep — but it is derived from the same two rules the grammar uses
 * (extension from the path, params = the query string's count) so the two agree.
 */
export function countFiltered(items: { path: string }[], filters: PrescanFilters): {
 extensions: number;
 noParameters: number;
 total: number;
} {
 const hidden = new Set(filters.hiddenExtensions.map(normaliseExtension).filter((e) => e !== ""));
 let extensions = 0;
 let noParameters = 0;
 for (const item of items) {
  // Each count answers its own switch's question, so a switch that is off contributes nothing:
  // reporting "3 items have no parameters" for a dialog with that filter off would be a number
  // about a filter nobody asked for.
  if (hidden.size > 0) {
   const ext = pathExtensionOf(item.path);
   if (ext !== null && hidden.has(ext)) extensions += 1;
  }
  if (filters.removeNoParameters && queryParamCountOf(item.path) === 0) noParameters += 1;
 }
 return { extensions, noParameters, total: extensions + noParameters };
}

/** The last path segment's extension, lower-cased, or null when there is none. Mirrors the grammar's
 *  pathExtension: absent is not empty, so an extensionless path is never "matched" by a list. */
export function pathExtensionOf(path: string): string | null {
 const clean = path.split(/[?#]/, 1)[0] ?? "";
 const last = clean.slice(clean.lastIndexOf("/") + 1);
 const dot = last.lastIndexOf(".");
 if (dot <= 0 || dot === last.length - 1) return null;
 return last.slice(dot + 1).toLowerCase();
}

/** The count of query parameters, which is what the grammar's `params` field reports. */
export function queryParamCountOf(path: string): number {
 const at = path.indexOf("?");
 if (at < 0 || at === path.length - 1) return 0;
 return path
  .slice(at + 1)
  .split("&")
  .filter((pair) => pair !== "").length;
}
