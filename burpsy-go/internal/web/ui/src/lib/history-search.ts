// The dedicated history search field (burpsy-react-ui-vlf).
//
// Burp's Search modifiers modify a dedicated search string, separate from any filter
// expression. burpsy's history page used to compile them against the DSL query box — a
// regex tick turned `host ~ "api" AND status = 200` into a RegExp tested against row
// fields, which matches nothing and empties the table. The compile step lives here as a
// pure function so that contract (and its failure mode) is testable without a page.
//
// Negation is deliberately not part of this helper: it composes at the call site as
// `keep the row when match === negate`, which is how the page already applies it and
// keeps "negative match" an exact inversion rather than a second matcher to keep in sync.

export interface HistorySearchOptions {
 caseSensitive: boolean;
 regex: boolean;
}

export interface CompiledHistorySearch {
 matcher: ((hay: string) => boolean) | null;
 error: string | null;
}

/** Compile the search field into a row predicate. Empty text means no search is active,
 * whatever the modifiers hold — a ticked checkbox alone must not narrow the table. */
export function compileHistorySearch(text: string, options: HistorySearchOptions): CompiledHistorySearch {
 const needle = text.trim();
 if (needle === "") return { matcher: null, error: null };

 if (options.regex) {
  try {
   const re = new RegExp(needle, options.caseSensitive ? "" : "i");
   return { matcher: (hay: string) => re.test(hay), error: null };
  } catch (failure) {
   return {
    matcher: null,
    error: failure instanceof Error ? failure.message : "invalid regular expression",
   };
  }
 }

 const cmp = options.caseSensitive ? needle : needle.toLowerCase();
 return {
  matcher: (hay: string) => (options.caseSensitive ? hay : hay.toLowerCase()).includes(cmp),
  error: null,
 };
}
