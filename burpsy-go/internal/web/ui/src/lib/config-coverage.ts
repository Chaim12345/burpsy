/**
 * A configuration bundle's own account of what it can carry.
 *
 * It lives in the FILE, not in the import response, and that split is deliberate on the server: a
 * bundle's coverage is evidence about the bundle, not an instruction to the importer
 * (configBundle.Coverage's doc in internal/web/api_config.go). So the console reads it out of the
 * document the operator chose, and uses the server's response only for what the server genuinely
 * knows — which surfaces this import applied.
 *
 * `undefined` is the load-bearing third state, and it is not the same as an empty list. A bundle
 * with no coverage block has told us nothing about its coverage, which is not the same as having
 * told us it carries everything. Reporting those two alike is how a partial transfer reads as a
 * complete one (burpsy-react-ui-f2kr).
 */
export interface BundleCoverage {
 /** True only when the file itself declares itself partial. */
 partial: boolean;
 /** The settings the file says it does not carry. */
 omitted: string[];
}

/**
 * Reads the coverage block out of a bundle's raw JSON text.
 *
 * Returns undefined — not an empty coverage — when the document has no usable coverage block, so
 * the caller can say "this file does not say what it can carry" instead of implying nothing was
 * left out. Every shape is narrowed rather than cast: this is an operator-supplied file, and an
 * unchecked assertion here would trust a shape nothing has checked.
 */
export function readBundleCoverage(text: string): BundleCoverage | undefined {
 let parsed: unknown;
 try {
  parsed = JSON.parse(text);
 } catch {
  return undefined;
 }
 if (!parsed || typeof parsed !== "object" || !("coverage" in parsed)) return undefined;
 const coverage = parsed.coverage;
 if (!coverage || typeof coverage !== "object") return undefined;
 const omittedRaw = "omitted" in coverage && Array.isArray(coverage.omitted) ? coverage.omitted : [];
 return {
  partial: "partial" in coverage && coverage.partial === true,
  omitted: omittedRaw.filter((x): x is string => typeof x === "string"),
 };
}

/**
 * The sections an import response reports having applied, named for a person.
 *
 * Derived from what the server said it applied rather than from a hand-written sentence. The
 * sentence this replaced read "Scope, intercept rules and session handling rules are affected",
 * which named three of the four carried sections and omitted uninteresting_headers even though it
 * IS in the bundle — a list that had already drifted from the server and would keep drifting.
 *
 * A section with nothing in it is not named: "0 scope rules applied" is a count in the detail line
 * already, and listing "scope" beside it tells the operator their scope was replaced when it was
 * not touched.
 */
export function appliedSectionLabels(response: {
 scope_rules?: unknown;
 intercept_dirs?: unknown;
 session_rules?: unknown;
 uninteresting_headers?: unknown;
}): string[] {
 const applied: string[] = [];
 if (typeof response.scope_rules === "number" && response.scope_rules > 0) applied.push("scope");
 if (typeof response.intercept_dirs === "number" && response.intercept_dirs > 0) applied.push("intercept rules");
 if (typeof response.session_rules === "number" && response.session_rules > 0) applied.push("session handling rules");
 if (response.uninteresting_headers === true) applied.push("uninteresting headers");
 return applied;
}
