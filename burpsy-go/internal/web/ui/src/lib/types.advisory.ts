/**
 * Wire shapes for the browsable issue-definition catalogue (GET /api/advisories).
 *
 * The detail shape is `Advisory` from ./types — the same one a finding carries on /api/issues, served
 * by the same Go function. It is imported rather than redeclared on purpose: one renderer reads both,
 * and a second copy of the type is how the two quietly stop matching.
 */
import type { Advisory } from "./types";

/**
 * One row of the catalogue list.
 *
 * Deliberately three fields. The catalogue is ~416 KB of prose across 183 definitions, and shipping
 * all of it to draw a list of names would be the same mistake as resolving message bodies to draw a
 * history table — so the description lives behind `GET /api/advisories/{type_index}` and arrives when
 * a row is opened.
 *
 * `type_index` is Burp's own hexadecimal identifier, which makes it both the join key for the detail
 * request and the thing an operator cross-checks against Burp.
 *
 * `typical_severity` is the severity this issue *class* usually carries. It is not a finding's
 * severity: nothing on this screen has been found, so there is no occurrence to rate.
 */
export interface AdvisoryIndexRow {
  type_index: string;
  name: string;
  typical_severity: string;
}

/**
 * The catalogue index response.
 *
 * `loaded`, `count` and `matched` are three separate facts and the screen reads all three, because
 * collapsing them is how an empty list starts lying. `loaded: false` means no catalogue was embedded
 * or supplied at all — a supported state, and the reason /api/issues reports its catalogue size.
 * `loaded: true` with `matched: 0` means the catalogue is present and the filter excluded everything.
 * Those call for opposite reactions, so the page says which one it is rather than showing one empty
 * state for both.
 */
export interface AdvisoryCatalogue {
  loaded: boolean;
  /** The whole catalogue, before any filter — the denominator in "N of M". */
  count: number;
  /** How many definitions survived the filter. Equal to `count` when nothing is filtered. */
  matched: number;
  /**
   * The whole catalogue partitioned by typical severity, keyed by the uppercase severity name. It
   * labels the severity filter's options, so it describes what selecting one *would* find rather
   * than what the current filter did find — and it sums to `count`, which the Go handler test
   * asserts.
   */
  severity_counts?: Record<string, number>;
  /** Why the catalogue is absent or empty. Absent when there is nothing to explain. */
  hint?: string;
  advisories: AdvisoryIndexRow[];
}

export type { Advisory };
