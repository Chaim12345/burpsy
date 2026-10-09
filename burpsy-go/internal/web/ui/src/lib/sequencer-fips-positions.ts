/**
 * The FIPS battery at each bit position (burpsy-react-ui-c0k3): the wire types and the pure geometry
 * the chart is drawn from.
 *
 * Burp's bit-level chart plots each position's significance as 6 + log10(p). A perfect position sits
 * at 6, the 1e-6 floor sits at 0, and a "FIPS pass level" line is drawn at 6 + log10(threshold). The
 * server floors significance at 1e-6 and sends the pass level, so this module only scales the values
 * into a box. The rule that a failing bar is marked by the server's verdict, not by where it falls
 * against the line, lives here so it can be tested: at N = 20,000 the verdict comes from the FIPS
 * intervals, and a bar may fail above the line or pass below it.
 */

export interface FipsPositionTest {
 id: "monobit" | "poker" | "runs" | "long_runs";
 name: string;
 disabled?: boolean;
 disable_reason?: string;
 /** The pass condition applied at this N, with its constants. */
 requirement: string;
 /** The significance a position must exceed when N != 20,000. */
 threshold: number;
 /** 6 + log10(threshold): where the pass line is drawn. */
 pass_level: number;
 statistic_label: string;
 /** Per position. All four arrays are [] when the test is switched off. */
 statistic: number[];
 significance: number[];
 passed: boolean[];
 failing_positions: number[];
 positions_passed: number;
 positions_failed: number;
}

export interface FipsPositionReport {
 computed: boolean;
 reason?: string;
 /** N: the sample size at every position. */
 tokens: number;
 tokens_not_analysed: number;
 positions_examined: number;
 positions_skipped_variable: number;
 positions_truncated: boolean;
 /** True at N = 20,000, where the FIPS intervals apply as written. */
 exact_intervals: boolean;
 method: string;
 affects_grade: boolean;
 tests: FipsPositionTest[];
}

/** The chart's y for a significance: 6 + log10(p), clamped to the axis [0, 6]. */
export function significanceScore(p: number): number {
 if (!(p > 0)) return 0;
 return Math.min(6, Math.max(0, 6 + Math.log10(p)));
}

export interface PositionBar {
 position: number;
 /** Left edge as a fraction of the plot width. */
 x: number;
 /** Width as a fraction of the plot width. */
 width: number;
 /** Height as a fraction of the plot height (score / 6). */
 height: number;
 passed: boolean;
 significance: number;
 statistic: number;
}

export interface PositionChart {
 bars: PositionBar[];
 /** The pass line's height as a fraction of the plot height. */
 passLine: number;
}

export function buildPositionChart(test: FipsPositionTest): PositionChart {
 const count = test.significance.length;
 const width = count > 0 ? 1 / count : 0;
 return {
  passLine: Math.min(1, Math.max(0, test.pass_level / 6)),
  bars: test.significance.map((significance, position) => ({
   position,
   x: position * width,
   width,
   height: significanceScore(significance) / 6,
   passed: test.passed[position] ?? false,
   significance,
   statistic: test.statistic[position] ?? 0,
  })),
 };
}

/** "0-3, 17, 40-41": failing positions as ranges, shortened past `limit` ranges. */
export function positionRanges(positions: number[], limit = 12): string {
 const ranges: string[] = [];
 let start = -1;
 let prev = -1;
 const flush = () => {
  if (start >= 0) ranges.push(start === prev ? `${start}` : `${start}-${prev}`);
 };
 for (const pos of positions) {
  if (pos === prev + 1 && start >= 0) {
   prev = pos;
   continue;
  }
  flush();
  start = pos;
  prev = pos;
 }
 flush();
 if (ranges.length <= limit) return ranges.join(", ");
 return `${ranges.slice(0, limit).join(", ")} and ${ranges.length - limit} more range(s)`;
}
