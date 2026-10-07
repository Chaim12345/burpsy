/**
 * The Sequencer's significance level and effective-entropy curve
 * (burpsy-react-ui-boq) — the wire types the Go report sends, and the pure
 * geometry the chart is drawn from.
 *
 * Burp makes the significance level the operator's input to the whole analysis
 * ("you can choose the probability you use to interpret the randomness of your
 * findings"), and makes the headline output a curve over it rather than one
 * number: "the Effective entropy chart shows the number of bits that pass the
 * randomness tests at various significance levels, ranging from > 0.001% to
 * 10%". This module holds the level list the operator picks from and the
 * arithmetic that turns the server's points into something drawable.
 *
 * The geometry lives here, apart from the page, for one reason: the rule that a
 * level the sample cannot answer is a GAP in the line and never a zero is a
 * claim worth a test, and a claim buried in JSX is a claim nobody can assert.
 * `buildEffectiveEntropyChart` is a pure function over the server's points and
 * `sequencer-significance.test.ts` pins that rule against it.
 */

/** One level on the curve. `bits` is null exactly when `computed` is false. */
export interface EffectiveEntropyPoint {
 /** The level as a percentage: 0.03 means 0.03%, not 3%. */
 significance_percent: number;
 /** The same level as a fraction, the form p-values are compared against. */
 significance: number;
 /** False when the sample cannot support an answer at this level. */
 computed: boolean;
 /** Bit positions not rejected at this level. Null exactly when `computed` is false —
  *  and it must be rendered as an absence, never as a zero, which would read as
  *  "no bit survived" rather than "this sample cannot say". */
 bits: number | null;
 /** Bit positions the sample could test at all: the ceiling `bits` counts against. */
 bits_examined: number;
 bits_rejected: number | null;
 /** significance x bits_examined: how many positions a perfect generator would be
  *  expected to lose to chance here. The curve applies no multiple-comparison
  *  correction — deliberately, since correcting flattens the slope the chart exists
  *  to show — so this is what a loss is read against. */
 expected_chance_rejections: number | null;
 /** Why there is no answer. Present exactly when `computed` is false. */
 reason?: string;
 /** True on the point at the level the operator chose. */
 chosen: boolean;
}

export interface EffectiveEntropyReport {
 significance_percent: number;
 /** True when no level was supplied and the server used its default, so the UI can
  *  say "default" rather than implying a choice was made. */
 significance_defaulted: boolean;
 chosen: EffectiveEntropyPoint;
 curve: EffectiveEntropyPoint[];
 /** The test set the bit counts come from. "Bits that pass the randomness tests" is
  *  not a quotable number until these are named, so the page renders them. */
 tests: string[];
 /** The server's own definition of the headline number, carried on the wire. */
 definition: string;
 tokens_used: number;
 bit_positions_examined: number;
 bit_positions_skipped_variable_length: number;
 positions_truncated: boolean;
 robust: boolean;
 robustness_note: string;
 /** How this curve and the FIPS grade beside it relate, in the server's words. */
 fips_agreement: string;
 /** Always false: the grade is the FIPS battery's. */
 affects_grade: boolean;
}

/**
 * The levels the operator can pick, matching the server's ladder
 * (`significanceLadder` in internal/sequencer/effective.go). The two bands are
 * the ones Burp names: FIPS work at 0.002%–0.03%, scientific work at 1%–5%.
 */
export const SIGNIFICANCE_LEVELS: readonly { percent: number; label: string; band?: string }[] = [
 { percent: 0.001, label: "0.001%" },
 { percent: 0.002, label: "0.002%", band: "FIPS" },
 { percent: 0.005, label: "0.005%", band: "FIPS" },
 { percent: 0.01, label: "0.01%", band: "FIPS" },
 { percent: 0.02, label: "0.02%", band: "FIPS" },
 { percent: 0.03, label: "0.03%", band: "FIPS" },
 { percent: 0.05, label: "0.05%" },
 { percent: 0.1, label: "0.1%" },
 { percent: 0.2, label: "0.2%" },
 { percent: 0.5, label: "0.5%" },
 { percent: 1, label: "1%", band: "scientific" },
 { percent: 2, label: "2%", band: "scientific" },
 { percent: 5, label: "5%", band: "scientific" },
 { percent: 10, label: "10%" },
];

/** The server's default, echoed here so the select can preselect it without a round trip. */
export const DEFAULT_SIGNIFICANCE_PERCENT = 1;

export interface ChartMark {
 percent: number;
 /** 0..1 across the plot, left to right. */
 x: number;
 /** 0..1 up the plot. Only present where the level was answered. */
 y: number;
 bits: number;
 chosen: boolean;
}

export interface ChartGap {
 percent: number;
 x: number;
 reason: string;
 chosen: boolean;
}

export interface EffectiveEntropyChart {
 /** The answered levels, in order. */
 marks: ChartMark[];
 /** The levels with no answer. Drawn as gaps, never as points at zero. */
 gaps: ChartGap[];
 /** Contiguous runs of answered levels. A run break is a level the sample could not
  *  answer: joining across it would draw a line through a value that does not exist. */
 runs: ChartMark[][];
 /** The y-axis top: bit positions examined, not the largest plotted count. A curve
  *  that loses every bit must look empty, not full. */
 maxBits: number;
 /** True when there is nothing to draw at all. */
 empty: boolean;
}

/**
 * Turn the server's curve into plot coordinates.
 *
 * x is logarithmic in the significance level, because the range spans four
 * decades (0.001% to 10%) and a linear axis would compress every FIPS-band level
 * into the leftmost pixel — which is precisely the band Burp tells operators to
 * use for FIPS work.
 *
 * y is the bit count against `bits_examined`, taken from the points rather than
 * from the plotted maximum: a sample that loses all of its bits has to render as
 * a floor, and rescaling to its own maximum would draw it as a full chart.
 */
export function buildEffectiveEntropyChart(points: readonly EffectiveEntropyPoint[]): EffectiveEntropyChart {
 const usable = points.filter((p) => Number.isFinite(p.significance_percent) && p.significance_percent > 0);
 if (usable.length === 0) return { marks: [], gaps: [], runs: [], maxBits: 0, empty: true };

 const logs = usable.map((p) => Math.log10(p.significance_percent));
 const lo = Math.min(...logs);
 const hi = Math.max(...logs);
 const span = hi - lo;
 const xFor = (percent: number): number => (span === 0 ? 0.5 : (Math.log10(percent) - lo) / span);

 const maxBits = usable.reduce((most, p) => Math.max(most, p.bits_examined), 0);
 const yFor = (bits: number): number => (maxBits === 0 ? 0 : bits / maxBits);

 const marks: ChartMark[] = [];
 const gaps: ChartGap[] = [];
 const runs: ChartMark[][] = [];
 let run: ChartMark[] = [];

 for (const point of usable) {
  // `computed` is the authority, not `bits != null`: a point that claims an answer
  // without a number is a server bug, and drawing it at zero would hide the bug
  // behind a plausible-looking dip.
  if (!point.computed || point.bits === null) {
   if (run.length > 0) {
    runs.push(run);
    run = [];
   }
   gaps.push({
    percent: point.significance_percent,
    x: xFor(point.significance_percent),
    reason: point.reason ?? "",
    chosen: point.chosen,
   });
   continue;
  }
  const mark: ChartMark = {
   percent: point.significance_percent,
   x: xFor(point.significance_percent),
   y: yFor(point.bits),
   bits: point.bits,
   chosen: point.chosen,
  };
  marks.push(mark);
  run.push(mark);
 }
 if (run.length > 0) runs.push(run);

 return { marks, gaps, runs, maxBits, empty: marks.length === 0 && gaps.length === 0 };
}

/**
 * An SVG polyline `points` attribute for one run, mapped into a box.
 *
 * Separated from the geometry so the chart's pixel arithmetic is testable without
 * a DOM: the y axis is flipped here (SVG counts down from the top) and getting
 * that backwards would draw a healthy sample as a collapsing one.
 */
export function runPolyline(run: readonly ChartMark[], width: number, height: number): string {
 return run.map((mark) => `${(mark.x * width).toFixed(2)},${((1 - mark.y) * height).toFixed(2)}`).join(" ");
}

/** The level's label, matching SIGNIFICANCE_LEVELS, for a level that may not be on the ladder. */
export function significanceLabel(percent: number): string {
 const known = SIGNIFICANCE_LEVELS.find((level) => level.percent === percent);
 return known ? known.label : `${percent}%`;
}

/**
 * Whether the movement across the curve is more than chance explains.
 *
 * `robust` on the server is strict equality — the honest reading of "the choice
 * of level does not change this verdict" — but a healthy 32-bit sample routinely
 * loses one or two positions at 5% and 10% purely to the level's own
 * false-positive rate, and styling that as a warning would call an artefact a
 * defect. This is the display question, kept apart from the server's claim: does
 * the spread exceed what a perfect generator would be expected to lose at the
 * loosest level on the curve?
 *
 * Only computed points count. An absent level contributes no bits and no
 * expectation; treating it as either would be inventing a data point.
 */
export function spreadExceedsChance(points: readonly EffectiveEntropyPoint[]): boolean {
 const answered = points.filter((p) => p.computed && p.bits !== null);
 if (answered.length < 2) return false;
 const counts = answered.map((p) => p.bits as number);
 const spread = Math.max(...counts) - Math.min(...counts);
 const expected = Math.max(...answered.map((p) => p.expected_chance_rejections ?? 0));
 return spread > expected;
}
