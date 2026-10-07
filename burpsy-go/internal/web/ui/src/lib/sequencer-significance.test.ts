import { describe, expect, test } from "bun:test";
import {
 buildEffectiveEntropyChart,
 runPolyline,
 significanceLabel,
 spreadExceedsChance,
 SIGNIFICANCE_LEVELS,
 type EffectiveEntropyPoint,
} from "./sequencer-significance";

// The rule this file exists to hold: a significance level the sample cannot
// answer is an absence in the chart, never a point at zero. A chart that plots
// an unanswerable level at zero tells the operator the generator produced no
// entropy there, which is the opposite of what the server said.

function computed(percent: number, bits: number, examined = 8): EffectiveEntropyPoint {
 return {
  significance_percent: percent,
  significance: percent / 100,
  computed: true,
  bits,
  bits_examined: examined,
  bits_rejected: examined - bits,
  expected_chance_rejections: (percent / 100) * examined,
  chosen: false,
 };
}

function absent(percent: number, examined = 8): EffectiveEntropyPoint {
 return {
  significance_percent: percent,
  significance: percent / 100,
  computed: false,
  bits: null,
  bits_examined: examined,
  bits_rejected: null,
  expected_chance_rejections: null,
  reason: "insufficient sample",
  chosen: false,
 };
}

describe("effective entropy chart geometry", () => {
 test("a level the sample cannot answer becomes a gap and never a plotted zero", () => {
  const chart = buildEffectiveEntropyChart([absent(0.001), absent(0.1), computed(1, 4), computed(10, 4)]);
  expect(chart.gaps.map((g) => g.percent)).toEqual([0.001, 0.1]);
  expect(chart.marks.map((m) => m.percent)).toEqual([1, 10]);
  // The claim in full: no mark anywhere carries a bit count the server did not send.
  expect(chart.marks.every((m) => Number.isFinite(m.bits))).toBe(true);
  expect(chart.marks.some((m) => m.bits === 0 && m.percent < 1)).toBe(false);
 });

 test("a gap breaks the line rather than being interpolated across", () => {
  const chart = buildEffectiveEntropyChart([computed(0.01, 8), absent(0.1), computed(1, 4), computed(10, 4)]);
  // Two runs, not one: joining 0.01% to 1% would draw a line through 0.1%, a level
  // at which this sample has no value at all.
  expect(chart.runs.length).toBe(2);
  expect(chart.runs[0]?.map((m) => m.percent)).toEqual([0.01]);
  expect(chart.runs[1]?.map((m) => m.percent)).toEqual([1, 10]);
 });

 test("the y axis is the bits examined, so a curve that loses everything renders as a floor", () => {
  const chart = buildEffectiveEntropyChart([computed(1, 0, 32), computed(10, 0, 32)]);
  expect(chart.maxBits).toBe(32);
  // Scaling to the plotted maximum instead would put both points at the top and
  // draw a sample with zero surviving bits as a full chart.
  expect(chart.marks.every((m) => m.y === 0)).toBe(true);
 });

 test("x is logarithmic in the level, so the FIPS band is not crushed into the left edge", () => {
  const chart = buildEffectiveEntropyChart([computed(0.001, 8), computed(0.1, 8), computed(10, 8)]);
  const [lowest, middle, highest] = chart.marks;
  expect(lowest?.x).toBeCloseTo(0, 10);
  expect(highest?.x).toBeCloseTo(1, 10);
  // Four decades span the axis, and 0.1% sits two decades in — at the halfway
  // point. On a linear axis it would sit at 0.00999, indistinguishable from the
  // left edge, and every level Burp names for FIPS work would be there with it.
  expect(middle?.x).toBeCloseTo(0.5, 10);
 });

 test("marks stay in ascending level order so the line is drawn left to right", () => {
  const chart = buildEffectiveEntropyChart([computed(0.01, 8), computed(0.1, 7), computed(1, 6), computed(10, 5)]);
  const xs = chart.marks.map((m) => m.x);
  expect(xs).toEqual([...xs].sort((a, b) => a - b));
  expect(chart.marks.map((m) => m.bits)).toEqual([8, 7, 6, 5]);
 });

 test("an empty curve is empty rather than a chart of one flat line at zero", () => {
  const chart = buildEffectiveEntropyChart([]);
  expect(chart.empty).toBe(true);
  expect(chart.marks).toEqual([]);
  expect(chart.runs).toEqual([]);
 });

 test("a curve with no answer at any level draws nothing but keeps its gaps", () => {
  const chart = buildEffectiveEntropyChart([absent(0.001), absent(1), absent(10)]);
  expect(chart.marks).toEqual([]);
  expect(chart.runs).toEqual([]);
  expect(chart.gaps.length).toBe(3);
  expect(chart.empty).toBe(false);
 });

 test("the polyline flips y, because SVG counts down from the top", () => {
  const chart = buildEffectiveEntropyChart([computed(1, 8, 8), computed(10, 0, 8)]);
  // 8 of 8 bits is the healthy end and must sit at the TOP of the box (y = 0 in
  // SVG); 0 of 8 must sit at the bottom (y = height). Getting this backwards
  // draws a perfect sample as a collapsing one.
  expect(runPolyline(chart.runs[0] ?? [], 100, 50)).toBe("0.00,0.00 100.00,50.00");
 });

 test("a point whose server said computed but sent no number is treated as an absence", () => {
  const broken: EffectiveEntropyPoint = { ...computed(1, 0), bits: null };
  const chart = buildEffectiveEntropyChart([broken]);
  // Drawing it at zero would hide a server bug behind a plausible-looking dip.
  expect(chart.marks).toEqual([]);
  expect(chart.gaps.map((g) => g.percent)).toEqual([1]);
 });
});

describe("the significance levels offered", () => {
 test("the ladder spans Burp's stated range and both bands it names", () => {
  const percents = SIGNIFICANCE_LEVELS.map((l) => l.percent);
  expect(Math.min(...percents)).toBe(0.001);
  expect(Math.max(...percents)).toBe(10);
  // Burp: "Scientific experiments often use levels between 1% and 5%. FIPS tests
  // often use levels between 0.002% and 0.03%." Both endpoints of both bands have
  // to be offerable, or the operator cannot reproduce the convention they were told.
  for (const wanted of [0.002, 0.03, 1, 5]) expect(percents).toContain(wanted);
 });

 test("every level is in ascending order, matching the server's ladder", () => {
  const percents = SIGNIFICANCE_LEVELS.map((l) => l.percent);
  expect(percents).toEqual([...percents].sort((a, b) => a - b));
 });

 test("a level off the ladder still gets a label rather than rendering as undefined", () => {
  expect(significanceLabel(1)).toBe("1%");
  expect(significanceLabel(3.7)).toBe("3.7%");
 });
});

describe("whether the curve's movement is more than chance", () => {
 test("a drop no larger than the chance expectation is not called a defect", () => {
  // 32 positions examined; at 10% a perfect generator is expected to lose 3.2 of
  // them. A spread of 2 across the curve is inside that, so flagging it would
  // present the level's own false-positive rate as a finding about the generator.
  const curve = [computed(1, 32, 32), computed(5, 31, 32), computed(10, 30, 32)];
  expect(spreadExceedsChance(curve)).toBe(false);
 });

 test("a drop larger than the chance expectation is flagged", () => {
  // Same 32 positions and the same 3.2 expected at 10%, but 20 positions lost.
  const curve = [computed(1, 32, 32), computed(10, 12, 32)];
  expect(spreadExceedsChance(curve)).toBe(true);
 });

 test("levels with no answer contribute neither a count nor an expectation", () => {
  // The absent point has no bits and no expectation. Reading it as zero bits
  // would manufacture a spread of 32 out of a curve that never moved.
  const curve = [absent(0.001, 32), computed(1, 32, 32), computed(10, 32, 32)];
  expect(spreadExceedsChance(curve)).toBe(false);
 });

 test("a single answered level cannot be said to move at all", () => {
  expect(spreadExceedsChance([computed(1, 4)])).toBe(false);
  expect(spreadExceedsChance([])).toBe(false);
 });
});
