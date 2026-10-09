import { describe, expect, test } from "bun:test";
import { buildPositionChart, positionRanges, significanceScore, type FipsPositionTest } from "./sequencer-fips-positions";

function fixture(significance: number[], passed: boolean[]): FipsPositionTest {
 return {
  id: "monobit",
  name: "Monobit Test",
  requirement: "",
  threshold: 1e-4,
  pass_level: 2,
  statistic_label: "count of ones",
  statistic: significance.map(() => 0),
  significance,
  passed,
  failing_positions: [],
  positions_passed: 0,
  positions_failed: 0,
 };
}

describe("per-position FIPS chart (c0k3)", () => {
 test("the score is Burp's 6 + log10(p), clamped to the axis", () => {
  expect(significanceScore(1)).toBe(6);
  expect(significanceScore(1e-6)).toBeCloseTo(0, 12);
  expect(significanceScore(1e-4)).toBeCloseTo(2, 12);
  expect(significanceScore(0)).toBe(0);
  expect(significanceScore(1e-9)).toBe(0);
 });

 test("the pass line is the server's pass level, and verdicts come from the server", () => {
  // At N = 20,000 the FIPS interval decides: position 1 sits above the line yet failed, and
  // position 2 sits below it yet passed. The chart must not re-derive either verdict.
  const chart = buildPositionChart(fixture([1, 0.5, 1e-5], [true, false, true]));
  expect(chart.passLine).toBeCloseTo(2 / 6, 12);
  expect(chart.bars.map((b) => b.passed)).toEqual([true, false, true]);
  expect(chart.bars[2]?.height).toBeCloseTo(1 / 6, 12);
  expect(chart.bars[1]?.x).toBeCloseTo(1 / 3, 12);
 });

 test("a switched-off test draws nothing", () => {
  expect(buildPositionChart(fixture([], [])).bars).toEqual([]);
 });

 test("failing positions read as ranges", () => {
  expect(positionRanges([0, 1, 2, 3, 17, 40, 41])).toBe("0-3, 17, 40-41");
  expect(positionRanges([])).toBe("");
  expect(positionRanges([1, 3, 5, 7], 2)).toBe("1, 3 and 2 more range(s)");
 });
});
