/**
 * Tests for the Sequencer analysis-settings rows (burpsy-react-ui-nm81, -3iao). Run with
 * `bun run test:lib`.
 */
import { describe, expect, test } from "bun:test";
import { analysisSettingRows, COUNT_KEY } from "./sequencer-settings";
import type { SequencerSettings } from "./types.workbench";

const keys = ["compression", "correlation", "count", "fips_long_run", "fips_monobit", "fips_poker", "fips_runs", "spectral", "transitions"];

function settings(overrides: Record<string, boolean> = {}): SequencerSettings {
 const token_analysis: Record<string, boolean> = Object.fromEntries(keys.map((k) => [k, true]));
 return { token_analysis: { ...token_analysis, ...overrides }, token_handling: { base_64_decode_before_analyzing: false }, keys };
}

describe("analysisSettingRows", () => {
 test("one row per server key, count first, FIPS before extended", () => {
  const rows = analysisSettingRows(settings());
  expect(rows.map((r) => r.burpKey)).toEqual([
   "count",
   "fips_monobit",
   "fips_poker",
   "fips_runs",
   "fips_long_run",
   "transitions",
   "spectral",
   "correlation",
   "compression",
  ]);
 });
 test("count is locked on even if the document says otherwise", () => {
  const count = analysisSettingRows(settings({ count: false })).find((r) => r.burpKey === COUNT_KEY);
  expect(count).toMatchObject({ on: true, locked: true });
 });
 test("a switched-off test reads as off", () => {
  expect(analysisSettingRows(settings({ fips_poker: false })).find((r) => r.burpKey === "fips_poker")?.on).toBe(false);
 });
 test("a key this console does not know still gets a row, under its own name", () => {
  const extra = { ...settings(), keys: [...keys, "future_test"] };
  const row = analysisSettingRows(extra).at(-1);
  expect(row).toMatchObject({ burpKey: "future_test", name: "future_test", on: true, locked: false });
 });
 test("nothing loaded is no rows", () => {
  expect(analysisSettingRows(undefined)).toEqual([]);
 });
});
