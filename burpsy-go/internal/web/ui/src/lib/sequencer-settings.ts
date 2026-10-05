/**
 * Burp's Sequencer analysis settings as this console renders them (burpsy-react-ui-nm81, -3iao).
 *
 * The server keys the switches by Burp's names (`fips_poker`) and the report names tests by burpsy's
 * ids (`poker`); this table is the console's copy of internal/sequencer/analysis_tests.go, which maps
 * one to the other. It is used for labels and ORDER only — the rows themselves come from the
 * server's `keys`, so a key added server-side still gets a checkbox (labelled by its key) instead of
 * silently going missing.
 */
import type { SequencerSettings } from "./types.workbench";

export interface AnalysisTestInfo {
 /** Burp's sequencer.token_analysis.* key. */
 burpKey: string;
 /** burpsy's test id — what a report row's `id` is. Empty for count, which has no row. */
 id: string;
 name: string;
 battery: "character" | "fips" | "extended";
}

/** The base characterisation every other result is read against; the server refuses switching it off. */
export const COUNT_KEY = "count";

export const SEQUENCER_ANALYSIS_TESTS: readonly AnalysisTestInfo[] = [
 { burpKey: COUNT_KEY, id: "", name: "Character count analysis", battery: "character" },
 { burpKey: "fips_monobit", id: "monobit", name: "Monobit Test", battery: "fips" },
 { burpKey: "fips_poker", id: "poker", name: "Poker Test", battery: "fips" },
 { burpKey: "fips_runs", id: "runs", name: "Runs Test", battery: "fips" },
 { burpKey: "fips_long_run", id: "long_runs", name: "Long Runs Test", battery: "fips" },
 { burpKey: "transitions", id: "transition", name: "Character transition analysis", battery: "extended" },
 { burpKey: "spectral", id: "spectral", name: "Spectral test", battery: "extended" },
 { burpKey: "correlation", id: "correlation", name: "Correlation test", battery: "extended" },
 { burpKey: "compression", id: "compression", name: "Compression test", battery: "extended" },
];

export interface AnalysisSettingRow {
 burpKey: string;
 name: string;
 /** Whether the analysis runs. */
 on: boolean;
 /** True for count: shown checked and disabled, never sent as false. */
 locked: boolean;
}

/**
 * One row per key the server reports, in the table's order (count first, then the FIPS four, then
 * the extended four), with any key this console does not know appended under its own name.
 */
export function analysisSettingRows(settings: SequencerSettings | undefined): AnalysisSettingRow[] {
 if (!settings) return [];
 const serverKeys = settings.keys?.length ? settings.keys : Object.keys(settings.token_analysis ?? {});
 const known = new Map(SEQUENCER_ANALYSIS_TESTS.map((test) => [test.burpKey, test] as const));
 const ordered = [
  ...SEQUENCER_ANALYSIS_TESTS.filter((test) => serverKeys.includes(test.burpKey)).map((test) => test.burpKey),
  ...serverKeys.filter((key) => !known.has(key)).sort(),
 ];
 return ordered.map((key) => ({
  burpKey: key,
  name: known.get(key)?.name ?? key,
  on: key === COUNT_KEY ? true : (settings.token_analysis?.[key] ?? true),
  locked: key === COUNT_KEY,
 }));
}
