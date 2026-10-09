// Saved table filters (mntt): the file round-trips, a wrong version or a wrong table is refused
// with the reason, and every value is checked against the table's own defaults before it applies.
import { describe, expect, test } from "bun:test";
import {
  differsFromDefaults,
  FILTER_DEFAULTS,
  FILTER_PRESET_VERSION,
  HISTORY_POPOVER_KEYS,
  parsePreset,
  readPresets,
  removePreset,
  sanitizeSettings,
  serializePreset,
  upsertPreset,
} from "./filter-presets";

const tuned = {
  ...FILTER_DEFAULTS.history,
  term: 'host = "api.example"',
  statusSet: ["4", "5"],
  onlyParameterized: true,
  limit: 2000,
  columnFilters: { host: "api", path: "", body: "" },
};

describe("the preset file", () => {
  test("round-trips: what is saved is what loads", () => {
    const text = serializePreset("history", "API errors", tuned, new Date("2026-10-08T00:00:00Z"));
    const parsed = parsePreset(text, "history");
    expect(parsed).toEqual({ ok: true, name: "API errors", settings: tuned, skipped: [] });
    expect(JSON.parse(text).burpsy_filter_preset).toBe(FILTER_PRESET_VERSION);
  });

  test("refuses an unknown version, naming both", () => {
    const text = JSON.stringify({ burpsy_filter_preset: 99, table: "history", name: "x", settings: {} });
    const parsed = parsePreset(text, "history");
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.reason).toBe(`Preset format version 99 is not one this build reads (it reads ${FILTER_PRESET_VERSION})`);
  });

  test("refuses another table's preset, naming it", () => {
    const parsed = parsePreset(serializePreset("logger", "x", FILTER_DEFAULTS.logger), "history");
    expect(parsed).toEqual({ ok: false, reason: "This preset is for Logger, not HTTP history" });
  });

  test("refuses what is not a preset at all", () => {
    expect(parsePreset("not json", "history")).toEqual({ ok: false, reason: "The file is not JSON" });
    expect(parsePreset("[]", "history")).toEqual({ ok: false, reason: "The file is not a filter preset" });
    expect(parsePreset('{"settings":{}}', "history")).toEqual({ ok: false, reason: "The file is not a burpsy filter preset" });
  });
});

describe("sanitizeSettings", () => {
  test("a wrong-typed value falls back to the default and is reported; unknown keys are dropped", () => {
    const { settings, skipped } = sanitizeSettings("history", { onlyCommented: "yes", limit: 100, injected: "x" });
    expect(settings.onlyCommented).toBe(false);
    expect(settings.limit).toBe(100);
    expect("injected" in settings).toBe(false);
    expect(skipped).toEqual(["onlyCommented"]);
  });

  test("a value outside a select's options is refused, element by element for sets", () => {
    const allowed = { statusSet: ["2", "4"], method: ["all", "GET"] };
    const { settings, skipped } = sanitizeSettings("history", { statusSet: ["2", "9"], method: "BREW" }, allowed);
    expect(settings.statusSet).toEqual([]);
    expect(settings.method).toBe("all");
    expect(skipped).toEqual(["statusSet", "method"]);
  });

  test("an object setting keeps the default's keys the file left out", () => {
    const { settings } = sanitizeSettings("history", { columnFilters: { host: "a" } });
    expect(settings.columnFilters).toEqual({ host: "a", path: "", body: "" });
  });

  test("a missing key takes the default — and never shares the defaults object", () => {
    const { settings } = sanitizeSettings("history", {});
    expect(settings).toEqual(FILTER_DEFAULTS.history);
    (settings.statusSet as string[]).push("2");
    expect(FILTER_DEFAULTS.history.statusSet).toEqual([]);
  });
});

describe("named presets", () => {
  test("upsert replaces by name and sorts; remove takes exactly that name", () => {
    let list = upsertPreset([], "b", tuned, "history");
    list = upsertPreset(list, "a", FILTER_DEFAULTS.history, "history");
    list = upsertPreset(list, "b", { ...tuned, limit: 50 }, "history");
    expect(list.map((preset) => preset.name)).toEqual(["a", "b"]);
    expect(list[1]!.settings.limit).toBe(50);
    expect(removePreset(list, "a").map((preset) => preset.name)).toEqual(["b"]);
  });

  test("a corrupt store reads as empty instead of throwing", () => {
    expect(readPresets({ getItem: () => "{oops" }, "history")).toEqual([]);
    expect(readPresets({ getItem: () => '{"not":"a list"}' }, "history")).toEqual([]);
    expect(readPresets({ getItem: () => null }, "history")).toEqual([]);
  });
});

describe("defaults", () => {
  test("Restore defaults is offered only when something differs", () => {
    expect(differsFromDefaults("organizer", FILTER_DEFAULTS.organizer)).toBe(false);
    expect(differsFromDefaults("organizer", { ...FILTER_DEFAULTS.organizer, annotatedOnly: true })).toBe(true);
  });

  test("History's Show all keys are all real filter keys with defaults", () => {
    for (const key of HISTORY_POPOVER_KEYS) expect(key in FILTER_DEFAULTS.history, key).toBe(true);
  });
});
