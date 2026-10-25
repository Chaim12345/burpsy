/**
 * Saved table filters: Burp's "Restore defaults", "Load settings" and "Save settings" in every
 * filter window (desktop/tools/filter.html, "Managing the filter settings"), for History, Logger
 * and Organizer (mntt).
 *
 * Three things an operator can do with a tuned filter:
 *   - name it and keep it in this browser (localStorage, per table), to pick from a list later;
 *   - save it to a file and load it elsewhere (Burp's Save/Load settings are files);
 *   - put everything back to the table's shipped defaults.
 *
 * The file is versioned and names its table. A preset from another table, or another version, is
 * refused with the reason rather than half-applied: applying History's `mimeSet` to Organizer
 * would set nothing and report success. Values are type-checked key by key against the table's
 * defaults, so a hand-edited file cannot put a string where a boolean belongs.
 */

export const FILTER_PRESET_VERSION = 1;

export type FilterTable = "history" | "logger" | "organizer";

export const FILTER_TABLE_LABEL: Record<FilterTable, string> = {
 history: "HTTP history",
 logger: "Logger",
 organizer: "Organizer",
};

/** One table's filter settings: plain JSON values only. */
export type FilterSettings = Record<string, string | number | boolean | string[] | Record<string, string>>;

/**
 * Each table's shipped defaults — the single definition behind "Restore defaults", and the schema
 * a loaded preset is checked against. History's "Show all" in the More filters popover resets a
 * subset of these (HISTORY_POPOVER_KEYS), from here.
 */
export const FILTER_DEFAULTS: Record<FilterTable, FilterSettings> = {
 history: {
  term: "",
  statusSet: [],
  mimeSet: [],
  filterOn: true,
  method: "all",
  limit: 500,
  scopeOnly: false,
  hideNoResponse: false,
  onlyParameterized: false,
  listenerPorts: "",
  onlyCommented: false,
  onlyHighlighted: false,
  showExtensions: "",
  hideExtensions: "",
  searchText: "",
  searchCase: false,
  searchRegex: false,
  searchNegate: false,
  columnFilters: { host: "", path: "", body: "" },
 },
 logger: {
  tool: "",
  term: "",
  annotatedOnly: false,
  method: "",
  statusClass: "",
  // Burp Logger's view filter axes (uvpb), added after the first logger presets were saved: a
  // preset written before them lacks these keys and loads with them at these defaults (3dyy).
  viewScopeOnly: false,
  viewHasResponse: false,
  viewParameterized: false,
  viewMime: "",
  viewExt: "",
 },
 organizer: {
  term: "",
  termRegex: false,
  termCase: false,
  termNegative: false,
  inScopeOnly: false,
  statusClass: "all",
  mimeFilter: "all",
  toolFilter: "all",
  workflowFilter: "all",
  extensionFilter: "all",
  annotatedOnly: false,
 },
};

/** The keys History's "More filters" popover owns; its "Show all" resets exactly these. */
export const HISTORY_POPOVER_KEYS = [
 "onlyParameterized",
 "onlyCommented",
 "onlyHighlighted",
 "showExtensions",
 "hideExtensions",
 "searchText",
 "searchCase",
 "searchRegex",
 "searchNegate",
] as const;

export interface FilterPresetFile {
 burpsy_filter_preset: number;
 table: FilterTable;
 name: string;
 saved_at: string;
 settings: FilterSettings;
}

function sameShape(value: unknown, template: unknown): boolean {
 if (Array.isArray(template)) return Array.isArray(value) && value.every((entry) => typeof entry === "string");
 if (template !== null && typeof template === "object") {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.entries(value as Record<string, unknown>).every(
   ([key, entry]) => key in (template as Record<string, unknown>) && typeof entry === "string",
  );
 }
 return typeof value === typeof template;
}

/**
 * The settings a preset may apply: every key the table knows, from the preset when its value has
 * the default's shape, otherwise the default. Unknown keys are dropped. `skipped` names the keys the
 * preset carried with the wrong shape, so the caller can say so.
 */
/**
 * Closed value sets for keys whose type alone does not make them valid — a select's options. A
 * value outside its set falls back to the default (and is reported), because applying it would
 * leave a select showing nothing and a filter matching nothing.
 */
export type AllowedValues = Record<string, readonly string[]>;

export function sanitizeSettings(
 table: FilterTable,
 raw: unknown,
 allowed: AllowedValues = {},
): { settings: FilterSettings; skipped: string[] } {
 const defaults = FILTER_DEFAULTS[table];
 const source = raw !== null && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
 const settings: FilterSettings = {};
 const skipped: string[] = [];
 for (const [key, fallback] of Object.entries(defaults)) {
  if (!(key in source)) {
   settings[key] = structuredClone(fallback);
   continue;
  }
  const value = source[key];
  const options = allowed[key];
  const inSet =
   !options ||
   (Array.isArray(value)
    ? value.every((entry) => options.includes(entry as string))
    : typeof value === "string" && options.includes(value));
  if (sameShape(value, fallback) && inSet) {
   // Object-valued settings keep the default's keys, so a file missing one does not unset it.
   settings[key] =
    fallback !== null && typeof fallback === "object" && !Array.isArray(fallback)
     ? { ...(fallback as Record<string, string>), ...(value as Record<string, string>) }
     : (structuredClone(value) as FilterSettings[string]);
  } else {
   settings[key] = structuredClone(fallback);
   skipped.push(key);
  }
 }
 return { settings, skipped };
}

export function serializePreset(table: FilterTable, name: string, settings: FilterSettings, now: Date = new Date()): string {
 const file: FilterPresetFile = {
  burpsy_filter_preset: FILTER_PRESET_VERSION,
  table,
  name,
  saved_at: now.toISOString(),
  settings: sanitizeSettings(table, settings).settings,
 };
 return JSON.stringify(file, null, 2);
}

export type ParsedPreset = { ok: true; name: string; settings: FilterSettings; skipped: string[] } | { ok: false; reason: string };

/** Read a preset file for `table`, or say exactly why it cannot be applied. */
export function parsePreset(text: string, table: FilterTable, allowed: AllowedValues = {}): ParsedPreset {
 let parsed: unknown;
 try {
  parsed = JSON.parse(text);
 } catch {
  return { ok: false, reason: "The file is not JSON" };
 }
 if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
  return { ok: false, reason: "The file is not a filter preset" };
 const file = parsed as Partial<FilterPresetFile>;
 if (file.burpsy_filter_preset === undefined) return { ok: false, reason: "The file is not a burpsy filter preset" };
 if (file.burpsy_filter_preset !== FILTER_PRESET_VERSION) {
  return {
   ok: false,
   reason: `Preset format version ${String(file.burpsy_filter_preset)} is not one this build reads (it reads ${FILTER_PRESET_VERSION})`,
  };
 }
 if (file.table !== table) {
  const from =
   typeof file.table === "string" && file.table in FILTER_TABLE_LABEL ? FILTER_TABLE_LABEL[file.table as FilterTable] : String(file.table);
  return { ok: false, reason: `This preset is for ${from}, not ${FILTER_TABLE_LABEL[table]}` };
 }
 const { settings, skipped } = sanitizeSettings(table, file.settings, allowed);
 return { ok: true, name: typeof file.name === "string" && file.name.trim() ? file.name : "Unnamed preset", settings, skipped };
}

// ---- named presets in this browser -------------------------------------------------------------

export interface NamedPreset {
 name: string;
 saved_at: string;
 settings: FilterSettings;
}

export function presetStorageKey(table: FilterTable): string {
 return `burpsy.filter-presets.${table}`;
}

/** The stored list, each entry re-sanitised; a corrupt store reads as empty rather than throwing. */
export function readPresets(storage: Pick<Storage, "getItem">, table: FilterTable, allowed: AllowedValues = {}): NamedPreset[] {
 try {
  const raw = storage.getItem(presetStorageKey(table));
  if (!raw) return [];
  const list: unknown = JSON.parse(raw);
  if (!Array.isArray(list)) return [];
  return list
   .filter((entry): entry is NamedPreset => entry !== null && typeof entry === "object" && typeof (entry as NamedPreset).name === "string")
   .map((entry) => ({
    name: entry.name,
    saved_at: String(entry.saved_at ?? ""),
    settings: sanitizeSettings(table, entry.settings, allowed).settings,
   }));
 } catch {
  return [];
 }
}

/** Save under `name`, replacing a preset of the same name. Returns the new list, sorted by name. */
export function upsertPreset(
 list: readonly NamedPreset[],
 name: string,
 settings: FilterSettings,
 table: FilterTable,
 now: Date = new Date(),
): NamedPreset[] {
 const entry: NamedPreset = { name, saved_at: now.toISOString(), settings: sanitizeSettings(table, settings).settings };
 return [...list.filter((preset) => preset.name !== name), entry].sort((a, b) => a.name.localeCompare(b.name));
}

export function removePreset(list: readonly NamedPreset[], name: string): NamedPreset[] {
 return list.filter((preset) => preset.name !== name);
}

/** Whether the settings differ from the table's defaults — "Restore defaults" is offered when so. */
export function differsFromDefaults(table: FilterTable, settings: FilterSettings): boolean {
 return JSON.stringify(sanitizeSettings(table, settings).settings) !== JSON.stringify(FILTER_DEFAULTS[table]);
}
