/**
 * A JSON theme import scoped to the tokens burpsy already has (burpsy-react-ui-fpew). This is NOT
 * Burp's 240-slot look-and-feel indirection, and NOT the group/highlight/status colour families
 * (those are burpsy-react-ui-axm9). It is the one affordance Burp's ThemeFactory.loadCustom gives an
 * operator — load a named palette — narrowed to the three semantic families burpsy's tokens model:
 * ui.text, ui.background, and the message editor's own colours.
 *
 * A theme file names a subset of these slots and a colour for each; the import fills only the slots
 * the file names and leaves the rest at the Penpot defaults (semantic.css). A file that names a slot
 * burpsy has no token for is refused, naming the slot — rather than silently dropped — because the
 * whole point of a house palette is that what you handed over is what you get.
 *
 * The token *values* are a settled design decision (the Penpot export is canonical); what was missing
 * was the ability to load a palette without a source edit. Keys are burpsy's own semantic token names
 * without the `--` prefix, so a theme file is legible next to semantic.css.
 */

/** The families an imported theme may fill, grouped as the operator reads them. The values are the
 *  burpsy semantic token slot names (the CSS custom property without its leading `--`). */
export const THEME_SLOT_FAMILIES: { family: string; slots: string[] }[] = [
 { family: "ui.text", slots: ["text", "text-soft", "muted", "ink"] },
 {
  family: "ui.background",
  slots: ["paper", "paper-raised", "paper-deep", "paper-sunken", "field-bg", "chrome", "chrome-hover", "line", "line-strong"],
 },
 { family: "ui.editor.message", slots: ["editor-bg", "editor-fg", "editor-gutter-bg", "editor-gutter-fg"] },
];

/** Every slot a theme file may legally name, flattened. */
export const THEME_SLOTS: ReadonlySet<string> = new Set(THEME_SLOT_FAMILIES.flatMap((f) => f.slots));

/** A parsed, validated theme: an optional display name and the slot→colour map, every key in
 *  THEME_SLOTS and every value a colour the stylesheet can take. */
export interface ImportedTheme {
 name?: string;
 tokens: Record<string, string>;
}

/**
 * Whether a string is a colour the import accepts: a hex (#rgb/#rgba/#rrggbb/#rrggbbaa) or an
 * rgb()/rgba()/hsl()/hsla() functional notation. Named colours and anything exotic are refused so the
 * refusal is a real check rather than a shrug — a value that is not a colour would be dropped silently
 * by the browser otherwise. Deliberately conservative; a palette author uses hex.
 */
export function isThemeColour(value: string): boolean {
 const v = value.trim();
 if (/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(v)) return true;
 return /^(rgb|rgba|hsl|hsla)\(\s*[0-9.,%/\sA-Za-z]+\)$/.test(v);
}

/** The allowed families, formatted for a refusal message. */
function allowedFamiliesHint(): string {
 return THEME_SLOT_FAMILIES.map((f) => `${f.family} (${f.slots.join(", ")})`).join("; ");
}

/**
 * Parse and validate a theme file's text. Returns the theme, or a single refusal string naming the
 * first thing wrong — a non-object, a missing/empty `tokens`, a slot burpsy has no token for, or a
 * value that is not a colour. The refusal is written to be shown to the operator verbatim.
 */
export function parseThemeFile(text: string): { theme: ImportedTheme } | { error: string } {
 let raw: unknown;
 try {
  raw = JSON.parse(text);
 } catch (err) {
  return { error: `Not valid JSON: ${err instanceof Error ? err.message : String(err)}` };
 }
 if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
  return { error: "A theme is a JSON object with a `tokens` map." };
 }
 const obj = raw as Record<string, unknown>;
 if (obj.name !== undefined && typeof obj.name !== "string") {
  return { error: "`name`, if present, must be a string." };
 }
 const tokens = obj.tokens;
 if (typeof tokens !== "object" || tokens === null || Array.isArray(tokens)) {
  return { error: "A theme needs a `tokens` object mapping slot names to colours." };
 }
 const entries = Object.entries(tokens as Record<string, unknown>);
 if (entries.length === 0) {
  return { error: "The theme names no tokens, so there is nothing to apply." };
 }
 const clean: Record<string, string> = {};
 for (const [slot, value] of entries) {
  if (!THEME_SLOTS.has(slot)) {
   return { error: `burpsy has no token for the slot "${slot}". Allowed: ${allowedFamiliesHint()}.` };
  }
  if (typeof value !== "string" || !isThemeColour(value)) {
   return { error: `The value for "${slot}" is not a hex or rgb()/hsl() colour: ${JSON.stringify(value)}.` };
  }
  clean[slot] = value.trim();
 }
 return { theme: { ...(typeof obj.name === "string" ? { name: obj.name } : {}), tokens: clean } };
}

/**
 * The CSS custom-property overrides for an imported theme: `{ "--paper": "#fff", ... }`. app.tsx sets
 * these on <html> (an inline override beats semantic.css's :root rule) and removes every other slot so
 * a reverted or narrower theme falls back to the Penpot default rather than keeping a stale override.
 */
export function themeTokenVars(theme: ImportedTheme): Record<string, string> {
 const vars: Record<string, string> = {};
 for (const [slot, value] of Object.entries(theme.tokens)) vars[`--${slot}`] = value;
 return vars;
}
