/**
 * "Define extract grep from response" (burpsy-react-ui-df8r): build a Grep - Extract rule from text the
 * operator highlighted in a stored response, instead of making them write the regex.
 *
 * Burp's response extraction dialog does this when "Update config based on selection" is on (Zh5c): it
 * grows a "start after" anchor backwards from the selection and an "end at" delimiter forwards from it,
 * in steps that end on token boundaries (whitespace / letters-and-digits / markup), at least 6 and at
 * most 200 characters, until the anchor's FIRST occurrence sits against the selection — and offers the
 * same rule as a regex group, `quote(prefix) + "(.*?)" + (suffix ? quote(suffix) : "$")`. burpsy's
 * Grep - Extract is a single regex (first capture group of the first match), so the rule is built in
 * that form directly. The group is `([\s\S]*?)` rather than `(.*?)`: a highlighted region can span
 * lines, and `[\s\S]` means "any character" identically in Go's RE2 (which runs the rule) and in the
 * browser's RegExp (which previews it), where neither engine's dot crosses a newline by default.
 *
 * Why "first occurrence" is the whole condition: Go returns the leftmost match. If the prefix's first
 * occurrence in the response is the one before the selection, the match starts there; the lazy group
 * then stops at the suffix's first occurrence after the selection's start, which the suffix search
 * pins to the selection's end. Anything weaker extracts something else from this very response, and
 * the preview below says so instead of letting the operator save it.
 */

/** Burp's anchor bounds (Zh5c.Zy / Zh5c.ZR): grown from 6 characters, at most 200. */
const MIN_ANCHOR = 6;
const MAX_ANCHOR = 200;

/** The engine's cap on an extracted value, in bytes (internal/intruder MAX_EXTRACT). */
export const MAX_EXTRACT_BYTES = 256;

type CharClass = "space" | "word" | "markup";

function classOf(ch: string): CharClass {
  if (/\s/.test(ch)) return "space";
  if (/[\p{L}\p{N}]/u.test(ch)) return "word";
  return "markup";
}

/**
 * A literal string as a regex that matches exactly it, in both RE2 and JS RegExp syntax. Control
 * characters are written as escapes (\r, \n, \t, \xHH) so the rule stays readable in a one-line field
 * and means the same bytes in both engines.
 */
export function escapeRegexLiteral(text: string): string {
  let out = "";
  for (const ch of text) {
    if ("\\.+*?()|[]{}^$".includes(ch)) out += `\\${ch}`;
    else if (ch === "\r") out += "\\r";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\t") out += "\\t";
    else if (ch.charCodeAt(0) < 0x20 || ch === "\x7f") out += `\\x${ch.charCodeAt(0).toString(16).padStart(2, "0")}`;
    else out += ch;
  }
  return out;
}

/**
 * Grow an anchor of `length` characters one step: at least one more, then on to the token boundary —
 * but never past MAX_ANCHOR. Burp extends to the boundary and abandons an anchor whose token runs past
 * 200 characters (a base64 blob, a JWT, a padding run), which leaves the selection with no delimiter
 * at all; cutting the run at 200 keeps a delimiter that still occurs first where it must, and the
 * first-occurrence check decides whether it is good enough.
 */
function growBackward(text: string, at: number, length: number): number {
  const limit = Math.min(at, MAX_ANCHOR);
  let next = Math.max(length + 1, Math.min(MIN_ANCHOR, limit));
  while (next < limit && classOf(text[at - next - 1]!) === classOf(text[at - next]!)) next++;
  return Math.min(next, at);
}

function growForward(text: string, at: number, length: number): number {
  const room = text.length - at;
  const limit = Math.min(room, MAX_ANCHOR);
  let next = Math.max(length + 1, Math.min(MIN_ANCHOR, limit));
  while (next < limit && classOf(text[at + next]!) === classOf(text[at + next - 1]!)) next++;
  return Math.min(next, room);
}

export interface ExtractRule {
  /** The Grep - Extract regex: escaped prefix, lazy group, escaped suffix (or end of response). */
  regex: string;
  /** "Start after expression" and "End at delimiter", as text. Either may be empty. */
  prefix: string;
  suffix: string;
}

export type ExtractBuild = { ok: true; rule: ExtractRule } | { ok: false; reason: string };

/**
 * The extract rule for the selection [start, end) of `text` — the response exactly as the editor holds
 * it, CRLF included. Refused for an empty or out-of-range selection.
 */
export function buildExtractRule(text: string, start: number, end: number): ExtractBuild {
  if (!(start >= 0 && end <= text.length && start < end)) {
    return { ok: false, reason: "Highlight the part of the response to extract first." };
  }
  // Prefix: grow backwards until its first occurrence in the response is the one ending at `start`.
  // Reaching the start of the response always qualifies (the whole head occurs first at 0).
  let prefixLen = 0;
  if (start > 0) {
    let len = growBackward(text, start, 0);
    let found = text.indexOf(text.slice(start - len, start)) === start - len;
    while (!found && len < start && len < MAX_ANCHOR) {
      len = growBackward(text, start, len);
      found = text.indexOf(text.slice(start - len, start)) === start - len;
    }
    // Burp's own give-up (Zh5c.Zp): no anchor within 200 characters means no anchor. The preview then
    // shows the rule extracting from the top of the response, rather than this inventing a longer one.
    prefixLen = found ? len : 0;
  }
  // Suffix: grow forwards until its first occurrence at or after the selection's start is `end`.
  // Reaching the end of the response means none is needed: the group runs to the end ("$").
  let suffix = "";
  if (end < text.length) {
    let len = growForward(text, end, 0);
    for (;;) {
      const candidate = text.slice(end, end + len);
      if (text.indexOf(candidate, start) === end) {
        suffix = candidate;
        break;
      }
      if (len >= MAX_ANCHOR || end + len >= text.length) break;
      len = growForward(text, end, len);
    }
  }
  const prefix = text.slice(start - prefixLen, start);
  const regex = `${escapeRegexLiteral(prefix)}([\\s\\S]*?)${suffix ? escapeRegexLiteral(suffix) : "$"}`;
  return { ok: true, rule: { regex, prefix, suffix } };
}

export type ExtractPreview =
  | { ok: false; reason: string }
  | {
      ok: true;
      /** What the rule extracts from this response, or null when it matches nothing. */
      value: string | null;
      /** Where the extracted value starts, or null when nothing matched. */
      at: number | null;
      /** True when the value is exactly the highlighted text, at the highlighted offset. */
      matchesSelection: boolean;
      /** True when the engine would cut the value at MAX_EXTRACT_BYTES. */
      truncated: boolean;
    };

/**
 * Run a Grep - Extract rule against `text` the way the engine does — the first capture group of the
 * first match, or the whole match when the rule has no group — and say whether that is the
 * highlighted text at the highlighted place. A leading inline flag group such as `(?i)` or `(?s)`
 * (RE2 syntax the browser's RegExp does not accept) is translated into RegExp flags.
 */
export function previewExtract(regex: string, text: string, selection?: { start: number; end: number }): ExtractPreview {
  let source = regex;
  let flags = "";
  const inline = /^\(\?([ims]+)\)/.exec(source);
  if (inline) {
    flags = [...new Set(inline[1]!.split(""))].join("");
    source = source.slice(inline[0].length);
  }
  let re: RegExp;
  try {
    re = new RegExp(source, flags + "d");
  } catch (error) {
    return {
      ok: false,
      reason: `The browser cannot compile this pattern to preview it (${error instanceof Error ? error.message : String(error)}). The server compiles Go RE2 syntax, which differs in places.`,
    };
  }
  const m = re.exec(text);
  if (!m) return { ok: true, value: null, at: null, matchesSelection: false, truncated: false };
  const group = m.length > 1 ? 1 : 0;
  const value = m[group];
  const indices = (m as RegExpExecArray & { indices?: [number, number][] }).indices;
  if (value === undefined || !indices?.[group]) return { ok: true, value: null, at: null, matchesSelection: false, truncated: false };
  const at = indices[group]![0];
  const matchesSelection = selection !== undefined && at === selection.start && at + value.length === selection.end;
  const truncated = new TextEncoder().encode(value).length > MAX_EXTRACT_BYTES;
  return { ok: true, value, at, matchesSelection, truncated };
}
