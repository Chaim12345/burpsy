// The editor's "Convert selection" codecs, as a table the palette can enumerate (burpsy-react-ui-1wrb).
//
// Burp treats encoding data as a *core* palette command (tools/command-palette.html), and the
// console already had every one of these transforms — on a context menu an operator has to
// already know about. Reaching them from mod+K needs one palette entry per transform, and the
// only honest way to build seventeen entries is from a list rather than by hand.
//
// A caveat worth stating rather than hiding: `ui/editor.tsx` still declares its own `codec(...)`
// rows (editor.tsx around line 775) and does not import this table, because the change that
// makes this the single source of truth is an edit to a file this work does not own. Until that
// one-line import lands the two lists are parallel — so `selection-codecs.test.ts` reads
// editor.tsx and fails when an id exists there and not here. A drift guard is not the same thing
// as a single source, and it is the strongest guarantee available from this side of the line.
import {
 base64Decode,
 base64Encode,
 base64UrlDecode,
 base64UrlEncode,
 constructString,
 htmlDecode,
 htmlEncodeAllCharsDecimal,
 htmlEncodeAllCharsHex,
 htmlEncodeKeyChars,
 urlDecode,
 urlEncodeAllChars,
 urlEncodeAllCharsUnicode,
 urlEncodeKeyChars,
 type ConstructDialect,
} from "./transforms";

/** One selection transform: the same id, label and chord the editor's menu row carries. */
export interface SelectionCodec {
 /** The editor menu's own action id, so the two lists can be compared by a test. */
 id: string;
 label: string;
 /** The editor's chord for this transform, or "" when it has none. Shown, never bound here. */
 shortcut: string;
 /** The menu group heading the editor files it under, reused as the palette's group. */
 group: "Convert selection" | "Construct string";
 transform: (input: string) => string;
}

/** The dialect labels, spelled as the editor spells them (its `CONSTRUCT_DIALECTS`). */
const CONSTRUCT_LABELS: Record<ConstructDialect, string> = {
 js_double: "JavaScript (double-quoted)",
 js_single: "JavaScript (single-quoted)",
 sql_mssql: "SQL for Microsoft SQL Server",
 sql_oracle: "SQL for Oracle",
 sql_mysql: "SQL for MySQL",
};

/**
 * Every transform the editor's selection menu offers, in the editor's own order.
 *
 * Order is the menu's order rather than alphabetical: an operator who has learned where
 * "URL-decode" sits in the context menu should find the palette list reading the same way.
 */
export const SELECTION_CODECS: SelectionCodec[] = [
 { id: "url-encode", label: "URL-encode", shortcut: "Ctrl+U", group: "Convert selection", transform: urlEncodeKeyChars },
 { id: "url-encode-all", label: "URL-encode all characters", shortcut: "", group: "Convert selection", transform: urlEncodeAllChars },
 {
  id: "url-encode-unicode",
  label: "URL-encode all characters (Unicode %uXXXX)",
  shortcut: "",
  group: "Convert selection",
  transform: urlEncodeAllCharsUnicode,
 },
 { id: "url-decode", label: "URL-decode", shortcut: "Ctrl+Shift+U", group: "Convert selection", transform: urlDecode },
 { id: "html-encode", label: "HTML-encode", shortcut: "Ctrl+H", group: "Convert selection", transform: htmlEncodeKeyChars },
 {
  id: "html-encode-decimal",
  label: "HTML-encode all characters (numeric)",
  shortcut: "",
  group: "Convert selection",
  transform: htmlEncodeAllCharsDecimal,
 },
 {
  id: "html-encode-hex",
  label: "HTML-encode all characters (hex)",
  shortcut: "",
  group: "Convert selection",
  transform: htmlEncodeAllCharsHex,
 },
 { id: "html-decode", label: "HTML-decode", shortcut: "Ctrl+Shift+H", group: "Convert selection", transform: htmlDecode },
 { id: "b64-encode", label: "Base64-encode", shortcut: "Ctrl+B", group: "Convert selection", transform: base64Encode },
 { id: "b64-decode", label: "Base64-decode", shortcut: "Ctrl+Shift+B", group: "Convert selection", transform: base64Decode },
 { id: "b64url-encode", label: "Base64-URL-encode", shortcut: "", group: "Convert selection", transform: base64UrlEncode },
 { id: "b64url-decode", label: "Base64-URL-decode", shortcut: "", group: "Convert selection", transform: base64UrlDecode },
 ...(Object.keys(CONSTRUCT_LABELS) as ConstructDialect[]).map((dialect) => ({
  id: `construct-${dialect}`,
  label: CONSTRUCT_LABELS[dialect],
  shortcut: "",
  group: "Construct string" as const,
  transform: (input: string) => constructString(input, dialect),
 })),
];
