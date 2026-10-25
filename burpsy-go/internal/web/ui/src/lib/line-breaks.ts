/**
 * CR and LF made visible and editable in a one-line field (burpsy-react-ui-ln2a).
 *
 * Burp's Inspector detail view lets an operator put "\r\n" inside a header name or value with
 * Shift+Return — the HTTP/2 header-injection technique its docs describe. A browser cannot hold that in
 * a form field: an <input> strips CR and LF from its value outright, and a <textarea>'s value folds
 * every CR LF and lone CR into LF (the HTML "API value" normalisation). Either way the CR is gone before
 * any handler sees it, which is the one octet the technique is about.
 *
 * So the detail view never puts a real line break into a field. It shows each CR as ␍ (U+240D) and each
 * LF as ␊ (U+240A) — the Unicode Control Pictures, which is also how the Inspector's code-point editor
 * already renders control characters — and turns them back on Apply. The mapping is only reversible
 * when the original text holds neither glyph, so `hasLineBreakGlyphs` lets the caller refuse that case
 * rather than turn a literal ␍ in a value into a CR it never contained.
 */

export const CR_GLYPH = "␍";
export const LF_GLYPH = "␊";
/** What Shift+Return inserts: CR then LF, as Burp's detail view does. */
export const CRLF_GLYPHS = CR_GLYPH + LF_GLYPH;

/** The text with every CR and LF shown as its glyph. */
export function showLineBreaks(text: string): string {
 return text.replace(/\r/g, CR_GLYPH).replace(/\n/g, LF_GLYPH);
}

/** The inverse of showLineBreaks: each glyph back to the octet it stands for. */
export function readLineBreaks(shown: string): string {
 return shown.replaceAll(CR_GLYPH, "\r").replaceAll(LF_GLYPH, "\n");
}

/** Whether the text already holds one of the two glyphs, which would make the mapping lossy. */
export function hasLineBreakGlyphs(text: string): boolean {
 return text.includes(CR_GLYPH) || text.includes(LF_GLYPH);
}

/** Whether the text holds a CR or an LF. */
export function hasLineBreak(text: string): boolean {
 return /[\r\n]/.test(text);
}

/**
 * Insert `insert` over the selection [start, end) of `text`, returning the new text and where the caret
 * goes — just after what was inserted, as typing would leave it.
 */
export function insertAt(text: string, start: number, end: number, insert: string): { text: string; caret: number } {
 const from = Math.max(0, Math.min(start, text.length));
 const to = Math.max(from, Math.min(end, text.length));
 return { text: text.slice(0, from) + insert + text.slice(to), caret: from + insert.length };
}
