/**
 * Manual payload markers — Burp's Add § (burpsy-react-ui-mun).
 *
 * A marker is a byte range of the base request the operator marked by hand. Burp renders the
 * marks by wrapping the selection in a "§" pair; these helpers do the same arithmetic for the
 * Positions tab: the editor shows the base request *with* the "§" characters spliced in, and
 * every offset the editor reports is a display offset that has to be mapped back to the raw
 * request before it can be sent as a `manual_points` span.
 *
 * The mapping is pure offset arithmetic on the sorted span list, because the editor is read-only
 * here — the displayed text cannot drift from the request the spans were measured against.
 *
 * Three coordinate spaces meet here, and confusing any two marks the wrong bytes
 * (burpsy-react-ui-ngao):
 *  - wire: UTF-8 byte offsets into the stored request. Spans are kept and sent in this space,
 *    because the server splices `msg.Raw()` by byte.
 *  - raw: UTF-16 indices into the request string (`MessageView.text`). A CRLF is two characters
 *    here, as it is two bytes on the wire; a non-ASCII character is one or two units but up to
 *    four bytes.
 *  - display: UTF-16 indices into `displayText` — raw plus the "§" pairs. The editor reports
 *    selections in this space only after mapping its own document positions back through
 *    `docPosToValuePos`, because CodeMirror normalises every CRLF to a single "\n": a document
 *    offset on line N of a CRLF request is N-1 short of the display offset it names.
 */

import { byteOffsetToCharIndex, charIndexToByteOffset } from "./message-views";

export const MARK_CHAR = "\u00a7";

/** A manual marker, as sent to the server. Offsets index the raw base request. */
export interface ManualSpan {
 start: number;
 end: number;
}

/** A marker plus the text it covers, so the positions list can show what was marked. */
export interface ManualSpanView extends ManualSpan {
 text: string;
}

export type AddSpanResult = { ok: true; spans: ManualSpanView[] } | { ok: false; reason: string };

/**
 * Insert one marker. Empty selections are refused (there is nothing to payload), spans are kept
 * sorted by start, and an overlap is refused client-side with the same rule the server enforces —
 * two overlapping markers would splice two payloads into the same bytes, and the earliest-wins
 * splice rule would silently drop one of them.
 */
export function addManualSpan(existing: ManualSpanView[], start: number, end: number, text: string): AddSpanResult {
 if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start) {
  return { ok: false, reason: "Select a non-empty range of the request to mark" };
 }
 for (const span of existing) {
  if (start < span.end && span.start < end) {
   return { ok: false, reason: `That range overlaps an existing marker around "${span.text}"` };
  }
 }
 const spans = [...existing, { start, end, text }].sort((a, b) => a.start - b.start);
 return { ok: true, spans };
}

/** The spans with their wire byte offsets turned into raw-string (UTF-16) indices. */
function spansInChars(raw: string, spans: ManualSpan[]): ManualSpan[] {
 return [...spans]
  .sort((a, b) => a.start - b.start)
  .map((span) => ({ start: byteOffsetToCharIndex(raw, span.start), end: byteOffsetToCharIndex(raw, span.end) }));
}

/**
 * The base request as the editor shows it: each marker's range wrapped in a "§" pair.
 *
 * Span offsets are wire bytes and are mapped to string indices first, so a marker after a
 * multi-byte character still wraps the bytes it names. The display text is the raw text plus
 * exactly two characters per marker.
 */
export function displayText(raw: string, spans: ManualSpan[]): string {
 let out = "";
 let cursor = 0;
 for (const span of spansInChars(raw, spans)) {
  out += raw.slice(cursor, span.start) + MARK_CHAR + raw.slice(span.start, span.end) + MARK_CHAR;
  cursor = span.end;
 }
 out += raw.slice(cursor);
 return out;
}

/** The display offsets at which "§" characters appear, for the sorted span list. */
function markDisplayPositions(sorted: ManualSpan[]): number[] {
 const positions: number[] = [];
 sorted.forEach((span, i) => {
  const inserted = 2 * i;
  positions.push(span.start + inserted, span.end + inserted + 1);
 });
 return positions;
}

/**
 * Map a display offset back to the raw offset it names. Both sides are string indices, so the
 * spans passed here must be in raw-string space too (identical to wire bytes for ASCII).
 */
export function displayToRaw(spans: ManualSpan[], displayOffset: number): number {
 const sorted = [...spans].sort((a, b) => a.start - b.start);
 const marks = markDisplayPositions(sorted);
 return displayOffset - marks.filter((position) => position < displayOffset).length;
}

export type RawSpanResult = { ok: true; start: number; end: number; text: string } | { ok: false; reason: string };

/**
 * Map a selection of the display text (string indices into `displayText(raw, spans)`, CRLF
 * counted as two — see the header) to the wire byte span `addManualSpan` wants, plus the raw
 * text it covers, CRLFs included.
 *
 * The selection may itself span "§" characters (marking across an existing marker reads as a
 * larger raw range); the overlap check downstream still refuses any real overlap.
 *
 * `wireLength` is the stored request's byte count (`MessageView.len`). The text is a lossy UTF-8
 * rendering, so when the two disagree some byte was not valid UTF-8 and arrived as U+FFFD; from
 * the first U+FFFD on, a string index no longer names a byte, and a marker there is refused
 * rather than sent at an offset that would splice the payload somewhere else.
 */
export function selectionToRawSpan(raw: string, spans: ManualSpan[], from: number, to: number, wireLength?: number): RawSpanResult {
 const charSpans = spansInChars(raw, spans);
 const rawFrom = Math.min(displayToRaw(charSpans, Math.min(from, to)), raw.length);
 const rawTo = Math.min(displayToRaw(charSpans, Math.max(from, to)), raw.length);
 if (wireLength !== undefined && charIndexToByteOffset(raw, raw.length) !== wireLength) {
  const firstLossy = raw.indexOf("\uFFFD");
  if (firstLossy >= 0 && rawTo > firstLossy) {
   return {
    ok: false,
    reason: "That range reaches bytes that are not valid UTF-8, so the text shown cannot name their offsets — mark only before them",
   };
  }
 }
 return {
  ok: true,
  start: charIndexToByteOffset(raw, rawFrom),
  end: charIndexToByteOffset(raw, rawTo),
  text: raw.slice(rawFrom, rawTo),
 };
}
