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
 */

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

export type AddSpanResult =
  | { ok: true; spans: ManualSpanView[] }
  | { ok: false; reason: string };

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

/**
 * The base request as the editor shows it: each marker's range wrapped in a "§" pair.
 *
 * Offsets are applied to the raw text and the insertions are folded in left to right, so the
 * display text is the raw text plus exactly two characters per marker.
 */
export function displayText(raw: string, spans: ManualSpanView[]): string {
  const sorted = [...spans].sort((a, b) => a.start - b.start);
  let out = "";
  let cursor = 0;
  for (const span of sorted) {
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

/** Map a display (editor) offset back to the raw request offset it names. */
export function displayToRaw(spans: ManualSpan[], displayOffset: number): number {
  const sorted = [...spans].sort((a, b) => a.start - b.start);
  const marks = markDisplayPositions(sorted);
  return displayOffset - marks.filter((position) => position < displayOffset).length;
}

/**
 * Map a display selection to raw offsets, as `addManualSpan` wants them.
 *
 * The selection may itself span "§" characters (marking across an existing marker reads as a
 * larger raw range); the overlap check downstream still refuses any real overlap.
 */
export function selectionToRawSpan(spans: ManualSpanView[], from: number, to: number): { start: number; end: number } {
  return { start: displayToRaw(spans, from), end: displayToRaw(spans, to) };
}
