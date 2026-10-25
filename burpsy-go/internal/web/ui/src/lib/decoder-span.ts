/**
 * Per-selection transform for the Decoder, matching Burp's "The transformation
 * applies to the whole data set. To apply the transformation to only a portion
 * of the data, select the relevant section before you choose an operation."
 *
 * The Decoder input is the shared CodeMirror editor, whose selection is read at
 * run time (see decoder.tsx). This module holds only the pure arithmetic of
 * turning a raw {from,to} into the span to transform and the surrounding text
 * to leave untouched, so it can be tested without a DOM.
 */

export interface Span {
  /** Start of the span to transform, a char index into the input. */
  from: number;
  /** End of the span to transform (exclusive). */
  to: number;
  /** True when the span is the entire input — the default, whole-input case. */
  whole: boolean;
}

/**
 * Resolve a raw selection against an input of `length` characters.
 *
 * A null endpoint (no editor mounted), a cursor with nothing selected, or any
 * range that collapses to empty after clamping falls back to the whole input —
 * the current behaviour — rather than transforming zero characters. Reversed
 * offsets (selecting right-to-left) are normalised, and offsets past the ends
 * are clamped, so a stale selection can never index outside the string.
 */
export function resolveSelection(length: number, from: number | null, to: number | null): Span {
  if (from === null || to === null) return { from: 0, to: length, whole: true };
  const lo = Math.max(0, Math.min(from, to, length));
  const hi = Math.max(0, Math.min(Math.max(from, to), length));
  if (lo >= hi) return { from: 0, to: length, whole: true };
  return { from: lo, to: hi, whole: false };
}

export interface SplitInput {
  /** Text before the span, rendered plain and left untouched by the transform. */
  before: string;
  /** The span fed through the transform pipeline. */
  span: string;
  /** Text after the span, rendered plain and left untouched by the transform. */
  after: string;
}

/**
 * Split an input into the untouched prefix, the span to transform, and the
 * untouched suffix. `before + span + after` is byte-identical to `input`, which
 * is what guarantees the unselected text survives a per-selection transform.
 */
export function splitInput(input: string, selection: Span): SplitInput {
  return {
    before: input.slice(0, selection.from),
    span: input.slice(selection.from, selection.to),
    after: input.slice(selection.to),
  };
}
