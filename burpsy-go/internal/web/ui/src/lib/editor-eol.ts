/**
 * Keeping a message's own line endings through a CodeMirror editor (burpsy-react-ui-eslt).
 *
 * CodeMirror splits its document on "\r\n", a lone "\r" and "\n", and hands every line back joined
 * by "\n": `doc.toString()` and `sliceDoc()` never contain a CR. The editor used to treat those
 * strings as the message, so:
 *  - ANY edit in an editable editor wrote the whole message back through onChange with LF line
 *    endings. Typing one character into a CRLF request in Repeater flattened every header break,
 *    and the request was sent that way — the server normalises only when the opt-in "normalize
 *    line endings" send option is on (repeater_options.go).
 *  - Convert selection, Ctrl+Alt+C and the palette's codecs read the selection with `sliceDoc`, so
 *    a selection spanning a header break was URL-encoded as %0A instead of %0D%0A, copied without
 *    its CR, and written back without it.
 *
 * The fix keeps CodeMirror's document as it is and keeps the message's real text beside it (the
 * `realText` facet, a ref the editor refreshes every render). Reads go through `sliceReal`, which
 * maps document positions to real-text positions with `docPosToValuePos`. Writes go through
 * `reconcile`, which replays each transaction's changes onto the real text instead of taking the
 * document's string: the bytes outside a change are never touched, and a line break the operator
 * inserts takes the ending of the line it is typed on. A programmatic rewrite whose output must
 * survive byte for byte (a codec's "%0D%0A" decoded back to CR LF) carries its exact strings on the
 * `exactChanges` annotation, so they are not re-guessed from the document.
 *
 * When the real text and the document disagree (a stale ref — which `realTextOf` checks for on
 * every read), everything falls back to the document, which is the old behaviour rather than a
 * corrupted splice.
 */
import { Annotation, Facet, type EditorState, type Transaction } from "@codemirror/state";
import { docPosToValuePos } from "./message-views";

/** A text holder the editor refreshes; the facet value is the holder, so it never goes stale itself. */
export interface RealTextRef {
  current: string;
}

export const realText = Facet.define<RealTextRef, RealTextRef | null>({
  combine: (values) => values[0] ?? null,
});

/** One change in the transaction's start-document coordinates, with the exact text to write. */
export interface ExactChange {
  from: number;
  to: number;
  insert: string;
}

/** Attached by a programmatic rewrite whose inserts must reach the message verbatim, CR included. */
export const exactChanges = Annotation.define<ExactChange[]>();

/** The document CodeMirror builds from a text: every CRLF and lone CR becomes one "\n". */
export function normalizeEol(text: string): string {
  return text.includes("\r") ? text.replace(/\r\n?/g, "\n") : text;
}

/** The real text behind this state's document, or null when there is none or it no longer matches. */
export function realTextOf(state: EditorState): string | null {
  const ref = state.facet(realText);
  if (!ref) return null;
  const text = ref.current;
  if (normalizeEol(text) !== state.doc.toString()) return null;
  return text;
}

/** The document range [from, to) as the message's real text — CR bytes included. */
export function sliceReal(state: EditorState, from: number, to: number): string {
  const real = realTextOf(state);
  if (real === null) return state.sliceDoc(from, to);
  return real.slice(docPosToValuePos(real, from), docPosToValuePos(real, to));
}

/** The main selection as real text: what a copy or a read-only conversion should see. */
export function selectionText(state: EditorState): string {
  const range = state.selection.main;
  return sliceReal(state, range.from, range.to);
}

/**
 * The line break a typed newline at real position `at` should become: the break that ends the line
 * it is typed on, or failing that (the last line) the one before it. "\n" when the text has none,
 * which is what CodeMirror would have written anyway.
 */
export function lineEndingAt(text: string, at: number): string {
  const breakAt = (index: number): string => (text[index] === "\r" ? (text[index + 1] === "\n" ? "\r\n" : "\r") : "\n");
  for (let index = Math.max(0, at); index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code === 13 || code === 10) return breakAt(index);
  }
  for (let index = Math.min(at, text.length) - 1; index >= 0; index--) {
    const code = text.charCodeAt(index);
    if (code === 10) return index > 0 && text[index - 1] === "\r" ? "\r\n" : "\n";
    if (code === 13) return "\r";
  }
  return "\n";
}

/** A change to apply to the real text: document coordinates, and whether `insert` is already exact. */
export interface DocChange extends ExactChange {
  exact: boolean;
}

/**
 * Apply document-coordinate changes to the real text. Changes must not overlap; they are applied
 * in document order. A non-exact insert's "\n"s take the ending of the line the change starts on.
 */
export function applyDocChanges(real: string, changes: DocChange[]): string {
  const sorted = [...changes].sort((a, b) => a.from - b.from || a.to - b.to);
  let out = "";
  let cursor = 0;
  for (const change of sorted) {
    const from = Math.max(cursor, docPosToValuePos(real, change.from));
    const to = Math.max(from, docPosToValuePos(real, change.to));
    const insert = change.exact ? change.insert : change.insert.replace(/\n/g, lineEndingAt(real, from));
    out += real.slice(cursor, from) + insert;
    cursor = to;
  }
  return out + real.slice(cursor);
}

/** The changes one transaction made, in its start document's coordinates. */
export function transactionChanges(tr: Transaction): DocChange[] {
  const exact = tr.annotation(exactChanges);
  if (exact) return exact.map((change) => ({ ...change, exact: true }));
  const changes: DocChange[] = [];
  tr.changes.iterChanges((fromA, toA, _fromB, _toB, inserted) => {
    changes.push({ from: fromA, to: toA, insert: inserted.toString(), exact: false });
  });
  return changes;
}

/**
 * The real text after these transactions, given the real text before them — or null when `before`
 * does not match the first transaction's start document, in which case the caller has nothing
 * trustworthy to splice into and must fall back to the document.
 */
export function reconcile(before: string, transactions: readonly Transaction[]): string | null {
  let real = before;
  let checked = false;
  for (const tr of transactions) {
    if (!tr.docChanged) continue;
    if (!checked) {
      if (normalizeEol(real) !== tr.startState.doc.toString()) return null;
      checked = true;
    }
    real = applyDocChanges(real, transactionChanges(tr));
  }
  return real;
}

/**
 * The transaction spec that rewrites every non-empty selected range through `transform`, reading
 * each range as real text and carrying the exact outputs, or null when nothing is selected. Shared
 * by the editor's Convert selection / codec hotkeys and the palette's codecs, so they cannot
 * disagree about what a conversion reads or writes.
 */
export function selectionTransformSpec(
  state: EditorState,
  transform: (input: string) => string,
): { changes: ExactChange[]; annotations: Annotation<ExactChange[]> } | null {
  const changes = state.selection.ranges
    .filter((range) => !range.empty)
    .map((range) => ({ from: range.from, to: range.to, insert: transform(sliceReal(state, range.from, range.to)) }));
  if (changes.length === 0) return null;
  return { changes, annotations: exactChanges.of(changes) };
}
