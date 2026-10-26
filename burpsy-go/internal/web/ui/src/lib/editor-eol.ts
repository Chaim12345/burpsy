/**
 * Keeping a message's own line endings through a CodeMirror editor (burpsy-react-ui-elam, the
 * root cause of ngao, eslt and oob3).
 *
 * By default CodeMirror splits its input on "\r\n", a lone "\r" and "\n" and joins lines back with
 * "\n", so every CR was lost on the way through: any edit wrote the message back with LF line
 * endings, a selection across a header break was read, converted and copied without its CR, and
 * undo restored LF from its history. This module used to patch that with a second, "real" copy of
 * the text kept beside the document and replayed every transaction onto it.
 *
 * `EditorState.lineSeparator` removes the cause. With it set, only that one string splits lines;
 * any other CR or LF stays a character inside its line, still a single document position. The
 * document therefore holds the message's bytes verbatim: `state.sliceDoc` (which joins lines with
 * `state.lineBreak`) returns them exactly, history stores them, and a typed Enter inserts the
 * message's own separator. No shadow text, no reconciliation.
 *
 * `doc.toString()` is the one reader that still joins with "\n" whatever the separator is. Read
 * through `documentText` / `selectionText` instead.
 */
import type { EditorState, Extension } from "@codemirror/state";
import { EditorView } from "@codemirror/view";

/**
 * The separator to build a message's editor state with. CRLF whenever the message holds one, so a
 * CRLF request is never flattened and a header break is one position; otherwise the first kind of
 * break the message uses, which is also what a typed Enter will insert. "\n" when it has none.
 * Breaks of any other kind in a mixed message stay characters in their line.
 */
export function lineSeparatorFor(text: string): "\r\n" | "\r" | "\n" {
 if (text.includes("\r\n")) return "\r\n";
 const first = text.search(/[\r\n]/);
 return first >= 0 && text.charCodeAt(first) === 13 ? "\r" : "\n";
}

/** The whole document as the message's own text, line endings included. */
export function documentText(state: EditorState): string {
 return state.sliceDoc(0);
}

/** The document range [from, to) as the message's own text. */
export function sliceReal(state: EditorState, from: number, to: number): string {
 return state.sliceDoc(from, to);
}

/** The main selection as the message's own text: what a copy or a read-only conversion should see. */
export function selectionText(state: EditorState): string {
 const range = state.selection.main;
 return state.sliceDoc(range.from, range.to);
}

/** One change in the transaction's start-document coordinates, with the exact text to write. */
export interface ExactChange {
 from: number;
 to: number;
 insert: string;
}

/**
 * The transaction spec that rewrites every non-empty selected range through `transform`, or null
 * when nothing is selected. Shared by the editor's Convert selection / codec hotkeys and the
 * palette's codecs, so they cannot disagree about what a conversion reads or writes.
 */
export function selectionTransformSpec(state: EditorState, transform: (input: string) => string): { changes: ExactChange[] } | null {
 const changes = state.selection.ranges
  .filter((range) => !range.empty)
  .map((range) => ({ from: range.from, to: range.to, insert: transform(state.sliceDoc(range.from, range.to)) }));
 return changes.length === 0 ? null : { changes };
}

/**
 * Pasted text takes the document's own separator. CodeMirror splits a paste on the state's
 * separator only, so LF text pasted into a CRLF request kept bare LFs inside one line, and CRLF text
 * pasted into an LF message kept its CRs. Every CR, LF and CRLF in the clipboard becomes
 * `state.lineBreak`. In a mixed message the one separator is the document's, so a paste into its
 * LF body gets CRLF when the head is CRLF.
 */
export const pasteLineBreaks: Extension = EditorView.clipboardInputFilter.of((text, state) => text.replace(/\r\n|\r|\n/g, state.lineBreak));
