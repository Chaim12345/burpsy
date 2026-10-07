// URL-encode as you type (burpsy-react-ui-js1) — the CodeMirror extension that implements
// Burp's toggle, factored out of ui/editor.tsx so the mode's whole logic is testable without
// a DOM: this module builds the transactionFilter, and the unit test drives it through a real
// EditorState the way CodeMirror will.
//
// A transaction filter rather than an onChange rewrite: the filter sees the insert BEFORE the
// document changes, so the operator sees %26 land under their cursor as they type & — an
// onChange rewrite would fight the cursor after every keystroke. Only keystrokes are encoded
// (userEvent "input.type"); paste is content the operator chose whole, and programmatic
// changes (reveal, sort) must not be re-encoded.
import { EditorState, Transaction, type TransactionSpec } from "@codemirror/state";
import { urlEncodeKeyChars } from "./transforms";

/** The filter's decision for one transaction: either the transaction unchanged, or the spec
 * with the typed insert re-encoded. Exported for the unit test. */
export function encodeTypedInsert(tr: Transaction): TransactionSpec | Transaction {
 if (!tr.docChanged || tr.annotation(Transaction.userEvent) !== "input.type") return tr;
 let mapped = false;
 tr.changes.iterChanges((_fromA, _toA, _fromB, _toB, inserted) => {
  mapped = mapped || inserted.toString() !== urlEncodeKeyChars(inserted.toString());
 });
 if (!mapped) return tr;
 // iterChanges hands each changed range's span; build a ChangeSpec array directly because
 // ChangeSet.toJSON()'s {pos, end} shape is NOT what a TransactionSpec's changes field takes —
 // the round-trip silently dropped every insert (caught by the filter's own unit tests, whose
 // first failing claim was a doc that never changed).
 const changes: { from: number; to?: number; insert: string }[] = [];
 tr.changes.iterChanges((fromA, toA, _fromB, _toB, inserted) => {
  changes.push({ from: fromA, to: toA, insert: urlEncodeKeyChars(inserted.toString()) });
 });
 return { changes, scrollIntoView: true };
}

/** The extension: installs the filter. The editor adds this only while the persisted toggle
 * is on, so the off path pays nothing. */
export function urlEncodeAsYouTypeExtension() {
 return EditorState.transactionFilter.of(encodeTypedInsert);
}
