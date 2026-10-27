// Which editor a palette-run codec acts on (burpsy-react-ui-1wrb).
//
// The rules here decide whether a palette row is offered as runnable at all, so the thing worth
// pinning is not that a target is found — it is that a target is *refused* in the two cases where
// picking one would be a guess: nothing selected, and two editors each holding a selection with
// no record of which the operator was last in. A guess here rewrites the bytes of a request.
//
// The DOM half (finding the views, reading CodeMirror state) needs a mounted console and is
// exercised live; these tests pin the choice the DOM half feeds.
import { describe, expect, test } from "bun:test";
import { chooseSelectionTarget, selectionHint, selectionRunnable, type CandidateEditor } from "./palette-selection";

/** A candidate named by a string, so a failure prints which editor was chosen. */
function editor(view: string, parts: Partial<Omit<CandidateEditor<string>, "view">> = {}): CandidateEditor<string> {
 return { view, hasSelection: true, writable: true, lastFocused: false, ...parts };
}

describe("choosing the editor a codec acts on", () => {
 test("with nothing selected anywhere there is no target, because a codec converts a selection", () => {
  const choice = chooseSelectionTarget([editor("request", { hasSelection: false })]);
  expect(
   choice.kind,
   "an empty selection that still resolved to a target would let a palette codec run against the whole message, or against nothing, instead of refusing",
  ).toBe("none");
 });

 test("the only editor holding a selection is the target, even though it was never focused", () => {
  const choice = chooseSelectionTarget([editor("request", { hasSelection: false }), editor("response")]);
  expect(
   choice.kind === "ready" ? choice.view : choice.kind,
   "with exactly one selection there is nothing to disambiguate: refusing here would disable the codecs in the ordinary case",
  ).toBe("response");
 });

 test("the editor the operator was last in wins when two hold a selection", () => {
  const choice = chooseSelectionTarget([editor("request"), editor("response", { lastFocused: true })]);
  expect(
   choice.kind === "ready" ? choice.view : choice.kind,
   "CodeMirror keeps a view's selection through a blur, so both panes hold one all the time; picking anything but the last-focused pane would convert bytes the operator was not looking at",
  ).toBe("response");
 });

 test("two selections and no record of the last focus is refused rather than guessed", () => {
  const choice = chooseSelectionTarget([editor("request"), editor("response")]);
  expect(
   choice,
   "silently converting the first pane in document order would rewrite a request the operator never pointed at — a disabled row is the lesser failure",
  ).toEqual({ kind: "ambiguous", count: 2 });
 });

 test("a read-only editor is still a target, because its result can be shown rather than written", () => {
  const choice = chooseSelectionTarget([editor("history", { writable: false })]);
  expect(choice.kind, "refusing a read-only message would drop the whole of history out of the codecs' reach").toBe("ready");
  expect(
   choice.kind === "ready" ? choice.writable : null,
   "the caller has to know the target is read-only: dispatching into one is dropped by CodeMirror without an error, which is the silent failure this flag exists to prevent",
  ).toBe(false);
 });

 test("only a ready choice is runnable, so 'none' and 'ambiguous' both disable the row", () => {
  expect(selectionRunnable({ kind: "none" }), "a runnable row with no selection is a row that closes the palette and does nothing").toBe(
   false,
  );
  expect(selectionRunnable({ kind: "ambiguous", count: 3 }), "an ambiguous target must not be offered as runnable").toBe(false);
  expect(selectionRunnable({ kind: "ready", view: "request", writable: true }), "a resolved writable target must be offered").toBe(true);
 });
});

describe("what the palette tells the operator about the target", () => {
 test("no selection is explained in the editor menu's own words", () => {
  expect(
   selectionHint({ kind: "none" }),
   "a disabled codec row with no explanation is a row an operator reads as broken rather than as waiting for a selection",
  ).toBe("select text in a message editor first");
 });

 test("an ambiguous target names how many editors are holding a selection", () => {
  expect(
   selectionHint({ kind: "ambiguous", count: 2 }),
   "'ambiguous' without the count or the remedy leaves the operator with no action to take",
  ).toBe("2 editors hold a selection — click into the one you mean");
 });

 test("a read-only target says where the result will go, because it does not go into the message", () => {
  expect(
   selectionHint({ kind: "ready", view: "history", writable: false }),
   "an operator who expects the message to change and finds it unchanged would read a working command as a broken one",
  ).toBe("read-only message — the result is copied to the clipboard");
 });

 test("a writable target needs no note, so the heading stays the plain menu heading", () => {
  expect(
   selectionHint({ kind: "ready", view: "repeater", writable: true }),
   "a note on the ordinary case would print a caveat above seventeen rows that have none",
  ).toBeUndefined();
 });
});
