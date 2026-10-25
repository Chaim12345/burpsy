/**
 * burpsy-react-ui-elam (root cause of ngao, eslt, oob3): the editor keeps a message's own line
 * endings by giving CodeMirror `EditorState.lineSeparator`, not by shadowing the text. Run with
 * `bun run test:lib`.
 *
 * States are built here exactly as ui/editor.tsx builds them: the message goes in verbatim and
 * `lineSeparatorFor(message)` is the separator. `state.sliceDoc(0)` is what the editor's onChange
 * writes back.
 */
import { describe, expect, test } from "bun:test";
import { EditorSelection, EditorState, type TransactionSpec } from "@codemirror/state";
import { history, undo, undoDepth } from "@codemirror/commands";
import type { EditorView } from "@codemirror/view";
import { documentText, lineSeparatorFor, selectionText, selectionTransformSpec } from "./editor-eol";
import { selectedText, transformSelectionIn } from "./palette-selection";
import { base64Decode, base64Encode, urlEncodeAllChars } from "./transforms";

const REQUEST = 'POST /login HTTP/1.1\r\nHost: target.example\r\nContent-Type: application/json\r\n\r\n{\n  "user": "a"\n}';

function editorFor(real: string, selection?: EditorSelection): EditorState {
 return EditorState.create({
  doc: real,
  selection,
  extensions: [EditorState.lineSeparator.of(lineSeparatorFor(real)), EditorState.allowMultipleSelections.of(true), history()],
 });
}

/** The doc position of the first occurrence of `needle`, found in the message's own text. */
function docIndex(state: EditorState, needle: string): number {
 const text = documentText(state);
 const at = text.indexOf(needle);
 if (at < 0) throw new Error(`no ${JSON.stringify(needle)} in the document`);
 // each CRLF before `at` is one document position
 return at - (text.slice(0, at).split(state.lineBreak).length - 1) * (state.lineBreak.length - 1);
}

function written(state: EditorState, spec: TransactionSpec): string {
 return documentText(state.update(spec).state);
}

describe("lineSeparatorFor", () => {
 test("CRLF wins whenever the message has one", () => {
  expect(lineSeparatorFor(REQUEST)).toBe("\r\n");
  expect(lineSeparatorFor("a\nb\r\nc")).toBe("\r\n");
 });
 test("LF, lone CR, and no break", () => {
  expect(lineSeparatorFor("a\nb")).toBe("\n");
  expect(lineSeparatorFor("a\rb")).toBe("\r");
  expect(lineSeparatorFor("GET / HTTP/1.1")).toBe("\n");
  expect(lineSeparatorFor("")).toBe("\n");
 });
 test("with no CRLF the first kind of break decides", () => {
  expect(lineSeparatorFor("a\rb\nc")).toBe("\r");
  expect(lineSeparatorFor("a\nb\rc")).toBe("\n");
 });
});

describe("the document round-trips the message natively", () => {
 test.each([
  ["CRLF", REQUEST],
  ["LF", "a\nb\nc"],
  ["lone CR", "a\rb\rc"],
  ["mixed CRLF and LF", "x\r\ny\nz\r\n"],
  ["trailing CRLF", "a\r\n"],
 ])("%s", (_name, message) => {
  expect(documentText(editorFor(message))).toBe(message);
 });

 test("a break is one document position, so message positions map as before", () => {
  const state = editorFor("ab\r\ncd");
  expect(state.doc.length).toBe(5);
  expect(state.doc.lines).toBe(2);
 });

 test("a break of another kind stays a character in its line, not a line", () => {
  const state = editorFor("x\r\ny\nz");
  expect(state.doc.lines).toBe(2);
  expect(documentText(state)).toBe("x\r\ny\nz");
 });
});

describe("an unrelated edit keeps CRLF (eslt)", () => {
 test("typing one character changes that character and nothing else", () => {
  const state = editorFor(REQUEST);
  const at = docIndex(state, "target.example") + "target".length;
  expect(written(state, { changes: { from: at, insert: "2" } })).toBe(REQUEST.replace("target.example", "target2.example"));
 });

 test("a deletion that spans a CRLF removes both bytes", () => {
  const state = editorFor("a\r\nb");
  expect(written(state, { changes: { from: 1, to: 2 } })).toBe("ab");
 });

 test("a typed line break takes the message's separator", () => {
  const state = editorFor("a\r\nb");
  expect(written(state, { changes: { from: 1, insert: state.lineBreak } })).toBe("a\r\n\r\nb");
 });

 test("lone CR messages stay lone CR", () => {
  const state = editorFor("a\rb");
  expect(written(state, { changes: { from: 3, insert: "!" } })).toBe("a\rb!");
 });
});

describe("undo keeps the CR bytes (oob3)", () => {
 test("undoing a conversion across a CRLF restores the CRLF", () => {
  const base = editorFor(REQUEST);
  const from = docIndex(base, "HTTP/1.1");
  const state = editorFor(REQUEST, EditorSelection.single(from, docIndex(base, "target")));
  const spec = selectionTransformSpec(state, urlEncodeAllChars)!;
  let next = state.update({ ...spec, userEvent: "input" }).state;
  expect(documentText(next)).not.toBe(REQUEST);
  expect(undoDepth(next)).toBe(1);
  let result = next;
  undo({
   state: next,
   dispatch: (tr) => {
    result = tr.state;
   },
  });
  expect(documentText(result)).toBe(REQUEST);
 });
});

describe("selection actions read and write the real bytes (ngao)", () => {
 const spanning = (state: EditorState) => EditorSelection.single(docIndex(state, "HTTP/1.1"), docIndex(state, "target"));

 test("Convert selection across a header break encodes the CR", () => {
  const state = editorFor(REQUEST, spanning(editorFor(REQUEST)));
  expect(selectionText(state)).toBe("HTTP/1.1\r\nHost: ");
  const spec = selectionTransformSpec(state, urlEncodeAllChars)!;
  expect(spec.changes[0]!.insert).toMatch(/%0d%0a/i);
  const text = written(state, spec);
  expect(text).toBe(REQUEST.replace("HTTP/1.1\r\nHost: ", urlEncodeAllChars("HTTP/1.1\r\nHost: ")));
 });

 test("a decode whose output holds CRLF writes those exact bytes, even into an LF body", () => {
  const encoded = base64Encode("x\r\ny");
  const withPayload = `POST / HTTP/1.1\r\nHost: a\r\n\r\nline1\n${encoded}\nline3`;
  const seed = editorFor(withPayload);
  const from = docIndex(seed, encoded);
  const state = editorFor(withPayload, EditorSelection.single(from, from + encoded.length));
  expect(written(state, selectionTransformSpec(state, base64Decode)!)).toBe(`POST / HTTP/1.1\r\nHost: a\r\n\r\nline1\nx\r\ny\nline3`);
 });

 test("every selected range converts, each from its own bytes", () => {
  const real = "A\r\nB\r\nC\r\nD";
  const seed = editorFor(real);
  const selection = EditorSelection.create([
   EditorSelection.range(docIndex(seed, "A"), docIndex(seed, "B") + 1),
   EditorSelection.range(docIndex(seed, "C"), docIndex(seed, "D") + 1),
  ]);
  const state = editorFor(real, selection);
  expect(written(state, selectionTransformSpec(state, (input) => `[${JSON.stringify(input)}]`)!)).toBe('["A\\r\\nB"]\r\n["C\\r\\nD"]');
 });

 test("an empty selection converts nothing", () => {
  expect(selectionTransformSpec(editorFor(REQUEST), (input) => input.toUpperCase())).toBeNull();
 });
});

describe("palette codecs (selectedText / transformSelectionIn)", () => {
 function fakeView(state: EditorState) {
  const view = {
   state,
   writes: [] as string[],
   dispatch(spec: TransactionSpec) {
    const tr = view.state.update(spec);
    view.writes.push(documentText(tr.state));
    view.state = tr.state;
   },
   focus() {},
  };
  return view;
 }
 const across = () => {
  const base = editorFor(REQUEST);
  return editorFor(REQUEST, EditorSelection.single(docIndex(base, "1.1"), docIndex(base, "Host") + 4));
 };

 test("the read-only path copies the bytes across a CRLF", () => {
  expect(selectedText(fakeView(across()) as unknown as EditorView)).toBe("1.1\r\nHost");
 });

 test("the writable path converts the CR and leaves the rest alone", () => {
  const view = fakeView(across());
  const reported = transformSelectionIn(view as unknown as EditorView, (input) => input.replace("\r\n", "<CRLF>"));
  expect(reported).toBe("1.1<CRLF>Host");
  expect(view.writes).toEqual([REQUEST.replace("1.1\r\nHost", "1.1<CRLF>Host")]);
 });
});
