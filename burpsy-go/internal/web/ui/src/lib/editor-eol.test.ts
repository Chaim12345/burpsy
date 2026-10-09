/**
 * burpsy-react-ui-eslt: editable editors keep the message's own line endings — through unrelated
 * edits, Convert selection, the copy-selection hotkey and the palette's codecs. Run with
 * `bun run test:lib`.
 *
 * The editor's CodeMirror document is built here exactly as ui/editor.tsx builds it: from the
 * CR-less text, with the real text beside it on the `realText` facet. Transactions are made with
 * `state.update`, which is what `view.dispatch` does before handing the ViewUpdate (and its
 * transactions) to the onChange the editor installs.
 */
import { describe, expect, test } from "bun:test";
import { EditorSelection, EditorState, type Transaction, type TransactionSpec } from "@codemirror/state";
import type { EditorView } from "@codemirror/view";
import {
  applyDocChanges,
  lineEndingAt,
  normalizeEol,
  realText,
  realTextOf,
  reconcile,
  selectionText,
  selectionTransformSpec,
  type RealTextRef,
} from "./editor-eol";
import { selectedText, transformSelectionIn } from "./palette-selection";
import { base64Decode, base64Encode, urlEncodeAllChars } from "./transforms";

const REQUEST = "POST /login HTTP/1.1\r\nHost: target.example\r\nContent-Type: application/json\r\n\r\n{\n  \"user\": \"a\"\n}";

function editorFor(real: string, selection?: EditorSelection): { state: EditorState; ref: RealTextRef } {
  const ref: RealTextRef = { current: real };
  const state = EditorState.create({
    doc: normalizeEol(real),
    selection,
    extensions: [realText.of(ref), EditorState.allowMultipleSelections.of(true)],
  });
  return { state, ref };
}

/** The doc position of the first occurrence of `needle` in the (CR-less) document. */
function docIndex(state: EditorState, needle: string): number {
  const at = state.doc.toString().indexOf(needle);
  if (at < 0) throw new Error(`no ${JSON.stringify(needle)} in the document`);
  return at;
}

/** What the editor's onChange now writes for one dispatch. */
function written(state: EditorState, ref: RealTextRef, spec: TransactionSpec): { tr: Transaction; text: string } {
  const tr = state.update(spec);
  const text = reconcile(ref.current, [tr]) ?? tr.state.doc.toString();
  return { tr, text };
}

describe("an unrelated edit keeps CRLF", () => {
  test("typing one character into a CRLF request changes that character and nothing else", () => {
    const { state, ref } = editorFor(REQUEST);
    const at = docIndex(state, "target.example") + "target".length;
    const { tr, text } = written(state, ref, { changes: { from: at, insert: "2" } });
    // The defect: CodeMirror's own string, which the editor used to write back, has lost every CR.
    expect(tr.state.doc.toString()).not.toContain("\r");
    expect(text).toBe(REQUEST.replace("target.example", "target2.example"));
  });

  test("a deletion that spans a CRLF removes both bytes", () => {
    const { state, ref } = editorFor("A: 1\r\nB: 2\r\n\r\n");
    const from = docIndex(state, "1") + 1;
    const { text } = written(state, ref, { changes: { from, to: from + 1 } });
    expect(text).toBe("A: 1B: 2\r\n\r\n");
  });

  test("a typed line break takes the ending of the line it is typed on, in a mixed message", () => {
    const { state, ref } = editorFor(REQUEST);
    const inHead = docIndex(state, "Content-Type");
    const head = written(state, ref, { changes: { from: inHead, insert: "X-New: 1\n" } }).text;
    expect(head).toBe(REQUEST.replace("Content-Type", "X-New: 1\r\nContent-Type"));
    const inBody = docIndex(state, '"user"');
    const body = written(state, ref, { changes: { from: inBody, insert: "\n" } }).text;
    expect(body).toBe(REQUEST.replace('"user"', '\n"user"'));
  });

  test("a pasted CRLF block in a CRLF head stays CRLF", () => {
    const { state, ref } = editorFor("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    const at = docIndex(state, "Host");
    // A paste reaches the document already split into lines; the inserted Text joins them with "\n".
    const { text } = written(state, ref, { changes: { from: at, insert: "A: 1\r\nB: 2\r\n" } });
    expect(text).toBe("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nHost: a\r\n\r\n");
  });

  test("successive transactions replay in order", () => {
    const { state, ref } = editorFor("A\r\nB\r\n");
    const first = state.update({ changes: { from: 0, insert: "x" } });
    const second = first.state.update({ changes: { from: first.state.doc.length, insert: "C" } });
    expect(reconcile(ref.current, [first, second])).toBe("xA\r\nB\r\nC");
  });

  test("lone CR line breaks are kept too", () => {
    const { state, ref } = editorFor("A\rB\rC");
    const { text } = written(state, ref, { changes: { from: docIndex(state, "B") + 1, insert: "!" } });
    expect(text).toBe("A\rB!\rC");
  });

  test("a stale real text is detected, and the document stands in rather than a bad splice", () => {
    const { state, ref } = editorFor("A\r\nB");
    ref.current = "something else\r\n";
    expect(realTextOf(state)).toBeNull();
    const tr = state.update({ changes: { from: 0, insert: "x" } });
    expect(reconcile(ref.current, [tr])).toBeNull();
    expect(selectionText(state.update({ selection: { anchor: 0, head: 3 } }).state)).toBe("A\nB");
  });
});

describe("selection actions read and write real text", () => {
  const spanning = (state: EditorState) => {
    const from = docIndex(state, "HTTP/1.1");
    return EditorSelection.single(from, docIndex(state, "target"));
  };

  test("Convert selection across a header break encodes the CR (editor transformSelection path)", () => {
    const base = editorFor(REQUEST);
    const { state, ref } = editorFor(REQUEST, spanning(base.state));
    expect(selectionText(state)).toBe("HTTP/1.1\r\nHost: ");
    const spec = selectionTransformSpec(state, urlEncodeAllChars)!;
    expect(spec.changes[0]!.insert).toMatch(/%0d%0a/i);
    const { text } = written(state, ref, spec);
    expect(text).toBe(REQUEST.replace("HTTP/1.1\r\nHost: ", urlEncodeAllChars("HTTP/1.1\r\nHost: ")));
    expect(text.slice(text.indexOf("target"))).toBe(REQUEST.slice(REQUEST.indexOf("target")));
  });

  test("a decode whose output holds CRLF writes those exact bytes, even into an LF body", () => {
    const message = "POST / HTTP/1.1\r\nHost: a\r\n\r\nline1\nPAYLOAD\nline3";
    const encoded = base64Encode("x\r\ny");
    const withPayload = message.replace("PAYLOAD", encoded);
    const seed = editorFor(withPayload);
    const from = docIndex(seed.state, encoded);
    const { state, ref } = editorFor(withPayload, EditorSelection.single(from, from + encoded.length));
    const { text } = written(state, ref, selectionTransformSpec(state, base64Decode)!);
    expect(text).toBe(message.replace("PAYLOAD", "x\r\ny"));
  });

  test("every selected range converts, each from its own real text", () => {
    const real = "A\r\nB\r\nC\r\nD";
    const seed = editorFor(real);
    const selection = EditorSelection.create([
      EditorSelection.range(docIndex(seed.state, "A"), docIndex(seed.state, "B") + 1),
      EditorSelection.range(docIndex(seed.state, "C"), docIndex(seed.state, "D") + 1),
    ]);
    const { state, ref } = editorFor(real, selection);
    const { text } = written(state, ref, selectionTransformSpec(state, (input) => `[${JSON.stringify(input)}]`)!);
    expect(text).toBe('["A\\r\\nB"]\r\n["C\\r\\nD"]');
  });

  test("Ctrl+Alt+C copies the selection with its CR bytes", () => {
    const base = editorFor(REQUEST);
    const { state } = editorFor(REQUEST, spanning(base.state));
    expect(selectionText(state)).toBe("HTTP/1.1\r\nHost: ");
    expect(realTextOf(state)).toBe(REQUEST);
  });

  test("an empty selection converts nothing", () => {
    const { state } = editorFor(REQUEST);
    expect(selectionTransformSpec(state, (input) => input.toUpperCase())).toBeNull();
  });
});

describe("palette codecs (selectedText / transformSelectionIn)", () => {
  /** Enough of an EditorView for the palette helpers: they read state, dispatch and focus. */
  function fakeView(state: EditorState, ref: RealTextRef) {
    const view = {
      state,
      writes: [] as string[],
      dispatch(spec: TransactionSpec) {
        const tr = view.state.update(spec);
        const next = reconcile(ref.current, [tr]) ?? tr.state.doc.toString();
        ref.current = next;
        view.writes.push(next);
        view.state = tr.state;
      },
      focus() {},
    };
    return view;
  }

  test("the read-only path copies real text across a CRLF", () => {
    const base = editorFor(REQUEST);
    const from = docIndex(base.state, "1.1");
    const { state, ref } = editorFor(REQUEST, EditorSelection.single(from, docIndex(base.state, "Host") + 4));
    expect(selectedText(fakeView(state, ref) as unknown as EditorView)).toBe("1.1\r\nHost");
  });

  test("the writable path converts the CR and leaves the rest of the message's endings alone", () => {
    const base = editorFor(REQUEST);
    const from = docIndex(base.state, "1.1");
    const { state, ref } = editorFor(REQUEST, EditorSelection.single(from, docIndex(base.state, "Host") + 4));
    const view = fakeView(state, ref);
    const reported = transformSelectionIn(view as unknown as EditorView, (input) => input.replace("\r\n", "<CRLF>"));
    expect(reported).toBe("1.1<CRLF>Host");
    expect(view.writes).toEqual([REQUEST.replace("1.1\r\nHost", "1.1<CRLF>Host")]);
  });
});

describe("helpers", () => {
  test("lineEndingAt reads the break that ends the line, else the one before", () => {
    expect(lineEndingAt("a\r\nb\nc", 0)).toBe("\r\n");
    expect(lineEndingAt("a\r\nb\nc", 3)).toBe("\n");
    expect(lineEndingAt("a\r\nb", 4)).toBe("\r\n");
    expect(lineEndingAt("abc", 1)).toBe("\n");
  });

  test("applyDocChanges keeps every byte outside the changes", () => {
    const real = "a\r\nb\r\nc";
    expect(applyDocChanges(real, [{ from: 2, to: 3, insert: "B", exact: false }])).toBe("a\r\nB\r\nc");
    expect(applyDocChanges(real, [{ from: 0, to: 0, insert: "z\r", exact: true }])).toBe("z\ra\r\nb\r\nc");
  });
});
