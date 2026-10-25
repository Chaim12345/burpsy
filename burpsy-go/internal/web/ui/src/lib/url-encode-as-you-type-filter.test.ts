// The URL-encode-as-you-type filter (burpsy-react-ui-js1), driven through a REAL CodeMirror
// EditorState — the same machinery the console's editor runs. This is the mode's whole logic:
// typed inserts re-encoded before the document changes; paste and programmatic changes left
// alone. A DOM-typing drive would test the browser's input plumbing, not the mode.
import { describe, expect, test } from "bun:test";
import { EditorState } from "@codemirror/state";
import { urlEncodeAsYouTypeExtension, encodeTypedInsert } from "./url-encode-as-you-type";

/** A state with the filter installed, like the editor's extensions array does. */
function stateWithFilter(doc = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") {
  return EditorState.create({ doc, extensions: [urlEncodeAsYouTypeExtension()] });
}

/** A state WITHOUT the filter — the toggle's off path. */
function stateWithoutFilter(doc = "") {
  return EditorState.create({ doc });
}

describe("URL-encode as you type", () => {
  test("typing & = and a space into the request encodes them as they land", () => {
    const state = stateWithFilter("a=b");
    const tr = state.update({ changes: { from: state.doc.length, insert: "&q=a b" }, userEvent: "input.type" });
    expect(
      tr.state.doc.toString(),
      "the whole point of the mode: a payload typed into a parameter arrives encoded, not raw",
    ).toBe("a=b%26q%3Da%20b");
  });

  test("typing ordinary prose changes nothing — a readable request stays readable", () => {
    const state = stateWithFilter("Host: example.com");
    const tr = state.update({ changes: { from: state.doc.length, insert: "x" }, userEvent: "input.type" });
    expect(tr.state.doc.toString()).toBe("Host: example.comx");
  });

  test("a paste is content the operator chose whole — it is not re-encoded", () => {
    const state = stateWithFilter("a=b");
    // input.paste is the userEvent CM6 records for a paste event
    const tr = state.update({ changes: { from: state.doc.length, insert: "&q=a b" }, userEvent: "input.paste" });
    expect(
      tr.state.doc.toString(),
      "re-encoding a pasted payload would corrupt it on arrival: %%26 for a literal the operator pasted",
    ).toBe("a=b&q=a b");
  });

  test("a programmatic change (reveal, sort, a store write) is never encoded", () => {
    const state = stateWithFilter("a=b");
    const tr = state.update({ changes: { from: 0, insert: "&" } });
    expect(tr.state.doc.toString()).toBe("&a=b");
  });

  test("without the extension installed, typing is untouched — the off path is a no-op", () => {
    const state = stateWithoutFilter("a=b");
    const tr = state.update({ changes: { from: state.doc.length, insert: "&x" }, userEvent: "input.type" });
    expect(tr.state.doc.toString()).toBe("a=b&x");
  });

  test("the typed percent itself encodes, so a literal percent survives as %25", () => {
    const state = stateWithFilter();
    const tr = state.update({ changes: { from: state.doc.length, insert: "%41" }, userEvent: "input.type" });
    expect(tr.state.doc.toString().endsWith("%2541")).toBe(true);
  });

  test("the raw decision helper passes a non-typing transaction through untouched", () => {
    const state = stateWithFilter("x");
    const tr = state.update({ changes: { from: 0, insert: "y" } });
    // A transaction that changes nothing the filter cares about is returned as itself.
    const verdict = encodeTypedInsert(tr);
    expect(verdict).toBe(tr);
  });
});
