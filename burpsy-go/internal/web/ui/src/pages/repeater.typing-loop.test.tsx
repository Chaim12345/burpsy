/**
 * CI run 40222233377: typing a request into the Repeater editor logged "Maximum update depth
 * exceeded" (the UAT console-error gate failed). Every draft edit replaces the store's tabs, which
 * re-runs the pruning effect, and that effect used to hand back a NEW object for each of its three
 * state slots even when nothing was pruned: a state update per keystroke that React counts as a
 * nested passive update, and stops at 50. The keystroke that tips it is just where the count ends.
 */
import { EditorView } from "@codemirror/view";
import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import { cleanup, waitFor } from "@testing-library/react";
import { useApp } from "../lib/store";
import { type FakeRepeater, fakeRepeaterApi, openOnlyTab, renderRepeater } from "../../test/repeater-fake";

let fake: FakeRepeater;
beforeEach(() => {
 fake = fakeRepeaterApi();
 // Another file's test leaves this on, and it would encode the typed request line.
 useApp.setState({ urlEncodeAsYouType: false });
});
afterEach(() => {
 cleanup();
 fake.restore();
});
const RAW = "GET /uat-smoke-send HTTP/1.1\nHost: 127.0.0.1:1\nConnection: close\n\n";

describe("typing a whole request into the Repeater request editor", () => {
 test("logs no console error, and Enter writes the template's CRLF", async () => {
  const errors = spyOn(console, "error").mockImplementation(() => {});
  try {
   openOnlyTab("http://127.0.0.1:1");
   const view = renderRepeater();
   const dom = await waitFor(() => {
    const el = view.container.querySelector(".editor-grid-inspected .cm-editor, .editor-grid .cm-editor") as HTMLElement | null;
    expect(el).toBeTruthy();
    return el as HTMLElement;
   });
   const cm = EditorView.findFromDOM(dom) as EditorView;
   cm.dispatch({ selection: { anchor: 0, head: cm.state.doc.length } });
   for (const ch of RAW) {
    const r = cm.state.selection.main;
    // One keystroke at a time, as the browser delivers them; a line break is one document position.
    cm.dispatch({
     changes: { from: r.from, to: r.to, insert: ch === "\n" ? cm.state.lineBreak : ch },
     selection: { anchor: r.from + 1 },
     userEvent: "input.type",
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
   }
   await waitFor(() => expect(cm.state.sliceDoc(0)).toBe(RAW.replace(/\n/g, "\r\n")));
   expect(errors.mock.calls.map((call) => String(call[0])).filter((text) => text.includes("Maximum update depth"))).toEqual([]);
  } finally {
   errors.mockRestore();
  }
 });
});
