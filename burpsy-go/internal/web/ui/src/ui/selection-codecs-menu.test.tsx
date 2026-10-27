/**
 * burpsy-react-ui-vln1 (replaces the editor.tsx source parse in lib/selection-codecs.test.ts): the
 * palette's codec table (burpsy-react-ui-1wrb) must offer the same transforms, spelled the same way,
 * as the real editor's selection context menu. The menu is opened in the rendered HttpEditor with a
 * selection, and its Convert selection and Construct string rows are read from the DOM.
 */
import { EditorView } from "@codemirror/view";
import { afterEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { SELECTION_CODECS } from "../lib/selection-codecs";
import { HttpEditor } from "./editor";

afterEach(cleanup);

/** The menu rows between Insert Collaborator payload and Find in this message, shortcut text removed. */
async function menuCodecLabels(): Promise<string[]> {
 const view = renderWithProviders(<HttpEditor value="GET /abc" onChange={() => {}} label="Request" views={false} />);
 const dom = await waitFor(() => {
  const el = view.container.querySelector(".cm-editor") as HTMLElement | null;
  expect(el).toBeTruthy();
  return el as HTMLElement;
 });
 (EditorView.findFromDOM(dom) as EditorView).dispatch({ selection: { anchor: 0, head: 5 } });
 fireEvent.contextMenu(view.container.querySelector(".cm-content") as HTMLElement);
 await screen.findByText("Find in this message", { exact: false });
 const rows = screen.getAllByRole("menuitem").map((item) => item.textContent ?? "");
 const from = rows.findIndex((text) => text.startsWith("Insert Collaborator payload")) + 1;
 const to = rows.findIndex((text) => text.startsWith("Find in this message"));
 return rows.slice(from, to).map((text) => text.replace(/Ctrl\+(Shift\+)?[A-Z]$/, ""));
}

describe("the palette's copy of the editor's selection codecs", () => {
 test("the rendered menu really lists codec rows, so an empty read can never pass this file", async () => {
  expect(
   (await menuCodecLabels()).length,
   "no codec rows found between the Collaborator and Find rows of the editor's context menu",
  ).toBeGreaterThan(10);
 });

 test("every transform on the editor's selection menu has a palette entry, spelled the way the editor spells it", async () => {
  const menu = (await menuCodecLabels()).sort();
  const palette = SELECTION_CODECS.map((codec) => codec.label).sort();
  expect(
   palette,
   "the palette's codec table and the editor's menu list different transforms (or word one differently): whichever is missing is a codec an operator can reach one way and not the other",
  ).toEqual(menu);
 });
});
