/**
 * burpsy-react-ui-vln1 (replaces the editor.tsx/store.ts source pins in
 * lib/url-encode-as-you-type.test.ts): URL-encode as you type (js1) in the real HttpEditor. A typed
 * insert is a CodeMirror "input.type" transaction, dispatched as the keystroke path does it.
 */
import { EditorView } from "@codemirror/view";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { useApp } from "../lib/store";
import { HttpEditor } from "./editor";

beforeEach(() => {
 window.localStorage.clear();
 useApp.setState({ urlEncodeAsYouType: false });
});
afterEach(cleanup);

async function mount() {
 const seen: string[] = [];
 const view = renderWithProviders(<HttpEditor value="GET /" onChange={(next) => seen.push(next)} label="Request" views={false} />);
 const dom = await waitFor(() => {
  const el = view.container.querySelector(".cm-editor") as HTMLElement | null;
  expect(el).toBeTruthy();
  return el as HTMLElement;
 });
 const cm = EditorView.findFromDOM(dom) as EditorView;
 const insert = (text: string, userEvent: string) => cm.dispatch({ changes: { from: cm.state.doc.length, insert: text }, userEvent });
 return { cm, insert, seen };
}

describe("URL-encode as you type", () => {
 test("off by default: a typed space stays a space", async () => {
  const { cm, insert } = await mount();
  insert(" a", "input.type");
  expect(cm.state.sliceDoc(0)).toBe("GET / a");
  expect(screen.getByRole("button", { name: "URL-encode as you type" }).getAttribute("aria-pressed")).toBe("false");
 });

 test("on: typed key characters are encoded under the cursor, and what the editor reports is the encoded text", async () => {
  const { cm, insert, seen } = await mount();
  fireEvent.click(screen.getByRole("button", { name: "URL-encode as you type" }));
  await waitFor(() =>
   expect(screen.getByRole("button", { name: "Stop URL-encoding as you type" }).getAttribute("aria-pressed")).toBe("true"),
  );
  insert("?a=b&c d", "input.type");
  await waitFor(() => expect(cm.state.sliceDoc(0)).toBe("GET /%3Fa%3Db%26c%20d"));
  expect(seen.at(-1)).toBe("GET /%3Fa%3Db%26c%20d");
 });

 test("on: only keystrokes are encoded, never a paste or a programmatic change", async () => {
  const { cm, insert } = await mount();
  fireEvent.click(screen.getByRole("button", { name: "URL-encode as you type" }));
  await screen.findByRole("button", { name: "Stop URL-encoding as you type" });
  insert("?x=1", "input.paste");
  await waitFor(() => expect(cm.state.sliceDoc(0)).toBe("GET /?x=1"));
 });

 test("the preference is persisted, so a typing preference survives a reload", async () => {
  await mount();
  fireEvent.click(screen.getByRole("button", { name: "URL-encode as you type" }));
  await waitFor(() => {
   const saved = JSON.parse(window.localStorage.getItem("burpsy.workspace") ?? "{}") as { state?: { urlEncodeAsYouType?: boolean } };
   expect(saved.state?.urlEncodeAsYouType).toBe(true);
  });
 });
});
