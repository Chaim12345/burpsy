/**
 * burpsy-react-ui-vln1 (replaces the editor.tsx source pins in lib/editor-tabs.test.ts and
 * lib/nonprinting.test.ts): the message editor's tab strip prefs (t94i) and the non-printing
 * toggle (whr), as the real HttpEditor behaves in a DOM.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { defaultEditorTabPrefs, useApp } from "../lib/store";
import { HttpEditor } from "./editor";

const REQUEST = "GET /?a=1 HTTP/1.1\r\nHost: x\r\nCookie: k=v\r\n\r\n";

beforeEach(() => {
 window.localStorage.clear();
 useApp.setState({ editorTabs: defaultEditorTabPrefs });
});
afterEach(cleanup);

const tabNames = () => screen.getAllByRole("tab").map((tab) => tab.textContent);
const editor = (value = REQUEST) => renderWithProviders(<HttpEditor value={value} onChange={() => {}} label="Request" />);
const content = (container: HTMLElement) => container.querySelector(".cm-content")?.textContent ?? "";

describe("the editor's tab strip prefs", () => {
 test("the five Burp extra tabs are offered", async () => {
  editor();
  await waitFor(() =>
   expect(tabNames()).toEqual(expect.arrayContaining(["Headers", "Query params", "Body params", "Cookies", "Attributes"])),
  );
 });

 test("unticking Show hides the tab, ticking it brings it back, and the choice is persisted", async () => {
  editor();
  await screen.findByRole("tab", { name: "Cookies" });
  const panel = screen.getByRole("group", { name: "Optional tabs" });
  fireEvent.click(within(panel).getByRole("checkbox", { name: /Cookies/ }));
  await waitFor(() => expect(tabNames()).not.toContain("Cookies"));
  const saved = JSON.parse(window.localStorage.getItem("burpsy.workspace") ?? "{}") as { state?: { editorTabs?: { hidden: string[] } } };
  expect(saved.state?.editorTabs?.hidden).toContain("cookies");
  fireEvent.click(within(panel).getByRole("checkbox", { name: /Cookies/ }));
  await waitFor(() => expect(tabNames()).toContain("Cookies"));
 });

 test("Move down reorders the strip rather than decorating it", async () => {
  editor();
  await screen.findByRole("tab", { name: "Headers" });
  const before = tabNames();
  expect(before.indexOf("Headers")).toBeLessThan(before.indexOf("Query params"));
  fireEvent.click(screen.getByRole("button", { name: "Move Headers tab down" }));
  await waitFor(() => {
   const after = tabNames();
   expect(after.indexOf("Headers")).toBeGreaterThan(after.indexOf("Query params"));
  });
 });

 test("hiding a tab does not re-show it when another is reordered", async () => {
  editor();
  await screen.findByRole("tab", { name: "Cookies" });
  const panel = screen.getByRole("group", { name: "Optional tabs" });
  fireEvent.click(within(panel).getByRole("checkbox", { name: /Cookies/ }));
  fireEvent.click(screen.getByRole("button", { name: "Move Headers tab down" }));
  await waitFor(() => expect(tabNames()).not.toContain("Cookies"));
 });
});

describe("the non-printing toggle", () => {
 test("starts off: no glyphs, the button is not pressed", async () => {
  const view = editor();
  await waitFor(() => expect(content(view.container)).toContain("GET /"));
  expect(content(view.container)).not.toContain("␊");
  expect(screen.getByRole("button", { name: "Show non-printing characters" }).getAttribute("aria-pressed")).toBe("false");
 });

 test("turning it on shows control characters and line-end markers together, and off removes both", async () => {
  const view = editor("GET / HTTP/1.1\r\nHost: x\u0000\r\n\r\n");
  await waitFor(() => expect(content(view.container)).toContain("GET /"));
  fireEvent.click(screen.getByRole("button", { name: "Show non-printing characters" }));
  await waitFor(() => expect(content(view.container)).toContain("␀"));
  expect(content(view.container)).toContain("␍␊");
  expect(screen.getByRole("button", { name: "Hide non-printing characters" }).getAttribute("aria-pressed")).toBe("true");
  fireEvent.click(screen.getByRole("button", { name: "Hide non-printing characters" }));
  await waitFor(() => expect(content(view.container)).not.toContain("␍␊"));
  // (CodeMirror draws a NUL as ␀ by itself; the toggle adds the line-end markers.)
 });

 test("the end-of-line marker names the message's own break: CRLF is ␍␊, a bare LF is ␊", async () => {
  const crlf = editor("a\r\nb");
  await waitFor(() => expect(content(crlf.container)).toContain("a"));
  fireEvent.click(screen.getByRole("button", { name: "Show non-printing characters" }));
  await waitFor(() => expect(content(crlf.container)).toContain("␍␊"));
  cleanup();

  const lf = editor("a\nb");
  await waitFor(() => expect(content(lf.container)).toContain("a"));
  fireEvent.click(screen.getByRole("button", { name: "Show non-printing characters" }));
  await waitFor(() => expect(content(lf.container)).toContain("␊"));
  expect(content(lf.container)).not.toContain("␍");
 });
});
