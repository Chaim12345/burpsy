/**
 * burpsy-react-ui-vln1 (replaces the Repeater half of lib/body-encoding-menu.test.ts, which pinned
 * the page's source): the body-encoding rows in the request editor's context menu, as the page
 * behaves. A tab is rendered, the menu is opened, a row is chosen, and the draft and the menu are read.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { act, cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { type FakeRepeater, fakeRepeaterApi, openOnlyTab, renderRepeater } from "../../test/repeater-fake";
import { BODY_ENCODINGS, BODY_ENCODING_LABELS } from "../lib/body-encoding";
import { useApp } from "../lib/store";

const JSON_BODY = 'POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{"a":1}';
const FORM = "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=1";

let fake: FakeRepeater;
beforeEach(() => {
 fake = fakeRepeaterApi();
});
afterEach(() => {
 cleanup();
 fake.restore();
});

async function openEditorMenu(container: HTMLElement): Promise<HTMLElement> {
 const content = await waitFor(() => {
  const el = container.querySelector(".cm-content");
  expect(el).toBeTruthy();
  return el as HTMLElement;
 });
 fireEvent.contextMenu(content);
 return await waitFor(() => {
  const menu = screen.getAllByRole("menu").at(-1);
  expect(menu).toBeTruthy();
  return menu as HTMLElement;
 });
}

const row = (menu: HTMLElement, name: RegExp) => within(menu).getByRole("menuitem", { name });
const isDisabled = (el: HTMLElement) => el.getAttribute("aria-disabled") === "true" || el.hasAttribute("data-disabled");
const draftOf = (id: string) => useApp.getState().repeaterTabs.find((tab) => tab.id === id)?.request ?? "";

describe("Repeater body-encoding menu", () => {
 test("offers one conversion row per encoding, and greys out the encoding the body is already in", async () => {
  openOnlyTab("https://target.test:443", { request: FORM });
  const view = renderRepeater();
  const menu = await openEditorMenu(view.container);
  for (const encoding of BODY_ENCODINGS) {
   expect(row(menu, new RegExp(`Change body encoding: ${BODY_ENCODING_LABELS[encoding]}`))).toBeTruthy();
  }
  expect(isDisabled(row(menu, /Change body encoding: Form URL-encoded/))).toBe(true);
  expect(isDisabled(row(menu, /Change body encoding: JSON/))).toBe(false);
 });

 test("the toggle is disabled until the tab has been converted, then names the encoding it goes back to", async () => {
  const id = openOnlyTab("https://target.test:443", { request: FORM });
  const view = renderRepeater();
  let menu = await openEditorMenu(view.container);
  expect(isDisabled(row(menu, /^Toggle body encoding/))).toBe(true);

  fireEvent.click(row(menu, /Change body encoding: JSON/));
  await waitFor(() => expect(draftOf(id)).not.toBe(FORM));
  expect(draftOf(id)).toContain('"a"');

  menu = await openEditorMenu(view.container);
  const toggle = row(menu, /^Toggle body encoding/);
  expect(isDisabled(toggle)).toBe(false);
  expect(toggle.textContent).toContain("back to Form URL-encoded");
  fireEvent.click(toggle);
  await waitFor(() => expect(draftOf(id).endsWith("a=1")).toBe(true));
 });

 test("the toggle's target is per tab: converting one tab does not arm another", async () => {
  const first = openOnlyTab("https://target.test:443", { request: FORM });
  const view = renderRepeater();
  let menu = await openEditorMenu(view.container);
  fireEvent.click(row(menu, /Change body encoding: JSON/));
  await waitFor(() => expect(draftOf(first)).not.toBe(FORM));

  let second = "";
  act(() => {
   // A different starting encoding than the first tab: a single shared slot would arm this tab too.
   second = useApp.getState().openRepeaterTab({ name: "b", target: "https://target.test:443", request: JSON_BODY });
  });
  await waitFor(() => expect(useApp.getState().activeRepeaterTab).toBe(second));
  menu = await openEditorMenu(view.container);
  expect(isDisabled(row(menu, /^Toggle body encoding/))).toBe(true);
 });

 test("a closed and reopened tab leaves no toggle direction behind", async () => {
  const id = openOnlyTab("https://target.test:443", { request: FORM });
  const view = renderRepeater();
  let menu = await openEditorMenu(view.container);
  fireEvent.click(row(menu, /Change body encoding: JSON/));
  await waitFor(() => expect(draftOf(id)).not.toBe(FORM));
  fireEvent.keyDown(document.body, { key: "Escape" });

  act(() => {
   useApp.getState().closeRepeaterTab(id);
  });
  act(() => {
   useApp.getState().reopenClosedRepeaterTab();
  });
  await waitFor(() => expect(useApp.getState().repeaterTabs.length).toBe(1));
  menu = await openEditorMenu(view.container);
  expect(isDisabled(row(menu, /^Toggle body encoding/))).toBe(true);
 });
});
