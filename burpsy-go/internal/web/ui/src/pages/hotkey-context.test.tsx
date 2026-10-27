// Hotkey capture for extensions (burpsy-react-ui-gqvg): a registered chord fires against
// POST /api/extensions/invoke carrying the rows highlighted in History and the open Repeater editor.
// Rendered with a faked API; the invoke body is read.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { MAX_HOTKEY_SELECTION, publishHotkeyRows } from "../lib/hotkey-context";
import { usePluginHotkeys } from "../lib/plugin-hotkeys";
import { useApp } from "../lib/store";
import { RepeaterPage } from "./repeater";
import { HistoryPage } from "./history";

const originalFetch = globalThis.fetch;
let invokes: Record<string, unknown>[] = [];
let invokeStatus = 200;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });

const EXTENSIONS = {
 allowlisted: 1,
 policy: {},
 extensions: [
  {
   name: "keys",
   path: "/k",
   state: "loaded",
   registrations: [{ id: "go", kind: "hotkey", label: "Go", chord: "Ctrl+K", binding: "mod+k" }],
  },
 ],
};
const row = (id: number) => ({
 id,
 request: id * 2 + 10,
 response: id * 2 + 11,
 host: `h${id}.test`,
 port: 443,
 method: "GET",
 path: "/p",
 status: 200,
 response_len: 2,
 request_params: 0,
 started_ms: 1,
 duration_ms: 1,
 ttfb_ms: 1,
 tls: true,
 protocol: "Http1",
});

function Hotkeys(): null {
 usePluginHotkeys();
 return null;
}

function installFetch() {
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/extensions") return json(EXTENSIONS);
  if (path === "/api/extensions/invoke") {
   invokes.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
   return invokeStatus === 200
    ? json({ result: { output: "ok" } })
    : new Response("a hotkey invocation carries at most 100 selected rows, got 101", { status: invokeStatus });
  }
  if (path === "/api/repeater/send") return json({ response: "HTTP/1.1 200 OK\r\n\r\n" });
  if (path === "/api/history") return json([row(0), row(1), row(2)]);
  if (path === "/api/scope") return json({ rules: [], enabled: false });
  return json({});
 }) as unknown as typeof fetch;
}
const press = () => {
 fireEvent.keyDown(document.body, { key: "Control", code: "ControlLeft", ctrlKey: true });
 fireEvent.keyDown(document.body, { key: "k", code: "KeyK", ctrlKey: true });
 fireEvent.keyUp(document.body, { key: "k", code: "KeyK", ctrlKey: true });
};

beforeEach(() => {
 invokes = [];
 invokeStatus = 200;
 // The ticked rows and a pending focus live in the shared store; another file's test may have left some.
 window.localStorage.clear();
 useApp.setState({ checkedExchanges: [], historyFocus: null });
 Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, get: () => 600 });
 Object.defineProperty(HTMLElement.prototype, "offsetWidth", { configurable: true, get: () => 900 });
 HTMLElement.prototype.getBoundingClientRect = () => ({
  x: 0,
  y: 0,
  top: 0,
  left: 0,
  right: 900,
  bottom: 600,
  width: 900,
  height: 600,
  toJSON() {},
 });
 installFetch();
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

describe("a plugin hotkey carries what the screen shows", () => {
 test("with nothing on screen the chord posts only name and registration", async () => {
  renderWithProviders(<Hotkeys />);
  await waitFor(() => expect(globalThis.fetch).toBeTruthy());
  await new Promise((r) => setTimeout(r, 100));
  press();
  await waitFor(() => expect(invokes).toHaveLength(1));
  expect(invokes[0]).toEqual({ name: "keys", registration: "go" });
 });

 test("ticked History rows travel as selected, and exchange 0 is not dropped", async () => {
  renderWithProviders(
   <>
    <Hotkeys />
    <HistoryPage />
   </>,
  );
  fireEvent.click(await screen.findByLabelText("Select row 0"));
  fireEvent.click(await screen.findByLabelText("Select row 2"));
  await new Promise((r) => setTimeout(r, 100));
  press();
  await waitFor(() => expect(invokes).toHaveLength(1));
  expect(invokes[0]).toMatchObject({ name: "keys", registration: "go", selected: [{ exchange: 0 }, { exchange: 2 }] });
 });

 test("the rows go away with the page: after it unmounts the chord carries no selection", async () => {
  const view = renderWithProviders(
   <>
    <Hotkeys />
    <HistoryPage />
   </>,
  );
  fireEvent.click(await screen.findByLabelText("Select row 0"));
  await new Promise((r) => setTimeout(r, 100));
  view.rerender(<Hotkeys />);
  await new Promise((r) => setTimeout(r, 100));
  press();
  await waitFor(() => expect(invokes).toHaveLength(1));
  expect(invokes[0]).not.toHaveProperty("selected");
 });

 test("an oversized selection is sent whole, so the server's 400 is what the operator reads, not a silently cut list", async () => {
  invokeStatus = 400;
  publishHotkeyRows(Array.from({ length: MAX_HOTKEY_SELECTION + 1 }, (_, exchange) => ({ exchange })));
  renderWithProviders(<Hotkeys />);
  await new Promise((r) => setTimeout(r, 100));
  press();
  await waitFor(() => expect(invokes).toHaveLength(1));
  expect(((invokes[0]?.selected ?? []) as unknown[]).length).toBe(MAX_HOTKEY_SELECTION + 1);
  publishHotkeyRows(null);
 });
});

describe("the open Repeater editor travels as editor", () => {
 test("its text is the editor raw, with no message id (a draft is not a stored message)", async () => {
  const REQ = "GET /draft HTTP/1.1\r\nHost: x\r\n\r\n";
  useApp.setState({ repeaterTabs: [], activeRepeaterTab: "" });
  useApp.getState().openRepeaterTab({ name: "t", target: "x.test:443", request: REQ });
  renderWithProviders(
   <>
    <Hotkeys />
    <RepeaterPage />
   </>,
  );
  await new Promise((r) => setTimeout(r, 150));
  press();
  await waitFor(() => expect(invokes).toHaveLength(1));
  expect(invokes[0]).toMatchObject({ name: "keys", registration: "go", editor: { raw: REQ } });
  expect(((invokes[0]?.editor ?? {}) as Record<string, unknown>).message).toBeUndefined();
 });
 test("stepped back to a past send, it carries that send's request, not the draft", async () => {
  const FIRST = "GET /first HTTP/1.1\r\nHost: x\r\n\r\n";
  const SECOND = "GET /second HTTP/1.1\r\nHost: x\r\n\r\n";
  useApp.setState({ repeaterTabs: [], activeRepeaterTab: "" });
  const id = useApp.getState().openRepeaterTab({ name: "t", target: "x.test:443", request: FIRST });
  renderWithProviders(
   <>
    <Hotkeys />
    <RepeaterPage />
   </>,
  );
  fireEvent.click(await screen.findByRole("button", { name: "Send" }));
  await screen.findByRole("group", { name: "Send history" }).catch(() => undefined);
  useApp.getState().updateRepeaterTab(id, { request: SECOND });
  await waitFor(() => expect((screen.getByRole("button", { name: "Send" }) as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(screen.getByRole("button", { name: "Send" }));
  fireEvent.click(await screen.findByRole("button", { name: "Previous send" }));
  // stepped back: the newest entry is now one step forward
  await waitFor(() => expect((screen.getByRole("button", { name: "Next send" }) as HTMLButtonElement).disabled).toBe(false));
  press();
  await waitFor(() => expect(invokes).toHaveLength(1));
  expect(invokes[0]).toMatchObject({ editor: { raw: FIRST } });
 });
});
