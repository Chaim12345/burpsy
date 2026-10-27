// The row menu's body-encoding and chunked-framing rows, as History behaves (burpsy-react-ui-wv5).
// vln1: replaces the source pins on lib/actions.ts in lib/body-encoding-menu.test.ts.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { BODY_ENCODINGS, BODY_ENCODING_LABELS } from "../lib/body-encoding";
import { useApp } from "../lib/store";
import { HistoryPage } from "./history";

const originalFetch = globalThis.fetch;
const FORM = "POST /p HTTP/1.1\r\nHost: probe.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=1";
const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200, headers: { "content-type": "application/json" } });

beforeEach(() => {
 useApp.setState({ repeaterTabs: [] });
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
 globalThis.fetch = (async (input: RequestInfo | URL) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/history")
   return json([
    {
     id: 1,
     request: 10,
     response: 11,
     host: "probe.test",
     port: 443,
     method: "POST",
     path: "/p",
     status: 200,
     response_len: 2,
     request_params: 1,
     started_ms: 1,
     duration_ms: 1,
     ttfb_ms: 1,
     tls: true,
     protocol: "Http1",
    },
   ]);
  if (path === "/api/message/10") return json({ text: FORM });
  if (path === "/api/message/11") return json({ text: "HTTP/1.1 200 OK\r\n\r\nok" });
  if (path === "/api/extensions") return json({ allowlisted: 0, policy: {}, extensions: [] });
  if (path === "/api/scope") return json({ rules: [], enabled: false });
  return json({});
 }) as unknown as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

async function openRowMenu() {
 renderWithProviders(<HistoryPage />);
 const cell = await screen.findByText("probe.test:443");
 fireEvent.contextMenu(cell);
 return await waitFor(() => {
  const menu = screen.getAllByRole("menu").at(-1);
  expect(menu).toBeTruthy();
  return menu as HTMLElement;
 });
}

describe("the two operations are separate rows with separate names", () => {
 test("the chunked toggle carries its own name, not Burp's name for the conversion", async () => {
  const menu = await openRowMenu();
  const labels = within(menu)
   .getAllByRole("menuitem")
   .map((m) => m.textContent ?? "");
  expect(labels.some((l) => l.includes("Toggle chunked transfer framing"))).toBe(true);
  expect(labels.some((l) => l.includes("Change body encoding (chunked)"))).toBe(false);
  expect(labels.filter((l) => l.startsWith("Change body encoding"))).toHaveLength(1);
 });
 test("the chunked row opens a Repeater tab with the body reframed as chunked", async () => {
  const menu = await openRowMenu();
  fireEvent.click(within(menu).getByRole("menuitem", { name: /Toggle chunked transfer framing/ }));
  await waitFor(() => expect(useApp.getState().repeaterTabs).toHaveLength(1));
  const tab = useApp.getState().repeaterTabs[0];
  expect(tab?.request.toLowerCase()).toContain("transfer-encoding: chunked");
  expect(tab?.name).toContain("chunked");
 });

 test("the conversion submenu lists exactly the labelled encodings and each row converts through the transform", async () => {
  const menu = await openRowMenu();
  const trigger = within(menu).getByRole("menuitem", { name: /^Change body encoding/ });
  fireEvent.keyDown(trigger, { key: "ArrowRight" });
  const json = await screen.findByRole("menuitem", { name: BODY_ENCODING_LABELS.json });
  const sub = (json.closest('[role="menu"]') as HTMLElement).querySelectorAll('[role="menuitem"]');
  expect([...sub].map((m) => m.textContent).sort()).toEqual(BODY_ENCODINGS.map((e) => BODY_ENCODING_LABELS[e]).sort());
  fireEvent.click(json);
  await waitFor(() => expect(useApp.getState().repeaterTabs).toHaveLength(1));
  const tab = useApp.getState().repeaterTabs[0];
  expect(tab?.request).toContain('{"a":');
  expect(tab?.request.toLowerCase()).toContain("application/json");
 });
});
