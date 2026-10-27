// History hands its two editors the stored-message ids, so a plugin's editor tab renders from the
// bytes on screen (burpsy-react-ui-ww5). Rendered with a faked API (vln1) in place of a source pin.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { HistoryPage } from "./history";

const originalFetch = globalThis.fetch;
let invokes: Record<string, unknown>[] = [];
let response: number | null = 11;

const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200, headers: { "content-type": "application/json" } });

beforeEach(() => {
 invokes = [];
 response = 11;
 // The virtual table renders no rows into a zero-height viewport; give elements a size.
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
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/history")
   return json([
    {
     id: 1,
     request: 10,
     response,
     host: "probe.test",
     port: 443,
     method: "GET",
     path: "/p",
     status: response === null ? null : 200,
     response_len: 2,
     request_params: 0,
     started_ms: 1,
     duration_ms: 1,
     ttfb_ms: 1,
     tls: true,
     protocol: "Http1",
    },
   ]);
  if (path === "/api/message/10") return json({ text: "GET /p HTTP/1.1\r\nHost: probe.test\r\n\r\n" });
  if (path === "/api/message/11") return json({ text: "HTTP/1.1 200 OK\r\n\r\nok" });
  if (path === "/api/extensions")
   return json({
    allowlisted: 1,
    policy: {},
    extensions: [
     { name: "demo", path: "/d", state: "loaded", registrations: [{ id: "derived", kind: "editor-tab", label: "Derived view" }] },
    ],
   });
  if (path === "/api/extensions/invoke") {
   invokes.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
   return json({ result: { text: "decoded" } });
  }
  if (path === "/api/scope") return json({ rules: [], enabled: false });
  return json({});
 }) as unknown as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

async function select() {
 fireEvent.click(await screen.findByText("probe.test:443"));
 await waitFor(() => expect(screen.getAllByRole("tab", { name: "Derived view" }).length).toBeGreaterThan(0));
}

describe("history hands its editors the stored-message ids", () => {
 test("the Request pane's plugin tab invokes with the request message, the Response pane's with the response message", async () => {
  renderWithProviders(<HistoryPage />);
  await select();
  const tabs = screen.getAllByRole("tab", { name: "Derived view" });
  expect(tabs).toHaveLength(2);
  fireEvent.click(tabs[0] as HTMLElement);
  await waitFor(() => expect(invokes).toHaveLength(1));
  expect(invokes[0]).toMatchObject({ name: "demo", registration: "derived", message: 10 });
  fireEvent.click(screen.getAllByRole("tab", { name: "Derived view" })[1] as HTMLElement);
  await waitFor(() => expect(invokes).toHaveLength(2));
  expect(invokes[1]).toMatchObject({ name: "demo", registration: "derived", message: 11 });
 });

 test("an exchange with no response hands the Response pane no message id, so its tab does not borrow another one", async () => {
  response = null;
  renderWithProviders(<HistoryPage />);
  await select();
  fireEvent.click(screen.getAllByRole("tab", { name: "Derived view" })[1] as HTMLElement);
  await new Promise((r) => setTimeout(r, 300));
  // With no message id there is nothing to invoke on: no call at all, not one on the request's bytes.
  expect(invokes).toHaveLength(0);
 });
});
