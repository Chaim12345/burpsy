/**
 * burpsy-react-ui-vln1 (replaces the editor.tsx source pins in lib/plugin-editor-tabs.test.ts): a
 * plugin's editor tab in the message editor's strip, rendered with a faked API (burpsy-react-ui-ww5).
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { HttpEditor } from "./editor";

const originalFetch = globalThis.fetch;
let invokes: Record<string, unknown>[] = [];
let invokeResponse: () => Response;

const extensions = {
 allowlisted: 2,
 policy: { admission: "allowlist", max_output_bytes: 4096, call_timeout_ms: 5000 },
 extensions: [
  {
   name: "demo",
   path: "/tmp/demo",
   state: "loaded",
   registrations: [
    { id: "derived", kind: "editor-tab", label: "Derived view" },
    { id: "act", kind: "menu", label: "Run" },
   ],
  },
  { name: "off", path: "/tmp/off", state: "unloaded", registrations: [{ id: "ghost", kind: "editor-tab", label: "Ghost view" }] },
 ],
};

function json(body: unknown, status = 200): Response {
 return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

beforeEach(() => {
 invokes = [];
 invokeResponse = () => json({ result: { text: "decoded: hello" } });
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/extensions") return json(extensions);
  if (path === "/api/message/7") return json({ text: "GET / HTTP/1.1\r\n\r\n" });
  if (path === "/api/extensions/invoke") {
   invokes.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
   return invokeResponse();
  }
  return json({});
 }) as unknown as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

const editor = (messageId?: number) => (
 <HttpEditor value={"GET / HTTP/1.1\r\n\r\n"} onChange={() => {}} label="Response" readOnly messageId={messageId} />
);

describe("plugin editor tabs in the strip", () => {
 test("a loaded plugin's editor tab sits in the same tablist as the built-in views; an unloaded plugin's does not", async () => {
  renderWithProviders(editor(7));
  await screen.findByRole("tab", { name: "Derived view" });
  expect(screen.queryByRole("tab", { name: "Ghost view" })).toBeNull();
  const list = screen.getByRole("tablist");
  expect(list.querySelectorAll('[role="tab"]').length).toBeGreaterThan(1);
 });

 test("opening it renders the plugin's text for the stored message, and clicking again closes it", async () => {
  renderWithProviders(editor(7));
  fireEvent.click(await screen.findByRole("tab", { name: "Derived view" }));
  expect(await screen.findByText("decoded: hello")).toBeTruthy();
  expect(invokes[0]).toMatchObject({ name: "demo", registration: "derived", message: 7, raw: "GET / HTTP/1.1\r\n\r\n" });
  fireEvent.click(screen.getByRole("tab", { name: "Derived view" }));
  await waitFor(() => expect(screen.queryByText("decoded: hello")).toBeNull());
 });

 test("a plugin failure is shown in the tab, not only toasted", async () => {
  invokeResponse = () => json({ error: "plugin crashed" }, 500);
  renderWithProviders(editor(7));
  fireEvent.click(await screen.findByRole("tab", { name: "Derived view" }));
  const note = await screen.findByRole("status");
  expect(note.textContent ?? "").not.toBe("");
  expect(screen.queryByText("decoded: hello")).toBeNull();
 });

 test("a pane with no stored message still offers the tab, and opening it says why nothing ran", async () => {
  renderWithProviders(editor(undefined));
  fireEvent.click(await screen.findByRole("tab", { name: "Derived view" }));
  expect((await screen.findByRole("status")).textContent).toContain("no stored message");
  expect(invokes.length).toBe(0);
 });
});
