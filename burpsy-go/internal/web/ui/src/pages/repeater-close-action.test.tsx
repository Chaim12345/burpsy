/**
 * 1944 remediation: closing a Repeater tab ends its custom action's life - the console forgets the
 * action server-side (config, store, persisted row) through the confirmation-gated DELETE. Reopen
 * restores the request draft, never the action.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { openOnlyTab, renderRepeater } from "../../test/repeater-fake";
import { useApp } from "../lib/store";

let calls: { method: string; path: string }[];
let originalFetch: typeof fetch;
beforeEach(() => {
 calls = [];
 originalFetch = globalThis.fetch;
 window.localStorage.clear();
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(String(input), "http://localhost");
  calls.push({ method: (init?.method ?? "GET").toUpperCase(), path: url.pathname });
  if (url.pathname === "/api/repeater/tabs/confirm") {
   return new Response(
    JSON.stringify({ token: "tok-1", binding: "b1", call: { method: "DELETE", url: "/", body_bytes: 0, body_sha256: "x", body_kind: "none" }, expiresAt: Date.now() + 60000 }),
    { status: 200, headers: { "content-type": "application/json" } },
   );
  }
  return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
 }) as unknown as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

describe("Repeater tab close forgets the tab's custom action", () => {
 test("closing the open tab issues the gated DELETE for its action", async () => {
  const id = openOnlyTab("https://target.test:443");
  renderRepeater();
  fireEvent.click(await screen.findByRole("button", { name: /Close t/ }));
  await waitFor(() => {
   expect(calls.some((c) => c.method === "DELETE" && c.path === `/api/repeater/tabs/${id}/action`)).toBe(true);
  });
  // Gated: the DELETE was minted for first.
  expect(calls.some((c) => c.method === "POST" && c.path === "/api/repeater/tabs/confirm")).toBe(true);
 });

 test("close-others forgets every closed tab's action, not the kept tab's", async () => {
  const first = openOnlyTab("https://one.test:443");
  const second = useApp.getState().openRepeaterTab({ name: "two", target: "https://two.test:443", request: "GET / HTTP/1.1\r\nHost: x\r\n\r\n" });
  renderRepeater();
  // The context menu on the second tab carries the bulk close.
  fireEvent.contextMenu(await screen.findByText("two"));
  fireEvent.click(await screen.findByText("Close other tabs"));
  await waitFor(() => {
   expect(calls.some((c) => c.method === "DELETE" && c.path === `/api/repeater/tabs/${first}/action`)).toBe(true);
  });
  expect(calls.some((c) => c.method === "DELETE" && c.path === `/api/repeater/tabs/${second}/action`)).toBe(false);
 });
});
