/**
 * 1944 remediation: closing a Repeater tab ends its custom action's life - the console forgets the
 * action server-side (config, store, persisted row) through the confirmation-gated DELETE. Reopen
 * restores the request draft, never the action.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { act, cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { openOnlyTab, renderRepeater } from "../../test/repeater-fake";
import { useApp } from "../lib/store";

let calls: { method: string; path: string; body: string; confirm: string | null }[];
let deleteStatuses: number[];
let originalFetch: typeof fetch;
beforeEach(() => {
 calls = [];
 deleteStatuses = [200];
 originalFetch = globalThis.fetch;
 window.localStorage.clear();
 useApp.setState({ failedActionCleanups: [] });
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(String(input), "http://localhost");
  const method = (init?.method ?? "GET").toUpperCase();
  calls.push({
   method,
   path: url.pathname,
   body: init?.body === undefined ? "" : String(init.body),
   confirm: new Headers(init?.headers).get("x-burpsy-confirm"),
  });
  if (url.pathname === "/api/repeater/tabs/confirm") {
   return new Response(
    JSON.stringify({ token: "tok-1", binding: "b1", call: { method: "DELETE", url: "/", body_bytes: 0, body_sha256: "x", body_kind: "none" }, expiresAt: Date.now() + 60000 }),
    { status: 200, headers: { "content-type": "application/json" } },
   );
  }
  if (method === "DELETE" && url.pathname.endsWith("/action")) {
   const status = deleteStatuses.length > 1 ? deleteStatuses.shift()! : deleteStatuses[0]!;
   return new Response(status === 200 ? "{}" : "the action store is unavailable", {
    status,
    headers: { "content-type": "application/json" },
   });
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

describe("Repeater tab close surfaces a failed action cleanup (1944 correction)", () => {
 test("a failed DELETE leaves a visible notice that stays, while the tab still closes", async () => {
  const id = openOnlyTab("https://target.test:443");
  deleteStatuses = [500];
  renderRepeater();
  fireEvent.click(await screen.findByRole("button", { name: /Close t/ }));
  const alert = await screen.findByRole("alert", { name: "Failed action cleanups" });
  expect(alert.textContent).toContain("did not forget its custom action");
  expect(alert.textContent).toContain("the action store is unavailable");
  // Not a toast: the notice persists until the cleanup is retried or dismissed.
  await new Promise((resolve) => setTimeout(resolve, 150));
  expect(screen.getByRole("alert", { name: "Failed action cleanups" }).textContent).toContain("did not forget its custom action");
  // The tab itself closed - closing is what the operator asked for.
  expect(useApp.getState().repeaterTabs.some((tab) => tab.id === id)).toBe(false);
 });

 test("retrying re-issues the gated DELETE and clears the notice once it succeeds", async () => {
  const id = openOnlyTab("https://target.test:443");
  deleteStatuses = [500, 200];
  renderRepeater();
  fireEvent.click(await screen.findByRole("button", { name: /Close t/ }));
  await screen.findByRole("alert", { name: "Failed action cleanups" });
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  // Flush the retry inside act rather than polling the DOM with waitFor: a waitFor whose
  // callback throws on the transient pre-retry state makes testing-library serialize the whole
  // page DOM per poll for its error message, which is seconds of work and gigabytes of string
  // garbage on a page this size - that is what the suite's SIGKILL came from. The store is the
  // cheap truth; one final DOM query confirms the notice unmounted with it.
  await act(async () => {
   for (let i = 0; i < 20 && useApp.getState().failedActionCleanups.length > 0; i++) {
    await new Promise((resolve) => setTimeout(resolve, 20));
   }
  });
  expect(useApp.getState().failedActionCleanups).toHaveLength(0);
  expect(screen.queryByRole("alert", { name: "Failed action cleanups" })).toBeNull();
  const deletes = calls.filter((c) => c.method === "DELETE" && c.path === `/api/repeater/tabs/${id}/action`);
  expect(deletes.length).toBe(2);
  // The retried call went through the gate too: one mint per DELETE.
  const mints = calls.filter((c) => c.method === "POST" && c.path === "/api/repeater/tabs/confirm");
  expect(mints.length).toBe(2);
 });

 test("a 404 answers as nothing-left-to-forget: no notice, and a stale entry clears on retry", async () => {
  // Fresh close, tab never had an action server-side: 404 is the common case, not a failure.
  const id = openOnlyTab("https://target.test:443");
  deleteStatuses = [404];
  renderRepeater();
  fireEvent.click(await screen.findByRole("button", { name: /Close t/ }));
  await waitFor(() => {
   expect(calls.some((c) => c.method === "DELETE" && c.path === `/api/repeater/tabs/${id}/action`)).toBe(true);
  });
  await new Promise((resolve) => setTimeout(resolve, 150));
  expect(screen.queryByRole("alert", { name: "Failed action cleanups" })).toBeNull();
  expect(useApp.getState().failedActionCleanups).toHaveLength(0);
 });

 test("retrying into a 404 clears the stale failure entry", async () => {
  const id = openOnlyTab("https://target.test:443");
  useApp.setState({ failedActionCleanups: [{ tabId: id, error: "the action store is unavailable" }] });
  deleteStatuses = [404];
  renderRepeater();
  await screen.findByRole("alert", { name: "Failed action cleanups" });
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await act(async () => {
   for (let i = 0; i < 20 && useApp.getState().failedActionCleanups.length > 0; i++) {
    await new Promise((resolve) => setTimeout(resolve, 20));
   }
  });
  // The orphan is gone (someone forgot it elsewhere), so the notice is done - not retried forever.
  expect(useApp.getState().failedActionCleanups).toHaveLength(0);
  expect(screen.queryByRole("alert", { name: "Failed action cleanups" })).toBeNull();
 });

 test("dismiss clears the notice without retrying - the orphan stays, and nothing more is sent", async () => {
  openOnlyTab("https://target.test:443");
  deleteStatuses = [500];
  renderRepeater();
  fireEvent.click(await screen.findByRole("button", { name: /Close t/ }));
  await screen.findByRole("alert", { name: "Failed action cleanups" });
  const deletesBefore = calls.filter((c) => c.method === "DELETE").length;
  fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
  await act(async () => {
   await new Promise((resolve) => setTimeout(resolve, 50));
  });
  expect(screen.queryByRole("alert", { name: "Failed action cleanups" })).toBeNull();
  expect(useApp.getState().failedActionCleanups).toHaveLength(0);
  // No second DELETE: dismiss never retries, it only clears the notice.
  expect(calls.filter((c) => c.method === "DELETE").length).toBe(deletesBefore);
 });

 test("a bulk close lists one notice per failed cleanup, and retry clears only its own", async () => {
  const alpha = openOnlyTab("https://one.test:443", { name: "alpha" });
  useApp.getState().openRepeaterTab({ name: "bravo", target: "https://two.test:443", request: "GET / HTTP/1.1\r\nHost: x\r\n\r\n" });
  const charlie = useApp.getState().openRepeaterTab({ name: "charlie", target: "https://three.test:443", request: "GET / HTTP/1.1\r\nHost: x\r\n\r\n" });
  deleteStatuses = [500];
  renderRepeater();
  fireEvent.contextMenu(await screen.findByText("bravo"));
  fireEvent.click(await screen.findByText("Close other tabs"));
  await screen.findByRole("alert", { name: "Failed action cleanups" });
  // One listed failure per orphaned tab, keyed by tab id - the kept tab was never asked to forget.
  await waitFor(() => expect(useApp.getState().failedActionCleanups).toHaveLength(2));
  expect(useApp.getState().failedActionCleanups.map((entry) => entry.tabId).sort()).toEqual([alpha, charlie].sort());
  expect(screen.getAllByRole("button", { name: "Retry" })).toHaveLength(2);
  expect(calls.some((c) => c.method === "DELETE" && c.path.includes("/bravo/"))).toBe(false);
  // Retry the first listed failure; the other stays put.
  deleteStatuses = [200];
  fireEvent.click(screen.getAllByRole("button", { name: "Retry" })[0]!);
  await act(async () => {
   for (let i = 0; i < 20 && useApp.getState().failedActionCleanups.length > 1; i++) {
    await new Promise((resolve) => setTimeout(resolve, 20));
   }
  });
  expect(useApp.getState().failedActionCleanups).toHaveLength(1);
  expect(useApp.getState().failedActionCleanups[0]!.tabId).toBe(charlie);
  expect(screen.getAllByRole("button", { name: "Retry" })).toHaveLength(1);
 });

 test("the confirmation token is minted for exactly the tab-action DELETE it then carries", async () => {
  const id = openOnlyTab("https://target.test:443");
  renderRepeater();
  fireEvent.click(await screen.findByRole("button", { name: /Close t/ }));
  await waitFor(() => {
   expect(calls.some((c) => c.method === "DELETE" && c.path === `/api/repeater/tabs/${id}/action`)).toBe(true);
  });
  // The mint's body describes the exact call it authorises: DELETE on this tab's action route.
  const mint = calls.find((c) => c.method === "POST" && c.path === "/api/repeater/tabs/confirm");
  expect(mint).toBeDefined();
  expect(JSON.parse(mint!.body)).toMatchObject({ method: "DELETE", url: `/api/repeater/tabs/${id}/action` });
  // And the DELETE carries the token that mint returned, in the gate's header.
  const del = calls.find((c) => c.method === "DELETE" && c.path === `/api/repeater/tabs/${id}/action`);
  expect(del!.confirm).toBe("tok-1");
 });
});
