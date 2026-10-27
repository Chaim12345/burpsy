// The compiled-in BCheck corpus on the Custom scan checks page (burpsy-react-ui-0vzb.27): a bundled
// row is labelled, can be viewed and switched, and is never offered for Edit or Delete.
import { afterEach, beforeEach, expect, test } from "bun:test";
import { cleanup, screen } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { ScannerChecksPage } from "./scannerchecks";

const originalFetch = globalThis.fetch;
beforeEach(() => {
 globalThis.fetch = (async (input: RequestInfo | URL) => {
  const path = new URL(String(input), "http://localhost").pathname;
  const body =
   path === "/api/scanner/checks"
    ? { enabled: true, passive_count: 0, active_count: 1, checks: [{ name: "Shipped check", active: true, loaded: true, origin: "bundled" }] }
    : {};
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
 }) as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

test("a bundled check is labelled, viewable and switchable, never editable or deletable", async () => {
 renderWithProviders(<ScannerChecksPage />);
 expect(await screen.findByText("bundled")).toBeTruthy();
 expect(screen.getByRole("button", { name: "View Shipped check" })).toBeTruthy();
 expect(screen.queryByRole("button", { name: "Edit Shipped check" })).toBeNull();
 expect(screen.queryByRole("button", { name: "Delete Shipped check" })).toBeNull();
 expect(screen.getByRole("switch", { name: "Disable Shipped check" })).toBeTruthy();
});
