/** burpsy-react-ui-08wx: a bottom dock shows All issues and the Event log under every tool. */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { BottomDock } from "./bottom-dock";

const originalFetch = globalThis.fetch;

function serve(routes: Record<string, unknown>) {
 globalThis.fetch = (async (input: RequestInfo | URL) => {
  const path = new URL(String(input), "http://localhost").pathname;
  return path in routes
   ? new Response(JSON.stringify(routes[path]), { status: 200, headers: { "content-type": "application/json" } })
   : new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
 }) as unknown as typeof fetch;
}

const finding = (name: string, severity: string, host = "a.test") => ({
 issue_name: name,
 severity,
 confidence: "firm",
 host,
 detail: "",
 remediation: "",
 times_seen: 1,
 merged_count: 0,
 occurrences: [],
});

beforeEach(() => window.localStorage.clear());
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

describe("BottomDock", () => {
 test("starts collapsed and says what is in it", async () => {
  serve({
   "/api/issues": { enabled: true, findings: [finding("SQL injection", "high"), finding("Cookie without Secure", "low")] },
   "/api/dashboard": { events: [{ kind: "listener", severity: "error", detail: "bind failed", at_ms: 1 }] },
  });
  renderWithProviders(<BottomDock />);
  await waitFor(() => expect(screen.getByRole("button", { name: /All issues \(2\)/ })).toBeTruthy());
  expect(screen.getByRole("button", { name: /Event log \(1\)/ })).toBeTruthy();
  expect(screen.queryByText("SQL injection")).toBeNull();
 });

 test("opening All issues lists the findings, worst first", async () => {
  serve({
   "/api/issues": { enabled: true, findings: [finding("Cookie without Secure", "low"), finding("SQL injection", "high")] },
   "/api/dashboard": { events: [] },
  });
  renderWithProviders(<BottomDock />);
  fireEvent.click(await screen.findByRole("button", { name: /All issues/ }));
  const names = await waitFor(() => {
   const rows = screen.getAllByTestId("dock-issue");
   expect(rows.length).toBe(2);
   return rows.map((row) => row.textContent ?? "");
  });
  expect(names[0]).toContain("SQL injection");
  expect(names[1]).toContain("Cookie without Secure");
 });

 test("the Event log tab lists newest events first and the choice survives a remount", async () => {
  serve({
   "/api/issues": { enabled: true, findings: [] },
   "/api/dashboard": {
    events: [
     { kind: "scan", severity: "info", detail: "older event", at_ms: 1 },
     { kind: "listener", severity: "error", detail: "newer event", at_ms: 2 },
    ],
   },
  });
  const first = renderWithProviders(<BottomDock />);
  fireEvent.click(await screen.findByRole("button", { name: /Event log/ }));
  await waitFor(() => expect(screen.getAllByTestId("dock-event").length).toBe(2));
  expect(screen.getAllByTestId("dock-event")[0]?.textContent).toContain("newer event");
  first.unmount();
  renderWithProviders(<BottomDock />);
  await waitFor(() => expect(screen.getAllByTestId("dock-event").length).toBe(2));
 });

 test("collapsing hides the lists", async () => {
  serve({ "/api/issues": { enabled: true, findings: [finding("X", "low")] }, "/api/dashboard": { events: [] } });
  renderWithProviders(<BottomDock />);
  const toggle = await screen.findByRole("button", { name: /All issues/ });
  fireEvent.click(toggle);
  await waitFor(() => expect(screen.getAllByTestId("dock-issue").length).toBe(1));
  fireEvent.click(screen.getByRole("button", { name: "Collapse dock" }));
  expect(screen.queryByTestId("dock-issue")).toBeNull();
 });
});
