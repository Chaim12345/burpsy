// Settings > Network, Revert (PR 363 review): a blanked number field must come back to the saved number
// when the operator reverts, even though the draft never left that number.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { NetworkSection } from "./settings";

const originalFetch = globalThis.fetch;
let puts: Record<string, unknown>[] = [];
let settings: Record<string, unknown>;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });

function baseSettings(): Record<string, unknown> {
 return {
  resolution: { overrides: null, policy: "system", resolver: "", timeout_ms: 0, family: null },
  timeouts: { connect_ms: 1000, read_ms: 2000, total_ms: 3000 },
  redirects: { mode: "never", max_hops: 10 },
  http1: { enable_keep_alive: false },
  http2: { enable_http2: true },
  continue: { understand_100_continue: true, remove_expect_header: false, expect_continue_timeout_ms: 1000 },
  streaming: { hosts: null, timeout_ms: 0 },
  tls: { verify: true, root_ca_path: "", min_version: 0 },
 };
}

beforeEach(() => {
 puts = [];
 settings = baseSettings();
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/network/settings/confirm")
   return json({
    token: "t",
    binding: "b",
    call: { method: "PUT", url: "/api/network/settings", body_bytes: 0, body_sha256: "", body_kind: "json" },
    expires_in: 60,
   });
  if (path === "/api/network/settings") {
   if (init?.method === "PUT") puts.push(JSON.parse(String(init.body ?? "{}")) as Record<string, unknown>);
   return json({
    settings,
    accepted: {
     resolution_policies: ["system", "resolver"],
     resolution_families: ["system"],
     redirect_modes: ["never"],
     max_timeout_ms: 1,
     max_redirect_hops: 1,
     max_host_overrides: 1,
     max_streaming_hosts: 1,
     keys: [],
    },
   });
  }
  return json({}, 404);
 }) as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

const field = async () => (await screen.findByLabelText("Connect (ms)")) as HTMLInputElement;

describe("Network Revert with a blanked number field", () => {
 test("restores the saved number and clears the invalid mark", async () => {
  renderWithProviders(<NetworkSection />);
  const input = await field();
  expect(input.value).toBe("1000");
  // A blank edit never commits, so the draft keeps 1000; an unrelated edit makes the section dirty.
  fireEvent.change(input, { target: { value: "" } });
  expect(input.getAttribute("aria-invalid")).toBe("true");
  fireEvent.click(await screen.findByLabelText("Default to HTTP/2 if the server supports it"));
  fireEvent.click(screen.getByRole("button", { name: "Revert" }));
  await waitFor(() => expect((screen.getByLabelText("Connect (ms)") as HTMLInputElement).value).toBe("1000"));
  expect(screen.getByLabelText("Connect (ms)").getAttribute("aria-invalid")).toBeNull();
 });

 test("a later Save sends nothing the field does not show", async () => {
  renderWithProviders(<NetworkSection />);
  const input = await field();
  fireEvent.change(input, { target: { value: "" } });
  fireEvent.click(await screen.findByLabelText("Default to HTTP/2 if the server supports it"));
  fireEvent.click(screen.getByRole("button", { name: "Revert" }));
  await waitFor(() => expect((screen.getByLabelText("Connect (ms)") as HTMLInputElement).value).toBe("1000"));
  expect((screen.getByRole("button", { name: "Save" }) as HTMLButtonElement).disabled).toBe(true);
  expect(puts).toEqual([]);
 });
});
