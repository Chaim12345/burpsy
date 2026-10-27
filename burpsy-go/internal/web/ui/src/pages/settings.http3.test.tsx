// The HTTP/3 Alt-Svc switch on Settings > Network (burpsy-react-ui-kidb): the proxy's kill switch for
// advertising h3 on forwarded responses. Default ON; the patch is {http3:{enable_http3_alt_svc}}.
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

const sw = async () => (await screen.findByLabelText("HTTP/3 Alt-Svc on forwarded responses")) as HTMLElement;
const save = () => fireEvent.click(screen.getByRole("button", { name: "Save" }));

describe("HTTP/3 Alt-Svc switch", () => {
 test("is on when the server never named http3", async () => {
  renderWithProviders(<NetworkSection />);
  expect((await sw()).getAttribute("aria-checked")).toBe("true");
 });

 test("is off when the server says so", async () => {
  settings.http3 = { enable_http3_alt_svc: false };
  renderWithProviders(<NetworkSection />);
  expect((await sw()).getAttribute("aria-checked")).toBe("false");
 });

 test("switching it off saves only the http3 section", async () => {
  renderWithProviders(<NetworkSection />);
  fireEvent.click(await sw());
  save();
  await waitFor(() => expect(puts.length).toBe(1));
  expect(puts[0]).toEqual({ http3: { enable_http3_alt_svc: false } });
 });

 test("switching it back on from off saves true", async () => {
  settings.http3 = { enable_http3_alt_svc: false };
  renderWithProviders(<NetworkSection />);
  fireEvent.click(await sw());
  save();
  await waitFor(() => expect(puts.length).toBe(1));
  expect(puts[0]).toEqual({ http3: { enable_http3_alt_svc: true } });
 });

 test("an edit elsewhere does not send http3", async () => {
  renderWithProviders(<NetworkSection />);
  fireEvent.click(await screen.findByLabelText("Default to HTTP/2 if the server supports it"));
  save();
  await waitFor(() => expect(puts.length).toBe(1));
  expect(puts[0]).toEqual({ http2: { enable_http2: false } });
 });

 test("says it governs discovery, not explicit HTTP/3 pins", async () => {
  renderWithProviders(<NetworkSection />);
  await sw();
  expect(screen.getByText(/explicit HTTP\/3 pin/, { selector: ".cell-dim" })).toBeTruthy();
 });
});
