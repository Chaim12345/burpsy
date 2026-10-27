// The Audit checks card on the Scanner page (burpsy-react-ui-ywgr): every switch the server's
// /api/scanner/config accepts is on the page, honestly described and grouped by intrusiveness, with
// the j1mk.37 defaults marked, and the xss_browser_targets routes are editable.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { ScannerLaunchPage } from "./scannerlaunch";

// scannerConfigBoolKeys in internal/web/api_scanner_config.go on backlog-b9, minus nothing.
const BOOL_KEYS = [
 "check_active_injection",
 "check_cache_poisoning",
 "check_client_ip_spoofing",
 "check_cookie_attributes",
 "check_corpus",
 "check_dom",
 "check_extended_active",
 "check_extended_coverage",
 "check_file_upload",
 "check_graphql_hardening",
 "check_headers",
 "check_host_discovery",
 "check_host_header",
 "check_idor",
 "check_insecure_deserialization",
 "check_js_vulns",
 "check_jwt_exposure",
 "check_jwt_forgery",
 "check_jwt_weak",
 "check_llm_prompt_injection",
 "check_login_rate_limit",
 "check_nosql_injection",
 "check_out_of_band",
 "check_passive_analysis",
 "check_passive_posture",
 "check_password_reset",
 "check_path_traversal",
 "check_reflection_probes",
 "check_request_smuggling",
 "check_response_dependence",
 "check_server_side_parameter_pollution",
 "check_session_management",
 "check_sqli",
 "check_sqli_heavy_query",
 "check_sqli_or_boolean",
 "check_sqli_stacked",
 "check_ssrf",
 "check_ssrf_in_band",
 "check_stored",
 "check_subdomain_takeover",
 "check_username_enumeration",
 "check_weak_crypto",
 "check_websocket_hijacking",
 "check_xss",
 "check_xss_browser_confirm",
 "check_xxe",
];
// The defaults NewActiveScanner sets (scanner.go, j1mk.37).
const DEFAULT_ON = [
 "check_sqli",
 "check_xss",
 "check_path_traversal",
 "check_ssrf",
 "check_xxe",
 "check_active_injection",
 "check_reflection_probes",
 "check_headers",
 "check_passive_posture",
 "check_passive_analysis",
 "check_host_discovery",
];

const originalFetch = globalThis.fetch;
let puts: Record<string, unknown>[] = [];
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });

function config() {
 const c: Record<string, unknown> = { max_concurrency: 10, timeout_ms: 0, probe_timeout_ms: 0, xss_browser_targets: [], only_rows: [] };
 for (const k of BOOL_KEYS) c[k] = DEFAULT_ON.includes(k);
 return c;
}

beforeEach(() => {
 puts = [];
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/scanner/config/confirm")
   return json({
    token: "t",
    binding: "b",
    call: { method: "PUT", url: "/api/scanner/config", body_bytes: 0, body_sha256: "", body_kind: "json" },
    expires_in: 60,
   });
  if (path === "/api/scanner/config") {
   if (init?.method === "PUT") {
    puts.push(JSON.parse(String(init.body ?? "{}")) as Record<string, unknown>);
    return json({ ...config(), ...puts[puts.length - 1] });
   }
   return json(config());
  }
  return json({}, 404);
 }) as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

const sw = (key: string) => document.getElementById(`audit-${key}`) as HTMLElement | null;
async function page() {
 renderWithProviders(<ScannerLaunchPage />);
 await waitFor(() => expect(sw("check_sqli")).not.toBeNull());
}

describe("audit check switches", () => {
 test("every key the server accepts has a switch", async () => {
  await page();
  expect(BOOL_KEYS.filter((k) => sw(k) === null)).toEqual([]);
 });

 test("the active-check labels say what the switch does", async () => {
  await page();
  const injection = sw("check_active_injection")!.closest("label")!.textContent ?? "";
  expect(injection).not.toContain("Generic active insertion probes");
  expect(injection).toContain("OS command");
  const extended = sw("check_extended_active")!.closest("label")!.textContent ?? "";
  expect(extended).not.toContain("More insertion points");
  expect(extended).toContain("request smuggling");
  expect(extended).toContain("JWT forgery");
 });

 test("the default-on checks are marked and the opt-in ones are not", async () => {
  await page();
  const marked = (k: string) => (sw(k)!.closest("label")!.textContent ?? "").includes("on by default");
  expect(BOOL_KEYS.filter((k) => marked(k))).toEqual(DEFAULT_ON.slice().sort());
 });

 test("reflection probing sits with the active checks, not under engines", async () => {
  await page();
  expect(within(screen.getByRole("region", { name: "Active injection" })).getByLabelText("Reflection probing")).toBeTruthy();
  expect(within(screen.getByRole("region", { name: "Engines & coverage" })).queryByLabelText("Reflection probing")).toBeNull();
 });

 test("the intrusive checks are grouped apart from the inert ones", async () => {
  await page();
  const intrusive = within(screen.getByRole("region", { name: "Intrusive" }));
  for (const k of ["check_file_upload", "check_login_rate_limit", "check_password_reset", "check_session_management"]) {
   expect(intrusive.getByLabelText(sw(k)!.getAttribute("aria-label")!)).toBeTruthy();
  }
 });

 test("turning on file upload and saving sends only that key", async () => {
  await page();
  fireEvent.click(sw("check_file_upload")!);
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
  await waitFor(() => expect(puts.length).toBe(1));
  expect(puts[0]).toEqual({ check_file_upload: true });
 });
});

describe("xss_browser_targets", () => {
 test("a route is added, filled in and saved as the whole list", async () => {
  await page();
  fireEvent.click(screen.getByRole("button", { name: "Add route" }));
  const set = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
  set("Route 1 root URL", "https://app.test/");
  set("Route 1 master selector", "#menu");
  set("Route 1 master text", "Search");
  set("Route 1 input selector", "#q");
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
  await waitFor(() => expect(puts.length).toBe(1));
  expect(puts[0]).toEqual({
   xss_browser_targets: [
    {
     match: "",
     root_url: "https://app.test/",
     master_selector: "#menu",
     master_text: "Search",
     level_selector: "",
     level_text: "",
     level_from_path: false,
     input_selector: "#q",
     submit_selector: "",
     click_trigger: false,
     sink: "",
    },
   ],
  });
 });

 test("a route can be removed again", async () => {
  await page();
  fireEvent.click(screen.getByRole("button", { name: "Add route" }));
  fireEvent.click(screen.getByRole("button", { name: "Remove route 1" }));
  expect(screen.queryByLabelText("Route 1 root URL")).toBeNull();
 });
});
