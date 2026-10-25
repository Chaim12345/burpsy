// The non-switch scan config inputs on the Scanner page (burpsy-react-ui-m4kx): login rate-limit burst,
// password-reset test identities and mailbox URL, and the only_rows selection, each saved through
// PUT /api/scanner/config as the key the server reads.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { ScannerLaunchPage } from "./scannerlaunch";

const originalFetch = globalThis.fetch;
let puts: Record<string, unknown>[] = [];
let stored: Record<string, unknown>;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });

beforeEach(() => {
 puts = [];
 stored = {
  max_concurrency: 10,
  timeout_ms: 0,
  probe_timeout_ms: 0,
  check_sqli: true,
  login_rate_limit_attempts: 0,
  reset_test_identities: [],
  reset_mailbox_url: "",
  only_rows: [],
  xss_browser_targets: [],
 };
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
    const body = JSON.parse(String(init.body ?? "{}")) as Record<string, unknown>;
    puts.push(body);
    stored = { ...stored, ...body };
   }
   return json(stored);
  }
  return json({}, 404);
 }) as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

async function page() {
 renderWithProviders(<ScannerLaunchPage />);
 await screen.findByLabelText("Login rate-limit burst");
}
const type = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const save = async () => {
 fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
 await waitFor(() => expect(puts.length).toBe(1));
};

describe("scan config inputs", () => {
 test("the burst size is saved as login_rate_limit_attempts", async () => {
  await page();
  type("Login rate-limit burst", "30");
  await save();
  expect(puts[0]).toEqual({ login_rate_limit_attempts: 30 });
 });

 test("the burst input says 0 means the scanner default and the allowed range", async () => {
  await page();
  expect(screen.getByText(/0 = scanner default \(20\), otherwise 5 to 100/)).toBeTruthy();
 });

 test("test identities are one per line, trimmed, blanks dropped", async () => {
  await page();
  type("Password-reset test identities", " alice@test.invalid \n\n bob \n");
  await save();
  expect(puts[0]).toEqual({ reset_test_identities: ["alice@test.invalid", "bob"] });
 });

 test("the mailbox URL is saved as reset_mailbox_url", async () => {
  await page();
  type("Password-reset mailbox URL", "https://mail.test/inbox?to={identity}");
  await save();
  expect(puts[0]).toEqual({ reset_mailbox_url: "https://mail.test/inbox?to={identity}" });
 });

 test("only_rows takes one issue name per line", async () => {
  await page();
  type("Restrict the audit to these issue rows", "SQL injection\nCross-site scripting (reflected)");
  await save();
  expect(puts[0]).toEqual({ only_rows: ["SQL injection", "Cross-site scripting (reflected)"] });
 });

 test("emptying a saved only_rows selection clears it", async () => {
  stored.only_rows = ["SQL injection"];
  await page();
  expect((screen.getByLabelText("Restrict the audit to these issue rows") as HTMLTextAreaElement).value).toBe("SQL injection");
  type("Restrict the audit to these issue rows", "");
  await save();
  expect(puts[0]).toEqual({ only_rows: [] });
 });

 test("saved values come back into the inputs", async () => {
  stored.reset_test_identities = ["carol"];
  stored.login_rate_limit_attempts = 12;
  await page();
  expect((screen.getByLabelText("Password-reset test identities") as HTMLTextAreaElement).value).toBe("carol");
  expect((screen.getByLabelText("Login rate-limit burst") as HTMLInputElement).value).toBe("12");
 });

 test("a server refusal reaches the operator and leaves the draft in place", async () => {
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
   const path = new URL(String(input), "http://localhost").pathname;
   if (path === "/api/scanner/config" && init?.method === "PUT")
    return new Response('key "login_rate_limit_attempts" wants 0', { status: 400 });
   return real(input, init);
  }) as typeof fetch;
  await page();
  type("Login rate-limit burst", "3");
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
  await waitFor(() => expect(screen.getByText("unsaved")).toBeTruthy());
  expect((screen.getByLabelText("Login rate-limit burst") as HTMLInputElement).value).toBe("3");
 });
});
