// Second Identity on the scan launch strip (burpsy-react-ui-0vzb.46): the four credential fields post
// as `second_identity` with the audit start request, are omitted when blank, and are never kept.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { useApp } from "../lib/store";
import { ScannerLaunchPage } from "./scannerlaunch";

const originalFetch = globalThis.fetch;
let starts: Record<string, unknown>[] = [];
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });

beforeEach(() => {
 starts = [];
 localStorage.clear();
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/audit/confirm")
   return json({
    token: "t",
    binding: "b",
    call: { method: "POST", url: "/api/audit/7", body_bytes: 0, body_sha256: "", body_kind: "json" },
    expires_in: 60,
   });
  if (path === "/api/audit/7") {
   starts.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
   return json({
    started: true,
    exchange_id: 7,
    active_checks: 1,
    unimplemented: 0,
    config_name: "",
    config: { time_budget_ms: 1000 },
   });
  }
  return json({}, 404);
 }) as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

const fill = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
async function launch() {
 renderWithProviders(<ScannerLaunchPage />);
 fireEvent.change(await screen.findByLabelText("Exchange ID"), { target: { value: "7" } });
}
const audit = () => fireEvent.click(screen.getByRole("button", { name: /^Audit$/ }));

describe("second identity on the launch strip", () => {
 test("shows that the credentials are used for this run only and never saved", async () => {
  await launch();
  expect(screen.getByText(/used for this run only, never saved/i)).toBeTruthy();
 });

 test("posts the pinned second_identity shape", async () => {
  await launch();
  fill("Second identity cookie header", "session=b");
  fill("Second identity authorization header", "Bearer b");
  fill("Second identity API key header", "X-API-Key");
  fill("Second identity API key value", "k-1");
  audit();
  await waitFor(() => expect(starts.length).toBe(1));
  expect(starts[0]?.second_identity).toEqual({
   cookie_header: "session=b",
   authorization_header: "Bearer b",
   api_key_header: "X-API-Key",
   api_key_value: "k-1",
  });
 });

 test("all blank (whitespace too) omits the key", async () => {
  await launch();
  fill("Second identity cookie header", "   ");
  audit();
  await waitFor(() => expect(starts.length).toBe(1));
  expect("second_identity" in (starts[0] ?? {})).toBe(false);
 });

 test("a partial fill still posts all four keys", async () => {
  await launch();
  fill("Second identity authorization header", "Bearer b");
  audit();
  await waitFor(() => expect(starts.length).toBe(1));
  expect(starts[0]?.second_identity).toEqual({
   cookie_header: "",
   authorization_header: "Bearer b",
   api_key_header: "",
   api_key_value: "",
  });
 });

 test("secret fields are masked", async () => {
  await launch();
  expect((screen.getByLabelText("Second identity authorization header") as HTMLInputElement).type).toBe("password");
  expect((screen.getByLabelText("Second identity API key value") as HTMLInputElement).type).toBe("password");
 });

 test("fields clear after launch and nothing is persisted", async () => {
  await launch();
  fill("Second identity cookie header", "session=SECRET-b");
  fill("Second identity authorization header", "Bearer SECRET-b");
  audit();
  await waitFor(() => expect(starts.length).toBe(1));
  await waitFor(() => expect((screen.getByLabelText("Second identity cookie header") as HTMLInputElement).value).toBe(""));
  expect((screen.getByLabelText("Second identity authorization header") as HTMLInputElement).value).toBe("");
  const dump = JSON.stringify({ ...localStorage }) + JSON.stringify(sessionStorage) + JSON.stringify(useApp.getState());
  expect(dump).not.toContain("SECRET-b");
 });
});
