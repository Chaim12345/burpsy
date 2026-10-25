// Plugin payload generators and processors in the Intruder UI (burpsy-react-ui-0qwh, vln1 style):
// the page rendered with a faked API, the run request body read.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { emptyIntruderConfig, useApp } from "../lib/store";
import { emptyRule } from "../lib/types.tools";
import { IntruderPage } from "./intruder";

const originalFetch = globalThis.fetch;
let runs: Record<string, unknown>[] = [];
const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200, headers: { "content-type": "application/json" } });

const EXTENSIONS = {
 allowlisted: 2,
 policy: {},
 extensions: [
  {
   name: "gen-plugin",
   path: "/g",
   state: "loaded",
   registrations: [
    { id: "words", kind: "payload-generator", label: "Word maker" },
    { id: "rewrite", kind: "payload-processor", label: "Rewriter" },
    { id: "tab", kind: "editor-tab", label: "Not a payload one" },
   ],
  },
  { name: "off", path: "/o", state: "unloaded", registrations: [{ id: "ghost", kind: "payload-generator", label: "Ghost maker" }] },
 ],
};

function seed(extra: Record<string, unknown> = {}) {
 useApp.setState({
  intruder: {
   ...emptyIntruderConfig(),
   msgId: "5",
   target: "x.test:443",
   mode: "sniper",
   points: [{ index: 0 }],
   selected: [0],
   ...extra,
  },
 } as never);
}

async function openPayloads() {
 renderWithProviders(<IntruderPage />);
 fireEvent.mouseDown(await screen.findByRole("tab", { name: "Payloads" }), { button: 0 });
 fireEvent.click(screen.getByRole("tab", { name: "Payloads" }));
}

beforeEach(() => {
 seed();
 runs = [];
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/extensions") return json(EXTENSIONS);
  // The run route is gated: the client mints a confirmation first (lib/api.ts gatedFetch).
  if (path === "/api/intruder/run/confirm")
   return json({
    token: "t",
    binding: "b",
    call: { method: "POST", url: "/api/intruder/run", body_bytes: 0, body_sha256: "", body_kind: "json" },
    expires_in: 60,
   });
  if (path === "/api/intruder/run") {
   runs.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
   return json({ task_id: 1 });
  }
  if (path === "/api/intruder/attacks") return json({ attacks: [] });
  if (path === "/api/intruder/points")
   return json({ points: [{ index: 0, kind: "query", label: "q", offset: 0, len: 1, current: "a", placement: "replace" }] });
  if (path === "/api/pools") return json({ pools: [] });
  return json({});
 }) as unknown as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

async function typeSelect(): Promise<HTMLSelectElement> {
 return await waitFor(() => {
  const found = screen
   .getAllByRole("combobox")
   .find((el) => [...(el as HTMLSelectElement).options].some((o) => o.textContent === "Simple list"));
  expect(found).toBeTruthy();
  return found as HTMLSelectElement;
 });
}

describe("payload source: plugin generator", () => {
 test("the type dropdown offers plugin generators from loaded plugins only", async () => {
  await openPayloads();
  const select = await typeSelect();
  expect([...select.options].map((o) => o.value)).toContain("plugin");
  fireEvent.change(select, { target: { value: "plugin" } });
  const provider = (await screen.findByLabelText("Plugin payload generator")) as HTMLSelectElement;
  await waitFor(() => expect([...provider.options].map((o) => o.textContent)).toContain("Word maker (gen-plugin)"));
  const labels = [...provider.options].map((o) => o.textContent);
  expect(labels.some((l) => l?.includes("Ghost maker"))).toBe(false);
  expect(labels.some((l) => l?.includes("Not a payload one"))).toBe(false);
 });
});

const runButton = () => screen.getByRole("button", { name: /Launch attack|Attacking/ }) as HTMLButtonElement;

describe("the run request names the chosen plugin", () => {
 test("a plugin source posts {type:'plugin', plugin:{plugin, registration}}", async () => {
  await openPayloads();
  fireEvent.change(await typeSelect(), { target: { value: "plugin" } });
  const provider = (await screen.findByLabelText("Plugin payload generator")) as HTMLSelectElement;
  expect(runButton().disabled, "no generator chosen: nothing the server could run").toBe(true);
  await waitFor(() => expect(provider.options.length).toBeGreaterThan(1));
  fireEvent.change(provider, { target: { value: [...provider.options].find((o) => o.textContent?.includes("Word maker"))!.value } });
  await waitFor(() => expect(runButton().disabled).toBe(false));
  fireEvent.click(runButton());
  await waitFor(() => expect(runs).toHaveLength(1));
  expect(runs[0]?.payload_sources).toEqual([{ type: "plugin", plugin: { plugin: "gen-plugin", registration: "words" } }]);
 });

 test("a plugin rule posts {rule:'plugin', plugin:{plugin, registration}} and nothing runs until one is chosen", async () => {
  seed({ rules: [emptyRule("plugin")] });
  await openPayloads();
  const processor = (await screen
   .findByLabelText("Rule 1 plugin processor", {}, { timeout: 3000 })
   .catch(() => null)) as HTMLSelectElement | null;
  expect(processor, "the rule row lists processors").toBeTruthy();
  expect(runButton().disabled, "a plugin rule with no processor chosen is not runnable").toBe(true);
  await waitFor(() => expect(processor!.options.length).toBeGreaterThan(1));
  expect([...processor!.options].some((o) => o.textContent?.includes("Rewriter (gen-plugin)"))).toBe(true);
  expect([...processor!.options].some((o) => o.textContent?.includes("Word maker"))).toBe(false);
  fireEvent.change(processor!, { target: { value: [...processor!.options].find((o) => o.textContent?.includes("Rewriter"))!.value } });
  await waitFor(() => expect(runButton().disabled).toBe(false));
  fireEvent.click(runButton());
  await waitFor(() => expect(runs).toHaveLength(1));
  expect(((runs[0]?.payload_rules ?? []) as Record<string, unknown>[])[0]).toMatchObject({
   rule: "plugin",
   plugin: { plugin: "gen-plugin", registration: "rewrite" },
  });
 });

 test("the rule operation dropdown offers the plugin processor, and choosing it shows the processor list", async () => {
  seed({ rules: [emptyRule("add_prefix")] });
  await openPayloads();
  const operation = (await screen.findByLabelText("Rule 1 operation")) as HTMLSelectElement;
  expect([...operation.options].some((o) => o.value === "plugin")).toBe(true);
  expect(screen.queryByLabelText("Rule 1 plugin processor")).toBeNull();
  fireEvent.change(operation, { target: { value: "plugin" } });
  expect(await screen.findByLabelText("Rule 1 plugin processor")).toBeTruthy();
 });
});
