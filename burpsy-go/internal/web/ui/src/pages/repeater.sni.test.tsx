/**
 * burpsy-react-ui-vln1 (replaces the source-text pins in lib/repeater-sni.test.ts): Override SNI
 * (k011) as the page behaves. The Repeater is rendered with a faked API and Send is pressed; what
 * the request body carries is the contract. The wire half is pinned in Go.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { useApp } from "../lib/store";
import { renderWithProviders } from "../../test/render";
import { RepeaterPage } from "./repeater";

const originalFetch = globalThis.fetch;
let sends: Record<string, unknown>[] = [];

beforeEach(() => {
  sends = [];
  window.localStorage.clear();
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(input), "http://localhost").pathname;
    if (path === "/api/repeater/send") {
      sends.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
      return new Response(JSON.stringify({ response: "HTTP/1.1 200 OK\r\n\r\n" }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
});
afterEach(() => {
  cleanup();
  globalThis.fetch = originalFetch;
});

function openTab(target: string, sni: string): void {
  useApp.setState({ repeaterTabs: [], activeRepeaterTab: "" });
  const id = useApp.getState().openRepeaterTab({ name: "t", target, request: "GET / HTTP/1.1\r\nHost: x\r\n\r\n" });
  useApp.getState().updateRepeaterTab(id, { sni });
}

async function pressSend(): Promise<void> {
  renderWithProviders(<RepeaterPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Send" }));
  await waitFor(() => expect(sends.length).toBe(1));
}

describe("Repeater Override SNI", () => {
  test("a TLS target with an SNI override sends it", async () => {
    openTab("https://target.test:443", " oast.example ");
    await pressSend();
    expect(sends[0]?.sni).toBe("oast.example");
  });

  test("a plain-HTTP target never sends one, even if the tab still holds a value", async () => {
    openTab("http://target.test:80", "oast.example");
    await pressSend();
    expect("sni" in (sends[0] ?? {})).toBe(false);
  });

  test("a blank override is omitted rather than sent empty", async () => {
    openTab("https://target.test:443", "   ");
    await pressSend();
    expect("sni" in (sends[0] ?? {})).toBe(false);
  });
});
