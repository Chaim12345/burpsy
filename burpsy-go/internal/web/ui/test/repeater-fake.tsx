/** A faked API for rendering the Repeater page and reading what its Send put on the wire (vln1). */
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect } from "bun:test";
import { RepeaterPage } from "../src/pages/repeater";
import { useApp } from "../src/lib/store";
import { renderWithProviders } from "./render";

export interface FakeRepeater {
 /** Bodies of POST /api/repeater/send-group. */
 groupSends: Record<string, unknown>[];
 sends: Record<string, unknown>[];
 restore: () => void;
}

export function fakeRepeaterApi(): FakeRepeater {
 const original = globalThis.fetch;
 const fake: FakeRepeater = { sends: [], groupSends: [], restore: () => void (globalThis.fetch = original) };
 window.localStorage.clear();
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = new URL(String(input), "http://localhost").pathname;
  if (path === "/api/repeater/send") {
   fake.sends.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
   return new Response(JSON.stringify({ response: "HTTP/1.1 200 OK\r\n\r\n", exchange_id: 5 }), {
    status: 200,
    headers: { "content-type": "application/json" },
   });
  }
  if (path === "/api/repeater/send-group") {
   const body = JSON.parse(String(init?.body ?? "{}")) as { mode?: string };
   fake.groupSends.push(body as Record<string, unknown>);
   return new Response(JSON.stringify({ mode: body.mode, batch_duration_ms: 1, items: [] }), {
    status: 200,
    headers: { "content-type": "application/json" },
   });
  }
  if (path.startsWith("/api/exchange/")) {
   return new Response(JSON.stringify({ id: 5, request: 9 }), { status: 200, headers: { "content-type": "application/json" } });
  }
  return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
 }) as unknown as typeof fetch;
 return fake;
}

/** Replace the open tabs with one tab and return its id. */
export function openOnlyTab(target: string, patch: Record<string, unknown> = {}): string {
 useApp.setState({ repeaterTabs: [], activeRepeaterTab: "" });
 const id = useApp.getState().openRepeaterTab({ name: "t", target, request: "GET / HTTP/1.1\r\nHost: x\r\n\r\n" });
 useApp.getState().updateRepeaterTab(id, patch);
 return id;
}

export function renderRepeater() {
 return renderWithProviders(<RepeaterPage />);
}

export async function pressSend(fake: FakeRepeater, nth = 1): Promise<void> {
 fireEvent.click(await screen.findByRole("button", { name: "Send" }));
 await waitFor(() => expect(fake.sends.length).toBe(nth));
}
