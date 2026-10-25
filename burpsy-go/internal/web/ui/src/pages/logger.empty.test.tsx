// The Logger's empty state names every tool whose requests land in it (burpsy-react-ui-7z8h).
import { afterEach, describe, expect, test } from "bun:test";
import { cleanup, screen } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { LoggerPage } from "./logger";

const originalFetch = globalThis.fetch;
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

describe("Logger empty state", () => {
 test("lists extensions among the tools whose traffic is recorded", async () => {
  globalThis.fetch = (async (_input: RequestInfo | URL) =>
   new Response(JSON.stringify({ entries: [], items: [], counts: {}, total: 0, filtered: 0 }), {
    status: 200,
    headers: { "content-type": "application/json" },
   })) as typeof fetch;
  renderWithProviders(<LoggerPage />);
  const text = (await screen.findByText(/Every request burpsy makes or relays/)).textContent ?? "";
  expect(text).toContain("extensions");
  expect(text).toContain("Sequencer");
 });
});
