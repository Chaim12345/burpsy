// Send to Sequencer hands the exchange's response over so the cookie picker can list what it carries.
// The page consumes the seed once (it clears it from the store); the response the picker reads must
// survive that, or the typed-name fallback shows for every hand-off.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { act, cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { useApp } from "../lib/store";
import { SequencerPage } from "./sequencer";

const originalFetch = globalThis.fetch;
const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200, headers: { "content-type": "application/json" } });

beforeEach(() => {
 globalThis.fetch = (async () =>
  json({
   token_handling: { base_64_decode_before_analyzing: false, significance_level: "" },
   captures: [],
   tokens: [],
  })) as unknown as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

describe("SequencerPage hand-off", () => {
 test("the handed-off response populates the cookie picker", async () => {
  renderWithProviders(<SequencerPage />);
  act(() => {
   useApp.getState().setSequencerSeed({
    request: "GET /x HTTP/1.1\r\nHost: h.test\r\n\r\n",
    target: "http://h.test:80",
    label: "#1 GET /x",
    response: "HTTP/1.1 200 OK\r\nSet-Cookie: E2E_SESSION=abc123; Path=/\r\nContent-Length: 0\r\n\r\n",
   });
  });
  fireEvent.mouseDown(await screen.findByRole("tab", { name: /Capture from a live exchange/ }), { button: 0, ctrlKey: false });
  await waitFor(() => expect(screen.getByLabelText("Cookie name").tagName).toBe("SELECT"));
 });
});
