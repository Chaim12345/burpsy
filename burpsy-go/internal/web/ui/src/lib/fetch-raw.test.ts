import { describe, expect, test } from "bun:test";
import { fetchRaw } from "./actions";
import type { Exchange } from "./types";

/**
 * A blind CONNECT tunnel has no request bytes: the proxy relayed it without looking inside. The wire
 * used to say so with `0`, which is the first message the project ever captured, so every one of
 * these callers fetched a DIFFERENT exchange's request and acted on it believing it was this row's
 * (burpsy-react-ui-wtov).
 *
 * The wire now says null, and these tests hold the other half of that: the refusal must be a
 * refusal, not a fallback. A test that only checked the type change would pass against an
 * implementation that quietly substituted something.
 */

const tunnel: Pick<Exchange, "request" | "response"> = { request: null, response: null };

describe("fetchRaw on an exchange with no request", () => {
 test("refuses rather than fetching some other message", async () => {
  // A thrown Error is the contract. What matters is that no request goes out: a silent fetch of
  // message 0 is the bug, and a test that only checked for a throw would not catch an
  // implementation that fetched and then threw.
  let fetched = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (...args: Parameters<typeof fetch>) => {
   fetched = true;
   return originalFetch(...args);
  }) as typeof fetch;
  try {
   await expect(fetchRaw(tunnel.request)).rejects.toThrow(/no request/i);
   expect(fetched).toBe(false);
  } finally {
   globalThis.fetch = originalFetch;
  }
 });

 test("the refusal names the reason and the way out", async () => {
  // An operator who hits this needs to know it is a blind tunnel rather than a capture failure,
  // and that interception is the switch which changes it. "Request not found" would send them to
  // look for a message that does exist.
  await expect(fetchRaw(tunnel.request)).rejects.toThrow(/blind tunnel/i);
  await expect(fetchRaw(tunnel.request)).rejects.toThrow(/interception/i);
 });

 test("a real id still fetches", async () => {
  // The other half: the change must not have made every request unreadable. There is no server in
  // a unit test, so this asserts the call is ATTEMPTED with the id rather than refused — a
  // null-check that rejected everything would satisfy the tests above.
  const originalFetch = globalThis.fetch;
  let seen: string | undefined;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
   seen = String(input);
   return new Response(JSON.stringify({ text: "GET / HTTP/1.1" }), {
    headers: { "content-type": "application/json" },
   });
  }) as typeof fetch;
  try {
   await expect(fetchRaw(7)).resolves.toContain("GET /");
   expect(seen).toContain("/api/message/7");
  } finally {
   globalThis.fetch = originalFetch;
  }
 });

 test("the response half names itself, so a missing response does not read as a missing request", async () => {
  await expect(fetchRaw(tunnel.response, "response")).rejects.toThrow(/no response/i);
 });
});
