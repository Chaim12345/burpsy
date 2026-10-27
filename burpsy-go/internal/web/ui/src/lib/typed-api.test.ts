import { afterEach, describe, expect, it, mock } from "bun:test";
import { typedApi } from "./typed-api";

// The typed client over a stubbed fetch: the path and verb are the document's, and a read returns
// the declared shape without any hand-mirrored type involved.
describe("typedApi", () => {
 const original = globalThis.fetch;
 afterEach(() => {
  globalThis.fetch = original;
 });

 it("GETs a declared route and returns its response", async () => {
  const calls: string[] = [];
  globalThis.fetch = mock(async (input: RequestInfo | URL) => {
   const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
   calls.push(url);
   return new Response(JSON.stringify({ loaded: true, count: 0, matched: 0, severity_counts: {}, advisories: [] }), {
    status: 200,
    headers: { "content-type": "application/json" },
   });
  }) as unknown as typeof fetch;
  const { data, error } = await typedApi.GET("/api/advisories", { params: { query: { q: "xss" } } });
  expect(error).toBeUndefined();
  expect(calls).toEqual(["http://console.invalid/api/advisories?q=xss"]);
  expect(data?.loaded).toBe(true);
 });

 it("a mutating call on a gated route mints before it sends", async () => {
  const sent: { url: string; confirm: string | null }[] = [];
  globalThis.fetch = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
   const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
   const confirm = new Headers(init?.headers).get("x-burpsy-confirm");
   sent.push({ url, confirm });
   if (url.endsWith("/confirm")) {
    return new Response(
     JSON.stringify({
      token: "tok",
      binding: "bnd",
      expires_in: 60,
      call: { method: "POST", url: "/api/scope", body_bytes: 0, body_sha256: "x", body_kind: "none" },
     }),
     { status: 200, headers: { "content-type": "application/json" } },
    );
   }
   return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  // /api/scope is confirm-gated (riskScope) in the generated ROUTE_GATED table.
  const { error } = await typedApi.POST("/api/scope", { body: { rules: [] } as never });
  expect(error).toBeUndefined();
  expect(sent.length).toBe(2);
  expect(sent[0]?.url.endsWith("/api/scope/confirm")).toBe(true);
  expect(sent[1]?.confirm).toBe("tok");
 });
});
