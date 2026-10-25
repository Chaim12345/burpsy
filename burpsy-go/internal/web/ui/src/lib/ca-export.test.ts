/**
 * Tests for the CA export client (burpsy-react-ui-j92x). Run with `bun run test:lib`.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { CONFIRM_HEADER } from "./api";
import { CA_EXPORT_URL, fetchCaExport, filenameFromDisposition, readCaExportRefusal } from "./ca-export";

describe("filenameFromDisposition", () => {
 test("reads the server's quoted filename", () => {
  expect(filenameFromDisposition('attachment; filename="burpsy-ca.p12"', "x")).toBe("burpsy-ca.p12");
 });
 test("prefers filename* and decodes it", () => {
  expect(filenameFromDisposition("attachment; filename=\"a.crt\"; filename*=UTF-8''b%20c.crt", "x")).toBe("b c.crt");
 });
 test("keeps only the base name", () => {
  expect(filenameFromDisposition('attachment; filename="../../etc/burpsy-ca.key"', "x")).toBe("burpsy-ca.key");
 });
 test("falls back when there is no usable name", () => {
  expect(filenameFromDisposition(null, "burpsy-ca.crt")).toBe("burpsy-ca.crt");
  expect(filenameFromDisposition('attachment; filename=".."', "burpsy-ca.crt")).toBe("burpsy-ca.crt");
 });
});

describe("readCaExportRefusal", () => {
 test("plain text is the reason", () => {
  expect(readCaExportRefusal(400, "a PKCS#12 export needs a password\n")).toBe("a PKCS#12 export needs a password");
 });
 test("the gate's JSON {error} is read", () => {
  expect(readCaExportRefusal(428, JSON.stringify({ error: "needs confirmation" }))).toBe("needs confirmation");
 });
 test("an empty 503 still says why", () => {
  expect(readCaExportRefusal(503, "")).toMatch(/no signing CA/);
 });
});

describe("fetchCaExport", () => {
 const originalFetch = globalThis.fetch;
 afterEach(() => {
  globalThis.fetch = originalFetch;
 });

 test("mints, spends the token, sends the kind and password, and returns the file", async () => {
  const seen: { url: string; token: string | null; body: string | null }[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
   const url = String(input);
   seen.push({ url, token: new Headers(init?.headers).get(CONFIRM_HEADER), body: (init?.body as string) ?? null });
   if (url === `${CA_EXPORT_URL}/confirm`) return new Response(JSON.stringify({ token: "tok", binding: "b", call: { method: "POST", url: "/", body_bytes: 0, body_sha256: "", body_kind: "none" } }), { status: 200 });
   return new Response(new Uint8Array([1, 2, 3]), {
    status: 200,
    headers: { "content-type": "application/x-pkcs12", "content-disposition": 'attachment; filename="burpsy-ca.p12"' },
   });
  }) as typeof fetch;

  const out = await fetchCaExport("pkcs12", "s3cret");
  expect(out.filename).toBe("burpsy-ca.p12");
  expect(out.blob.size).toBe(3);
  expect(seen.map((s) => s.url)).toEqual([`${CA_EXPORT_URL}/confirm`, CA_EXPORT_URL]);
  expect(seen[1]?.token).toBe("tok");
  expect(JSON.parse(seen[1]?.body ?? "{}")).toEqual({ kind: "pkcs12", password: "s3cret" });
 });

 test("a cert export sends no password field at all", async () => {
  let body = "";
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
   if (String(input).endsWith("/confirm")) return new Response(JSON.stringify({ token: "tok", binding: "b", call: { method: "POST", url: "/", body_bytes: 0, body_sha256: "", body_kind: "none" } }), { status: 200 });
   body = String(init?.body ?? "");
   return new Response("-----BEGIN CERTIFICATE-----\n", { status: 200 });
  }) as typeof fetch;
  const out = await fetchCaExport("cert", "ignored");
  expect(JSON.parse(body)).toEqual({ kind: "cert" });
  expect(out.filename).toBe("burpsy-ca.crt");
 });

 test("a refusal throws the server's text with its status", async () => {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
   if (String(input).endsWith("/confirm")) return new Response(JSON.stringify({ token: "tok", binding: "b", call: { method: "POST", url: "/", body_bytes: 0, body_sha256: "", body_kind: "none" } }), { status: 200 });
   return new Response("TLS interception is off, so there is no signing CA to export", { status: 503 });
  }) as typeof fetch;
  await expect(fetchCaExport("key")).rejects.toThrow(/TLS interception is off/);
 });
});
