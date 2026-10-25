/**
 * A confirmation is bound to the exact call, and the operator can be shown that call before it is
 * sent (burpsy-react-ui-e0yq). The server half is internal/web/confirm_binding_test.go; this is the
 * console's half: what the mint describes, and what gatedFetch does with an approver.
 * Run with `bun run test:lib`.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { api, CONFIRM_HEADER, ConfirmationDeclined, describeCall, gatedFetch, type ConfirmedCallPreview } from "./api";

const preview: ConfirmedCallPreview = {
 method: "DELETE",
 url: "/api/collaborator/server",
 body_bytes: 30,
 body_sha256: "ab".repeat(32),
 body_kind: "json",
 body: '{\n  "discard_open_channel": true\n}',
};

interface Seen {
 url: string;
 method: string;
 token: string | null;
 body: string | null;
}

/** A fetch double: each mint answers the next of `mints` (token, binding); anything else answers {}. */
function fakeConsole(mints: { token: string; binding: string; expires_in?: number }[]): Seen[] {
 const seen: Seen[] = [];
 let next = 0;
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  seen.push({
   url,
   method: init?.method ?? "GET",
   token: new Headers(init?.headers).get(CONFIRM_HEADER),
   body: (init?.body as string) ?? null,
  });
  if (url.endsWith("/confirm")) {
   const m = mints[next++] ?? mints[mints.length - 1]!;
   return new Response(JSON.stringify({ ...m, expires_in: m.expires_in ?? 60, call: preview }), { status: 200 });
  }
  return new Response("{}", { status: 200 });
 }) as typeof fetch;
 return seen;
}

describe("the mint describes the exact call", () => {
 const originalFetch = globalThis.fetch;
 afterEach(() => {
  globalThis.fetch = originalFetch;
 });

 test("method, path with query, and the body bytes the call will send", async () => {
  const seen = fakeConsole([{ token: "t1", binding: "b1" }]);
  const body = JSON.stringify({ discard_open_channel: true });
  await api("/api/collaborator/server?x=1", { method: "DELETE", body });
  expect(seen.map((s) => [s.method, s.url])).toEqual([
   ["POST", "/api/collaborator/server/confirm"],
   ["DELETE", "/api/collaborator/server?x=1"],
  ]);
  expect(JSON.parse(seen[0]!.body ?? "{}")).toEqual({ method: "DELETE", url: "/api/collaborator/server?x=1", body });
  expect(seen[1]!.body).toBe(body);
  expect(seen[1]!.token).toBe("t1");
 });

 test("a call with no body is described as having none", async () => {
  expect(await describeCall("/api/backup", { method: "POST" })).toEqual({ method: "POST", url: "/api/backup" });
 });

 test("binary bodies are described as base64 of the bytes sent", async () => {
  expect(await describeCall("/api/x", { method: "PUT", body: new Uint8Array([0xff, 0x00, 0x41]) })).toEqual({
   method: "PUT",
   url: "/api/x",
   body_base64: "/wBB",
  });
  expect((await describeCall("/api/x", { method: "PUT", body: new Blob(["hi"]) })).body_base64).toBe("aGk=");
 });

 test("a body the browser assembles at send time cannot be confirmed, and nothing is minted", async () => {
  const seen = fakeConsole([{ token: "t1", binding: "b1" }]);
  const form = new FormData();
  form.set("a", "b");
  await expect(gatedFetch("/api/backup", { method: "POST", body: form })).rejects.toThrow(/cannot be confirmed/);
  expect(seen).toEqual([]);
 });
});

describe("gatedFetch with an approver", () => {
 const originalFetch = globalThis.fetch;
 afterEach(() => {
  globalThis.fetch = originalFetch;
 });

 test("the approver is shown the server's preview, and an approval sends the call with the bound token", async () => {
  const seen = fakeConsole([{ token: "t1", binding: "b1" }]);
  const shown: ConfirmedCallPreview[] = [];
  await gatedFetch("/api/collaborator/server", { method: "DELETE", body: "{}" }, { approve: async (call) => (shown.push(call), true) });
  expect(shown).toEqual([preview]);
  expect(seen.map((s) => [s.method, s.url, s.token])).toEqual([
   ["POST", "/api/collaborator/server/confirm", null],
   ["DELETE", "/api/collaborator/server", "t1"],
  ]);
 });

 test("a declined preview sends nothing and says so as a cancel", async () => {
  const seen = fakeConsole([{ token: "t1", binding: "b1" }]);
  await expect(gatedFetch("/api/collaborator/server", { method: "DELETE" }, { approve: async () => false })).rejects.toBeInstanceOf(
   ConfirmationDeclined,
  );
  expect(seen.map((s) => s.url)).toEqual(["/api/collaborator/server/confirm"]);
 });

 test("an answer slower than the token's life re-mints, and spends only a token bound to the same call", async () => {
  // expires_in 0: the first token is already past its margin when the operator answers.
  const seen = fakeConsole([
   { token: "t1", binding: "b1", expires_in: 0 },
   { token: "t2", binding: "b1" },
  ]);
  await gatedFetch("/api/collaborator/server", { method: "DELETE" }, { approve: async () => true });
  expect(seen.map((s) => [s.url, s.token])).toEqual([
   ["/api/collaborator/server/confirm", null],
   ["/api/collaborator/server/confirm", null],
   ["/api/collaborator/server", "t2"],
  ]);
 });

 test("a re-mint bound to a different call than the one shown sends nothing", async () => {
  const seen = fakeConsole([
   { token: "t1", binding: "b1", expires_in: 0 },
   { token: "t2", binding: "DIFFERENT" },
  ]);
  await expect(gatedFetch("/api/collaborator/server", { method: "DELETE" }, { approve: async () => true })).rejects.toThrow(
   /changed between the preview and the send/,
  );
  expect(seen.filter((s) => !s.url.endsWith("/confirm"))).toEqual([]);
 });
});
