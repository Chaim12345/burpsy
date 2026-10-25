/**
 * Tests for the in-console project switch's pure half (burpsy-react-ui-dlw2). Run with
 * `bun run test:lib`.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { ApiError, api, CONFIRM_HEADER } from "./api";
import { existingProjectFor, newProjectFilename, projectEntries, readProjectRefusal } from "./project-switch";
import type { ProjectList } from "./types";

const list: ProjectList = {
 projects: [
  { path: "/work/a.db", name: "Client A", named: true, active: true },
  { path: "/work/b.db", name: "b", named: false, active: false },
 ],
 active: "/work/a.db",
 project_dir: "/work",
};

describe("projectEntries", () => {
 test("Go's nil slice reads as no rows, not a crash", () => {
  expect(projectEntries({ projects: null, active: "", note: "no -db" })).toEqual([]);
  expect(projectEntries(undefined)).toEqual([]);
 });
});

describe("newProjectFilename", () => {
 test("appends .db, because the list only shows .db files", () => {
  expect(newProjectFilename(" client-c ")).toBe("client-c.db");
 });
 test("keeps an extension the operator already typed, in any case", () => {
  expect(newProjectFilename("c.db")).toBe("c.db");
  expect(newProjectFilename("C.DB")).toBe("C.DB");
 });
 test("blank stays blank so nothing can be staged", () => {
  expect(newProjectFilename("   ")).toBe("");
 });
});

describe("existingProjectFor", () => {
 test("a bare name that is already listed is an open, not a create", () => {
  expect(existingProjectFor("b.db", list)?.path).toBe("/work/b.db");
 });
 test("an absolute path that is listed matches too", () => {
  expect(existingProjectFor("/work/a.db", list)?.name).toBe("Client A");
 });
 test("a new name matches nothing", () => {
  expect(existingProjectFor("c.db", list)).toBeUndefined();
  expect(existingProjectFor("", list)).toBeUndefined();
 });
});

describe("readProjectRefusal", () => {
 test("reads the handler's {reason, remedy} rather than showing raw JSON", () => {
  const body = JSON.stringify({ reason: "could not open /x.db: not a database", remedy: "the current project is unchanged" });
  const refusal = readProjectRefusal(new ApiError(body, 400, body));
  expect(refusal.reason).toBe("could not open /x.db: not a database");
  expect(refusal.remedy).toBe("the current project is unchanged");
 });
 test("a reason without a remedy has no remedy", () => {
  const body = JSON.stringify({ reason: "/tmp is a directory, not a project file" });
  expect(readProjectRefusal(new ApiError(body, 400, body))).toEqual({ reason: "/tmp is a directory, not a project file" });
 });
 test("plain-text refusals and the gate's {error} fall back to the message", () => {
  expect(readProjectRefusal(new ApiError("A project file path is required", 400, "A project file path is required\n")).reason).toBe(
   "A project file path is required",
  );
  const gate = JSON.stringify({ error: "the confirmation for this route is not valid" });
  expect(readProjectRefusal(new ApiError("the confirmation for this route is not valid", 428, gate)).reason).toBe(
   "the confirmation for this route is not valid",
  );
 });
});

describe("api() on a gated route", () => {
 const originalFetch = globalThis.fetch;
 afterEach(() => {
  globalThis.fetch = originalFetch;
 });

 test("mints at <route>/confirm, then spends that token on the route", async () => {
  const calls: { url: string; method: string; token: string | null; body: string | null }[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
   const url = String(input);
   const headers = new Headers(init?.headers);
   calls.push({ url, method: init?.method ?? "GET", token: headers.get(CONFIRM_HEADER), body: (init?.body as string) ?? null });
   if (url.endsWith("/confirm")) return new Response(JSON.stringify({ token: "t-1", binding: "b", call: { method: "POST", url: "/", body_bytes: 0, body_sha256: "", body_kind: "none" } }), { status: 200 });
   return new Response(JSON.stringify({ name: "B", unnamed: false, persisted: true, backupable: true }), { status: 200 });
  }) as typeof fetch;

  const view = await api<{ name: string }>("/api/project/open", { method: "POST", body: JSON.stringify({ path: "b.db" }) });
  expect(view.name).toBe("B");
  expect(calls.map((c) => [c.method, c.url])).toEqual([
   ["POST", "/api/project/open/confirm"],
   ["POST", "/api/project/open"],
  ]);
  expect(calls[0]?.token).toBeNull();
  expect(calls[1]?.token).toBe("t-1");
  expect(calls[1]?.body).toBe(JSON.stringify({ path: "b.db" }));
 });

 test("a failed mint sends nothing to the gated route", async () => {
  const urls: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL) => {
   urls.push(String(input));
   return new Response("no such route", { status: 404 });
  }) as typeof fetch;
  await expect(api("/api/project/open", { method: "POST" })).rejects.toThrow(/no such route/);
  expect(urls).toEqual(["/api/project/open/confirm"]);
 });
});

describe("forgetOutgoingProjectPointers", () => {
 test("drops every id into the project being left, and keeps the drafts' text", async () => {
  const { forgetOutgoingProjectPointers } = await import("./data");
  const { useApp } = await import("./store");
  useApp.setState((state) => ({
   historyFocus: 0,
   issueFocus: 3,
   checkedExchanges: [0, 1],
   historyQuery: "host = a",
   repeaterTabs: [{ id: "t1", name: "login", target: "https://a", protocol: "https", request: "GET / HTTP/1.1\r\n\r\n", fromExchange: 7 }],
   closedRepeaterTabs: [{ id: "t0", name: "old", target: "https://a", protocol: "https", request: "GET /x HTTP/1.1\r\n\r\n", fromExchange: 2 }],
   intruder: { ...state.intruder, msgId: "4", target: "https://a", payloadTexts: ["admin"] },
  }));

  forgetOutgoingProjectPointers();

  const after = useApp.getState();
  expect(after.historyFocus).toBeNull();
  expect(after.issueFocus).toBeNull();
  expect(after.checkedExchanges).toEqual([]);
  expect(after.historyQuery).toBe("");
  expect(after.repeaterTabs[0]?.fromExchange).toBeUndefined();
  expect(after.repeaterTabs[0]?.request).toBe("GET / HTTP/1.1\r\n\r\n");
  expect(after.closedRepeaterTabs[0]?.fromExchange).toBeUndefined();
  expect(after.intruder.msgId).toBe("");
  expect(after.intruder.points).toEqual([]);
  expect(after.intruder.payloadTexts).toEqual(["admin"]);
 });
});

describe("existingProjectFor and the open project", () => {
 test("typing the open project's own name finds the active entry", () => {
  expect(existingProjectFor("a.db", list)?.active).toBe(true);
 });
});
