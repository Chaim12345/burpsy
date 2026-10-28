import { afterEach, beforeEach, expect, test } from "bun:test";
import { loadIssueDocument, resetIssueWorkerForTests } from "./issue-worker";

/**
 * The real worker script wired to the real client through an in-process channel: the worker's
 * postMessage feeds the client's listeners, the client's postMessage calls the worker's onmessage.
 * What the server returns is a mutable array, so each test changes the "store" between loads.
 */
type Row = { id: number; name: string; severity: string; comment?: string };
let store: Row[] = [];
const g = globalThis as unknown as Record<string, any>;
const saved = { window: g.window, Worker: g.Worker, fetch: g.fetch, postMessage: g.postMessage, onmessage: g.onmessage, toString: Function.prototype.toString };
const posted: Array<{ type: string; findings?: Row[]; order?: number[]; version?: number }> = [];
let clientListeners: Array<(e: { data: any }) => void> = [];
let workerLoaded = false;

class ChannelWorker {
 addEventListener(type: string, fn: (e: any) => void) {
  if (type === "message") clientListeners.push(fn);
 }
 removeEventListener(type: string, fn: (e: any) => void) {
  if (type === "message") clientListeners = clientListeners.filter((f) => f !== fn);
 }
 postMessage(data: unknown) {
  queueMicrotask(() => g.onmessage?.({ data }));
 }
 terminate() {}
}

beforeEach(async () => {
 resetIssueWorkerForTests();
 posted.length = 0;
 clientListeners = [];
 store = [];
 g.window = { location: { origin: "http://x.test" } };
 g.Worker = ChannelWorker;
 g.postMessage = (data: any) => {
  posted.push(data);
  for (const fn of [...clientListeners]) fn({ data });
 };
 const stub = (async () => new Response(JSON.stringify({ enabled: true, findings: store }), { status: 200 })) as unknown as typeof fetch;
 g.fetch = stub;
 const orig = Function.prototype.toString;
 Function.prototype.toString = function () {
  return this === stub ? "function fetch() { [native code] }" : orig.call(this);
 };
 if (!workerLoaded) {
  await import("../issues.worker");
  workerLoaded = true;
 }
 // The worker script announces itself once on import; re-announce for each fresh client.
 queueMicrotask(() => g.postMessage({ id: 0, type: "ready" }));
});
afterEach(() => {
 Object.assign(g, { window: saved.window, Worker: saved.Worker, fetch: saved.fetch, postMessage: saved.postMessage });
 Function.prototype.toString = saved.toString;
 resetIssueWorkerForTests();
});

const rows = (n: number): Row[] => Array.from({ length: n }, (_, i) => ({ id: i + 1, name: `f${i + 1}`, severity: "high" }));

test("second load posts only changed and new rows, and reuses the held objects", async () => {
 store = rows(500);
 const first = await loadIssueDocument("/api/issues?summary=1");
 expect(first.findings.length).toBe(500);
 posted.length = 0;
 store = rows(500);
 store[3] = { ...store[3]!, comment: "edited" };
 store.push({ id: 501, name: "f501", severity: "low" });
 const second = await loadIssueDocument("/api/issues?summary=1");
 const sentRows = posted.filter((m) => m.type === "chunk").flatMap((m) => m.findings ?? []);
 expect(sentRows.map((r) => r.id).sort((a, b) => a - b)).toEqual([4, 501]);
 expect(second.findings.length).toBe(501);
 expect(second.findings[3]).toMatchObject({ id: 4, comment: "edited" });
 expect(second.findings[0]).toBe(first.findings[0]); // unchanged row: same object, nothing cloned
 expect(second.findings[499]).toBe(first.findings[499]);
});

test("a deleted row and a reorder come out right", async () => {
 store = rows(10);
 await loadIssueDocument("/api/issues?summary=1");
 store = rows(10).filter((r) => r.id !== 5).reverse();
 const doc = await loadIssueDocument("/api/issues?summary=1");
 expect(doc.findings.map((f) => f.id)).toEqual([10, 9, 8, 7, 6, 4, 3, 2, 1]);
});

test("an empty store after a full one clears the list", async () => {
 store = rows(3);
 await loadIssueDocument("/api/issues?summary=1");
 store = [];
 const doc = await loadIssueDocument("/api/issues?summary=1");
 expect(doc.findings).toEqual([]);
});

test("a cancelled load does not make the next one lose rows", async () => {
 store = rows(5);
 const first = await loadIssueDocument("/api/issues?summary=1");
 store = rows(5);
 store[0] = { ...store[0]!, severity: "low" };
 const ac = new AbortController();
 const p = loadIssueDocument("/api/issues?summary=1", ac.signal);
 ac.abort();
 await p.catch(() => undefined);
 await new Promise((r) => setTimeout(r, 20));
 const next = await loadIssueDocument("/api/issues?summary=1");
 expect(next.findings.map((f) => f.severity)).toEqual(["low", "high", "high", "high", "high"]);
 expect(next.findings[1]).toBe(first.findings[1]);
});
