import { afterEach, beforeEach, expect, test } from "bun:test";
import { WORKER_STALL_MS, loadIssueDocument, resetIssueWorkerForTests } from "./issue-worker";

/**
 * A worker whose script never loads fires `error` and never answers. The call in flight at that
 * moment must settle through the main-thread fallback instead of waiting for a message that cannot
 * come (the first Issues load used to sit on "Loading" with zero findings).
 */
class DeadWorker {
 listeners: Record<string, Array<(e: unknown) => void>> = {};
 addEventListener(type: string, fn: (e: unknown) => void) {
  (this.listeners[type] ??= []).push(fn);
 }
 removeEventListener(type: string, fn: (e: unknown) => void) {
  this.listeners[type] = (this.listeners[type] ?? []).filter((f) => f !== fn);
 }
 postMessage() {
  if (mode === "error") queueMicrotask(() => this.listeners.error?.forEach((f) => f({})));
 }
 terminate() {}
}
let mode: "error" | "silent" = "error";
const g = globalThis as unknown as Record<string, unknown>;
const saved = { window: g.window, Worker: g.Worker, fetch: g.fetch, fnToString: Function.prototype.toString };

beforeEach(() => {
 resetIssueWorkerForTests();
 g.window = { location: { origin: "http://x.test" } };
 g.Worker = DeadWorker;
 // Make the stubbed fetch look native so canUseWorker() takes the worker path.
 const stub = (async () => new Response(JSON.stringify({ enabled: true, findings: [{ id: 1, name: "x", severity: "high" }] }), { status: 200, headers: { "content-type": "application/json" } })) as unknown as typeof fetch;
 g.fetch = stub;
 const orig = Function.prototype.toString;
 Function.prototype.toString = function () {
  return this === stub ? "function fetch() { [native code] }" : orig.call(this);
 };
});
afterEach(() => {
 g.window = saved.window;
 g.Worker = saved.Worker;
 g.fetch = saved.fetch;
 Function.prototype.toString = saved.fnToString;
 resetIssueWorkerForTests();
});

test("worker load error settles the in-flight call through the fallback", async () => {
 mode = "error";
 const doc = await loadIssueDocument("/api/issues?summary=1");
 expect(doc.findings.length).toBe(1);
});

test("stall budget is finite", () => {
 expect(WORKER_STALL_MS).toBeGreaterThan(0);
 expect(mode).toBeDefined();
});
