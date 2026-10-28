/**
 * Main-thread client for issues.worker.ts.
 *
 * A native fetch means a real browser: the worker parses the document and posts it back in chunks,
 * so the click that opened the page is not the task that parses it. Unit tests replace fetch, and
 * a missing worker script (the embed was built without it) falls back to parsing on this thread —
 * same rows, worse responsiveness, never a blank Issues page.
 */
import { api } from "./api";
import { taskFindings, topFindings } from "./issue-index";
import type { FindingDetail, IssuesDetail } from "./types.attack";

const WORKER_URL = "/issues.worker.js";

interface ChunkMessage {
 id: number;
 type: "chunk";
 findings: FindingDetail[];
}
interface DoneMessage {
 id: number;
 type: "done";
 enabled: boolean;
 hint?: string;
 loaded?: number;
 counts?: Record<string, number>;
}
interface TopMessage {
 id: number;
 type: "top";
 enabled: boolean;
 hint?: string;
 total: number;
 findings: FindingDetail[];
}
interface TaskMessage {
 id: number;
 type: "task";
 enabled: boolean;
 hint?: string;
 shown: FindingDetail[];
 hidden: number;
}
interface ErrorMessage {
 id: number;
 type: "error";
 message: string;
}
type WorkerMessage = ChunkMessage | DoneMessage | TopMessage | TaskMessage | ErrorMessage;

let worker: Worker | null = null;
let workerBroken = false;
let nextId = 1;

/**
 * No message at all from the worker for this long means it never started or is wedged. The
 * worker's own fetch, parse and chunk posts each reset the clock on the call that owns them, so a
 * slow parse that keeps posting is never cut off; a worker that went silent is.
 */
export const WORKER_STALL_MS = 20_000;

/** A worker that has not announced itself in this long never loaded (blocked, hung or silently dead). */
export const WORKER_START_MS = 6_000;
let workerReady = false;

/** Every in-flight call's failure hook, so one worker failure settles all of them. */
const pendingFailures = new Set<(reason: Error) => void>();

function failWorker(reason: string, permanent = true): void {
 workerReady = false;
 // A stall may be a slow server rather than a bad worker, so it retires this worker instance and
 // lets the next call start a fresh one; load and message errors disable workers for the session.
 if (permanent) workerBroken = true;
 const dead = worker;
 worker = null;
 dead?.terminate();
 for (const fail of [...pendingFailures]) fail(new Error(reason));
}

/** Test seam: forget a broken worker so the next call may try one again. */
export function resetIssueWorkerForTests(): void {
 worker?.terminate();
 worker = null;
 workerBroken = false;
 workerReady = false;
 pendingFailures.clear();
}

function nativeFetch(): boolean {
 return typeof fetch === "function" && /\[native code\]/.test(Function.prototype.toString.call(fetch));
}

function canUseWorker(): boolean {
 return nativeFetch() && typeof Worker === "function" && typeof window !== "undefined" && !workerBroken;
}

function getWorker(): Worker | null {
 if (!canUseWorker()) return null;
 if (worker) return worker;
 try {
  worker = new Worker(new URL(WORKER_URL, window.location.origin), { type: "module" });
  workerReady = false;
  const created = worker;
  created.addEventListener("message", (event: MessageEvent) => {
   if (created === worker && event.data?.type === "ready") workerReady = true;
  });
  worker.addEventListener("error", () => failWorker("issue worker failed to load"));
  worker.addEventListener("messageerror", () => failWorker("issue worker sent an unreadable message"));
  return worker;
 } catch {
  failWorker("issue worker could not be created");
  return null;
 }
}

function callWorker<T>(body: Record<string, unknown>, take: (message: WorkerMessage, resolve: (value: T) => void) => boolean, signal?: AbortSignal): Promise<T> {
 const current = getWorker();
 if (!current) return Promise.reject(new Error("no issue worker"));
 const id = nextId++;
 return new Promise<T>((resolve, reject) => {
  let stall: ReturnType<typeof setTimeout> | undefined;
  const arm = () => {
   clearTimeout(stall);
   const wait = workerReady ? WORKER_STALL_MS : WORKER_START_MS;
   stall = setTimeout(() => {
    if (workerReady && wait === WORKER_START_MS) {
     arm();
     return;
    }
    failWorker(workerReady ? "issue worker stopped responding" : "issue worker never started", false);
   }, wait);
  };
  const onFail = (reason: Error) => {
   cleanup();
   reject(reason);
  };
  const onMessage = (event: MessageEvent<WorkerMessage>) => {
   const message = event.data;
   if (!message || message.id !== id) return;
   arm();
   if (message.type === "error") {
    cleanup();
    reject(new Error(message.message));
    return;
   }
   if (take(message, resolve)) cleanup();
  };
  const onAbort = () => {
   current.postMessage({ id, type: "cancel" });
   cleanup();
   reject(new DOMException("aborted", "AbortError"));
  };
  const cleanup = () => {
   clearTimeout(stall);
   pendingFailures.delete(onFail);
   current.removeEventListener("message", onMessage);
   signal?.removeEventListener("abort", onAbort);
  };
  if (signal?.aborted) {
   reject(new DOMException("aborted", "AbortError"));
   return;
  }
  signal?.addEventListener("abort", onAbort);
  pendingFailures.add(onFail);
  arm();
  current.addEventListener("message", onMessage);
  current.postMessage({ id, ...body });
 });
}

export async function loadIssueDocument(url: string, signal?: AbortSignal): Promise<IssuesDetail> {
 if (!canUseWorker()) return api<IssuesDetail>(url, { signal });
 try {
  const findings: FindingDetail[] = [];
  const doc = await callWorker<IssuesDetail>(
   { type: "document", url },
   (message, resolve) => {
    if (message.type === "chunk") {
     findings.push(...message.findings);
     return false;
    }
    if (message.type === "done") {
     resolve({
      enabled: message.enabled,
      hint: message.hint,
      loaded: message.loaded,
      counts: message.counts,
      findings,
     });
     return true;
    }
    return false;
   },
   signal,
  );
  return doc;
 } catch (err) {
  if (signal?.aborted) throw err;
  return api<IssuesDetail>(url, { signal });
 }
}

export interface TopIssues {
 enabled: boolean;
 hint?: string;
 total: number;
 findings: FindingDetail[];
}

export async function loadTopIssues(url: string, limit: number, signal?: AbortSignal): Promise<TopIssues> {
 if (!canUseWorker()) return topFromDocument(await api<IssuesDetail>(url, { signal }), limit);
 try {
  return await callWorker<TopIssues>(
   { type: "top", url, limit },
   (message, resolve) => {
    if (message.type !== "top") return false;
    resolve({ enabled: message.enabled, hint: message.hint, total: message.total, findings: message.findings });
    return true;
   },
   signal,
  );
 } catch (err) {
  if (signal?.aborted) throw err;
  return topFromDocument(await api<IssuesDetail>(url, { signal }), limit);
 }
}

function topFromDocument(doc: IssuesDetail, limit: number): TopIssues {
 const findings = Array.isArray(doc.findings) ? doc.findings : [];
 return { enabled: doc.enabled, hint: doc.hint, total: findings.length, findings: topFindings(findings, limit) };
}

export interface TaskIssues {
 enabled: boolean;
 hint?: string;
 shown: FindingDetail[];
 hidden: number;
}

export async function loadTaskIssues(url: string, taskId: number, limit: number, signal?: AbortSignal): Promise<TaskIssues> {
 if (!canUseWorker()) {
  const doc = await api<IssuesDetail>(url, { signal });
  const sliced = taskFindings(doc.findings, taskId, limit);
  return { enabled: doc.enabled, hint: doc.hint, shown: sliced.shown, hidden: sliced.hidden };
 }
 try {
  return await callWorker<TaskIssues>(
   { type: "task", url, taskId, limit },
   (message, resolve) => {
    if (message.type !== "task") return false;
    resolve({ enabled: message.enabled, hint: message.hint, shown: message.shown, hidden: message.hidden });
    return true;
   },
   signal,
  );
 } catch (err) {
  if (signal?.aborted) throw err;
  const doc = await api<IssuesDetail>(url, { signal });
  const sliced = taskFindings(doc.findings, taskId, limit);
  return { enabled: doc.enabled, hint: doc.hint, shown: sliced.shown, hidden: sliced.hidden };
 }
}
