/**
 * Parses issues documents off the console's main thread.
 *
 * The page script stays a single embedded /app.js. This file is the one extra script the embed
 * serves, at /issues.worker.js, because a module worker cannot live inside app.js. Nothing here
 * touches the DOM. The main thread asks for one of three results: the summary rows (in chunks),
 * the dock's worst handful, or one task's activity. The parsed document is not kept: the next
 * invalidation must see the store, not a worker cache from the previous event.
 */
import { ISSUE_CHUNK, readIssueDocument, taskFindings, topFindings } from "./lib/issue-index";
import type { FindingDetail } from "./lib/types.attack";

interface LoadRequest {
 id: number;
 type: "document" | "top" | "task";
 url: string;
 limit?: number;
 taskId?: number;
 /** The list version the page holds, so only rows that differ from it are posted. */
 base?: number;
}

interface CancelRequest {
 id: number;
 type: "cancel";
}

type Inbound = LoadRequest | CancelRequest;

const scope = globalThis as unknown as {
 onmessage: ((event: MessageEvent<Inbound>) => void) | null;
 postMessage(data: unknown): void;
};

const cancelled = new Set<number>();

/**
 * What the page last received, per list version, as one JSON string per row. A new document is
 * compared against the version the page says it holds, and only new or changed rows are posted;
 * the rest of the page's own row objects are reused. Without this every refetch of a big list
 * structured-cloned every row to the main thread. The page names the version it holds, and a
 * version that is no longer kept (or never existed) gets the full list, so a cancelled request
 * or a restarted worker can only cost a full send, never a stale row. Only the last few
 * versions are kept, so memory is bounded by a few copies of the signatures.
 */
const KEPT_VERSIONS = 3;
const snapshots = new Map<number, Map<number, string>>();
let latestVersion = 0;

// Tells the page the script loaded and ran, so a worker that never starts is told apart from a slow one.
scope.postMessage({ id: 0, type: "ready" });

scope.onmessage = (event) => {
 const message = event.data;
 if (message.type === "cancel") {
  cancelled.add(message.id);
  return;
 }
 void run(message);
};

async function run(message: LoadRequest): Promise<void> {
 try {
  // The page names the URL, so the worker only ever reads the issues document: it cannot be
  // pointed at a mutating or gated route, and it never sends a body or a confirm token.
  if (!/^\/api\/issues(\?|$)/.test(message.url)) throw new Error("issue worker only reads /api/issues");
  const response = await fetch(message.url);
  const text = await response.text();
  if (cancelled.has(message.id)) return;
  if (!response.ok) {
   scope.postMessage({ id: message.id, type: "error", message: text || response.statusText });
   return;
  }
  const doc = readIssueDocument(text);
  if (cancelled.has(message.id)) return;
  if (message.type === "top") {
   const limit = message.limit ?? 40;
   scope.postMessage({
    id: message.id,
    type: "top",
    enabled: doc.enabled,
    hint: doc.hint,
    total: doc.findings.length,
    findings: topFindings(doc.findings, limit),
   });
   return;
  }
  if (message.type === "task") {
   const sliced = taskFindings(doc.findings, message.taskId ?? 0, message.limit ?? 20);
   scope.postMessage({
    id: message.id,
    type: "task",
    enabled: doc.enabled,
    hint: doc.hint,
    shown: sliced.shown,
    hidden: sliced.hidden,
   });
   return;
  }
  const sigs = new Map<number, string>();
  for (const f of doc.findings) sigs.set(f.id, JSON.stringify(f));
  // Ids must be unique numbers for a row to be addressed by id; anything else is sent in full.
  const addressable = sigs.size === doc.findings.length && doc.findings.every((f) => typeof f.id === "number");
  const before = addressable && message.base !== undefined ? snapshots.get(message.base) : undefined;
  const send = before ? doc.findings.filter((f) => before.get(f.id) !== sigs.get(f.id)) : doc.findings;
  postChunks(message.id, send);
  if (cancelled.has(message.id)) return;
  let version: number | undefined;
  if (addressable) {
   version = ++latestVersion;
   snapshots.set(version, sigs);
   for (const old of [...snapshots.keys()]) if (old <= version - KEPT_VERSIONS) snapshots.delete(old);
  }
  scope.postMessage({
   id: message.id,
   type: "done",
   enabled: doc.enabled,
   hint: doc.hint,
   loaded: doc.loaded,
   counts: doc.counts,
   version,
   order: before ? doc.findings.map((f) => f.id) : undefined,
  });
 } catch (err) {
  if (cancelled.has(message.id)) return;
  scope.postMessage({ id: message.id, type: "error", message: err instanceof Error ? err.message : "issue worker failed" });
 }
}

function postChunks(id: number, findings: FindingDetail[]): void {
 for (let offset = 0; offset < findings.length; offset += ISSUE_CHUNK) {
  if (cancelled.has(id)) return;
  scope.postMessage({ id, type: "chunk", findings: findings.slice(offset, offset + ISSUE_CHUNK) });
 }
 if (findings.length === 0) scope.postMessage({ id, type: "chunk", findings: [] });
}
