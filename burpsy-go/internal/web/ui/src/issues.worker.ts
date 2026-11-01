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
  postChunks(message.id, doc.findings);
  if (cancelled.has(message.id)) return;
  scope.postMessage({
   id: message.id,
   type: "done",
   enabled: doc.enabled,
   hint: doc.hint,
   loaded: doc.loaded,
   counts: doc.counts,
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
