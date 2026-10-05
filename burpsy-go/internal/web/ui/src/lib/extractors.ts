// Custom history extractor columns (burpsy-react-ui-28n8) — Caido Automate's "custom extractor as a
// column". A named extractor is defined once and rendered as a derived column in HTTP history: each
// row runs it against its stored RESPONSE and shows the captured value.
//
// # Why this reuses the session-rule extraction shape
//
// An extractor is the SAME primitive the session-rule editor already edits (session.tsx's
// ExtractionRows): a name, a source (body or a named header), and a method (a regex with a capture
// group, a dotted JSON path, or the whole value). The server decodes both through one Go type —
// sessionExtractDto in internal/web/api_session.go — so the wire shape here is literally
// SessionExtraction, not a parallel one that could drift from it. compileHistoryExtractor on the Go
// side reuses the session extractor's own decoding for exactly this reason.
//
// The draft<->wire mapping below follows session.tsx's extractionIn/extractionOut, with two
// deliberate corrections documented at their call sites: the name and header name are trimmed, and a
// blank capture-group box falls back to the default of 1 rather than `Number("")` → 0. It is kept
// pure and here (rather than imported from the page) so the history manager can edit extractors
// without pulling in the session page, and so the round-trip is pinned by a test rather than inferred
// from a screenshot. The test in extractors.test.ts asserts the wire shapes an operator can produce,
// which is the contract the Go handler validates.

import type { SessionExtractFrom, SessionExtractHow, SessionExtraction } from "./types.policy";

/**
 * A saved history extractor. Identical to a session-rule extraction on the wire — `{ name, from?,
 * how }` — because the server decodes both with the same type. `from` absent means the body.
 */
export type HistoryExtractor = SessionExtraction;

/** The server's own bounds (internal/web/api_history_extractors.go). Mirrored so the console can
 *  say "no" before the round trip, while still relying on the server's 400 for the real refusal. */
export const MAX_HISTORY_EXTRACTORS = 32; // maxHistoryExtractors
export const MAX_EXTRACT_ROWS = 1000; // maxHistoryExtractRows — one /extract call cannot exceed this

/**
 * One extractor as the manager's form edits it: the two wire unions flattened into plain fields so
 * every part an operator changes is a real control instead of a JSON blob. Mirrors session.tsx's
 * ExtractDraft exactly.
 */
export interface ExtractorDraft {
 name: string;
 fromKind: "body" | "header";
 header: string;
 how: "regex" | "json_path" | "whole";
 pattern: string;
 /** Blank means the server's default of 1 (the first capture), not group 0. */
 group: string;
}

export function emptyExtractorDraft(): ExtractorDraft {
 return { name: "", fromKind: "body", header: "", how: "regex", pattern: "", group: "1" };
}

/** Wire -> draft. Mirrors session.tsx's extractionIn. */
export function extractorToDraft(extractor: HistoryExtractor): ExtractorDraft {
 const from: SessionExtractFrom = extractor.from ?? "body";
 const how = extractor.how;
 const draft: ExtractorDraft = {
  name: extractor.name,
  fromKind: typeof from === "object" ? "header" : "body",
  header: typeof from === "object" ? from.header : "",
  how: "regex",
  pattern: "",
  group: "1",
 };
 if (how === "whole") draft.how = "whole";
 else if ("json_path" in how) {
  draft.how = "json_path";
  draft.pattern = how.json_path;
 } else {
  draft.pattern = how.regex.pattern;
  draft.group = String(how.regex.group ?? 1);
 }
 return draft;
}

/** Draft -> wire. Mirrors session.tsx's extractionOut. The name is trimmed here, so a stray space
 *  cannot make two columns the operator reads as one name collide on the server. */
export function draftToExtractor(draft: ExtractorDraft): HistoryExtractor {
 const from: SessionExtractFrom = draft.fromKind === "header" ? { header: draft.header.trim() } : "body";
 let how: SessionExtractHow;
 if (draft.how === "whole") how = "whole";
 else if (draft.how === "json_path") how = { json_path: draft.pattern };
 else {
  // Blank, non-integer or negative all fall back to the server's default of 1 (the first capture).
  // A blank string is called out because `Number("")` is 0, not NaN — so a left-empty group box
  // would otherwise send group 0 (the whole match), which is not what "leave it to default" means.
  const trimmed = draft.group.trim();
  const parsed = Number(trimmed);
  const group = trimmed !== "" && Number.isInteger(parsed) && parsed >= 0 ? parsed : 1;
  how = { regex: { pattern: draft.pattern, group } };
 }
 return { name: draft.name.trim(), from, how };
}

/**
 * The table column id for an extractor, namespaced so a user-chosen name can never collide with a
 * built-in column id (a `status` or `path` extractor must not shadow those columns) and so the
 * persisted visibility/order keys for derived columns are distinguishable from the fixed ones.
 */
export function extractorColumnId(name: string): string {
 return `extractor:${name}`;
}

/**
 * A stable signature of the saved set, used as part of the value cache key: when the definitions
 * change, the cached values are no longer about the current columns and must be refetched. Order is
 * part of the signature because the column order follows it.
 */
export function extractorSignature(extractors: readonly HistoryExtractor[]): string {
 return JSON.stringify(extractors);
}

/**
 * Light client-side validation that mirrors the server's 400s (empty name, duplicate name, too
 * many). It exists to give an instant, inline answer on the obvious mistakes; the server's 400 is
 * still the authority — a bad regex or an unsupported JSON-path construct is only caught there, and
 * its message is what the manager shows. Returns a human message, or null when the drafts look
 * saveable.
 */
export function validateDrafts(drafts: readonly ExtractorDraft[]): string | null {
 if (drafts.length > MAX_HISTORY_EXTRACTORS) {
  return `Too many extractors: at most ${MAX_HISTORY_EXTRACTORS} columns.`;
 }
 const seen = new Set<string>();
 for (const draft of drafts) {
  const name = draft.name.trim();
  if (name === "") return "An extractor needs a name to be a column.";
  if (seen.has(name)) return `Two extractors are named "${name}"; a column name must be unique.`;
  seen.add(name);
  if (draft.fromKind === "header" && draft.header.trim() === "") {
   return `"${name}" reads from a header with no name.`;
  }
  if (draft.how === "regex" && draft.pattern.trim() === "") {
   return `"${name}" extracts by a regex but has no pattern.`;
  }
  if (draft.how === "json_path" && draft.pattern.trim() === "") {
   return `"${name}" extracts by a JSON path but has no path.`;
  }
 }
 return null;
}
