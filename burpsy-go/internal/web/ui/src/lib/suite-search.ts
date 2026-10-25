import type { Exchange } from "./types";

/**
 * Burp's suite-wide Search dialog (burpsy-react-ui-vs9k).
 *
 * The pure half of the feature lives here so the parts that can be wrong without a server — how a
 * form becomes a query string, which bytes get highlighted, what the header claims was searched —
 * are testable on their own. The component renders; this decides.
 */

/** Burp's request-versus-response axis. */
export type SearchLocation = "both" | "request" | "response";
/** Burp's headers-versus-body axis. "headers" is the whole head, request/status line included. */
export type SearchArea = "both" | "headers" | "body";

/** One entry of the endpoint's tool vocabulary. Served, never hardcoded here — see below. */
export interface SearchTool {
 id: string;
 label: string;
}

export interface SearchOptions {
 term: string;
 caseSensitive: boolean;
 regex: boolean;
 negate: boolean;
 inScope: boolean;
 location: SearchLocation;
 area: SearchArea;
 /** Empty means every tool, which is the dialog's opening state. */
 tools: string[];
}

/** One match location. `offset`/`len` index the bytes `/api/message/{message_id}` returns. */
export interface SearchMatch {
 direction: "request" | "response";
 area: "headers" | "body";
 message_id: number;
 offset: number;
 len: number;
}

/**
 * A result row is an Exchange plus what the search found in it.
 *
 * Composed rather than re-declared, because the results table has the same columns as the history
 * table (Source/Host/URL/Status/Length/Time) and a second row shape would be a second thing to keep
 * in step with the first — the console already knows how to render an Exchange everywhere else.
 */
export type SearchResult = Exchange & {
 organizer: boolean;
 match_count: number;
 matches: SearchMatch[];
 matches_truncated: boolean;
};

export interface SearchResponse {
 term: string;
 /** Exchanges the scan examined, so "no matches" is distinguishable from "nothing was looked at". */
 scanned: number;
 returned: number;
 /** True when the scan stopped at the limit with traffic left unexamined. */
 truncated: boolean;
 negate: boolean;
 /** The selection that ran, echoed. Empty means every tool. */
 tools: string[];
 /** The vocabulary the endpoint accepts. Rendered from this, so the dialog cannot offer a tool the
  *  server would refuse — the same reason the session tools-scope checklist is served. */
 tool_options: SearchTool[];
 results: SearchResult[];
}

export const EMPTY_SEARCH_OPTIONS: SearchOptions = {
 term: "",
 caseSensitive: false,
 regex: false,
 negate: false,
 inScope: false,
 location: "both",
 area: "both",
 tools: [],
};

/**
 * Turn the dialog's form into the endpoint's query string (without the leading `?`).
 *
 * Defaults are omitted rather than sent, so the URL a user sees in devtools reads as the search that
 * actually ran. The term is always sent — including when it is blank, where the endpoint answers
 * with the tool vocabulary and no results rather than an error.
 */
export function buildSearchQuery(options: SearchOptions): string {
 const params = new URLSearchParams();
 params.set("q", options.term);
 if (options.caseSensitive) params.set("case", "1");
 if (options.regex) params.set("regex", "1");
 if (options.negate) params.set("negate", "1");
 if (options.inScope) params.set("in_scope", "1");
 if (options.location !== "both") params.set("location", options.location);
 if (options.area !== "both") params.set("area", options.area);
 if (options.tools.length > 0) params.set("tools", [...options.tools].sort().join(","));
 return params.toString();
}

/**
 * What the header says was searched.
 *
 * Stated rather than implied: the results below are only interpretable against the filters that
 * produced them, and a dialog whose options scroll out of view would otherwise leave a short result
 * list looking like a short answer.
 */
export function describeSearch(options: SearchOptions): string {
 const modes = [options.regex ? "regular expression" : "literal text"];
 modes.push(options.caseSensitive ? "case sensitive" : "case insensitive");
 if (options.negate) modes.push("negative matches");
 if (options.inScope) modes.push("in scope only");

 const where = options.location === "both" ? "requests and responses" : `${options.location}s`;
 const area = options.area === "both" ? "headers and bodies" : options.area;
 const tools = options.tools.length > 0 ? options.tools.join(", ") : "every tool";

 return `${modes.join(", ")} — ${where}, ${area}, across ${tools}`;
}

/** A slice of a message to render, and whether anything was left out of either end. */
export interface MessageWindow {
 start: number;
 end: number;
 leading: boolean;
 trailing: boolean;
}

/**
 * The part of a message worth showing around a match.
 *
 * A preview pane cannot render a message that is not there, and rendering all of one to highlight
 * four bytes is how a 40 MB response locks up the tab. So the window is bounded, and whether either
 * end was cut is returned rather than implied — a truncated preview that does not say it is
 * truncated shows a request's opening as though it were the whole request.
 */
export function matchWindow(offset: number, length: number, total: number, radius = 2000): MessageWindow {
 const size = Math.max(1, length) + radius * 2;
 if (total <= size) return { start: 0, end: total, leading: false, trailing: false };
 let start = Math.max(0, offset - radius);
 const end = Math.min(total, start + size);
 // Re-anchor after clamping the end, so the window keeps its size at the tail of a message.
 start = Math.max(0, end - size);
 return { start, end, leading: start > 0, trailing: end < total };
}

/** A run of message text, either matched or not. */
export interface HighlightSegment {
 text: string;
 hit: boolean;
}

/**
 * Split a rendered window into plain and matched runs.
 *
 * The offsets come from the server, which is the whole point: the console must not re-run its own
 * matcher over the text it fetched and hope the two dialects agree. A JavaScript `RegExp` and Go's
 * `regexp` do not accept quite the same patterns, so a client-side re-match could highlight bytes
 * the server never matched — showing a match count and a highlight that disagree about the same
 * response.
 *
 * Spans are clipped to the window and to each other: overlapping highlights were impossible from
 * this endpoint (matches are non-overlapping) but a highlight covering the same byte twice is a
 * rendering artefact either way, so the later span is dropped rather than doubled.
 */
export function highlightSegments(text: string, windowStart: number, matches: SearchMatch[]): HighlightSegment[] {
 const spans = matches
  .map((match) => ({
   // Clamped to the window at both ends before anything is sliced: an unclamped negative start
   // reaches String.slice as a from-the-end index, which highlights a run of bytes at the *tail*
   // of the pane that the server never matched.
   start: Math.max(0, match.offset - windowStart),
   end: Math.min(text.length, match.offset - windowStart + match.len),
  }))
  .filter((span) => span.end > 0 && span.start < text.length && span.end > span.start)
  .sort((a, b) => a.start - b.start);

 const out: HighlightSegment[] = [];
 let cursor = 0;
 for (const span of spans) {
  if (span.start < cursor) continue;
  if (span.start > cursor) out.push({ text: text.slice(cursor, span.start), hit: false });
  out.push({ text: text.slice(span.start, span.end), hit: true });
  cursor = span.end;
 }
 if (cursor < text.length) out.push({ text: text.slice(cursor), hit: false });
 return out;
}

/**
 * The match a preview should open at: the first one, in the order the server reported.
 *
 * Not "the best" match — there is no such ranking, and a pane that jumped to whichever match a
 * heuristic preferred would make the row's count unexplainable.
 */
export function firstMatch(result: SearchResult): SearchMatch | null {
 const [first] = result.matches;
 return first ?? null;
}

/** How a row's match count reads. Truncation is stated, never rounded away into "200+". */
export function matchCountLabel(result: SearchResult): string {
 if (result.match_count === 0) return "0";
 if (result.matches_truncated) return `${result.matches.length} of ${result.match_count}`;
 return `${result.match_count}`;
}
