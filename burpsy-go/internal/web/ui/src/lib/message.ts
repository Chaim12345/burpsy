/**
 * Raw HTTP message parsing, shared by the editor's Pretty/Hex views and the
 * Inspector. Everything here works on the exact bytes the server captured — it
 * never re-serialises a message, because the whole point of a proxy tool is that
 * what you see is what went over the wire.
 *
 * The second half of the file writes messages, for the editable Inspector. The
 * rule that makes reading trustworthy is what makes writing hard: an edit to one
 * header must not reflow the rest of the message. So every writer here SPLICES a
 * span of the original string and leaves every byte outside that span alone.
 * Nothing is ever rebuilt from the parsed form.
 */

/** A half-open region of a raw message: `[start, end)` in string-index terms. */
export interface Span {
 start: number;
 end: number;
}

export interface ParsedMessage {
 startLine: string;
 headers: [string, string][];
 body: string;
 /** Byte offset in the original string where the body begins. */
 bodyOffset: number;
}

/** Where the head stops and the body starts. Shared so every function agrees on the boundary. */
function headBounds(raw: string): { headEnd: number; bodyOffset: number } {
 const separator = /\r?\n\r?\n/.exec(raw);
 if (!separator) return { headEnd: raw.length, bodyOffset: raw.length };
 return { headEnd: separator.index, bodyOffset: separator.index + separator[0].length };
}

/**
 * Index of the end of the line's *content* starting at `from`: the LF, or the CR
 * of a CRLF, or `limit`. Deliberately blind to a lone CR so this agrees exactly
 * with `split(/\r?\n/)`, which the previous parser used.
 */
function lineEnd(raw: string, from: number, limit: number): number {
 const newline = raw.indexOf("\n", from);
 const stop = newline < 0 || newline > limit ? limit : newline;
 return stop > from && raw.charCodeAt(stop - 1) === 13 ? stop - 1 : stop;
}

/** Index just past the line ending that begins at `at`, or `at` when there is none. */
function skipEol(raw: string, at: number): number {
 if (raw.charCodeAt(at) === 13 && raw.charCodeAt(at + 1) === 10) return at + 2;
 const code = raw.charCodeAt(at);
 return code === 13 || code === 10 ? at + 1 : at;
}

/** Index where the line ending immediately *before* `at` begins, or `at` when there is none. */
function eolStart(raw: string, at: number): number {
 if (raw.charCodeAt(at - 1) !== 10) return at;
 return raw.charCodeAt(at - 2) === 13 ? at - 2 : at - 1;
}

export interface HeaderSpan extends Span {
 name: string;
 value: string;
}

/**
 * Every header line, with the exact region it occupies.
 *
 * `parseMessage` derives its `headers` from this, which is the point: index `i`
 * of `parsed.headers` is index `i` here, by construction rather than by two
 * scanners happening to skip the same lines. An Inspector row that wrote to the
 * wrong header because the two disagreed about a continuation line would be a
 * silent corruption of the message being sent.
 */
export function headerSpans(raw: string): HeaderSpan[] {
 const { headEnd } = headBounds(raw);
 const out: HeaderSpan[] = [];
 let cursor = skipEol(raw, lineEnd(raw, 0, headEnd));
 while (cursor < headEnd) {
  const start = cursor;
  const end = lineEnd(raw, start, headEnd);
  const line = raw.slice(start, end);
  const colon = line.indexOf(":");
  if (colon > 0) out.push({ name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim(), start, end });
  cursor = skipEol(raw, end);
  if (cursor <= start) break;
 }
 return out;
}

export function parseMessage(raw: string): ParsedMessage {
 const { headEnd, bodyOffset } = headBounds(raw);
 return {
  startLine: raw.slice(0, lineEnd(raw, 0, headEnd)),
  headers: headerSpans(raw).map(({ name, value }) => [name, value] as [string, string]),
  body: raw.slice(bodyOffset),
  bodyOffset,
 };
}

export function headerValue(headers: [string, string][], name: string): string | undefined {
 const wanted = name.toLowerCase();
 return headers.find(([key]) => key.toLowerCase() === wanted)?.[1];
}

export interface RequestLine {
 method: string;
 target: string;
 version: string;
}

export function parseRequestLine(startLine: string): RequestLine | null {
 const parts = startLine.trim().split(/\s+/);
 if (parts.length < 2) return null;
 return { method: parts[0] ?? "", target: parts[1] ?? "", version: parts[2] ?? "" };
}

export interface StatusLine {
 version: string;
 status: number;
 reason: string;
}

export function parseStatusLine(startLine: string): StatusLine | null {
 const match = /^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)$/.exec(startLine.trim());
 if (!match) return null;
 return { version: match[1] ?? "", status: Number(match[2]), reason: match[3] ?? "" };
}

export function isResponse(raw: string): boolean {
 return /^HTTP\/[\d.]+\s+\d{3}/.test(raw.trimStart());
}

/** A name/value pair together with the region of the raw message it came from. */
export interface PairSpan extends Span {
 name: string;
 value: string;
 /**
  * How the region is written, when writing it back needs to know. A JSON member
  * is `"key": value` and its value keeps its type; a query or cookie pair is
  * `name=value` and everything in it is text.
  */
 form?: "json";
 /** A JSON member's value exactly as it is written, so a number can stay a number. */
 source?: string;
}

/**
 * Name/value pairs of an "&"-separated string, each with the span it occupies.
 * `offset` shifts the spans into the coordinates of the message the string came from.
 */
export function pairSpans(input: string, offset = 0): PairSpan[] {
 const out: PairSpan[] = [];
 let cursor = 0;
 while (cursor <= input.length) {
  const found = input.indexOf("&", cursor);
  const stop = found < 0 ? input.length : found;
  if (stop > cursor) {
   const chunk = input.slice(cursor, stop);
   const equals = chunk.indexOf("=");
   out.push({
    name: safeDecode(equals < 0 ? chunk : chunk.slice(0, equals)),
    value: equals < 0 ? "" : safeDecode(chunk.slice(equals + 1)),
    start: offset + cursor,
    end: offset + stop,
   });
  }
  cursor = stop + 1;
 }
 return out;
}

/** Name/value pairs from a query string or an urlencoded body. */
export function parsePairs(input: string): [string, string][] {
 return pairSpans(input).map(({ name, value }) => [name, value] as [string, string]);
}

function safeDecode(input: string): string {
 try {
  return decodeURIComponent(input.replace(/\+/g, " "));
 } catch {
  return input;
 }
}

export function queryOf(target: string): [string, string][] {
 const mark = target.indexOf("?");
 if (mark < 0) return [];
 const hash = target.indexOf("#", mark);
 return parsePairs(target.slice(mark + 1, hash < 0 ? undefined : hash));
}

/** Request cookies come from one Cookie header; response cookies from each Set-Cookie. */
export function cookiesOf(headers: [string, string][], response: boolean): [string, string][] {
 if (response) {
  return headers
   .filter(([name]) => name.toLowerCase() === "set-cookie")
   .map(([, value]) => {
    const first = value.split(";")[0] ?? "";
    const equals = first.indexOf("=");
    return equals < 0 ? [first.trim(), ""] : [first.slice(0, equals).trim(), first.slice(equals + 1).trim()];
   });
 }
 const jar = headerValue(headers, "cookie");
 if (!jar) return [];
 return jar
  .split(";")
  .map((chunk) => {
   const equals = chunk.indexOf("=");
   return equals < 0
    ? ([chunk.trim(), ""] as [string, string])
    : ([chunk.slice(0, equals).trim(), chunk.slice(equals + 1).trim()] as [string, string]);
  })
  .filter(([name]) => name !== "");
}

/**
 * Body parameters and the region each occupies, in one implementation so the row
 * an operator edits and the bytes that get rewritten cannot drift apart.
 *
 * They could drift, and it would be invisible: `Object.entries` reorders
 * integer-like keys ahead of the rest regardless of how the JSON was written, so
 * rows from `Object.entries` and spans from the source text disagree about which
 * member is row 0 for `{"b":1,"2":2}`. Reading the rows off the spans removes the
 * possibility rather than documenting it.
 */
function bodyParamSpansIn(body: string, contentType: string | undefined, offset: number): PairSpan[] {
 if (!body.trim()) return [];
 const type = (contentType ?? "").toLowerCase();
 if (type.includes("application/x-www-form-urlencoded")) {
  const lead = body.length - body.trimStart().length;
  return pairSpans(body.trim(), offset + lead);
 }
 if (type.includes("json")) {
  return jsonMemberSpans(body, offset).map(({ name, source, start, end }) => ({
   name,
   value: jsonDisplay(source),
   form: "json" as const,
   source,
   start,
   end,
  }));
 }
 return [];
}

export function bodyParamsOf(body: string, contentType: string | undefined): [string, string][] {
 return bodyParamSpansIn(body, contentType, 0).map(({ name, value }) => [name, value] as [string, string]);
}

/** Body parameters of a whole message, with spans in the message's own coordinates. */
export function bodyParamSpans(raw: string): PairSpan[] {
 const { headers, body, bodyOffset } = parseMessage(raw);
 return bodyParamSpansIn(body, headerValue(headers, "content-type"), bodyOffset);
}

/**
 * Whether body parameters can be written back into this message. Urlencoded and
 * JSON bodies can; a multipart or binary body cannot, and the Inspector says so
 * rather than offering a field that would do nothing.
 */
export function bodyParamsEditable(raw: string): boolean {
 const type = (headerValue(parseMessage(raw).headers, "content-type") ?? "").toLowerCase();
 return type.includes("application/x-www-form-urlencoded") || type.includes("json");
}

/** A JSON member's value as text: the decoded string for a string, the source otherwise. */
function jsonDisplay(source: string): string {
 if (!source.startsWith('"')) return source;
 try {
  return JSON.parse(source) as string;
 } catch {
  return source;
 }
}

/**
 * Reformats only the body, leaving the head byte-identical. JSON is re-indented;
 * XML and HTML get one tag per line. Anything else is returned untouched rather
 * than mangled by a guess.
 */
export function prettyMessage(raw: string): string {
 const { startLine, headers, body, bodyOffset } = parseMessage(raw);
 if (!body.trim()) return raw;
 const type = (headerValue(headers, "content-type") ?? "").toLowerCase();
 let pretty: string | null = null;

 if (type.includes("json") || looksLikeJson(body)) {
  try {
   pretty = JSON.stringify(JSON.parse(body), null, 2);
   // JSON has no text nodes, so compactMessage rebuilds it whole and the separator never reaches the wire.
   if (raw.includes("\r\n")) pretty = pretty.replace(/\n/g, "\r\n");
  } catch {
   pretty = null;
  }
 } else if (type.includes("xml") || type.includes("html") || /^\s*<[a-z!?]/i.test(body)) {
  pretty = prettyMarkup(body, raw.includes("\r\n") ? "\r\n" : "\n");
 } else if (type.includes("css") || looksLikeCss(body)) {
  pretty = prettyCss(body);
 } else if (type.includes("javascript") || type.includes("ecmascript") || looksLikeJs(body)) {
  pretty = prettyJs(body);
 }

 if (pretty === null) return raw;
 void startLine;
 // The editor splits a document on one separator, CRLF whenever the message holds one, so a JSON body
 // pretty-printed with bare LFs under a CRLF head would show as one line; it takes the head's separator
 // above (PR 363 review). Markup takes it only at the tag breaks prettyMarkup inserts, so a text node's
// own newlines are never rewritten; CSS and JS keep LF, since their write-back keeps the pretty text.
 return raw.slice(0, bodyOffset) + pretty;
}

/** A CSS body: the text IS one when it looks like rules, so a text/css label is not required. */
function looksLikeCss(body: string): boolean {
 return /[{]\s*[-a-zA-Z]+\s*:/.test(body) || /[}][^{}]*[{]/.test(body);
}

/** A JavaScript body: sniffed from statements, since a label is often missing on responses. */
function looksLikeJs(body: string): boolean {
 const trimmed = body.trim();
 return /\b(function|var|let|const|if|for|while|return|=>)\b/.test(trimmed) && !trimmed.startsWith("<");
}

/**
 * CSS: one declaration per line, two-space indented inside its block. Selectors are kept
 * verbatim — reformatting one would change what the document says.
 */
function prettyCss(body: string): string {
 return (
  body
   .replace(/\s*{\s*/g, " {\n  ")
   .replace(/;\s*(?=[^\s}])/g, ";\n  ")
   .replace(/\s*}\s*/g, "\n}\n")
   .replace(/\n\s*\n/g, "\n")
   .trim() + "\n"
 );
}

/**
 * JavaScript: one statement per line where the break is safe — after `;` and `{`/`}` that
 * are not inside a string literal. Statements are never re-indented (a guess that changes
 * indentation changes nothing the bytes say, and can break a template literal's meaning).
 */
function prettyJs(body: string): string {
 let out = "";
 let i = 0;
 const n = body.length;
 while (i < n) {
  const ch = body[i]!;
  if (ch === '"' || ch === "'" || ch === "`") {
   let j = i + 1;
   while (j < n && body[j] !== ch) {
    if (body[j] === "\\") j += 1;
    j += 1;
   }
   out += body.slice(i, Math.min(j + 1, n));
   i = Math.min(j + 1, n);
   continue;
  }
  if (ch === "/" && body[i + 1] === "/") {
   const end = body.indexOf("\n", i);
   out += body.slice(i, end < 0 ? n : end);
   i = end < 0 ? n : end;
   continue;
  }
  out += ch;
  if ((ch === ";" || ch === "{" || ch === "}") && body[i + 1] !== "\n") out += "\n";
  i += 1;
 }
 return out;
}

function looksLikeJson(body: string): boolean {
 const trimmed = body.trim();
 return (trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"));
}

/**
 * The write-back half of prettyMessage: turns a possibly-edited Pretty view back
 * into the bytes that go on the wire (burpsy-react-ui-dmf).
 *
 * The head is kept exactly as the operator left it — Pretty never rewrites the
 * head, so any edit to it is a real edit to real bytes. Only the body is
 * compacted, and only by inverting what the formatter did: JSON is re-stringified
 * minified (a JSON parse failing means the operator is mid-edit, and their text
 * passes through unchanged — Raw then shows precisely what they typed, so nothing
 * is hidden), and markup collapses the exact `>` newline `<` breaks prettyMarkup
 * inserted, leaving text nodes that sit on their own lines untouched. Whatever
 * this returns becomes the message's value, so Raw, Hex and the send path all
 * agree with what the Pretty view showed.
 */
export function compactMessage(pretty: string): string {
 const { body, bodyOffset } = parseMessage(pretty);
 if (!body.trim()) return pretty;
 const trimmed = body.trim();
 if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
  try {
   return pretty.slice(0, bodyOffset) + JSON.stringify(JSON.parse(body));
  } catch {
   return pretty;
  }
 }
 return pretty.slice(0, bodyOffset) + body.replace(/>\r?\n\s*</g, "><");
}

/**
 * Indents markup with one break between tags: adjacent tags, and tags the body already separated with
 * a line break (the break and the whitespace around it are replaced). `sep` is the break it writes,
 * the message's own separator, so a CRLF response's Pretty view splits into lines in an editor that
 * splits on CRLF. A line break inside a text node keeps its own CR/LF; only the indentation around it
 * changes.
 */
function prettyMarkup(input: string, sep = "\n"): string {
 let depth = 0;
 const indent = (line: string) => {
  const trimmed = line.trim();
  if (/^<\/[^>]+>/.test(trimmed)) depth = Math.max(0, depth - 1);
  const indented = "  ".repeat(depth) + trimmed;
  const opens =
   /^<[^/!?][^>]*[^/]>$/.test(trimmed) && !/^<(area|base|br|col|embed|hr|img|input|link|meta|source|track|wbr)\b/i.test(trimmed);
  if (opens) depth += 1;
  return indented;
 };
 return input
  .split(/(?<=>)(?:[ \t]*\r?\n\s*)?(?=<)/)
  .map((part) =>
   part
    .split(/(\r?\n)/)
    .map((piece, i) => (i % 2 === 1 ? piece : indent(piece)))
    .join(""),
  )
  .join(sep);
}

/* ==== the message editor's hide-headers lists (burpsy-react-ui-whr) ========
 *
 * Burp keeps two editable lists under Settings > User interface > Message editor and an
 * eye button above each message that hides whatever they name, in the Pretty tab only.
 * The Burp-side keys are recoverable and were used as the shape here:
 * `user_options.misc.uninteresting_headers` (request),
 * `user_options.misc.uninteresting_response_headers` (response), and
 * `user_options.misc.uninteresting_headers.hide_uninteresting_headers_by_default`
 * (the master toggle) — burp.Zf4w / burp.Zhs4 / burp.Zblz in map_root.tsv. The default
 * *contents* of those lists are not recoverable from the evidence base (no literal in the
 * extracted strings, and the docs do not publish them), so the lists below are burpsy's
 * own starting sets, chosen from protocol-level noise, and the settings section is where
 * an operator replaces them. Claiming they were Burp's would be a fabricated citation.
 *
 * Deliberately NOT the Comparer's lists (Settings > Comparer: uninteresting headers).
 * Those name headers whose *differences* are dimmed in a diff and nothing is ever hidden
 * there. Two lists rather than one because the two answer different questions — "what do I
 * not want to read right now?" versus "what should not count as a difference?" — and one
 * list serving both would make the eye's behaviour change whenever someone tuned a diff.
 */

/** Request headers the eye hides out of the box: what the client's own stack adds to every
 *  request and no application behaviour lives in. */
export const DEFAULT_HIDE_REQUEST_HEADERS: string[] = ["accept", "accept-encoding", "accept-language", "connection"];

/** Response headers the eye hides out of the box: connection and framing bookkeeping, cache
 *  validators, and server metadata. Deliberately excludes `set-cookie` (a rotated session
 *  token can be the finding), `content-type`/`content-length` (a reader checking truncation
 *  or a mislabelled body needs them) and the security headers, which are findings-relevant. */
export const DEFAULT_HIDE_RESPONSE_HEADERS: string[] = [
 "cache-control",
 "connection",
 "content-security-policy-report-only",
 "date",
 "etag",
 "expires",
 "keep-alive",
 "last-modified",
 "pragma",
 "server",
 "transfer-encoding",
 "vary",
];

/**
 * Turn one textarea's contents into a list of header names.
 *
 * One name per line. A pasted whole header line (`Cache-Control: no-store`) is tolerated by
 * taking what precedes the colon, which is also what the server-side Comparer list does — an
 * operator who pastes a line and gets a silent no-match would conclude the setting is broken.
 * Names fold, so they are stored lower-cased (RFC 9110 §5.1); a duplicate is dropped rather
 * than hiding the same line twice.
 */
export function parseHeaderNames(text: string): string[] {
 const seen = new Set<string>();
 for (const line of text.split(/\r?\n/)) {
  const colon = line.indexOf(":");
  const name = (colon >= 0 ? line.slice(0, colon) : line).trim().toLowerCase();
  if (name !== "") seen.add(name);
 }
 return [...seen];
}

/**
 * Remove the named header lines from a message's head, for display.
 *
 * Pure, and it splices rather than rebuilding: every byte outside a dropped line is the byte
 * the server captured, so the start line, the surviving headers, their spacing and the body
 * come through untouched — the same discipline the editor's writers follow, for the same
 * reason (the Pretty view is the message, minus some lines).
 *
 * A dropped header takes any folded continuation lines with it: leaving an orphan
 * continuation behind would fold it onto the *previous* surviving header and change that
 * header's value, which is a silent corruption rather than a display filter.
 *
 * The message's own line ending is whatever the bytes say — this walks lines with the same
 * helpers `headerSpans` uses rather than splitting on `\r\n`, so an LF-only message filters
 * too.
 */
export function hideHeadersIn(raw: string, names: readonly string[]): string {
 const hidden = new Set(names.map((name) => name.trim().toLowerCase()).filter((name) => name !== ""));
 if (hidden.size === 0) return raw;
 const { headEnd, bodyOffset } = headBounds(raw);
 const drops: Span[] = [];
 for (const span of headerSpans(raw)) {
  if (!hidden.has(span.name.toLowerCase())) continue;
  // The line plus its terminator, then every folded continuation line after it: a
  // continuation belongs to the header above it, so leaving one behind would fold it onto
  // the previous surviving header and change that header's value.
  //
  // The advance is clamped at `bodyOffset`, not `headEnd`: the last header line's terminator
  // is the first CRLF of the blank-line separator, so stopping at `headEnd` would remove the
  // line's text and leave its terminator behind as an extra blank line. Clamping at
  // `bodyOffset` takes exactly that one terminator and leaves the separator's second CRLF —
  // the blank line that ends the head — intact.
  let stop = span.end;
  for (;;) {
   const next = Math.min(skipEol(raw, lineEnd(raw, stop, headEnd)), bodyOffset);
   if (next <= stop) break;
   stop = next;
   if (stop >= headEnd) break;
   const first = raw[stop];
   if (first !== " " && first !== "\t") break;
  }
  drops.push({ start: span.start, end: stop });
 }
 if (drops.length === 0) return raw;
 let out = "";
 let cursor = 0;
 for (const drop of drops) {
  out += raw.slice(cursor, drop.start);
  cursor = drop.end;
 }
 return out + raw.slice(cursor);
}

/** Classic 16-byte-per-line dump with an ASCII gutter, like Burp's Hex view. */
export function hexDump(input: string): string {
 return hexDumpBytes(new TextEncoder().encode(input));
}

/** hexDump over bytes the caller already holds. The charset work (burpsy-react-ui-p836) needs
 *  this: for a non-UTF-8 body `input` has already been through a UTF-8 round trip that replaced
 *  every byte >= 0x80 with U+FFFD, and re-encoding that string dumps EF BF BD triplets where the
 *  wire bytes belong — a hex view that lies about the bytes is worse than no hex view. */
export function hexDumpBytes(bytes: Uint8Array): string {
 const lines: string[] = [];
 for (let offset = 0; offset < bytes.length; offset += 16) {
  const slice = bytes.subarray(offset, offset + 16);
  const hex: string[] = [];
  let ascii = "";
  for (let i = 0; i < 16; i++) {
   const byte = slice[i];
   hex.push(byte === undefined ? "  " : byte.toString(16).padStart(2, "0"));
   if (byte !== undefined) ascii += byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".";
  }
  const left = hex.slice(0, 8).join(" ");
  const right = hex.slice(8).join(" ");
  lines.push(`${offset.toString(16).padStart(8, "0")}  ${left}  ${right}  |${ascii}|`);
 }
 return lines.length ? lines.join("\n") : "(empty)";
}

/** The body alone, for the Render view's sandboxed iframe. */
export function bodyOf(raw: string): string {
 return parseMessage(raw).body;
}

export function contentTypeOf(raw: string): string {
 return headerValue(parseMessage(raw).headers, "content-type") ?? "";
}

/* ==== the JSON scanner ====================================================
 *
 * A hand-rolled scanner rather than JSON.parse, because parse throws the
 * positions away and the positions are the whole point: writing one member back
 * by splicing its value leaves every other byte — key order, indentation, number
 * formatting, a trailing newline — exactly as the server wrote it.
 */

export interface JsonMemberSpan extends Span {
 name: string;
 /** The member's value exactly as written. */
 source: string;
}

function skipWhitespace(text: string, at: number): number {
 let cursor = at;
 while (cursor < text.length && /\s/.test(text[cursor]!)) cursor += 1;
 return cursor;
}

/** Index just past the JSON string literal starting at `at`, or -1 if there is not one. */
function endOfJsonString(text: string, at: number): number {
 if (text[at] !== '"') return -1;
 let cursor = at + 1;
 while (cursor < text.length) {
  const character = text[cursor];
  if (character === "\\") {
   cursor += 2;
   continue;
  }
  if (character === '"') return cursor + 1;
  cursor += 1;
 }
 return -1;
}

/** Index just past the JSON value starting at `at`, or -1 if it is unterminated. */
function endOfJsonValue(text: string, at: number): number {
 const first = text[at];
 if (first === '"') return endOfJsonString(text, at);
 if (first === "{" || first === "[") {
  let depth = 0;
  let cursor = at;
  while (cursor < text.length) {
   const character = text[cursor]!;
   if (character === '"') {
    const end = endOfJsonString(text, cursor);
    if (end < 0) return -1;
    cursor = end;
    continue;
   }
   if (character === "{" || character === "[") depth += 1;
   else if (character === "}" || character === "]") {
    depth -= 1;
    if (depth === 0) return cursor + 1;
   }
   cursor += 1;
  }
  return -1;
 }
 // A number, true, false or null: runs until a structural character or space.
 let cursor = at;
 while (cursor < text.length && !/[,}\]\s]/.test(text[cursor]!)) cursor += 1;
 return cursor > at ? cursor : -1;
}

/**
 * The top-level members of a JSON object, in the order they are written, each
 * span covering `"key": value` so one splice can rewrite either half.
 *
 * Returns nothing for input that is not a well-formed object — an array, a bare
 * scalar, a truncated body. Refusing to guess is the point: a partial parse would
 * hand the Inspector spans that no longer mean what they say.
 */
export function jsonMemberSpans(text: string, offset = 0): JsonMemberSpan[] {
 const out: JsonMemberSpan[] = [];
 let cursor = skipWhitespace(text, 0);
 if (text[cursor] !== "{") return [];
 cursor = skipWhitespace(text, cursor + 1);
 while (cursor < text.length && text[cursor] !== "}") {
  const start = cursor;
  const keyEnd = endOfJsonString(text, cursor);
  if (keyEnd < 0) return [];
  let name: string;
  try {
   name = JSON.parse(text.slice(cursor, keyEnd)) as string;
  } catch {
   return [];
  }
  cursor = skipWhitespace(text, keyEnd);
  if (text[cursor] !== ":") return [];
  cursor = skipWhitespace(text, cursor + 1);
  const valueEnd = endOfJsonValue(text, cursor);
  if (valueEnd < 0) return [];
  out.push({ name, source: text.slice(cursor, valueEnd), start: offset + start, end: offset + valueEnd });
  cursor = skipWhitespace(text, valueEnd);
  if (text[cursor] !== ",") break;
  cursor = skipWhitespace(text, cursor + 1);
 }
 return out;
}

/* ==== writing ==============================================================
 *
 * Each function takes the whole message and returns the whole message. They are
 * indexed by position in the corresponding reader's output — `setHeaderAt(raw, 2,
 * …)` writes the header `parseMessage(raw).headers[2]` describes — and each one
 * re-derives its spans from the string it is given, so they compose: the output
 * of one is a valid input to the next.
 */

function splice(raw: string, span: Span, text: string): string {
 return raw.slice(0, span.start) + text + raw.slice(span.end);
}

/**
 * CR and LF in a header name or value would inject a second header, or end the
 * head early and turn the rest of the request into a body. HTTP/1 has no escape
 * for them, so they are removed rather than encoded.
 */
function oneLine(input: string): string {
 return input.replace(/[\r\n]+/g, "");
}

/** The line ending this message uses, so an inserted line matches the rest of it. */
export function eolOf(raw: string): "\r\n" | "\n" {
 const newline = raw.indexOf("\n");
 if (newline < 0) return "\r\n";
 return newline > 0 && raw.charCodeAt(newline - 1) === 13 ? "\r\n" : "\n";
}

export function byteLength(input: string): number {
 return new TextEncoder().encode(input).length;
}

/* ---- the start line ------------------------------------------------------ */

/** The whitespace-separated tokens of the start line: method, target, version — or version, status. */
export function startLineSpans(raw: string): Span[] {
 const { headEnd } = headBounds(raw);
 const end = lineEnd(raw, 0, headEnd);
 const spans: Span[] = [];
 let cursor = 0;
 const space = (at: number) => raw.charCodeAt(at) === 32 || raw.charCodeAt(at) === 9;
 while (cursor < end) {
  while (cursor < end && space(cursor)) cursor += 1;
  if (cursor >= end) break;
  const start = cursor;
  while (cursor < end && !space(cursor)) cursor += 1;
  spans.push({ start, end: cursor });
 }
 return spans;
}

/**
 * Replace one token of the start line. Splicing the token rather than rebuilding
 * the line preserves the original spacing, which a request crafted to exercise a
 * parser may depend on.
 */
export function setStartLineToken(raw: string, index: number, text: string): string {
 const spans = startLineSpans(raw);
 const clean = oneLine(text).replace(/\s+/g, "");
 const span = spans[index];
 if (span) return splice(raw, span, clean);
 // A start line short of that field gets it appended, so setting a version on a
 // two-token request line adds one instead of silently doing nothing.
 if (index !== spans.length) return raw;
 const end = lineEnd(raw, 0, headBounds(raw).headEnd);
 return `${raw.slice(0, end)} ${clean}${raw.slice(end)}`;
}

/**
 * Replace everything from the `index`th start-line token to the end of the line.
 * For a response's reason phrase, which is the one start-line field allowed to
 * contain spaces.
 */
export function setStartLineTail(raw: string, index: number, text: string): string {
 const end = lineEnd(raw, 0, headBounds(raw).headEnd);
 const span = startLineSpans(raw)[index];
 const clean = oneLine(text);
 if (!span) return `${raw.slice(0, end)}${clean === "" ? "" : ` ${clean}`}${raw.slice(end)}`;
 return raw.slice(0, span.start) + clean + raw.slice(end);
}

/* ---- headers ------------------------------------------------------------- */

export function setHeaderAt(raw: string, index: number, name: string, value: string): string {
 const span = headerSpans(raw)[index];
 if (!span) return raw;
 return splice(raw, span, `${oneLine(name)}: ${oneLine(value)}`);
}

export function removeHeaderAt(raw: string, index: number): string {
 const span = headerSpans(raw)[index];
 if (!span) return raw;
 // The line ending that goes with a header is the one BEFORE it. The last
 // header's own terminator is the first half of the blank-line separator, so
 // taking the following one instead would merge the head into the body.
 return raw.slice(0, eolStart(raw, span.start)) + raw.slice(span.end);
}

/** Append a header to the end of the head, using the message's own line ending. */
export function addHeader(raw: string, name: string, value: string): string {
 const { headEnd } = headBounds(raw);
 return `${raw.slice(0, headEnd)}${eolOf(raw)}${oneLine(name)}: ${oneLine(value)}${raw.slice(headEnd)}`;
}

/* ---- the body, and the length that has to agree with it ------------------ */

/**
 * Make Content-Length tell the truth about the body that is actually there.
 *
 * Corrected when the header exists, and ADDED when a body arrives at a message
 * that declared none — a body the framing does not announce is a body the peer
 * will not read, which is a worse surprise than an extra header. Left alone
 * entirely when Transfer-Encoding is present: there the chunk framing owns the
 * length, and a Content-Length beside it is the shape of a smuggling request
 * rather than a correction.
 */
export function fixContentLength(raw: string): string {
 const { headers, body } = parseMessage(raw);
 if (headerValue(headers, "transfer-encoding") !== undefined) return raw;
 const length = String(byteLength(body));
 const index = headers.findIndex(([name]) => name.toLowerCase() === "content-length");
 if (index >= 0) {
  const existing = headers[index]!;
  return existing[1] === length ? raw : setHeaderAt(raw, index, existing[0], length);
 }
 return body === "" ? raw : addHeader(raw, "Content-Length", length);
}

/** Replace the body, keeping the head byte-identical apart from Content-Length. */
export function setBody(raw: string, body: string): string {
 const { headEnd, bodyOffset } = headBounds(raw);
 const separator = raw.slice(headEnd, bodyOffset) || eolOf(raw).repeat(2);
 return fixContentLength(`${raw.slice(0, headEnd)}${separator}${body}`);
}

/* ---- query parameters ---------------------------------------------------- */

/**
 * Re-encode a name or value that `parsePairs` decoded. Not byte-identical for a
 * pair that was written with `+` for space — `a+b` comes back as `a%20b` — but
 * only ever applied to the one pair the operator edited, so nothing they did not
 * touch changes shape.
 */
function encodePair(input: string): string {
 return encodeURIComponent(input);
}

/** Where the request target's query string lives, excluding the "?" and any fragment. */
export function querySpan(raw: string): Span | null {
 const target = startLineSpans(raw)[1];
 if (!target) return null;
 const text = raw.slice(target.start, target.end);
 const mark = text.indexOf("?");
 if (mark < 0) return null;
 const hash = text.indexOf("#", mark);
 return { start: target.start + mark + 1, end: hash < 0 ? target.end : target.start + hash };
}

export function querySpans(raw: string): PairSpan[] {
 const span = querySpan(raw);
 return span ? pairSpans(raw.slice(span.start, span.end), span.start) : [];
}

export function setQueryParamAt(raw: string, index: number, name: string, value: string): string {
 const span = querySpans(raw)[index];
 if (!span) return raw;
 return splice(raw, span, `${encodePair(name)}=${encodePair(value)}`);
}

export function removeQueryParamAt(raw: string, index: number): string {
 const spans = querySpans(raw);
 const span = spans[index];
 if (!span) return raw;
 // The separator goes with the parameter, so removing one never leaves "a=1&&c=3".
 if (index > 0) return raw.slice(0, spans[index - 1]!.end) + raw.slice(span.end);
 if (spans.length > 1) return raw.slice(0, span.start) + raw.slice(spans[1]!.start);
 // The last parameter takes the "?" with it, leaving a bare path.
 const query = querySpan(raw)!;
 return raw.slice(0, query.start - 1) + raw.slice(query.end);
}

export function addQueryParam(raw: string, name: string, value: string): string {
 const pair = `${encodePair(name)}=${encodePair(value)}`;
 const query = querySpan(raw);
 if (query) return `${raw.slice(0, query.end)}${query.end > query.start ? "&" : ""}${pair}${raw.slice(query.end)}`;
 const target = startLineSpans(raw)[1];
 if (!target) return raw;
 const hash = raw.slice(target.start, target.end).indexOf("#");
 const at = hash < 0 ? target.end : target.start + hash;
 return `${raw.slice(0, at)}?${pair}${raw.slice(at)}`;
}

/* ---- request cookies ----------------------------------------------------- */

/**
 * Request cookies with the span each occupies inside the Cookie header.
 *
 * Mirrors `cookiesOf(headers, false)` exactly, including its rule that a segment
 * whose name is empty is not a cookie. `message.test.ts` asserts the two agree.
 */
export function cookieSpans(raw: string): PairSpan[] {
 const header = headerSpans(raw).find(({ name }) => name.toLowerCase() === "cookie");
 if (!header) return [];
 const line = raw.slice(header.start, header.end);
 const colon = line.indexOf(":");
 const base = header.start + colon + 1;
 const jar = line.slice(colon + 1);
 const out: PairSpan[] = [];
 let cursor = 0;
 while (cursor <= jar.length) {
  const found = jar.indexOf(";", cursor);
  const stop = found < 0 ? jar.length : found;
  const chunk = jar.slice(cursor, stop);
  const equals = chunk.indexOf("=");
  const name = (equals < 0 ? chunk : chunk.slice(0, equals)).trim();
  if (name !== "") {
   const lead = chunk.length - chunk.trimStart().length;
   out.push({
    name,
    value: equals < 0 ? "" : chunk.slice(equals + 1).trim(),
    start: base + cursor + lead,
    end: base + cursor + lead + chunk.trim().length,
   });
  }
  cursor = stop + 1;
 }
 return out;
}

/** A ";" would split one cookie into two, so it goes the way CR and LF do. */
function oneCookie(input: string): string {
 return input.replace(/[\r\n;]+/g, "");
}

export function setCookieAt(raw: string, index: number, name: string, value: string): string {
 const span = cookieSpans(raw)[index];
 if (!span) return raw;
 return splice(raw, span, `${oneCookie(name)}=${oneCookie(value)}`);
}

export function removeCookieAt(raw: string, index: number): string {
 const spans = cookieSpans(raw);
 const span = spans[index];
 if (!span) return raw;
 if (index > 0) return raw.slice(0, spans[index - 1]!.end) + raw.slice(span.end);
 if (spans.length > 1) return raw.slice(0, span.start) + raw.slice(spans[1]!.start);
 // The last cookie takes the header with it: an empty `Cookie:` is not a jar.
 const header = headerSpans(raw).findIndex(({ name }) => name.toLowerCase() === "cookie");
 return removeHeaderAt(raw, header);
}

export function addCookie(raw: string, name: string, value: string): string {
 const pair = `${oneCookie(name)}=${oneCookie(value)}`;
 const spans = cookieSpans(raw);
 const last = spans.at(-1);
 if (last) return `${raw.slice(0, last.end)}; ${pair}${raw.slice(last.end)}`;
 const header = headerSpans(raw).find(({ name: key }) => key.toLowerCase() === "cookie");
 if (!header) return addHeader(raw, "Cookie", pair);
 return splice(raw, header, `Cookie: ${pair}`);
}

/* ---- body parameters ----------------------------------------------------- */

/**
 * A JSON member's replacement text. A member that was not written as a string
 * keeps its type when the new text is still valid JSON; anything else becomes a
 * JSON string, which is the only lossless thing to do with arbitrary text. A
 * member that WAS a string stays one, so typing `42` into a string field does not
 * silently change the type the server will see.
 */
function jsonValueText(source: string, next: string): string {
 if (!source.startsWith('"')) {
  try {
   JSON.parse(next);
   return next;
  } catch {
   // Not JSON, so it can only go in as a string.
  }
 }
 return JSON.stringify(next);
}

export function setBodyParamAt(raw: string, index: number, name: string, value: string): string {
 const span = bodyParamSpans(raw)[index];
 if (!span) return raw;
 const replacement =
  span.form === "json"
   ? `${JSON.stringify(oneLine(name))}: ${jsonValueText(span.source ?? '""', value)}`
   : `${encodePair(name)}=${encodePair(value)}`;
 return fixContentLength(splice(raw, span, replacement));
}

export function removeBodyParamAt(raw: string, index: number): string {
 const spans = bodyParamSpans(raw);
 const span = spans[index];
 if (!span) return raw;
 // The separator that joined it to a neighbour goes too, so the list stays well
 // formed — "&&" in a form body and a trailing comma in JSON are both malformed.
 let from = span.start;
 let to = span.end;
 if (index > 0) from = spans[index - 1]!.end;
 else if (spans.length > 1) to = spans[1]!.start;
 return fixContentLength(raw.slice(0, from) + raw.slice(to));
}

export function addBodyParam(raw: string, name: string, value: string): string {
 const { body, bodyOffset } = parseMessage(raw);
 const json = contentTypeOf(raw).toLowerCase().includes("json");
 const last = bodyParamSpans(raw).at(-1);
 const text = json ? `${JSON.stringify(oneLine(name))}: ${JSON.stringify(value)}` : `${encodePair(name)}=${encodePair(value)}`;
 if (last) return fixContentLength(`${raw.slice(0, last.end)}${json ? ", " : "&"}${text}${raw.slice(last.end)}`);
 if (!json) return setBody(raw, text);
 // A JSON body with no members yet: write into the object if there is one, else make one.
 const brace = body.indexOf("{");
 if (brace < 0) return setBody(raw, `{${text}}`);
 const at = bodyOffset + brace + 1;
 return fixContentLength(`${raw.slice(0, at)}${text}${raw.slice(at)}`);
}

/* ---- reordering (burpsy-react-ui-ybmd) ------------------------------------ */

/**
 * Swap the text of two non-overlapping spans, leaving every other byte where it was.
 *
 * Reordering is a swap of span TEXT, never a re-render of the list: what sits between the two
 * spans (a header's own line ending, which may be CRLF on one line and bare LF on the next; the
 * "&" or "; " or ", " that joins two pairs) stays exactly as it was, a repeated name keeps its
 * own spelling, and nothing outside the two spans moves. Header order is a smuggling and desync
 * variable, so a reorder that also normalised a line ending would be changing a second variable
 * behind the operator's back.
 */
function swapSpans(raw: string, a: Span, b: Span): string {
 const [first, second] = a.start < b.start ? [a, b] : [b, a];
 if (first.end > second.start) return raw;
 return (
  raw.slice(0, first.start) +
  raw.slice(second.start, second.end) +
  raw.slice(first.end, second.start) +
  raw.slice(first.start, first.end) +
  raw.slice(second.end)
 );
}

/** Which span list a reorder moves within. */
export type ReorderDomain = "header" | "query" | "cookie" | "body";

function spansOf(raw: string, domain: ReorderDomain): Span[] {
 switch (domain) {
  case "header":
   return headerSpans(raw);
  case "query":
   return querySpans(raw);
  case "cookie":
   return cookieSpans(raw);
  case "body":
   return bodyParamSpans(raw);
 }
}

/**
 * Move item `index` of a domain one place up (-1) or down (+1). A move off either end returns
 * the message unchanged rather than wrapping. A body reorder keeps the body's length, so
 * Content-Length still tells the truth without being touched.
 */
export function moveItem(raw: string, domain: ReorderDomain, index: number, direction: -1 | 1): string {
 const spans = spansOf(raw, domain);
 const from = spans[index];
 const to = spans[index + direction];
 if (!from || !to) return raw;
 return swapSpans(raw, from, to);
}

/**
 * Return `head` (a message's headers plus the blank-line separator) with its Content-Length set to
 * `bodyLength`, when it carries a Content-Length at all (burpsy-react-ui-3x2g). A head with none is
 * returned unchanged — a gRPC-over-HTTP/2 body does not use Content-Length, and inventing one would
 * be a header the operator did not have; Repeater's "update Content-Length" send option covers the
 * HTTP/1 case where the server does want it recomputed.
 */
export function withContentLength(head: string, bodyLength: number): string {
 const re = /^(content-length:)[^\r\n]*/im;
 if (re.test(head)) return head.replace(re, `$1 ${bodyLength}`);
 return head;
}

/**
 * Build the faithful base64 of a request whose body is binary (burpsy-react-ui-ytkk): its ASCII head
 * (headers up to the blank-line separator) concatenated with the exact body bytes from `bodyBase64`.
 *
 * A JSON string cannot carry a binary body — a non-UTF-8 byte becomes U+FFFD — so a protobuf/gRPC
 * body edited in Repeater must go to the server base64-encoded, not as the request text. The head is
 * ASCII and the body bytes (atob → one char per byte) are ≤ 0xFF, so btoa over head+body yields the
 * exact request octets. The caller is responsible for the head's Content-Length matching the body.
 */
export function faithfulRequestBase64(requestText: string, bodyBase64: string): string {
 const offset = parseMessage(requestText).bodyOffset;
 const head = requestText.slice(0, offset);
 return btoa(head + atob(bodyBase64));
}

/**
 * Whether two request texts differ in their *body* — the bytes after the header separator — ignoring
 * any change confined to the head (burpsy-react-ui-ytkk). Compares the body slices rather than the
 * byte offsets, because a header edit shifts the offset without touching the body and must count as
 * unchanged.
 *
 * This decides when a tab's stored faithful binary body (requestBodyBase64) has gone stale: a body
 * edit in the raw editor — or a body-encoding transform, or loading a different request — rewrites
 * the body text and must drop the base64 so the operator's edit is what resends; a header-only edit
 * keeps it, so editing headers around a binary body still works.
 */
export function requestBodyChanged(prev: string, next: string): boolean {
 return prev.slice(parseMessage(prev).bodyOffset) !== next.slice(parseMessage(next).bodyOffset);
}

/**
 * The path of a request's target — "/pkg.Service/Method" for a gRPC call — from its request line, or
 * undefined for anything that is not a request (burpsy-react-ui-3pco). An absolute-form target (a
 * proxied request line, "POST https://h/p HTTP/1.1") keeps only its path. The query is kept; the gRPC
 * resolver ignores it.
 */
export function requestTargetPath(raw: string): string | undefined {
 const target = /^[A-Z]+ (\S+)/.exec(raw)?.[1];
 if (!target) return undefined;
 if (target.startsWith("/")) return target;
 try {
  return new URL(target).pathname;
 } catch {
  return undefined;
 }
}

/**
 * The body_base64 an *editable* surface may hold as the faithful body (burpsy-react-ui-3pco): a
 * MessageView's body_base64 is the body with Content-Encoding and chunking undone, so rebuilding the
 * message as head + those bytes is only exact when the head describes no encoding. Otherwise the
 * rebuilt message would send a decoded body under a head that still claims gzip or chunked. Returns
 * undefined then, and the surface falls back to the text — no Protobuf editing, rather than a corrupt
 * resend. Read-only views can use body_base64 directly.
 */
export function editableBodyBase64(view: { text?: string; body_base64?: string; content_encoding?: string }): string | undefined {
 if (!view.body_base64) return undefined;
 const encoding = view.content_encoding?.trim().toLowerCase();
 if (encoding && encoding !== "identity") return undefined;
 const head = (view.text ?? "").slice(0, parseMessage(view.text ?? "").bodyOffset);
 if (/^transfer-encoding:[^\r\n]*chunked/im.test(head)) return undefined;
 return view.body_base64;
}

/**
 * The cookie name/value spans of one Cookie or Set-Cookie header line, line-relative, for the editor's
 * cookie colouring (burpsy-react-ui-axm9 — Burp colours cookies in the message editor, cookieName /
 * cookieValue). A Cookie line yields every `name=value` pair; a Set-Cookie line only its first pair,
 * because what follows the first `;` are attributes (Path, Secure, …), not cookies. Any other line
 * yields nothing.
 */
export function cookieHeaderTokens(line: string): { cls: "cookie-name" | "cookie-value"; start: number; end: number }[] {
 const colon = line.indexOf(":");
 if (colon <= 0) return [];
 const header = line.slice(0, colon).trim().toLowerCase();
 if (header !== "cookie" && header !== "set-cookie") return [];
 const out: { cls: "cookie-name" | "cookie-value"; start: number; end: number }[] = [];
 let cursor = colon + 1;
 while (cursor < line.length) {
  const semi = line.indexOf(";", cursor);
  const stop = semi < 0 ? line.length : semi;
  const chunk = line.slice(cursor, stop);
  const lead = chunk.length - chunk.trimStart().length;
  const pair = chunk.trim();
  if (pair !== "") {
   const start = cursor + lead;
   const eq = pair.indexOf("=");
   if (eq < 0) {
    out.push({ cls: "cookie-name", start, end: start + pair.length });
   } else {
    if (eq > 0) out.push({ cls: "cookie-name", start, end: start + eq });
    if (eq + 1 < pair.length) out.push({ cls: "cookie-value", start: start + eq + 1, end: start + pair.length });
   }
  }
  if (header === "set-cookie") break;
  cursor = stop + 1;
 }
 return out;
}
