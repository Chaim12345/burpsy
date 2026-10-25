/**
 * The message editor's typed views, and the byte model its Hex view edits.
 *
 * Two rules run through everything here, and they are the reason this file exists
 * rather than the detection being inlined into the editor:
 *
 *  1. A view is offered only when the message actually warrants it. Pretty already
 *     works that way — it is hidden unless reformatting would change something — and
 *     a GraphQL tab that appears on every request and is empty on all but three is
 *     worse than no tab at all. Every `detect*` function below returns null rather
 *     than an empty shell.
 *  2. A view that could not parse its input says so. Nothing here renders a blank
 *     pane where a decode failed: an undecodable JWT segment carries the reason it
 *     could not be decoded, and a variables blob that is not JSON is shown as the
 *     text it is with the parse error beside it.
 */

import { bodyParamsOf, cookiesOf, headerValue, isResponse, parseMessage, parsePairs, pairSpans, queryOf, type Span } from "./message";
import { htmlDecode, urlDecode } from "./transforms";

/* ===========================================================================
   the byte model
   ===========================================================================

   The console carries messages as JavaScript strings, and the Go side turns the
   string it receives back into bytes with a plain []byte(s) — a UTF-8 encode. So
   the bytes that go on the wire are exactly `new TextEncoder().encode(value)`,
   and that is the model the Hex view edits.

   That has one hard consequence, and pretending otherwise would be the dishonest
   option: not every byte sequence is valid UTF-8, and there is no JavaScript
   string whose UTF-8 encoding is a lone 0x80. Such an edit cannot be carried by
   this transport at all — not by the Hex view and not by the Raw view either. So
   the Hex view refuses to commit it and names the offset, instead of substituting
   U+FFFD and reporting success over three bytes the operator never asked for. */

export function messageBytes(value: string): Uint8Array {
 return new TextEncoder().encode(value);
}

export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
 if (a.length !== b.length) return false;
 for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
 return true;
}

/**
 * Offset of the first byte that is not part of a well-formed UTF-8 sequence, or -1.
 *
 * Written out rather than delegated to TextDecoder's `fatal` mode because the
 * offset is the point: "0x80 at offset 42 cannot be carried" is actionable and
 * "The encoded data was not valid" is not. Overlong forms, the surrogate range and
 * everything above U+10FFFF are rejected, which is what makes the round trip in
 * `bytesToMessage` exact rather than merely usually exact.
 */
export function firstInvalidUtf8(bytes: Uint8Array): number {
 let i = 0;
 while (i < bytes.length) {
  const lead = bytes[i]!;
  if (lead < 0x80) {
   i += 1;
   continue;
  }
  let continuations: number;
  let secondLow = 0x80;
  let secondHigh = 0xbf;
  if (lead >= 0xc2 && lead <= 0xdf) {
   continuations = 1;
  } else if (lead === 0xe0) {
   continuations = 2;
   secondLow = 0xa0;
  } else if (lead >= 0xe1 && lead <= 0xec) {
   continuations = 2;
  } else if (lead === 0xed) {
   // 0xED 0xA0.. is the UTF-16 surrogate range; it is not a scalar value.
   continuations = 2;
   secondHigh = 0x9f;
  } else if (lead >= 0xee && lead <= 0xef) {
   continuations = 2;
  } else if (lead === 0xf0) {
   continuations = 3;
   secondLow = 0x90;
  } else if (lead >= 0xf1 && lead <= 0xf3) {
   continuations = 3;
  } else if (lead === 0xf4) {
   continuations = 3;
   secondHigh = 0x8f;
  } else {
   // 0x80..0xC1 is a stray continuation or an overlong two-byte lead; 0xF5..0xFF
   // encodes nothing.
   return i;
  }
  if (i + continuations >= bytes.length) return i;
  const second = bytes[i + 1]!;
  if (second < secondLow || second > secondHigh) return i;
  for (let k = 2; k <= continuations; k += 1) {
   const byte = bytes[i + k]!;
   if (byte < 0x80 || byte > 0xbf) return i;
  }
  i += continuations + 1;
 }
 return -1;
}

export interface BytesToMessage {
 text: string;
 /** True when `messageBytes(text)` is byte-identical to the input. */
 exact: boolean;
 /** Offset of the first byte the transport cannot carry, or -1. */
 badOffset: number;
}

/**
 * Bytes back to the string the rest of the console passes around.
 *
 * `exact` is checked by re-encoding and comparing, not inferred: the round trip is
 * the invariant the Hex view's whole claim rests on, so it is measured on every
 * commit rather than argued from the validator.
 */
export function bytesToMessage(bytes: Uint8Array): BytesToMessage {
 const badOffset = firstInvalidUtf8(bytes);
 const text = new TextDecoder().decode(bytes);
 return { text, exact: badOffset < 0 && sameBytes(messageBytes(text), bytes), badOffset };
}

/**
 * The UTF-16 index in `value` at which the byte at `byteOffset` begins.
 *
 * Used to turn a Hex selection into a Raw selection. When the offset lands inside a
 * multi-byte character the index of that character is returned — the selection
 * snaps outward to a whole character rather than to a position no editor can hold.
 */
export function byteOffsetToCharIndex(value: string, byteOffset: number): number {
 if (byteOffset <= 0) return 0;
 let bytes = 0;
 let index = 0;
 while (index < value.length) {
  const code = value.codePointAt(index)!;
  // A lone surrogate is not a scalar value; TextEncoder emits U+FFFD's three
  // bytes for it, so its width is 3 rather than 2.
  const width = code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
  if (bytes + width > byteOffset) return index;
  bytes += width;
  index += code > 0xffff ? 2 : 1;
  if (bytes >= byteOffset) return index;
 }
 return value.length;
}

/**
 * The UTF-8 byte offset at which the character at `charIndex` begins.
 *
 * Inverse of `byteOffsetToCharIndex`. Used to turn a CodeMirror selection (UTF-16
 * code-unit indices) into the `[start, end)` byte span the server's audit endpoint
 * needs (burpsy-react-ui-c6oq) — the raw request is `[]byte(string)` on the Go side,
 * so a character's byte offset is the cumulative UTF-8 width of every character
 * before it.
 */
export function charIndexToByteOffset(value: string, charIndex: number): number {
 if (charIndex <= 0) return 0;
 let bytes = 0;
 let index = 0;
 while (index < value.length && index < charIndex) {
  const code = value.codePointAt(index)!;
  const width = code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
  bytes += width;
  index += code > 0xffff ? 2 : 1;
 }
 return bytes;
}

/**
 * Map a position in a CodeMirror document back to the position it names in the raw
 * `value` string (burpsy-react-ui-c6oq).
 *
 * The editor's document counts a line break as ONE position whatever its spelling
 * (lineSeparator, lib/editor-eol.ts), so an editor selection indexes the
 * SHORTENED text while the audit span the server wants indexes the raw bytes. Every
 * "\r" between the two spellings is a one-byte shift: a selection on the third header
 * line of a CRLF request is two ahead in the document of where it sits in the request.
 *
 * The lockstep walk consumes a value-side "\r\n" as one document character, so the
 * returned position always lands where the operator's selection starts in the raw
 * string. A docPos that stops at a normalised break returns the break's own value-side
 * index (the "\r"), which is the first byte of the pair — a span beginning there names
 * the break, never a position inside it, because the document holds no position
 * between the "\r" and the "\n" to stop at.
 */
export function docPosToValuePos(value: string, docPos: number): number {
 if (docPos <= 0) return 0;
 let vi = 0;
 let di = 0;
 while (di < docPos && vi < value.length) {
  if (value.charCodeAt(vi) === 13) {
   di += 1;
   vi += value.charCodeAt(vi + 1) === 10 ? 2 : 1;
  } else {
   di += 1;
   vi += 1;
  }
 }
 return vi;
}

/* ===========================================================================
   JWT
   ===========================================================================

   The decode deliberately mirrors internal/tools/codec.go's LayerJWT byte for
   byte: the same tolerant base64url (skip anything outside the alphabet, stop at
   the first '='), the same "three parts, header and payload non-empty" rule, the
   same "pretty-print it if it is JSON, otherwise show the text" fallback, and the
   same refusal to touch the signature. A second JWT decoder that disagreed with
   /api/tools/decode about the same token would make one of the two a liar. */

const B64URL = new Map<string, number>();
{
 const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
 for (let i = 0; i < alphabet.length; i += 1) B64URL.set(alphabet[i]!, i);
}

/** Tolerant base64url, matching tools.Base64Decode(input, true). */
export function base64UrlDecodeTolerant(input: string): Uint8Array {
 const out: number[] = [];
 let acc = 0;
 let bits = 0;
 for (const character of input) {
  if (character === "=") break;
  const value = B64URL.get(character);
  if (value === undefined) continue;
  // Wraps at 32 bits exactly as the Go accumulator does; the mask below is what
  // makes the high garbage irrelevant, in both languages.
  acc = (acc << 6) | value;
  bits += 6;
  if (bits >= 8) {
   bits -= 8;
   out.push((acc >> bits) & 0xff);
  }
 }
 return new Uint8Array(out);
}

export interface JwtSegment {
 /** Pretty-printed JSON, or the decoded text when the segment is not JSON. */
 text: string;
 /** Present when the segment could not be decoded or is not JSON. Never silent. */
 note: string | null;
 /** True only when the segment decoded to well-formed JSON. */
 json: boolean;
}

export interface DecodedJwt {
 token: string;
 header: JwtSegment;
 payload: JwtSegment;
 /** The third part, verbatim. Never decoded, never verified. */
 signature: string;
 /** The `alg` claim from the header, when the header decoded to JSON that has one. */
 alg: string | null;
}

function decodeSegment(part: string, what: string): JwtSegment {
 const bytes = base64UrlDecodeTolerant(part);
 if (bytes.length === 0) {
  return { text: "", note: `${what} could not be decoded: no base64url characters in "${part}"`, json: false };
 }
 const invalid = firstInvalidUtf8(bytes);
 const text = new TextDecoder().decode(bytes);
 try {
  const parsed: unknown = JSON.parse(text);
  return { text: JSON.stringify(parsed, null, 2), note: null, json: true };
 } catch (error) {
  const why = error instanceof Error ? error.message : String(error);
  const utf8Note =
   invalid < 0
    ? ""
    : ` The decoded bytes are not valid UTF-8 (first bad byte at offset ${invalid}), so the text below shows U+FFFD in its place.`;
  return {
   text,
   note: `${what} decoded to ${bytes.length} bytes that are not JSON (${why}); shown as text.${utf8Note}`,
   json: false,
  };
 }
}

/**
 * Decode one compact JWT, or null when the input is not one.
 *
 * Null rather than a half-filled result: "this is not a JWT" and "this is a JWT
 * whose payload will not decode" are different facts and the caller shows them
 * differently.
 */
export function decodeJwt(input: string): DecodedJwt | null {
 // codec.go refuses non-ASCII before doing anything else, on the grounds that a
 // JWT is ASCII by construction; matching that keeps the two decoders honest
 // about the same inputs.
 if (/[^\x00-\x7f]/.test(input)) return null;
 const token = input
  .trim()
  .replace(/^Bearer\s+/i, "")
  .trim();
 const parts = token.split(".");
 if (parts.length !== 3) return null;
 if (!parts[0] || !parts[1]) return null;
 const header = decodeSegment(parts[0], "header");
 const payload = decodeSegment(parts[1], "payload");
 let alg: string | null = null;
 if (header.json) {
  try {
   const parsed: unknown = JSON.parse(header.text);
   if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const candidate = (parsed as Record<string, unknown>)["alg"];
    if (typeof candidate === "string") alg = candidate;
   }
  } catch {
   alg = null;
  }
 }
 return { token, header, payload, signature: parts[2] ?? "", alg };
}

export interface JwtFinding extends DecodedJwt {
 /** Where in the message the token was found, e.g. `Authorization header`. */
 locations: string[];
}

export interface JwtReport {
 tokens: JwtFinding[];
 /** True when the body was too large to scan in full. */
 truncated: boolean;
 /** How much of the body was actually searched, in characters. */
 scannedBodyChars: number;
}

/**
 * A JWT is short and lives in a header, a cookie or a small JSON body, so the scan
 * stops after this many characters of the body. A megabyte upload does not contain
 * a token worth finding, and scanning one on every keystroke would make the editor
 * stutter. When the cap bites the report says so rather than reporting "no tokens".
 */
const JWT_BODY_SCAN_LIMIT = 128 * 1024;

/** Three dot-separated base64url runs. Validated afterwards; this only finds candidates. */
const JWT_CANDIDATE = /[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g;

/**
 * Every JWT in a message, with where each one was found.
 *
 * The candidate regex alone would fire on `jquery.min.js` and on any three
 * dot-separated words, so a candidate only counts once its first segment decodes
 * to a JSON object carrying a string `alg`. That is the cheapest test that is
 * actually about JWTs rather than about dots, and it is what stops this tab
 * appearing on messages that contain no token.
 */
export function findJwts(raw: string): JwtReport {
 const parsed = parseMessage(raw);
 const found = new Map<string, JwtFinding>();

 const scan = (text: string, location: string): void => {
  if (!text.includes(".")) return;
  JWT_CANDIDATE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = JWT_CANDIDATE.exec(text)) !== null) {
   const candidate = match[0];
   const existing = found.get(candidate);
   if (existing) {
    if (!existing.locations.includes(location)) existing.locations.push(location);
    continue;
   }
   const decoded = decodeJwt(candidate);
   if (!decoded || !decoded.header.json || !decoded.alg) continue;
   found.set(candidate, { ...decoded, locations: [location] });
  }
 };

 for (const [name, value] of parsed.headers) {
  scan(value, `${name} header`);
 }
 // Query and cookie values are scanned as their decoded selves too: a token that
 // arrived percent-encoded is still a token, and the raw header scan above would
 // have missed it.
 for (const [name, value] of queryOf(parsed.startLine.split(/\s+/)[1] ?? "")) {
  scan(value, `query parameter ${name}`);
 }
 for (const [name, value] of cookiesOf(parsed.headers, isResponse(raw))) {
  scan(value, `cookie ${name}`);
 }

 const truncated = parsed.body.length > JWT_BODY_SCAN_LIMIT;
 const bodyRegion = truncated ? parsed.body.slice(0, JWT_BODY_SCAN_LIMIT) : parsed.body;
 scan(bodyRegion, "body");

 return { tokens: [...found.values()], truncated, scannedBodyChars: bodyRegion.length };
}

/* ===========================================================================
   GraphQL
   ===========================================================================

   The three carriers below are exactly the three pkg/graphqlmap can emit
   (EncodingJSON, EncodingForm, EncodingGet), so the view reads back everything
   this project's own GraphQL client can send. That package is a Go prober — a
   transport, an introspection client and injection sweeps — and has no
   request-shape detector or browser-reachable endpoint, so nothing in it could be
   reused here; its Encoding enum is the part that transferred. */

export interface GraphQLOperationText {
 text: string;
 /** Set when the text is present but is not the JSON it is supposed to be. */
 error: string | null;
}

export interface GraphQLOperation {
 operationName: string | null;
 query: string;
 /** Null when the request carried no variables at all — different from "{}". */
 variables: GraphQLOperationText | null;
 extensions: GraphQLOperationText | null;
}

export interface GraphQLDocument {
 /** Human-readable carrier, shown in the view so the source is never a guess. */
 source: string;
 operations: GraphQLOperation[];
}

/** Body bigger than this is not a GraphQL document; skip the parse rather than run it per keystroke. */
const GRAPHQL_BODY_LIMIT = 512 * 1024;

/**
 * Does this text read as a GraphQL document?
 *
 * The shape test, not the parameter name, is what decides. `{"query": "shoes"}` is
 * a search API and `?query=blue+widgets` is a search box; both would light up a
 * GraphQL tab if the name alone were enough, which is the failure this whole file
 * is written to avoid.
 */
export function looksLikeGraphQLDocument(text: string): boolean {
 // Leading `#` comments are legal GraphQL and would otherwise hide the operation.
 const trimmed = text.replace(/^(?:\s*#[^\n]*\n)+/, "").trimStart();
 if (!trimmed) return false;
 if (/^(?:query|mutation|subscription|fragment)\b/.test(trimmed)) return true;
 if (!trimmed.startsWith("{")) return false;
 // An anonymous GraphQL operation and a JSON object both start with `{`. Only one
 // of them parses as JSON.
 try {
  JSON.parse(trimmed);
  return false;
 } catch {
  return true;
 }
}

function asText(value: unknown, what: string): GraphQLOperationText | null {
 if (value === undefined || value === null) return null;
 if (typeof value === "string") {
  // Some clients send variables as a JSON *string* rather than an object.
  try {
   return { text: JSON.stringify(JSON.parse(value), null, 2), error: null };
  } catch (error) {
   return { text: value, error: `${what} is a string that is not JSON: ${(error as Error).message}` };
  }
 }
 return { text: JSON.stringify(value, null, 2), error: null };
}

function operationFrom(record: Record<string, unknown>): GraphQLOperation | null {
 const query = record["query"];
 if (typeof query !== "string" || !looksLikeGraphQLDocument(query)) return null;
 const name = record["operationName"];
 return {
  operationName: typeof name === "string" && name ? name : null,
  query,
  variables: asText(record["variables"], "variables"),
  extensions: asText(record["extensions"], "extensions"),
 };
}

/**
 * The GraphQL document a request carries, or null when it carries none.
 *
 * Responses are excluded on purpose: a GraphQL response is a JSON envelope and the
 * Pretty view already renders it better than a query/variables split would.
 */
export function detectGraphQL(raw: string): GraphQLDocument | null {
 if (isResponse(raw)) return null;
 const parsed = parseMessage(raw);
 const contentType = (headerValue(parsed.headers, "content-type") ?? "").toLowerCase();
 const body = parsed.body;

 // application/graphql: the body IS the document, no envelope.
 if (contentType.includes("application/graphql") && !contentType.includes("json")) {
  if (!looksLikeGraphQLDocument(body)) return null;
  return {
   source: "application/graphql body",
   operations: [{ operationName: null, query: body, variables: null, extensions: null }],
  };
 }

 if (body.length <= GRAPHQL_BODY_LIMIT && body.includes("query")) {
  if (contentType.includes("x-www-form-urlencoded")) {
   const pairs = parsePairs(body.trim());
   const query = pairs.find(([name]) => name === "query")?.[1];
   if (query !== undefined && looksLikeGraphQLDocument(query)) {
    const variablesRaw = pairs.find(([name]) => name === "variables")?.[1];
    const nameRaw = pairs.find(([name]) => name === "operationName")?.[1];
    return {
     source: "urlencoded body",
     operations: [
      {
       operationName: nameRaw ?? null,
       query,
       variables: variablesRaw === undefined ? null : asText(variablesRaw, "variables"),
       extensions: null,
      },
     ],
    };
   }
  } else {
   let decoded: unknown;
   let parsedOk = true;
   try {
    decoded = JSON.parse(body);
   } catch {
    parsedOk = false;
   }
   if (parsedOk) {
    if (Array.isArray(decoded)) {
     const operations = decoded
      .filter((entry): entry is Record<string, unknown> => Boolean(entry) && typeof entry === "object" && !Array.isArray(entry))
      .map(operationFrom)
      .filter((entry): entry is GraphQLOperation => entry !== null);
     if (operations.length) return { source: `batched JSON body (${operations.length} operations)`, operations };
    } else if (decoded && typeof decoded === "object") {
     const operation = operationFrom(decoded as Record<string, unknown>);
     if (operation) return { source: "JSON body", operations: [operation] };
    }
   }
  }
 }

 // GET /graphql?query={__typename} — the third encoding graphqlmap can emit.
 const target = parsed.startLine.split(/\s+/)[1] ?? "";
 const inQuery = queryOf(target);
 const query = inQuery.find(([name]) => name === "query")?.[1];
 if (query !== undefined && looksLikeGraphQLDocument(query)) {
  const variablesRaw = inQuery.find(([name]) => name === "variables")?.[1];
  const nameRaw = inQuery.find(([name]) => name === "operationName")?.[1];
  return {
   source: "query string",
   operations: [
    {
     operationName: nameRaw ?? null,
     query,
     variables: variablesRaw === undefined ? null : asText(variablesRaw, "variables"),
     extensions: null,
    },
   ],
  };
 }

 return null;
}

/* ===========================================================================
   Params
   =========================================================================== */

export type ParamKind = "query" | "body" | "cookie";

export interface ParamRow {
 kind: ParamKind;
 name: string;
 value: string;
}

export interface ParamReport {
 rows: ParamRow[];
 /** What was present but not parsed. Empty when everything in the message was read. */
 notes: string[];
}

/**
 * Query, body and cookie parameters in one table — Burp's Params tab.
 *
 * The parsers are message.ts's, unchanged: a second set that split a cookie jar
 * slightly differently from the Inspector would put two answers about the same
 * bytes on screen at once. What is added is the notes list, because a body this
 * cannot split (multipart, protobuf, anything binary) must be named as unparsed
 * rather than left looking like a body with no parameters in it.
 */
export function paramsOf(raw: string): ParamReport {
 const parsed = parseMessage(raw);
 const response = isResponse(raw);
 const contentType = headerValue(parsed.headers, "content-type");
 const rows: ParamRow[] = [];
 const notes: string[] = [];

 if (!response) {
  const target = parsed.startLine.split(/\s+/)[1] ?? "";
  for (const [name, value] of queryOf(target)) rows.push({ kind: "query", name, value });
 }
 for (const [name, value] of cookiesOf(parsed.headers, response)) rows.push({ kind: "cookie", name, value });

 if (parsed.body.trim()) {
  const bodyRows = bodyParamsOf(parsed.body, contentType);
  for (const [name, value] of bodyRows) rows.push({ kind: "body", name, value });
  if (!bodyRows.length) {
   const type = contentType ? contentType.split(";")[0]?.trim() : "";
   notes.push(
    type
     ? `The ${type} body was not split into parameters — burpsy only parses urlencoded and JSON bodies here. Its bytes are on the Raw view.`
     : "The body carries no Content-Type, so it was not split into parameters. Its bytes are on the Raw view.",
   );
  }
 }

 return { rows, notes };
}

/**
 * The line-ending glyphs Burp's \n toggle names (burpsy-react-ui-1e4): which break bytes
 * actually separate the lines of this text, in order. CodeMirror joins lines with its
 * separator rather than the message's own spelling when read with doc.toString(), so that cannot tell a CRLF message from an LF
 * one - and certifying "LF only" on a CRLF message is the one wrong answer this toggle must
 * never give. Reading the breaks off the raw message text keeps the glyphs honest; the raw
 * text and the rendered document agree line-for-line (every break spelling still breaks
 * exactly one line), so the nth glyph here is the break after the nth rendered line.
 */
export function breakGlyphs(text: string): string[] {
 const glyphs: string[] = [];
 for (const match of text.matchAll(/\r\n|\r|\n/g)) {
  glyphs.push(match[0] === "\r\n" ? "\u240d\u240a" : match[0] === "\n" ? "\u240a" : "\u240d");
 }
 return glyphs;
}

/* ==== the message editor's body tokenisation (burpsy-react-ui-6fq) ========
 *
 * Burp colourises the body by content type — JSON, HTML/XML, JavaScript, CSS — and
 * distinguishes request parameters. This is that feature's data half: the same body the
 * editor renders, tokenised into spans the editor turns into `Decoration.mark`s.
 *
 * Deliberately span-shaped rather than a CodeMirror language pack: a `@codemirror/lang-*`
 * extension owns the WHOLE document, so applying one to a raw HTTP message would parse the
 * start line and every header as the body's language and replace the header decorations.
 * The body is a sub-region; these functions are too, and the editor scopes them behind
 * `headerEnd`.
 *
 * Everything is bounded and refusal-first: a truncated or non-HTTP body tokenises to
 * nothing rather than to spans that lie about it, and the cost is proportional to the
 * text actually scanned, never to the document.
 */

/** TokenClass is the vocabulary the editor maps to decoration classes. */
export type TokenClass =
 | "json-key"
 | "json-string"
 | "json-number"
 | "json-constant"
 | "html-tag"
 | "html-attr-name"
 | "html-attr-value"
 | "js-keyword"
 | "js-string"
 | "js-comment"
 | "css-property"
 | "css-value"
 | "url-param-name"
 | "url-param-value"
 // Cookie and Set-Cookie header pairs (burpsy-react-ui-axm9), coloured inside the header block.
 | "cookie-name"
 | "cookie-value";

export interface BodyToken extends Span {
 cls: TokenClass;
}

const JS_KEYWORDS = new Set([
 "async",
 "await",
 "break",
 "case",
 "catch",
 "class",
 "const",
 "continue",
 "debugger",
 "default",
 "delete",
 "do",
 "else",
 "export",
 "extends",
 "finally",
 "for",
 "function",
 "if",
 "import",
 "in",
 "instanceof",
 "let",
 "new",
 "return",
 "static",
 "super",
 "switch",
 "this",
 "throw",
 "try",
 "typeof",
 "var",
 "void",
 "while",
 "with",
 "yield",
]);

const JSON_CONSTANTS = new Set(["true", "false", "null"]);

/**
 * The body's token spans, for the editor's colouring.
 *
 * One scan, dispatching on what the text actually is rather than on the header — the same
 * negotiation `prettyMessage` does (Content-Type first, then a sniff), but over the body
 * text the caller already chose. A body that is none of the four returns [] and the editor
 * keeps the plain BODY_LINE: a flat colour that says "nothing to highlight here" is honest;
 * spans that pretend a plain-text body was JSON are not.
 */
export function bodyTokens(body: string, contentType = ""): BodyToken[] {
 const type = contentType.toLowerCase();
 if (type.includes("json") || looksLikeJsonBody(body)) return jsonTokens(body);
 if (type.includes("html") || type.includes("xhtml") || type.includes("svg") || /^\s*<[a-z!?]/i.test(body)) return htmlTokens(body);
 if (type.includes("javascript") || type.includes("ecmascript") || type.includes("application/ecmascript")) return jsTokens(body);
 if (type.includes("css")) return cssTokens(body);
 return [];
}

function looksLikeJsonBody(body: string): boolean {
 const trimmed = body.trim();
 return (trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"));
}

/** JSON: keys, strings, numbers and the three constants, over a well-formed document. */
export function jsonTokens(body: string): BodyToken[] {
 const out: BodyToken[] = [];
 let i = 0;
 const n = body.length;
 const push = (cls: TokenClass, from: number, to: number) => {
  if (to > from) out.push({ cls, start: from, end: to });
 };
 while (i < n) {
  const ch = body[i]!;
  if (ch === '"') {
   // A quoted region: is it a key (a colon follows the closing quote) or a string value?
   let j = i + 1;
   while (j < n && body[j] !== '"') {
    if (body[j] === "\\") j += 1;
    j += 1;
   }
   if (j >= n) break;
   let k = j + 1;
   while (k < n && /\s/.test(body[k]!)) k += 1;
   if (body[k] === ":") {
    push("json-key", i, j + 1);
   } else {
    push("json-string", i, j + 1);
   }
   i = j + 1;
   continue;
  }
  if (/[0-9-]/.test(ch)) {
   let j = i;
   while (j < n && /[0-9.eE+-]/.test(body[j]!)) j += 1;
   // A number is a JSON member's value only when the preceding token was a key — but any
   // bare number token outside a string is a number; classifying it as one cannot mislead.
   push("json-number", i, j);
   i = j;
   continue;
  }
  if (/[a-zA-Z_$]/.test(ch)) {
   let j = i;
   while (j < n && /[a-zA-Z0-9_$]/.test(body[j]!)) j += 1;
   const word = body.slice(i, j);
   if (JSON_CONSTANTS.has(word)) push("json-constant", i, j);
   i = j;
   continue;
  }
  i += 1;
 }
 return out;
}

/** HTML/XML: tag names, attribute names and values. Comments and text stay undecorated. */
export function htmlTokens(body: string): BodyToken[] {
 const out: BodyToken[] = [];
 let i = 0;
 const n = body.length;
 const push = (cls: TokenClass, from: number, to: number) => {
  if (to > from) out.push({ cls, start: from, end: to });
 };
 while (i < n) {
  const lt = body.indexOf("<", i);
  if (lt < 0) break;
  if (body.startsWith("<!--", lt)) {
   const close = body.indexOf("-->", lt);
   if (close < 0) break;
   i = close + 3;
   continue;
  }
  // A tag. The name runs to whitespace, '/', or '>'.
  let j = lt + 1;
  while (j < n && !/[\s/]/.test(body[j]!) && body[j] !== ">") j += 1;
  const isClosing = body[lt + 1] === "/";
  const nameEnd = isClosing ? j : j;
  if (j > lt + 1) push("html-tag", lt + (isClosing ? 1 : 0), nameEnd);
  if (isClosing) {
   const gt = body.indexOf(">", j);
   if (gt < 0) break;
   i = gt + 1;
   continue;
  }
  // Attributes until the tag closes.
  while (j < n && body[j] !== ">") {
   while (j < n && /\s/.test(body[j]!)) j += 1;
   if (j >= n || body[j] === ">" || body[j] === "/") break;
   const nameStart = j;
   while (j < n && !/[=\s/]/.test(body[j]!) && body[j] !== ">") j += 1;
   push("html-attr-name", nameStart, j);
   while (j < n && /\s/.test(body[j]!)) j += 1;
   if (body[j] === "=") {
    j += 1;
    while (j < n && /\s/.test(body[j]!)) j += 1;
    const quote = body[j];
    if (quote === '"' || quote === "'") {
     const close = body.indexOf(quote, j + 1);
     const end = close < 0 ? n : close + 1;
     push("html-attr-value", j, end);
     j = end;
    } else {
     const valueStart = j;
     while (j < n && !/[\s>]/.test(body[j]!)) j += 1;
     push("html-attr-value", valueStart, j);
    }
   }
  }
  const gt = body.indexOf(">", j);
  if (gt < 0) break;
  i = gt + 1;
 }
 return out;
}

/** JavaScript: keywords, strings and comments. A body that never parses still colourises —
 *  this is display, not execution. */
export function jsTokens(body: string): BodyToken[] {
 const out: BodyToken[] = [];
 let i = 0;
 const n = body.length;
 const push = (cls: TokenClass, from: number, to: number) => {
  if (to > from) out.push({ cls, start: from, end: to });
 };
 while (i < n) {
  const ch = body[i]!;
  if (ch === "/" && body[i + 1] === "/") {
   const end = body.indexOf("\n", i);
   push("js-comment", i, end < 0 ? n : end);
   i = end < 0 ? n : end + 1;
   continue;
  }
  if (ch === "/" && body[i + 1] === "*") {
   const end = body.indexOf("*/", i + 2);
   push("js-comment", i, end < 0 ? n : end + 2);
   i = end < 0 ? n : end + 2;
   continue;
  }
  if (ch === '"' || ch === "'" || ch === "`") {
   let j = i + 1;
   while (j < n && body[j] !== ch) {
    if (body[j] === "\\") j += 1;
    j += 1;
   }
   push("js-string", i, Math.min(j + 1, n));
   i = Math.min(j + 1, n);
   continue;
  }
  if (/[a-zA-Z_$]/.test(ch)) {
   let j = i;
   while (j < n && /[a-zA-Z0-9_$]/.test(body[j]!)) j += 1;
   if (JS_KEYWORDS.has(body.slice(i, j))) push("js-keyword", i, j);
   i = j;
   continue;
  }
  i += 1;
 }
 return out;
}

/** CSS: property names and values, one declaration per scan. Selectors stay undecorated —
 *  a selector is markup, and colourising it as a property would misstate the document. */
export function cssTokens(body: string): BodyToken[] {
 const out: BodyToken[] = [];
 let i = 0;
 const n = body.length;
 while (i < n) {
  const open = body.indexOf("{", i);
  if (open < 0) break;
  const close = body.indexOf("}", open);
  if (close < 0) break;
  // Declarations inside the block: name: value;
  let j = open + 1;
  while (j < close) {
   const colon = body.indexOf(":", j);
   if (colon < 0 || colon >= close) break;
   const nameStart = j;
   while (j < close && /\s/.test(body[j]!)) j += 1;
   const nameEnd = colon;
   if (colon > nameStart) {
    let from = nameStart;
    while (from < close && /\s/.test(body[from]!)) from += 1;
    if (nameEnd > from) out.push({ cls: "css-property", start: from, end: nameEnd });
    const valueEnd = body.indexOf(";", colon);
    const stop = valueEnd < 0 || valueEnd > close ? close : valueEnd;
    let vFrom = colon + 1;
    while (vFrom < stop && /\s/.test(body[vFrom]!)) vFrom += 1;
    if (stop > vFrom) out.push({ cls: "css-value", start: vFrom, end: stop });
    j = stop + 1;
   } else {
    j = colon + 1;
   }
  }
  i = close + 1;
 }
 return out;
}

/* ==== hover decode (burpsy-react-ui-6fq) ==================================
 *
 * Burp's mouse-over popups: URL-decode in requests, HTML-decode in responses. The decoders
 * are the transforms module's own; this is the decision half — which decoder applies, and
 * when the popup exists at all.
 *
 * A no-op decode returns null: a plain ASCII token does not grow a popup that restates
 * itself, because a popup whose text is the token verbatim says nothing the screen did not
 * already say. The popup exists to make an encoded value readable.
 */

/**
 * The URL-encoded parameter spans of a request's query string and form body, for the
 * editor's parameter colouring and the hover decode.
 *
 * `pairSpans` already splits each pair into a decoded name and value; what the editor's
 * two decorations and the hover popup additionally need is the *byte range* of each half
 * inside the raw text, so hovering the NAME answers "what parameter is this" and hovering
 * the VALUE decodes what it carries. A pair with no `=` is still reported as a name-only
 * pair — a bare flag like `?debug` is a parameter Burp shows too.
 */
/**
 * The hover decode (burpsy-react-ui-6fq): Burp's mouse-over popups, which URL-decode in
 * requests and HTML-decode in responses.
 *
 * A no-op decode returns null, so a plain ASCII token does not grow a popup that restates
 * itself — the popup exists to make an encoded value readable, and a popup whose text is
 * the token verbatim says nothing the screen did not already say. The token's own byte
 * range decides which half is being hovered, so the caller passes the spans it coloured.
 */
export function decodeHoverToken(text: string, from: number, to: number, isResponseMsg: boolean, contentType = ""): string | null {
 const token = text.slice(from, to);
 if (token === "") return null;
 // Form values and query values are both URL-encoded; a response body is HTML-escaped.
 let decoded: string;
 if (isResponseMsg && !contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
  decoded = htmlDecode(token);
 } else {
  decoded = urlDecode(token);
 }
 return decoded === token ? null : decoded;
}

export function urlParamTokens(query: string, body: string, contentType = ""): BodyToken[] {
 const out: BodyToken[] = [];
 const add = (text: string, base: number) => {
  for (const pair of pairSpans(text)) {
   const from = pair.start;
   const to = pair.end;
   const eq = text.indexOf("=", from);
   if (eq < 0 || eq >= to) {
    out.push({ cls: "url-param-name", start: base + from, end: base + to });
   } else {
    out.push({ cls: "url-param-name", start: base + from, end: base + eq });
    out.push({ cls: "url-param-value", start: base + eq + 1, end: base + to });
   }
  }
 };
 add(query, 0);
 // Form params only when the body IS one: a JSON/multipart body's `&` is data, not a
 // separator, and colourising inside it would misstate the document (the same refusal
 // `bodyParamSpansEditable` makes).
 if (contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
  for (const pair of pairSpans(body)) {
   const eq = body.indexOf("=", pair.start);
   if (eq < 0 || eq >= pair.end) {
    out.push({ cls: "url-param-name", start: pair.start, end: pair.end });
   } else {
    out.push({ cls: "url-param-name", start: pair.start, end: eq });
    out.push({ cls: "url-param-value", start: eq + 1, end: pair.end });
   }
  }
 }
 return out;
}
