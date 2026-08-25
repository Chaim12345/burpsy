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

import { bodyParamsOf, cookiesOf, headerValue, isResponse, parseMessage, parsePairs, queryOf } from "./message";

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
  const token = input.trim().replace(/^Bearer\s+/i, "").trim();
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
