/**
 * Burp's "Change body encoding": convert a request body between form
 * URL-encoding, multipart encoding and JSON.
 *
 * This is a different operation from the chunked-framing toggle in actions.ts,
 * which only swaps Content-Length for Transfer-Encoding and leaves the body's
 * *encoding* alone. Both are useful and both now carry their own label
 * (burpsy-react-ui-wv5).
 *
 * # The model
 *
 * All three encodings are a list of name/value pairs, so a conversion is
 * read-into-pairs then write-from-pairs. Order is preserved in every direction
 * and duplicates survive form <-> multipart, because a parameter an operator
 * cannot see is a parameter they cannot test.
 *
 * # Refusal over a half-conversion
 *
 * Every reader refuses rather than guessing, and the reason is written for the
 * operator to read in a toast. A body that is silently half-converted is worse
 * than no conversion at all: the request still looks sendable, so the operator
 * learns something false about the server. The refusals are listed on
 * `changeBodyEncoding` below.
 *
 * # Declared normalisations
 *
 * A conversion is not always byte-reversible, and the parts that are not are
 * stated here rather than discovered later. Each one has a test named after it
 * in body-encoding.test.ts.
 *
 * 1. The form writer canonicalises percent-encoding: it decodes and re-encodes
 *    with `encodeURIComponent`, so `+` becomes `%20`, lowercase escapes become
 *    uppercase, and a needless escape is dropped. This is the same trade
 *    `encodePair` in message.ts already makes for a single edited parameter.
 * 2. The JSON writer emits every value as a JSON *string*, because a form or
 *    multipart body carries no types. `{"a":1}` -> form -> JSON is `{"a":"1"}`.
 *    Refusing instead would block the probe this exists for, so the loss is
 *    declared and tested rather than hidden.
 * 3. The JSON writer is compact (no spaces, no newlines) and escapes with
 *    `JSON.stringify`.
 * 4. The multipart writer generates its own boundary — a fixed literal,
 *    extended until it appears nowhere in the data — uses CRLF, and writes one
 *    `Content-Disposition` line per part. An incoming boundary is therefore not
 *    preserved across a conversion away from multipart and back.
 *
 * Round trips that ARE byte-exact, and are asserted as such: form <-> multipart
 * on a canonical form body, and compact all-string JSON -> form -> JSON and
 * JSON -> multipart -> JSON.
 */

import { addHeader, byteLength, headerValue, jsonMemberSpans, pairSpans, parseMessage, setBody, setHeaderAt } from "./message";

export type BodyEncoding = "urlencoded" | "multipart" | "json";

/** Menu order, and the only three Burp offers. */
export const BODY_ENCODINGS: BodyEncoding[] = ["urlencoded", "multipart", "json"];

export const BODY_ENCODING_LABELS: Record<BodyEncoding, string> = {
 urlencoded: "Form URL-encoded",
 multipart: "Multipart form",
 json: "JSON",
};

export type BodyEncodingResult = { ok: true; raw: string } | { ok: false; reason: string };

type Pairs = [string, string][];
type Read = { ok: true; pairs: Pairs } | { ok: false; reason: string };
type Written = { ok: true; body: string; contentType: string } | { ok: false; reason: string };

const refuse = (reason: string): { ok: false; reason: string } => ({ ok: false, reason });

/**
 * Which of the three encodings a message's body is in, read from Content-Type
 * alone. Deliberately no sniffing: `a=1&b=2` under `text/plain` is a plain-text
 * body that happens to look like a form, and re-encoding it would be the tool
 * inventing a content type the operator never set.
 */
export function detectBodyEncoding(raw: string): BodyEncoding | null {
 const type = (headerValue(parseMessage(raw).headers, "content-type") ?? "").toLowerCase();
 if (type.includes("application/x-www-form-urlencoded")) return "urlencoded";
 if (type.includes("multipart/form-data")) return "multipart";
 if (type.includes("json")) return "json";
 return null;
}

/* ---- reading ------------------------------------------------------------- */

/**
 * A urlencoded body, exactly as written. Not trimmed: a trailing newline is a
 * byte of the last value and survives as `%0D%0A` rather than vanishing.
 */
function readUrlencoded(body: string): Read {
 const segments = body.split("&");
 if (segments.some((segment) => segment === "")) {
  return refuse("the form body has an empty parameter (a stray or doubled '&'), which no other encoding can carry");
 }
 if (segments.some((segment) => !segment.includes("="))) {
  return refuse("a form parameter has no '=', and giving it an empty value would change what is sent");
 }
 // pairSpans decodes through message.ts's `safeDecode`, which returns the input UNCHANGED when
 // decodeURIComponent throws. That is right for the Inspector, which only displays it, and wrong
 // here: `q=%FF` would come back as the literal text "%FF" and be re-encoded as "q=%25FF" — a
 // different request, sent without a word. A raw-byte escape is a deliberate probe, so the
 // conversion refuses rather than doubling it.
 for (const segment of segments) {
  const equals = segment.indexOf("=");
  for (const half of [segment.slice(0, equals), segment.slice(equals + 1)]) {
   try {
    decodeURIComponent(half.replace(/\+/g, " "));
   } catch {
    return refuse(
     "the form body holds a percent-escape that does not decode as UTF-8 text, so re-encoding it would change the bytes that are sent",
    );
   }
  }
 }
 return { ok: true, pairs: pairSpans(body).map(({ name, value }) => [name, value] as [string, string]) };
}

/** The `boundary` parameter of a multipart Content-Type, quoted or bare. */
function boundaryOf(contentType: string): string | null {
 const match = /;\s*boundary=("([^"]*)"|[^;\s]+)/i.exec(contentType);
 if (!match) return null;
 const value = match[2] ?? match[1] ?? "";
 return value === "" ? null : value;
}

/**
 * A multipart/form-data body. Strict on purpose — every shape this refuses is
 * one where a conversion would drop something the operator put there: a file
 * part carries a filename and a type that no form or JSON body can express, and
 * a preamble or epilogue is bytes between the parts that the pair list has
 * nowhere to keep.
 */
function readMultipart(body: string, contentType: string): Read {
 const boundary = boundaryOf(contentType);
 if (!boundary) return refuse("the multipart Content-Type has no boundary parameter, so its parts cannot be located");
 const delimiter = `--${boundary}`;
 if (!body.startsWith(delimiter)) return refuse("the multipart body does not start at its first boundary (a preamble would be lost)");
 const segments = `\r\n${body}`.split(`\r\n${delimiter}`);
 const closing = segments.pop();
 if (closing === undefined || !closing.startsWith("--")) return refuse("the multipart body has no closing boundary, so it is truncated");
 if (closing.slice(2).replace(/\r\n$/, "") !== "")
  return refuse("the multipart body has an epilogue after its closing boundary, which no other encoding can carry");
 segments.shift(); // the empty string before the first delimiter
 if (segments.length === 0) return refuse("the multipart body has no parts to convert");
 const pairs: Pairs = [];
 for (const segment of segments) {
  if (!segment.startsWith("\r\n"))
   return refuse("a multipart boundary line carries trailing characters, so the part it opens cannot be read");
  const part = segment.slice(2);
  const split = part.indexOf("\r\n\r\n");
  if (split < 0) return refuse("a multipart part has no blank line between its headers and its content");
  const lines = part.slice(0, split).split("\r\n");
  if (lines.length !== 1)
   return refuse("a multipart part carries headers beyond Content-Disposition (a per-part type or encoding cannot survive the conversion)");
  const header = lines[0] ?? "";
  if (!/^content-disposition:\s*form-data\s*;/i.test(header))
   return refuse("a multipart part is not a form-data part, so it has no parameter name");
  if (/;\s*filename\*?=/i.test(header)) return refuse("a multipart part is a file upload, which a form or JSON body cannot carry");
  const named = /^content-disposition:\s*form-data;\s*name="([^"]*)"$/i.exec(header);
  if (!named) {
   // Anchored end-to-end on purpose: a disposition carrying a further parameter — a charset, a
   // size — would have it dropped on the rewrite, and a dropped parameter is the silent loss
   // this module exists to refuse.
   return refuse(
    'a multipart part\'s Content-Disposition is not exactly form-data with a quoted name="...", so rewriting it would drop something',
   );
  }
  const name = named[1] ?? "";
  if (/[\r\n]/.test(name)) return refuse("a multipart part name contains a line break");
  pairs.push([name, part.slice(split + 4)]);
 }
 return { ok: true, pairs };
}

/**
 * A JSON object body, in source order.
 *
 * `jsonMemberSpans` supplies the order and the value source text — never
 * `Object.entries`, which hoists integer-like keys and would reorder
 * `{"b":1,"2":2}`. `JSON.parse` is used only to decide validity and shape, and
 * to catch the duplicate members it collapses and the scanner does not.
 */
function readJson(body: string): Read {
 let parsed: unknown;
 try {
  parsed = JSON.parse(body);
 } catch {
  return refuse("the body is not valid JSON");
 }
 if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
  return refuse("the JSON body's top level is not an object, so it has no named parameters");
 }
 const spans = jsonMemberSpans(body);
 const names = Object.keys(parsed as Record<string, unknown>);
 if (names.length === 0) return refuse("the JSON body has no members to convert");
 if (spans.length > names.length) return refuse("the JSON body has duplicate member names, and only one of each would survive");
 if (spans.length !== names.length) return refuse("the JSON body could not be read member by member without losing one");
 const pairs: Pairs = [];
 for (const { name, source } of spans) {
  if (source.startsWith("{") || source.startsWith("[")) {
   return refuse(`the JSON member "${name}" holds an object or an array, which a form body has no way to express`);
  }
  if (source.startsWith('"')) {
   pairs.push([name, JSON.parse(source) as string]);
  } else {
   // A number, true, false or null keeps the text the operator wrote.
   pairs.push([name, source]);
  }
 }
 return { ok: true, pairs };
}

/* ---- writing ------------------------------------------------------------- */

function writeUrlencoded(pairs: Pairs): Written {
 // encodeURIComponent THROWS on a lone surrogate — reachable from a JSON body, where
 // {"a":"\ud800"} is valid. An exception here would escape the Repeater click handler, so it
 // becomes a refusal like every other shape this cannot carry.
 let body: string;
 try {
  body = pairs.map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`).join("&");
 } catch {
  return refuse("a parameter holds an unpaired surrogate, which has no percent-encoding");
 }
 return { ok: true, body, contentType: "application/x-www-form-urlencoded" };
}

const BOUNDARY_SEED = "----burpsyBodyEncoding";

/**
 * A boundary that appears nowhere in the data, chosen deterministically so the
 * same request converts to the same bytes every time — a boundary with a random
 * tail would make two conversions of one request diff against each other.
 */
function freeBoundary(pairs: Pairs): string {
 let boundary = BOUNDARY_SEED;
 const collides = () => pairs.some(([name, value]) => name.includes(`--${boundary}`) || value.includes(`--${boundary}`));
 while (collides()) boundary += "x";
 return boundary;
}

function writeMultipart(pairs: Pairs): Written {
 for (const [name] of pairs) {
  if (/["\r\n]/.test(name)) {
   return refuse(`the parameter name "${name}" contains a quote or a line break, which a multipart part name cannot quote`);
  }
 }
 const boundary = freeBoundary(pairs);
 const parts = pairs.map(([name, value]) => `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`);
 return { ok: true, body: `${parts.join("")}--${boundary}--\r\n`, contentType: `multipart/form-data; boundary=${boundary}` };
}

/**
 * Built by concatenation rather than `JSON.stringify(Object.fromEntries(pairs))`
 * for the reason message.ts documents about `Object.entries`: an object literal
 * hoists integer-like keys, so `{"b":..,"2":..}` would come back reordered and
 * the operator would be sending a different request from the one they converted.
 */
function writeJson(pairs: Pairs): Written {
 const seen = new Set<string>();
 for (const [name] of pairs) {
  if (seen.has(name)) return refuse(`the parameter "${name}" appears more than once, and a JSON object can only keep one of them`);
  seen.add(name);
 }
 const members = pairs.map(([name, value]) => `${JSON.stringify(name)}:${JSON.stringify(value)}`);
 return { ok: true, body: `{${members.join(",")}}`, contentType: "application/json" };
}

/** Replace Content-Type in place, keeping the header's position and its name's casing. */
function setContentType(raw: string, value: string): string {
 const { headers } = parseMessage(raw);
 const index = headers.findIndex(([name]) => name.toLowerCase() === "content-type");
 if (index < 0) return addHeader(raw, "Content-Type", value);
 return setHeaderAt(raw, index, headers[index]![0], value);
}

/**
 * Convert a whole request between body encodings, adjusting Content-Type and
 * Content-Length, or refuse with a reason the operator can read.
 *
 * It refuses when: the message has no body; it declares two Content-Type
 * headers; it carries Transfer-Encoding (the chunk framing owns the body, so it
 * has to be dechunked first); its Content-Type is not one of the three; it is
 * already in the target encoding; the body holds bytes the text view could not
 * represent; or the source body has a shape the pair list cannot hold without
 * losing something — see each reader for those — or a value the target encoding has no way to
 * write, which is `writeUrlencoded`'s unpaired surrogate and `writeMultipart`'s quoted name.
 */
export function changeBodyEncoding(raw: string, target: BodyEncoding): BodyEncodingResult {
 const { headers, body } = parseMessage(raw);
 if (headers.filter(([name]) => name.toLowerCase() === "content-type").length > 1) {
  return refuse("the request declares two Content-Type headers, so which one describes the body is ambiguous");
 }
 if (headerValue(headers, "transfer-encoding") !== undefined) {
  return refuse("the request is chunked, and the chunk framing owns the body — undo it with “Toggle chunked transfer framing” first");
 }
 if (body === "") return refuse("the request has no body to re-encode");
 // fetchRaw hands us the server's text view of the bytes. U+FFFD means that
 // view already lost something, and re-encoding would write the loss back.
 if (body.includes("�")) return refuse("the body holds bytes the text view could not represent, so re-encoding it would corrupt them");
 const source = detectBodyEncoding(raw);
 if (source === null) {
  const type = headerValue(headers, "content-type");
  return refuse(
   type
    ? `the body's Content-Type (${type}) is not a form, multipart or JSON body`
    : "the request has no Content-Type, so what its body is cannot be known",
  );
 }
 if (source === target) return refuse(`the body is already ${BODY_ENCODING_LABELS[target]}`);

 const contentType = headerValue(headers, "content-type") ?? "";
 const read = source === "urlencoded" ? readUrlencoded(body) : source === "multipart" ? readMultipart(body, contentType) : readJson(body);
 if (!read.ok) return read;
 const written =
  target === "urlencoded" ? writeUrlencoded(read.pairs) : target === "multipart" ? writeMultipart(read.pairs) : writeJson(read.pairs);
 if (!written.ok) return written;

 const next = setContentType(setBody(raw, written.body), written.contentType);
 // setBody goes through fixContentLength, so this only fires if that contract
 // ever changes. A body whose declared length is wrong is a body the peer
 // truncates, which is the one failure that must not be silent.
 if (headerValue(parseMessage(next).headers, "content-length") !== String(byteLength(written.body))) {
  return refuse("the converted request's Content-Length did not come out matching its body, so it was not applied");
 }
 return { ok: true, raw: next };
}
