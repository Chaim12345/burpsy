// Lossless rendering of stored HTTP messages.
//
// The API serves every message twice (`MessageView`): `text`, the lossy UTF-8 rendering,
// and `b64`, the exact raw bytes. The lossy rendering is unavoidable on the wire —
// encoding/json replaces any byte that is not valid UTF-8 with U+FFFD — so a Windows-1252
// body or a gzip-compressed body shows up as a wall of replacement characters. This module
// decodes the exact bytes back into what the peer actually sent: it splits the message into
// head and body, decompresses the body per Content-Encoding, decodes it per charset, and
// renders bytes that still are not text as a hex dump. The head is kept verbatim so the
// operator can see the original Content-Encoding/Content-Type declarations next to the
// decoded body — decoding silently is lying.

export interface DecodedMessage {
  text: string;
  encoding: string | null;
  charset: string;
  wasCompressed: boolean;
  failedEncodings: string[];
  binary: boolean;
}

/** b64 -> exact bytes. Decodes in 64 KiB chunks so an atob() of a multi-megabyte body never
 * materialises one giant intermediate string (the UI is a traffic viewer; the bodies it shows
 * are the sizes the store is built to hold). */
export function b64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, "");
  const groups = (clean.length + 3) >> 2;
  const out = new Uint8Array(groups * 3);
  let written = 0;
  const chunk = 0x10000;
  for (let i = 0; i < clean.length; i += chunk) {
    const bin = atob(clean.slice(i, i + chunk));
    for (let j = 0; j < bin.length; j++) out[written++] = bin.charCodeAt(j);
  }
  return out.subarray(0, written);
}

function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder("utf-8").decode(bytes);
}

/** Split an HTTP message at the first blank line. The head (status/request line + headers) is
 * ASCII by construction, so decoding it as UTF-8 loses nothing; the body is kept as bytes. */
export function splitMessage(bytes: Uint8Array): { head: Uint8Array; body: Uint8Array; headText: string } {
  const n = bytes.length;
  for (let i = 0; i + 3 < n; i++) {
    if (bytes[i] === 13 && bytes[i + 1] === 10 && bytes[i + 2] === 13 && bytes[i + 3] === 10) {
      return { head: bytes.subarray(0, i), body: bytes.subarray(i + 4), headText: utf8Decode(bytes.subarray(0, i)) };
    }
  }
  for (let i = 0; i + 1 < n; i++) {
    if (bytes[i] === 10 && bytes[i + 1] === 10) {
      return { head: bytes.subarray(0, i), body: bytes.subarray(i + 2), headText: utf8Decode(bytes.subarray(0, i)) };
    }
  }
  return { head: bytes, body: new Uint8Array(0), headText: utf8Decode(bytes) };
}

/** First value of a header in the head text, case-insensitive, or null. The head is small so
 * splitting it is cheap. */
export function headerValue(headText: string, name: string): string | null {
  const want = name.toLowerCase();
  for (const line of headText.split(/\r?\n/)) {
    const at = line.indexOf(":");
    if (at <= 0) continue;
    if (line.slice(0, at).toLowerCase() === want) return line.slice(at + 1).trim();
  }
  return null;
}

export function charsetFromContentType(contentType: string | null): string | null {
  if (!contentType) return null;
  const m = /charset\s*=\s*"?([^";\s]+)"?/i.exec(contentType);
  return m ? m[1]!.trim() : null;
}

/** Map common legacy aliases to the names TextDecoder understands. WHATWG folds ISO-8859-1 into
 * Windows-1252 (the de-facto byte semantics); the latin1/utf8 spellings are the same game. */
export function normalizeCharset(name: string): string {
  switch (name.trim().toLowerCase()) {
    case "utf8":
    case "unicode-1-1-utf-8":
      return "utf-8";
    case "latin1":
    case "latin-1":
    case "iso-8859-1":
    case "iso8859-1":
    case "iso_8859-1":
      return "windows-1252";
    default:
      return name.trim();
  }
}

function bomCharset(bytes: Uint8Array): string | null {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return "utf-8";
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) return "utf-16le";
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) return "utf-16be";
  return null;
}

function validUtf8(bytes: Uint8Array): boolean {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

/** Charset for a body: a byte-order mark wins, then an explicit charset parameter, then validity
 * (a body that is not valid UTF-8 is almost certainly Windows-1252, the web's dominant legacy
 * single-byte encoding). Never guesses a "default charset" — that hides U+FFFD rather than
 * fixing it. */
export function chooseCharset(bytes: Uint8Array, hint: string | null): string {
  const bom = bomCharset(bytes);
  if (bom) return bom;
  if (hint) return normalizeCharset(hint);
  return validUtf8(bytes) ? "utf-8" : "windows-1252";
}

/** Decode with the chosen charset; an unsupported name falls back to UTF-8 rather than throwing
 * into the render path. */
export function decodeBytes(bytes: Uint8Array, charset: string): string {
  try {
    return new TextDecoder(normalizeCharset(charset)).decode(bytes);
  } catch {
    return new TextDecoder("utf-8").decode(bytes);
  }
}

/** Whether a decoded body is actually text. A body that survived decompression but still contains
 * control characters (NULs, byte-coded EOFs, ...) is binary no matter what its charset header
 * claims; rendering it as text is exactly the U+FFFD wall the decode path exists to remove. */
export function isBinaryText(text: string): boolean {
  if (text.length === 0) return false;
  const n = Math.min(text.length, 512);
  let controls = 0;
  for (let i = 0; i < n; i++) {
    const c = text.charCodeAt(i);
    if (c === 0 || (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || c === 0x7f) controls++;
  }
  return controls / n > 0.1;
}

/** Compact hex dump for binary bodies. Capped: the point is to read the first bytes, not to ship
 * the whole file through innerHTML. */
export function hexDump(bytes: Uint8Array, limit = 8192): string {
  const n = Math.min(bytes.length, limit);
  const rows: string[] = [];
  for (let off = 0; off < n; off += 16) {
    const slice = bytes.subarray(off, Math.min(off + 16, n));
    const hex = Array.from(slice, (b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
    const ascii = Array.from(slice, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    rows.push(`${off.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  |${ascii}|`);
  }
  if (bytes.length > limit) rows.push(`… ${bytes.length - limit} more bytes`);
  return rows.join("\n");
}

function normFormat(enc: string): "gzip" | "deflate" | "brotli" | "zstd" | null {
  switch (enc.trim().toLowerCase()) {
    case "gzip":
    case "x-gzip":
      return "gzip";
    case "deflate":
      return "deflate";
    case "br":
    case "brotli":
      return "brotli";
    case "zstd":
      return "zstd";
    default:
      return null;
  }
}

/** Decompress one content-coding. Returns the input unchanged when the coding is unknown or the
 * runtime cannot do it, so callers can tell the operator honestly rather than dropping the bytes. */
async function decompressOne(body: Uint8Array, enc: string): Promise<{ bytes: Uint8Array; ok: boolean }> {
  const fmt = normFormat(enc);
  if (!fmt) return { bytes: body, ok: false };
  if (typeof DecompressionStream === "undefined") return { bytes: body, ok: false };
  try {
    const stream = new Blob([body as unknown as BlobPart]).stream().pipeThrough(new DecompressionStream(fmt as never));
    const buf = await new Response(stream).arrayBuffer();
    return { bytes: new Uint8Array(buf), ok: true };
  } catch {
    return { bytes: body, ok: false };
  }
}

/** Human summary of what the decode path did, or "" when nothing is worth saying. Shown next to
 * the response so the operator always knows the bytes were transformed, never silently. */
export function decodeNote(d: DecodedMessage): string {
  const parts: string[] = [];
  if (d.wasCompressed) parts.push(`decompressed ${d.encoding}`);
  if (d.failedEncodings.length) parts.push(`could not decode ${d.failedEncodings.join(", ")}`);
  if (d.charset !== "utf-8") parts.push(`charset ${d.charset}`);
  if (d.binary) parts.push("binary — hex dump");
  return parts.join(" · ");
}

/** The full pipeline for a stored message: bytes -> split -> decompress (Content-Encoding lists
 * application order, so decoding runs in reverse) -> charset -> text or hex dump. The head is
 * returned verbatim so syntax highlighting shows the original headers beside the decoded body. */
export async function decodeMessageB64(b64: string): Promise<DecodedMessage> {
  const bytes = b64ToBytes(b64);
  const { body, headText } = splitMessage(bytes);

  const contentType = headerValue(headText, "Content-Type");
  const encodingHeader = headerValue(headText, "Content-Encoding");
  const encodings = (encodingHeader ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "" && s.toLowerCase() !== "identity");

  let bodyBytes = body;
  const applied: string[] = [];
  const failed: string[] = [];
  for (let i = encodings.length - 1; i >= 0; i--) {
    const enc = encodings[i]!;
    const { bytes: out, ok } = await decompressOne(bodyBytes, enc);
    if (ok) {
      bodyBytes = out;
      applied.unshift(enc);
    } else {
      failed.unshift(enc);
    }
  }

  const charset = chooseCharset(bodyBytes, charsetFromContentType(contentType));
  const decoded = decodeBytes(bodyBytes, charset);
  const binary = isBinaryText(decoded);
  const bodyText = binary ? hexDump(bodyBytes) : decoded;

  return {
    text: headText + "\r\n\r\n" + bodyText,
    encoding: encodings.length ? encodings.join(", ") : null,
    charset,
    wasCompressed: applied.length > 0,
    failedEncodings: failed,
    binary,
  };
}
