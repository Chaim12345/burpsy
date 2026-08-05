/**
 * Raw HTTP message parsing, shared by the editor's Pretty/Hex views and the
 * Inspector. Everything here works on the exact bytes the server captured — it
 * never re-serialises a message, because the whole point of a proxy tool is that
 * what you see is what went over the wire.
 */

export interface ParsedMessage {
  startLine: string;
  headers: [string, string][];
  body: string;
  /** Byte offset in the original string where the body begins. */
  bodyOffset: number;
}

export function parseMessage(raw: string): ParsedMessage {
  const separator = /\r?\n\r?\n/.exec(raw);
  const headEnd = separator ? separator.index : raw.length;
  const bodyOffset = separator ? separator.index + separator[0].length : raw.length;
  const head = raw.slice(0, headEnd);
  const lines = head.split(/\r?\n/);
  const startLine = lines[0] ?? "";
  const headers: [string, string][] = [];
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    headers.push([line.slice(0, colon).trim(), line.slice(colon + 1).trim()]);
  }
  return { startLine, headers, body: raw.slice(bodyOffset), bodyOffset };
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

/** Name/value pairs from a query string or an urlencoded body. */
export function parsePairs(input: string): [string, string][] {
  const out: [string, string][] = [];
  for (const chunk of input.split("&")) {
    if (!chunk) continue;
    const equals = chunk.indexOf("=");
    const name = equals < 0 ? chunk : chunk.slice(0, equals);
    const value = equals < 0 ? "" : chunk.slice(equals + 1);
    out.push([safeDecode(name), safeDecode(value)]);
  }
  return out;
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
      return equals < 0 ? ([chunk.trim(), ""] as [string, string]) : ([chunk.slice(0, equals).trim(), chunk.slice(equals + 1).trim()] as [string, string]);
    })
    .filter(([name]) => name !== "");
}

export function bodyParamsOf(body: string, contentType: string | undefined): [string, string][] {
  if (!body.trim()) return [];
  const type = (contentType ?? "").toLowerCase();
  if (type.includes("application/x-www-form-urlencoded")) return parsePairs(body.trim());
  if (type.includes("json")) {
    try {
      const parsed: unknown = JSON.parse(body);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return Object.entries(parsed as Record<string, unknown>).map(([key, value]) => [
          key,
          typeof value === "object" ? JSON.stringify(value) : String(value),
        ]);
      }
    } catch {
      return [];
    }
  }
  return [];
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
    } catch {
      pretty = null;
    }
  } else if (type.includes("xml") || type.includes("html") || /^\s*<[a-z!?]/i.test(body)) {
    pretty = prettyMarkup(body);
  }

  if (pretty === null) return raw;
  void startLine;
  return raw.slice(0, bodyOffset) + pretty;
}

function looksLikeJson(body: string): boolean {
  const trimmed = body.trim();
  return (trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"));
}

function prettyMarkup(input: string): string {
  const withBreaks = input.replace(/></g, ">\n<");
  let depth = 0;
  return withBreaks
    .split("\n")
    .map((line) => {
      const trimmed = line.trim();
      if (/^<\/[^>]+>/.test(trimmed)) depth = Math.max(0, depth - 1);
      const indented = "  ".repeat(depth) + trimmed;
      const opens = /^<[^/!?][^>]*[^/]>$/.test(trimmed) && !/^<(area|base|br|col|embed|hr|img|input|link|meta|source|track|wbr)\b/i.test(trimmed);
      if (opens) depth += 1;
      return indented;
    })
    .join("\n");
}

/** Classic 16-byte-per-line dump with an ASCII gutter, like Burp's Hex view. */
export function hexDump(input: string): string {
  const bytes = new TextEncoder().encode(input);
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
