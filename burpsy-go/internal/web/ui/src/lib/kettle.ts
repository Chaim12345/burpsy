/**
 * Kettled HTTP/2 requests in Repeater (burpsy-react-ui-jae5).
 *
 * Burp calls an HTTP/2 request "kettled" when an Inspector edit makes its header list something HTTP/1
 * text cannot show without losing information — a CR/LF inside a value, an uppercase name, a second
 * :path. From then on the header list, not the text, is the request: Burp shows "This request is kettled
 * because:" with the reasons in place of the headers, keeps the body editable, and sends the list
 * exactly as edited.
 *
 * burpsy's tab carries that list as `RepeaterTab.h2Headers`. This file is the client half of the model:
 *
 *   - `seedH2Fields` turns the HTTP/1-shaped draft into the field list a kettling edit starts from, and
 *     says which list entry each Inspector header row became, so the edit lands on the right field.
 *   - `renderNormalised` is the HTTP/1 text the tab keeps beside the list. It is what Burp calls
 *     normalising: what a downgrade, To Intruder or any raw-text edit falls back to, with every change
 *     HTTP/1 cannot carry discarded. Keeping it current means the draft text is never stale — if the list
 *     is dropped, the text is the list as near as HTTP/1 can say it, not whatever was typed before.
 *   - `requestHeadChanged` is what the store's chokepoint asks: an edit that changed the head of the text
 *     without supplying a list is an edit to the text, and the list it no longer matches is dropped
 *     (the shadow-copy lesson — a cached copy the send prefers over the field the operator edited is the
 *     one way an edit is silently lost).
 *
 * Whether a list is kettled, and whether it would be refused, is the server's answer
 * (POST /api/http2/kettle, internal/http2's KettleReasons and Authorise) — never re-derived here.
 */
import { headerSpans, parseMessage, parseRequestLine } from "./message";

export interface H2Field {
  name: string;
  value: string;
}

export interface KettleReason {
  kind: string;
  index: number;
  name: string;
  text: string;
}

/** POST /api/http2/kettle's answer. */
export interface KettleAnswer {
  kettled: boolean;
  reasons: KettleReason[];
  send_refusals: string[];
}

/** The request draft's version token is HTTP/2. */
export function isHttp2Request(raw: string): boolean {
  return parseRequestLine(parseMessage(raw).startLine)?.version === "HTTP/2";
}

/** The pseudo-header names, in the order a seeded list carries them. */
const PSEUDO_ORDER = [":method", ":scheme", ":authority", ":path"] as const;

/**
 * The HTTP/2 field list an HTTP/1-shaped draft describes, and where each header row went.
 *
 * Pseudo-headers first (:method, :scheme from the target, :authority from the first Host, :path), then
 * every other header in order with its name lowercased — an uppercase name is itself a kettle reason,
 * and seeding one would kettle the request before the operator had changed anything. Nothing is dropped
 * or added beyond that: the list is what will be sent, and a Connection header is the tab's Strip
 * Connection setting's business, as it is for a text send.
 *
 * `headerRowField[i]` is the list index Inspector header row i became (the first Host row maps to
 * :authority).
 */
export function seedH2Fields(raw: string, tls: boolean): { fields: H2Field[]; headerRowField: number[] } {
  const request = parseRequestLine(parseMessage(raw).startLine);
  const spans = headerSpans(raw);
  const hostRow = spans.findIndex((span) => span.name.toLowerCase() === "host");
  const pseudo: Record<(typeof PSEUDO_ORDER)[number], string | undefined> = {
    ":method": request?.method ?? "GET",
    ":scheme": tls ? "https" : "http",
    ":authority": hostRow >= 0 ? spans[hostRow]!.value : undefined,
    ":path": request?.target || "/",
  };
  const fields: H2Field[] = [];
  const at: Partial<Record<string, number>> = {};
  for (const name of PSEUDO_ORDER) {
    const value = pseudo[name];
    if (value === undefined) continue;
    at[name] = fields.length;
    fields.push({ name, value });
  }
  const headerRowField = spans.map((span, row) => {
    if (row === hostRow) return at[":authority"]!;
    fields.push({ name: span.name.toLowerCase(), value: span.value });
    return fields.length - 1;
  });
  return { fields, headerRowField };
}

/** CR and LF removed — what normalising does to a field HTTP/1 cannot carry. */
function flatten(text: string): string {
  return text.replace(/[\r\n]/g, "");
}

/**
 * The HTTP/1-shaped text a field list normalises to, with `body` after it.
 *
 * The first :method and :path make the request line (version HTTP/2, so the tab stays an HTTP/2 tab),
 * the first :authority the Host header, and every regular field a line of its own with CR and LF
 * removed. Other pseudo-headers — a second :path, an unknown :protocol — and any name with a colon in it
 * have no HTTP/1 form and are dropped. Several `cookie` fields are joined with "; " into one Cookie line,
 * which is what RFC 9113 §8.2.3 says passing them to HTTP/1 means.
 */
export function renderNormalised(fields: H2Field[], body: string): string {
  const first = (name: string) => fields.find((field) => field.name.toLowerCase() === name)?.value;
  const method = flatten(first(":method") ?? "GET").replace(/ /g, "") || "GET";
  const path = flatten(first(":path") ?? "/").replace(/ /g, "%20") || "/";
  const authority = first(":authority");
  const lines = [`${method} ${path} HTTP/2`];
  if (authority !== undefined) lines.push(`Host: ${flatten(authority)}`);
  const cookies = fields.filter((field) => field.name.toLowerCase() === "cookie").map((field) => flatten(field.value));
  let cookieWritten = false;
  for (const field of fields) {
    const name = flatten(field.name);
    if (name === "" || name.includes(":")) continue;
    if (name.toLowerCase() === "cookie") {
      if (cookieWritten) continue;
      cookieWritten = true;
      lines.push(`${name}: ${cookies.join("; ")}`);
      continue;
    }
    lines.push(`${name}: ${flatten(field.value)}`);
  }
  return `${lines.join("\r\n")}\r\n\r\n${body}`;
}

/** The body of a draft: everything after its head. */
export function requestBody(raw: string): string {
  return raw.slice(parseMessage(raw).bodyOffset);
}

/** Whether two drafts differ anywhere before the body. */
export function requestHeadChanged(before: string, after: string): boolean {
  return before.slice(0, parseMessage(before).bodyOffset) !== after.slice(0, parseMessage(after).bodyOffset);
}

/**
 * The list after a header row was edited in a way that kettles it: the draft seeded, then the one field
 * that row became replaced. The name is kept as seeded (lowercase) unless the operator changed it, so an
 * edit to a value alone never adds an uppercase-name reason the operator did not ask for.
 */
export function kettleHeaderEdit(raw: string, tls: boolean, row: number, originalName: string, name: string, value: string): H2Field[] {
  const { fields, headerRowField } = seedH2Fields(raw, tls);
  const index = headerRowField[row];
  if (index === undefined) return fields;
  const seeded = fields[index]!;
  const renamed = name !== originalName;
  fields[index] = { name: renamed ? name : seeded.name, value };
  return fields;
}
