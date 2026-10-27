import { ROUTE_GATED } from "./gated-routes";

export class ApiError extends Error {
 constructor(
  message: string,
  readonly status: number,
  readonly body: string,
 ) {
  super(message);
  this.name = "ApiError";
 }
}

/** Go handlers answer with either a bare string or {"error": "..."}; show whichever we get. */
function readFailure(text: string, fallback: string): string {
 const trimmed = text.trim();
 if (!trimmed) return fallback;
 if (trimmed.startsWith("{")) {
  try {
   const parsed = JSON.parse(trimmed) as { error?: unknown; message?: unknown };
   const detail = parsed.error ?? parsed.message;
   if (typeof detail === "string" && detail) return detail;
  } catch {
   return trimmed;
  }
 }
 return trimmed;
}

/** The header the confirmation gate (internal/web/confirm_gate.go) reads a spent token from. */
export const CONFIRM_HEADER = "X-Burpsy-Confirm";

/**
 * The manifest pattern a path resolves to, by the gate's own rule (routeRiskFor and patternMatches in
 * confirm_gate.go): among the patterns the path falls under, the one with the most literal text
 * (the mux's literal-beats-wildcard rule), "/" matching everything. Over every pattern, gated or
 * not, because an ungated pattern can be the most specific match under a gated one.
 *
 * Patterns are in their mux spelling: "{x...}" as the last segment is the remainder (the prefix
 * subtree, empty and nested paths included), "{x}" is one non-empty segment, "{$}" anchors the one
 * path with the trailing slash. A tie in literal text is a conflict the mux would not have let
 * through; the server then picks the more severe risk class, which this table does not carry, so
 * the client fails closed the same way: the gated entry, then the pattern string.
 */
export function manifestPatternFor(path: string, table: Readonly<Record<string, boolean>> = ROUTE_GATED): string | undefined {
 let best: string | undefined;
 for (const pattern of Object.keys(table)) {
  if (pattern !== "/" && !patternMatches(pattern, path)) continue;
  if (best === undefined) {
   best = pattern;
   continue;
  }
  const mine = literalLen(pattern);
  const theirs = literalLen(best);
  if (
   mine > theirs ||
   (mine === theirs && (Boolean(table[pattern]) > Boolean(table[best]) || (table[pattern] === table[best] && pattern < best)))
  )
   best = pattern;
 }
 return best;
}

/** A pattern's literal text: its length with every {wildcard} removed (confirm_gate.go literalLen). */
function literalLen(pattern: string): number {
 return pattern.replace(/\{[^}]*\}/g, "").length;
}

/** Whether `path` falls under `pattern` (confirm_gate.go patternMatches). */
function patternMatches(pattern: string, path: string): boolean {
 // A trailing "{name...}" is the remainder wildcard: it resolves as the subtree, the prefix up to
 // and including its last slash.
 const slash = pattern.lastIndexOf("/");
 if (slash >= 0 && pattern.endsWith("...}") && pattern.slice(slash + 1).startsWith("{")) pattern = pattern.slice(0, slash + 1);
 if (pattern.endsWith("/{$}")) {
  const p = pattern.slice(0, -"{$}".length).split("/");
  const a = path.split("/");
  return a.length === p.length && segmentsMatch(p, a);
 }
 if (!pattern.includes("{")) return hasSegmentPrefix(path, pattern);
 const subtree = pattern.endsWith("/");
 const p = (subtree ? pattern.slice(0, -1) : pattern).split("/");
 const a = path.split("/");
 if (subtree) return a.length >= p.length && segmentsMatch(p, a.slice(0, p.length));
 return a.length === p.length && segmentsMatch(p, a);
}

/** A "{...}" segment matches one non-empty segment; anything else must be equal. */
function segmentsMatch(patternSegments: string[], pathSegments: string[]): boolean {
 return patternSegments.every((seg, i) => (seg.startsWith("{") && seg.endsWith("}") ? pathSegments[i] !== "" : seg === pathSegments[i]));
}

function hasSegmentPrefix(path: string, pattern: string): boolean {
 if (!path.startsWith(pattern)) return false;
 return path.length === pattern.length || pattern.endsWith("/") || path[pattern.length] === "/";
}

/** The gated pattern a mutating call to `url` must carry a confirmation for, or undefined. */
export function gatedPatternFor(url: string, table: Readonly<Record<string, boolean>> = ROUTE_GATED): string | undefined {
 const path = new URL(url, "http://console.invalid").pathname;
 // A mint request is not a gated call: the gate answers `<gated pattern>/confirm` from its mint
 // mux before resolving risk, so minting for it would be minting for the mint.
 if (path.endsWith("/confirm")) {
  const stripped = path.slice(0, -"/confirm".length);
  if (table[stripped] || table[`${stripped}/`]) return undefined;
 }
 const pattern = manifestPatternFor(path, table);
 return pattern !== undefined && table[pattern] ? pattern : undefined;
}

/** Where the gate mints for a pattern: one /confirm per pattern, shared by an `/x` + `/x/` pair. */
export function confirmUrlFor(pattern: string): string {
 return `${pattern.replace(/\/+$/, "")}/confirm`;
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);

/**
 * The call a confirmation is bound to, as the server resolved it — what the approver is shown.
 * Mirrors confirmPreview in internal/web/confirm_binding.go.
 */
export interface ConfirmedCallPreview {
 method: string;
 /** The path plus the canonical query, secret-looking query values withheld (listed in `redacted` as "?name"). For reading. */
 url: string;
 /** The decoded path exactly as bound, never redacted. */
 path?: string;
 body_bytes: number;
 body_sha256: string;
 body_kind: "none" | "json" | "text" | "binary";
 /** Pretty-printed JSON (secret-named members withheld) or text; absent for none/binary. */
 body?: string;
 body_truncated?: boolean;
 /** JSON members whose values the preview withheld; the hash still covers them. */
 redacted?: string[];
}

/** A minted confirmation: the token, the digest it is bound to, and the server's preview of the call. */
export interface MintedConfirmation {
 token: string;
 binding: string;
 call: ConfirmedCallPreview;
 /** Epoch ms after which the server no longer accepts the token. */
 expiresAt: number;
}

/** The mint request body: the call the token will authorise (confirmCall in confirm_binding.go). */
export interface CallDescription {
 method: string;
 url: string;
 body?: string;
 body_base64?: string;
}

function base64OfBytes(bytes: Uint8Array): string {
 let binary = "";
 for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
 return btoa(binary);
}

/**
 * Describe the call `fetch(url, init)` will send, for a mint (burpsy-react-ui-e0yq).
 *
 * The token is bound to exactly this request — method, path and query, and body — so the body is
 * described in the bytes fetch will send. A body fetch serialises with bytes this side never sees (a
 * FormData, whose multipart boundary the browser picks at send time, or a stream) cannot be described
 * and is refused here rather than minted for something else.
 */
export async function describeCall(url: string, init: RequestInit = {}): Promise<CallDescription> {
 const parsed = new URL(url, "http://console.invalid");
 const description: CallDescription = { method: (init.method ?? "GET").toUpperCase(), url: `${parsed.pathname}${parsed.search}` };
 const body = init.body;
 if (body === undefined || body === null) return description;
 if (typeof body === "string") description.body = body;
 else if (body instanceof URLSearchParams) description.body = body.toString();
 else if (body instanceof Blob) description.body_base64 = base64OfBytes(new Uint8Array(await body.arrayBuffer()));
 else if (body instanceof ArrayBuffer) description.body_base64 = base64OfBytes(new Uint8Array(body));
 else if (ArrayBuffer.isView(body)) description.body_base64 = base64OfBytes(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
 else
  throw new ApiError("this request's body is assembled by the browser at send time, so it cannot be confirmed as the exact call", 0, "");
 return description;
}

/**
 * Mint a one-time confirmation for the one call `fetch(url, init)` will make.
 *
 * The token is bound to that call (burpsy-react-ui-e0yq: method, path, query and body; a token tried
 * on any other request — or any other route — is refused and burned), lives 60 seconds and is spent
 * by one call. The answer carries the server's preview of the call, which is what an approver is
 * shown. A raw fetch rather than `api()`, because `/x/confirm` itself resolves under a gated `/x/`
 * subtree and `api()` would try to mint for the mint.
 */
export async function mintConfirmation(url: string, init: RequestInit = {}): Promise<MintedConfirmation> {
 const pattern = gatedPatternFor(url) ?? new URL(url, "http://console.invalid").pathname;
 const description = await describeCall(url, init);
 const response = await fetch(confirmUrlFor(pattern), {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(description),
  cache: "no-store",
 });
 const text = await response.text();
 if (!response.ok) throw new ApiError(readFailure(text, response.statusText), response.status, text);
 let parsed: Partial<{ token: string; binding: string; call: ConfirmedCallPreview; expires_in: number }> = {};
 try {
  parsed = JSON.parse(text) as typeof parsed;
 } catch {
  parsed = {};
 }
 if (!parsed.token || !parsed.binding || !parsed.call)
  throw new ApiError("the confirmation endpoint returned no token bound to a call", response.status, text);
 return { token: parsed.token, binding: parsed.binding, call: parsed.call, expiresAt: Date.now() + (parsed.expires_in ?? 60) * 1000 };
}

/** The operator declined the previewed call; nothing was sent. Callers treat it as a cancel, not a failure. */
export class ConfirmationDeclined extends Error {
 constructor() {
  super("the call was not confirmed, and nothing was sent");
  this.name = "ConfirmationDeclined";
 }
}

/** Options for a gated call. */
export interface GatedOptions {
 /**
  * Show the operator the server's preview of the exact call and resolve whether they approve it. The
  * call is sent only on true; false throws ConfirmationDeclined. Without it the click that led here
  * is the approval, as before — the token is still bound to the exact call.
  */
 approve?: (call: ConfirmedCallPreview) => Promise<boolean>;
}

/** How close to expiry a token may be and still be spent, rather than re-minted, after a preview. */
const REMINT_MARGIN_MS = 5000;

/**
 * `fetch` for the console: a mutating call (anything but GET/HEAD/OPTIONS/TRACE — the gate's own
 * methodMutates rule) to a route the server gates (scope, attack, credential, destructive) first
 * mints a confirmation for exactly that call and sends it (burpsy-react-ui-p1uz, e0yq).
 *
 * Why in the client and not at each call site: the gate landed (cc972e0) after most of the console
 * was written, and a dozen operator actions — Regenerate CA, Back up now, every scope edit, rule
 * saves and deletes — silently became 428s. One rule here, driven by a table generated from the Go
 * manifest (gated-routes.ts, drift-tested), means a newly gated route cannot regress the same way.
 *
 * With `options.approve`, the server's preview of the call is put in front of the operator before
 * anything is sent. An operator who takes longer than the token's life to answer gets a fresh token,
 * and that token is spent only if the server bound it to the same call (equal binding digests) — the
 * drift check between what was shown and what runs.
 *
 * What this does NOT change: every console mutation is an operator's click (or an operator-armed
 * task), so minting on its behalf records that act. The gate exists for callers with no human
 * present — agents, scripts, other pages — and they still get 428. A caller that already holds a
 * token (an explicit mint) is left alone.
 */
export async function gatedFetch(url: string, init: RequestInit = {}, options: GatedOptions = {}): Promise<Response> {
 const method = (init.method ?? "GET").toUpperCase();
 const headers = new Headers(init.headers);
 if (!SAFE_METHODS.has(method) && !headers.has(CONFIRM_HEADER) && gatedPatternFor(url) !== undefined) {
  let minted = await mintConfirmation(url, init);
  if (options.approve) {
   if (!(await options.approve(minted.call))) throw new ConfirmationDeclined();
   if (Date.now() > minted.expiresAt - REMINT_MARGIN_MS) {
    const again = await mintConfirmation(url, init);
    if (again.binding !== minted.binding) {
     throw new ApiError("the request changed between the preview and the send, so nothing was sent; try again", 409, "");
    }
    minted = again;
   }
  }
  headers.set(CONFIRM_HEADER, minted.token);
 }
 return fetch(url, { ...init, headers });
}

export async function api<T>(url: string, init?: RequestInit, options?: GatedOptions): Promise<T> {
 const headers = new Headers(init?.headers);
 if (init?.body !== undefined && !headers.has("content-type")) headers.set("content-type", "application/json");
 const response = await gatedFetch(url, { ...init, headers }, options);
 const text = await response.text();
 if (!response.ok) throw new ApiError(readFailure(text, response.statusText), response.status, text);
 if (!text) return null as T;
 try {
  return JSON.parse(text) as T;
 } catch {
  throw new ApiError("response was not JSON", response.status, text);
 }
}

export function json(method: string, body?: unknown): RequestInit {
 return { method, body: body === undefined ? undefined : JSON.stringify(body) };
}

export function query(params: Record<string, string | number | boolean | undefined | null>): string {
 const search = new URLSearchParams();
 for (const [key, value] of Object.entries(params)) {
  if (value === undefined || value === null || value === "") continue;
  search.set(key, String(value));
 }
 const encoded = search.toString();
 return encoded ? `?${encoded}` : "";
}

export function formatBytes(value: number): string {
 if (!Number.isFinite(value)) return "—";
 if (value < 1024) return `${value} B`;
 if (value < 1048576) return `${(value / 1024).toFixed(1)} KB`;
 if (value < 1073741824) return `${(value / 1048576).toFixed(2)} MB`;
 return `${(value / 1073741824).toFixed(2)} GB`;
}

export function formatCount(value: number | undefined | null): string {
 return typeof value === "number" && Number.isFinite(value) ? value.toLocaleString() : "—";
}

export function formatDuration(ms: number | undefined | null): string {
 if (typeof ms !== "number" || !Number.isFinite(ms)) return "—";
 if (ms < 1000) return `${Math.round(ms)} ms`;
 if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
 const minutes = Math.floor(ms / 60000);
 return `${minutes}m ${Math.round((ms % 60000) / 1000)}s`;
}

/**
 * Whether an exchange's note is the proxy's HTTP/2-downgrade explanation.
 *
 * The note is a free-text field the proxy composes (`DowngradeNote` in
 * `internal/proxy/alpn.go`), so this matches its fixed opening clause rather than the whole string:
 * a row whose note also carries a second clause — a held request the operator edited, say — is
 * still a downgraded row, and an exact match would miss it. A note that merely mentions HTTP/2 is
 * not one, which is why this tests the clause the proxy writes rather than searching for a keyword.
 *
 * burpsy-react-ui-y0l2.
 */
export function isProtocolDowngrade(notes: string | null | undefined): boolean {
 return typeof notes === "string" && notes.startsWith("client offered HTTP/2;");
}

export function relativeTime(atMs: number, now = Date.now()): string {
 if (!Number.isFinite(atMs) || atMs <= 0) return "—";
 const seconds = Math.max(0, Math.round((now - atMs) / 1000));
 if (seconds < 1) return "now";
 if (seconds < 60) return `${seconds}s ago`;
 if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
 if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
 return `${Math.round(seconds / 86400)}d ago`;
}

export function absoluteTime(atMs: number): string {
 if (!Number.isFinite(atMs) || atMs <= 0) return "unknown";
 return new Date(atMs).toLocaleString();
}

/** Coarse family of an HTTP status, used for colour and filter buckets. */
export function statusTone(status: number | null | undefined): "neutral" | "good" | "info" | "warn" | "bad" {
 if (status === null || status === undefined) return "neutral";
 if (status >= 500) return "bad";
 if (status >= 400) return "warn";
 if (status >= 300) return "info";
 if (status >= 200) return "good";
 return "neutral";
}

/**
 * How a row's `mime` renders, and the one place that decides it.
 *
 * `mime === ""` covers two different facts, and rendering both as a blank cell is what this exists to
 * prevent. An operator reading an empty MIME cell cannot tell "nothing came back yet" from "the
 * server answered and named no type", and would reasonably read the second as a bug in burpsy rather
 * than a fact about the server. `response` is what distinguishes them and it is already on the index
 * row, so telling the truth here costs no new wire field:
 *
 *  - no response at all -> an em dash, the same glyph every other column uses for "not applicable".
 *    The Status column already reads `pending` on such a row, so the two agree.
 *  - a response that declared no Content-Type -> "untyped", a word rather than a punctuation mark,
 *    because it is a positive statement about the response and not an absence.
 *  - otherwise the media type itself.
 *
 * It lives here rather than in history.tsx because the sitemap has the identical column, and one page
 * importing a helper from another page is how two pages come to disagree about what an empty cell
 * means. The parameter is structural, not `Exchange`, so this module keeps its existing shape-typed
 * style and nothing has to import types.ts to call it.
 *
 * The CSV export deliberately does NOT go through this: `historyToCSV` writes the raw value, because a
 * spreadsheet cell reading "untyped" or "—" would be a value no server ever sent, and an empty cell
 * is how a CSV says "no value".
 */
export function mimeLabel(row: { mime?: string; response: number | null }): string {
 if (row.mime) return row.mime;
 return row.response === null ? "—" : "untyped";
}

export async function copyToClipboard(text: string): Promise<void> {
 try {
  await navigator.clipboard.writeText(text);
 } catch {
  // Clipboard API needs a secure context; fall back to a detached textarea.
  const scratch = document.createElement("textarea");
  scratch.value = text;
  scratch.setAttribute("readonly", "");
  scratch.style.position = "fixed";
  scratch.style.opacity = "0";
  document.body.appendChild(scratch);
  scratch.select();
  document.execCommand("copy");
  document.body.removeChild(scratch);
 }
}

export function downloadText(filename: string, text: string, type = "text/plain"): void {
 const url = URL.createObjectURL(new Blob([text], { type }));
 const anchor = document.createElement("a");
 anchor.href = url;
 anchor.download = filename;
 anchor.click();
 URL.revokeObjectURL(url);
}

/**
 * Hand a fetched file to the browser as a download. The object URL is revoked on the next tick
 * rather than synchronously, so the navigation the click started has the URL to read from; after
 * that the only copy is the one the operator saved.
 */
export function downloadBlob(filename: string, blob: Blob): void {
 const url = URL.createObjectURL(blob);
 const anchor = document.createElement("a");
 anchor.href = url;
 anchor.download = filename;
 anchor.rel = "noopener";
 anchor.click();
 window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

/**
 * Serialise history index rows to CSV. The one CSV shape in the app: the History
 * page's export button and the desktop shell's File > Export History both render
 * through this, so the two doors cannot drift into separate formats. Rows are
 * index rows (ids and byte lengths, never bodies) — all /api/history ever hands
 * out — so an export can never quietly copy message payloads.
 */
/** Extension of a path's last segment, lower-cased, or "" when it has none. */
function csvExtension(path: string): string {
 const cut = path.indexOf("?");
 const route = cut === -1 ? path : path.slice(0, cut);
 const segment = route.slice(route.lastIndexOf("/") + 1);
 const dot = segment.lastIndexOf(".");
 return dot > 0 && dot < segment.length - 1 ? segment.slice(dot + 1).toLowerCase() : "";
}

/** Query-parameter count. A bare `?` is zero, not one empty parameter. */
function csvQueryCount(path: string): number {
 const cut = path.indexOf("?");
 if (cut === -1) return 0;
 const query = path.slice(cut + 1);
 return query === "" ? 0 : query.split("&").filter((pair) => pair !== "").length;
}

/**
 * Burp's CSV export specifies an Excel formula guard (burpsy-react-ui-656): a value starting
 * with -, +, = or @ would otherwise execute as a formula when the file is opened in Excel,
 * which is a real injection vector for a security tool's output — a host or path captured
 * from the target could carry "=cmd|...'!A0". The guard quotes the leading character so the
 * cell reads as text. History's export gains this retroactively through the shared cell writer.
 */
export function csvCell(value: string | number | null | undefined): string {
 const text = value === null || value === undefined ? "" : String(value);
 const guarded = /^[+\-=@]/.test(text) ? `'${text}` : text;
 return `"${guarded.replace(/"/g, '""')}"`;
}

export function historyToCSV(
 exchanges: {
  id: number;
  started_ms: number;
  method: string;
  host: string;
  port: number;
  path: string;
  status: number | null;
  response_len: number;
  mime?: string;
  duration_ms: number;
  tls?: boolean;
  notes?: string | null;
  /** Burp's "Edited" flag (burpsy-react-ui-c05, corrected by sd0d): the operator edited this row by
   *  hand in Intercept — not merely "burpsy's bytes differ from the peer's", which is true of traffic
   *  nobody touched. Optional because a caller holding an older row shape still exports; absent reads
   *  as "not edited", which is the flag's own default. */
  variants?: { edited: boolean };
 }[],
): string {
 // Extension and Query are derived here rather than read off the row, for the same reason the
 // history table derives them: they are a property of the path, which the export already has.
 // Both doors -- this button and the desktop shell's File > Export History -- render through this
 // one helper precisely so the CSV and the table cannot disagree about what a column means.
 //
 // "Edited" sits next to Status rather than at the end because it belongs with the row's identity,
 // not with the operator's annotation: an export read to find out which rows the operator changed by
 // hand must not need its last column to be scrolled to. (An automatic rewrite is a different
 // question with a different answer — see Exchange variants for the readings that carry it — and
 // this column deliberately does not answer both, which is what sd0d was.)
 const headers = [
  "ID",
  "Timestamp",
  "Method",
  "Host",
  "Port",
  "Path",
  "Extension",
  "Query",
  "TLS",
  "Edited",
  "Status",
  "Length",
  "MIME",
  "Duration",
  "Comment",
 ];
 const rows = exchanges.map((ex) => [
  ex.id,
  new Date(ex.started_ms).toISOString(),
  ex.method,
  ex.host,
  ex.port,
  ex.path,
  csvExtension(ex.path),
  csvQueryCount(ex.path),
  ex.tls === undefined ? "" : ex.tls ? "yes" : "no",
  ex.variants?.edited ? "yes" : "no",
  ex.status ?? "",
  ex.response_len,
  ex.mime ?? "",
  ex.duration_ms,
  ex.notes ?? "",
 ]);
 return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
}

/**
 * Serialise tool-log rows to CSV (burpsy-react-ui-656). Same guard, same quoting, one shape:
 * the columns the Logger table shows, index data only — the log stores no request bodies.
 */
export function toolLogToCSV(
 entries: {
  id: number;
  started_ms: number;
  tool: string;
  host: string;
  port: number;
  method: string;
  path: string;
  status: number | null;
  response_len: number | null;
  duration_ms: number;
  comment: string;
 }[],
): string {
 const headers = ["ID", "Timestamp", "Tool", "Host", "Port", "Method", "Path", "Status", "Length", "Duration", "Comment"];
 const rows = entries.map((e) => [
  e.id,
  new Date(e.started_ms).toISOString(),
  e.tool,
  e.host,
  e.port,
  e.method,
  e.path,
  e.status ?? "",
  e.response_len ?? "",
  e.duration_ms,
  e.comment,
 ]);
 return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
}

/**
 * Serialise Organizer items to CSV (burpsy-react-ui-656): the item's own fields, with the
 * exchange id rather than the exchange body — the Organizer's export shares History's
 * index-rows-only rule.
 */
export function organizerToCSV(
 items: {
  id: number;
  title: string;
  note: string;
  highlight: string;
  workflow_status: string;
  exchange: number;
 }[],
): string {
 const headers = ["ID", "Title", "Note", "Highlight", "Status", "Exchange"];
 const rows = items.map((item) => [item.id, item.title, item.note, item.highlight, item.workflow_status, item.exchange]);
 return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
}

/** Build a minimal raw HTTP/1.1 request for a target, used when seeding Repeater by hand. */
export function templateRequest(host: string, path = "/"): string {
 return [`GET ${path} HTTP/1.1`, `Host: ${host}`, "Accept: */*", "", ""].join("\r\n");
}

/**
 * Build a request from a typed or pasted host/URL — Burp's "Paste host / URL as
 * request" (burpsy-react-ui-ce8). Accepts "shop.test", "shop.test:8080",
 * "http://shop.test/shop", and ws(s):// which becomes an upgrade handshake. A
 * bare host defaults to https:443 — the same convention the rest of the UI uses
 * — and a path is preserved.
 *
 * `protocol` carries the transport decision and `target` is always http:// or
 * https://, never ws://: the server parses `target` with targetParts, which
 * knows only those two schemes. Returns null when the fragment cannot name an
 * origin, or names a scheme this transport cannot carry.
 */
export function requestFromUrl(input: string): { target: string; protocol: string; request: string } | null {
 const raw = input.trim();
 if (!raw) return null;
 let protocol = "https";
 let rest = raw;
 // Strip scheme (http://, https://, ws(s):// map to http(s) transport below).
 const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(raw)?.[1]?.toLowerCase();
 let websocket = false;
 if (scheme) {
  // Only the four schemes this transport can actually carry. Anything else — ftp:, file:,
  // chrome-extension: — is refused here rather than turned into a tab, because the target string
  // is parsed server-side by targetParts, which accepts http, https or no scheme and answers 400
  // on everything else. Building the tab anyway would put the failure three clicks later, on Send,
  // with a message about a scheme the operator never typed into the target field.
  if (scheme !== "http" && scheme !== "https" && scheme !== "ws" && scheme !== "wss") return null;
  websocket = scheme === "ws" || scheme === "wss";
  protocol = scheme === "http" || scheme === "ws" ? "http" : "https";
  rest = raw.slice(scheme.length + 3);
 }
 // Split authority and path.
 const slash = rest.indexOf("/");
 const hostPort = slash >= 0 ? rest.slice(0, slash) : rest;
 const path = slash >= 0 ? rest.slice(slash) : "/";
 const pathPart = path && !path.startsWith("/") ? `/${path}` : path || "/";
 // Split host and port.
 const colonIdx = hostPort.lastIndexOf(":");
 let host = hostPort;
 let port = "";
 if (colonIdx > 0 && /^\d+$/.test(hostPort.slice(colonIdx + 1))) {
  host = hostPort.slice(0, colonIdx);
  port = hostPort.slice(colonIdx + 1);
 }
 if (!host || /\s/.test(host)) return null;
 if (websocket) {
  // A WebSocket upgrade is the honest rendering of a ws(s) URL: the key is filler
  // (RFC 6455 wants 16 base64 bytes; the server must answer a handshake, not echo it),
  // and the operator is expected to edit it — the point of sending to Repeater.
  const hostHeader = port ? hostPort : host;
  const req = [
   `GET ${pathPart} HTTP/1.1`,
   `Host: ${hostHeader}`,
   "Upgrade: websocket",
   "Connection: Upgrade",
   "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
   "Sec-WebSocket-Version: 13",
   "",
   "",
  ].join("\r\n");
  return { target: `${protocol}://${hostPort}`, protocol, request: req };
 }
 const hostHeader = port ? hostPort : host;
 return { target: `${protocol}://${hostPort}`, protocol, request: templateRequest(hostHeader, pathPart) };
}

/** Pull the authority out of a raw request's Host header so Repeater can prefill a target. */
export function authorityFromRaw(raw: string, fallbackProtocol = "https"): string {
 const match = /^host:[ \t]*(.+)$/im.exec(raw);
 const host = match?.[1]?.trim();
 if (!host) return "";
 return host.includes("://") ? host : `${fallbackProtocol}://${host}`;
}
