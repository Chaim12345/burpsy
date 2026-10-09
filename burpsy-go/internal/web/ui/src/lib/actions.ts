import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
 ArrowRightLeft,
 Combine,
 Copy,
 FlagTriangleRight,
 Crosshair,
 Download,
 FileCode2,
 ExternalLink,
 FileOutput,
 FolderTree,
 Globe,
 Highlighter,
 KeyRound,
 Link2,
 Map,
 MessageSquarePlus,
 NotebookPen,
 Radar,
 Repeat2,
 ScanSearch,
 ShieldCheck,
 Terminal,
 Waypoints, Activity } from "lucide-react";
import { openDetailWindow } from "../pages/detailwindow";
import { toast } from "sonner";
import { openUrlInBrowser } from "./data.browser";
import { useHotkeys } from "react-hotkeys-hook";
import { editableBodyBase64 } from "./message";
import { api, copyToClipboard, downloadText, json } from "./api";
import { BODY_ENCODINGS, BODY_ENCODING_LABELS, changeBodyEncoding as convertBody, type BodyEncoding } from "./body-encoding";
import { useAnnotateExchange } from "./data";
import { formDialog, promptDialog } from "./dialogs";
import { manyMenuGroups } from "./actions-many";
import { useChord } from "./keymap";
import { useApp } from "./store";
import { useCsrfPoc } from "./csrf-poc";
import { HIGHLIGHTS, type Exchange, type MessageView } from "./types";
import { HIGHLIGHT_ICONS } from "../ui/highlight-icons";
import type { MenuGroup } from "../ui/menu";

/**
 * `protocol` on the wire is the HTTP version ("Http1"/"Http2"), so the scheme has
 * to come from `tls`. Getting this wrong sent every captured HTTP request to
 * Repeater as https, where it failed the TLS handshake.
 */
function schemeOf(exchange: Pick<Exchange, "tls" | "port">): "http" | "https" {
 if (typeof exchange.tls === "boolean") return exchange.tls ? "https" : "http";
 return exchange.port === 443 ? "https" : "http";
}

export function exchangeUrl(exchange: Pick<Exchange, "tls" | "host" | "port" | "path">): string {
 const scheme = schemeOf(exchange);
 const defaultPort = scheme === "https" ? 443 : 80;
 const authority = exchange.port === defaultPort ? exchange.host : `${exchange.host}:${exchange.port}`;
 return `${scheme}://${authority}${exchange.path}`;
}

export function exchangeAuthority(exchange: Pick<Exchange, "tls" | "host" | "port">): string {
 return `${schemeOf(exchange)}://${exchange.host}:${exchange.port}`;
}

/**
 * Fetch one stored message's raw bytes.
 *
 * `messageId` is `number | null` because an exchange can have no request at all: a blind CONNECT
 * tunnel has no request bytes to record, and the wire now says so with null rather than with 0
 * (burpsy-react-ui-wtov). Null here is a refusal with a reason an operator can act on, not a
 * fallback to some other message — the earlier behaviour fetched message 0, which is the first
 * request the project ever captured, and every one of these callers then operated on another
 * exchange's bytes while believing they were this row's.
 */
export async function fetchRaw(messageId: number | null, what = "request"): Promise<string> {
 if (messageId === null) {
  throw new Error(
   `This exchange has no ${what} to read — it is a blind tunnel, and burpsy did not look inside it. ` +
   `Turn interception off for this host to relay its bytes untouched.`,
  );
 }
 const message = await api<MessageView>(`/api/message/${messageId}`);
 return message.text ?? "";
}

/**
 * Every link a response carries, in first-seen order without repeats (burpsy-react-ui-4d4).
 * Both quoted attributes (href/src/action/data-*) and bare absolute URLs, because harvests
 * feed crawl seeds and wordlists where a JS-built URL counts as much as an anchor. Fragments,
 * javascript: and mailto: are not links out, and trailing sentence punctuation is stripped so
 * "see http://x/y," does not seed a 404 for "http://x/y,". As-found, never resolved: the
 * response may be off-scope or rewritten, and resolving against a base would invent URLs.
 */
export function extractLinks(text: string): string[] {
 const seen = new Set<string>();
 const out: string[] = [];
 const push = (link: string) => {
  const cleaned = link.trim().replace(/[.,;:!?]+$/, "");
  if (!cleaned || cleaned.startsWith("#")) return;
  const scheme = cleaned.split(":")[0]?.toLowerCase() ?? "";
  if (scheme === "javascript" || scheme === "mailto" || scheme === "data") return;
  if (!seen.has(cleaned)) {
   seen.add(cleaned);
   out.push(cleaned);
  }
 };
 for (const match of text.matchAll(/(?:href|src|action|data-[a-z-]+)\s*=\s*["']([^"']+)["']/gi)) {
  const value = match[1];
  if (value) push(value);
 }
 for (const match of text.matchAll(/https?:\/\/[^\s"'<>\\)]+/gi)) push(match[0]);
 // Unquoted CSS url() references: the one bare-relative form with unambiguous delimiters.
 // Anything looser (a bare /path token) also matches regex literals and division.
 for (const match of text.matchAll(/url\(\s*["']?([^"'()\s]+)["']?\s*\)/gi)) {
  const value = match[1];
  if (value) push(value);
 }
 return out;
}

/** Translate a captured request into a runnable curl command. */
export function rawToCurl(raw: string, url: string): string {
 const [head = ""] = raw.split(/\r?\n\r?\n/, 1);
 const lines = head.split(/\r?\n/);
 const requestLine = lines[0] ?? "";
 const method = requestLine.split(" ")[0] ?? "GET";
 const bodyIndex = raw.search(/\r?\n\r?\n/);
 const body = bodyIndex >= 0 ? raw.slice(bodyIndex).replace(/^\r?\n\r?\n/, "") : "";

 const parts = [`curl -i -X ${method} ${JSON.stringify(url)}`];
 for (const line of lines.slice(1)) {
  const colon = line.indexOf(":");
  if (colon <= 0) continue;
  const name = line.slice(0, colon).trim();
  if (name.toLowerCase() === "content-length") continue;
  parts.push(`  -H ${JSON.stringify(`${name}: ${line.slice(colon + 1).trim()}`)}`);
 }
 if (body.trim()) parts.push(`  --data-raw ${JSON.stringify(body)}`);
 return parts.join(" \\\n");
}

/**
 * Swap a raw request between GET and POST, Burp's "Change request method" semantics: the token
 * flips and the body follows HTTP semantics — a request becoming GET loses Content-Length and the
 * body (a GET with a body is the discrepancy some servers reject), while a request becoming POST
 * keeps whatever body it had so the operator can populate one.
 */
export function toggleRequestMethod(raw: string): string {
 const split = raw.search(/\r?\n\r?\n/);
 const head = split >= 0 ? raw.slice(0, split) : raw;
 const rest = split >= 0 ? raw.slice(split) : "";
 const lines = head.split(/\r?\n/);
 const requestLine = lines[0] ?? "";
 const method = requestLine.split(" ")[0] ?? "GET";
 const next = method === "GET" ? "POST" : "GET";
 lines[0] = `${next}${requestLine.slice(method.length)}`;
 let out = lines.join("\r\n") + rest;
 if (next === "GET") {
  // Collapse to a bodyless request: drop Content-Length and everything past the blank line.
  out = out
   .split(/\r?\n/)
   .filter((line) => !/^content-length:/i.test(line))
   .join("\r\n");
  out = out.replace(/\r?\n\r?\n[\s\S]*$/, "\r\n\r\n");
 }
 return out;
}

/** Dechunk a Transfer-Encoding: chunked body back into plain bytes. */
export function dechunkBody(raw: string): string {
 const split = raw.search(/\r?\n\r?\n/);
 if (split < 0) return raw;
 const head = raw.slice(0, split);
 let body = raw.slice(split + 4).replace(/^\r?\n/, "");
 if (!/transfer-encoding:\s*chunked/i.test(head)) return raw;
 let plain = "";
 for (; ;) {
  const lineEnd = body.indexOf("\r\n");
  if (lineEnd < 0) break;
  const size = parseInt(body.slice(0, lineEnd).trim(), 16);
  if (Number.isNaN(size) || size === 0) break;
  plain += body.slice(lineEnd + 2, lineEnd + 2 + size);
  body = body.slice(lineEnd + 2 + size + 2); // chunk + its trailing CRLF
 }
 return `${head.split(/\r?\n/).filter((line) => !/^transfer-encoding:/i.test(line)).join("\r\n")}\r\n\r\n${plain}`;
}

/** Chunk a plain body with hex-length framing and swap Content-Length for Transfer-Encoding. */
export function chunkBody(raw: string): string {
 const split = raw.search(/\r?\n\r?\n/);
 if (split < 0) return raw;
 const head = raw.slice(0, split);
 const body = raw.slice(split + 4).replace(/^\r?\n/, "");
 if (!body || /transfer-encoding:\s*chunked/i.test(head)) return raw;
 const framed = `${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`;
 const kept = head.split(/\r?\n/).filter((line) => !/^content-length:/i.test(line));
 kept.push("Transfer-Encoding: chunked");
 return `${kept.join("\r\n")}\r\n\r\n${framed}`;
}

/** Whether the request currently carries chunked framing. */
function isChunked(raw: string): boolean {
 return /^transfer-encoding:\s*chunked/im.test(raw.split(/\r?\n\r?\n/, 1)[0] ?? "");
}

/**
 * The cross-tool actions an exchange supports. Kept in one place so History,
 * Site map, Scanner, WebSocket history and the Tool log all offer an identical
 * menu, the way a desktop tool does.
 */
export function useExchangeActions(): {
 sendToRepeater: (exchange: Exchange) => Promise<void>;
 sendToIntruder: (exchange: Exchange) => void;
 sendToSequencer: (exchange: Exchange) => Promise<void>;
 sendToComparer: (exchange: Exchange, slot: "a" | "b") => Promise<void>;
 addToOrganizer: (exchange: Exchange) => Promise<void>;
 /** Burp's "Add to site map" (amu): record this URL on the map without sending traffic to it. The
  *  server says whether it was new or already observed, and the toast says the same — "you noted
  *  this" and "this was already on the map because we saw it" are different facts. */
 addToSiteMap: (exchange: Exchange) => Promise<void>;
 copyUrl: (exchange: Exchange) => Promise<void>;
 copyCurl: (exchange: Exchange) => Promise<void>;
 filterByHost: (exchange: Exchange) => void;
 addToScope: (exchange: Exchange) => Promise<void>;
 auditExchange: (exchange: Exchange) => Promise<void>;
 /** Actively audit a marked selection: posts the exchange with insertion_spans so the scanner
  *  probes only the selected byte range (burpsy-react-ui-c6oq, backend: burpsy-react-ui-806w). */
 auditSelection: (exchange: Exchange, spans: [number, number][]) => Promise<void>;
 sendToDecoder: (exchange: Exchange) => Promise<void>;
 copyRequestToFile: (exchange: Exchange) => Promise<void>;
 saveItems: (exchange: Exchange) => Promise<void>;
 copyLinks: (exchange: Exchange) => Promise<void>;
 requestInBrowser: (exchange: Exchange) => void;
 showResponseInBrowser: (exchange: Exchange) => void;
 changeRequestMethod: (exchange: Exchange) => Promise<void>;
 /** Burp's separate operation, kept under its own label: swap Content-Length for chunk framing. */
 toggleChunkedFraming: (exchange: Exchange) => Promise<void>;
 /** Burp's "Change body encoding": re-encode the body as form, multipart or JSON (wv5). */
 convertBodyEncoding: (exchange: Exchange, target: BodyEncoding) => Promise<void>;
 crawlFrom: (exchange: Exchange, scope: "branch" | "host") => Promise<void>;
 setHighlight: (exchange: Exchange, colour: string) => void;
 addComment: (exchange: Exchange) => void;
 /** Burp's "Record an issue": prompts for name/description/severity and posts the finding
  *  against this exchange (burpsy-react-ui-4qqz). */
 recordIssue: (exchange: Exchange) => void;
 menu: (exchange: Exchange, extra?: MenuGroup[]) => MenuGroup[];
 /** The multi-row menu (fe16): what a right-click inside a selection of two or more rows offers. */
 menuMany: (exchanges: Exchange[], extra?: MenuGroup[]) => MenuGroup[];
 /** Add each host to scope as an include rule, one request per host, and say which failed. */
 addHostsToScope: (hosts: string[]) => Promise<void>;
} {
 const openRepeaterTab = useApp((state) => state.openRepeaterTab);
 const setRoute = useApp((state) => state.setRoute);
 const setIntruderSeed = useApp((state) => state.setIntruderSeed);
 const setSequencerSeed = useApp((state) => state.setSequencerSeed);
 const setComparerSlot = useApp((state) => state.setComparerSlot);
 const setHistoryQuery = useApp((state) => state.setHistoryQuery);
 const setDecoderSeed = useApp((state) => state.setDecoderSeed);
 const setHiddenInputsTarget = useApp((state) => state.setHiddenInputsTarget);
 const annotate = useAnnotateExchange();
 // Record an issue (burpsy-react-ui-4qqz): POST /api/issues/record with the exchange the menu
 // was invoked on. The issues list invalidates by key prefix after any triage write, so the
 // recorded finding appears without a manual refresh.
 const queryClient = useQueryClient();
 const record = useMutation<{ id: number; recorded: boolean }, Error, { name: string; description: string; severity: string; exchange_id: number }>({
  mutationFn: (body) => api("/api/issues/record", json("POST", body)),
  onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["issues"] }),
 });

 const sendToRepeater = async (exchange: Exchange) => {
  try {
   // Fetch the whole MessageView, not just fetchRaw's lossy `text` (burpsy-react-ui-ytkk): a
   // binary request body — a protobuf/gRPC capture is the motivating case — survives the trip
   // only as base64 (`body_base64`, populated server-side exactly when the body is not UTF-8).
   // Carrying it into the tab as `requestBodyBase64` is what lets Repeater decode the Protobuf
   // tab faithfully and resend the edited bytes; a text body leaves it undefined and nothing
   // changes.
   if (exchange.request === null) {
    throw new Error(
     "This exchange has no request to read — it is a blind tunnel, and burpsy did not look inside it. " +
     "Turn interception off for this host to relay its bytes untouched.",
    );
   }
   const message = await api<MessageView>(`/api/message/${exchange.request}`);
   openRepeaterTab({
    name: `#${exchange.id} ${exchange.method} ${exchange.path}`.slice(0, 42),
    target: exchangeAuthority(exchange),
    protocol: schemeOf(exchange),
    request: message.text ?? "",
    // editableBodyBase64, not body_base64 as-is: the tab resends head + these bytes, which is only exact
    // when the head describes no Content-Encoding or chunking (burpsy-react-ui-3pco).
    requestBodyBase64: editableBodyBase64(message),
    fromExchange: exchange.id,
   });
   setRoute("repeater");
   toast.success(`Exchange #${exchange.id} sent to Repeater`);
  } catch (error) {
   toast.error(`Could not load request bytes: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 const sendToIntruder = (exchange: Exchange) => {
  setIntruderSeed({
   msgId: exchange.request,
   target: exchangeAuthority(exchange),
   label: `#${exchange.id} ${exchange.method} ${exchange.path}`,
  });
  setRoute("intruder");
  toast.success(`Exchange #${exchange.id} sent to Intruder`);
 };

  // Send to Sequencer (fhp): the capture needs the request bytes and the authority — exactly
  // what the exchange carries. Fetching the raw bytes here (like sendToComparer) means the
  // capture tab is filled on arrival, not on the sequencer page's own fetch.
  const sendToSequencer = async (exchange: Exchange) => {
   try {
    const raw = await fetchRaw(exchange.request);
    // The response rides along when it exists (6t8): the token-location picker lists the
    // cookies, headers and form fields actually present in it. A request with no response yet
    // (a hand-off before any send) seeds the request alone.
    let response: string | null = null;
    if (exchange.response !== null) {
     try {
      response = await fetchRaw(exchange.response);
     } catch {
      response = null; // a response that cannot be read leaves the picker to the typed path
     }
    }
    setSequencerSeed({
     request: raw,
     target: exchangeAuthority(exchange),
     label: `#${exchange.id} ${exchange.method} ${exchange.path}`,
     response,
    });
    setRoute("sequencer");
    toast.success(`Exchange #${exchange.id} sent to Sequencer`);
   } catch (error) {
    toast.error(`Could not load request bytes: ${error instanceof Error ? error.message : String(error)}`);
   }
  };

 const sendToComparer = async (exchange: Exchange, slot: "a" | "b") => {
  try {
   const raw = await fetchRaw(exchange.request);
   setComparerSlot(slot, raw);
   setRoute("comparer");
   toast.success(`Exchange #${exchange.id} loaded into slot ${slot.toUpperCase()}`);
  } catch (error) {
   toast.error(`Could not load request bytes: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 const addToOrganizer = async (exchange: Exchange) => {
  try {
   await api<unknown>("/api/tools/organizer", {
    method: "POST",
    body: JSON.stringify({ exchange: exchange.id }),
   });
   toast.success(`Exchange #${exchange.id} added to Organizer`);
  } catch (error) {
   toast.error(`Could not organize exchange: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

// "Add to site map" (amu). Burp's own wording for the row action, on the row's own host/port/path —
// not a URL the operator types, because a map node names an authority and a path, and the exchange
// already carries exactly that.
//
// The response's `already_seen` is what makes the toast honest: a URL the proxy has already seen is
// on the map because of traffic, and telling an operator they "added" it would credit them with a
// fact the map recorded for a stronger reason.
const addToSiteMap = async (exchange: Exchange) => {
 try {
  const out = await api<{ inserted?: string; already_seen?: boolean; note?: string }>("/api/sitemap", {
   method: "POST",
   body: JSON.stringify({ host: exchange.host, port: exchange.port, tls: exchange.tls, path: exchange.path }),
  });
  if (out.already_seen) {
   toast.message(`${exchange.path || "/"} is already on the site map — it was observed there, which is a stronger fact than a note to self`);
  } else {
   toast.success(`${exchange.host}${exchange.path} added to the site map — recorded by you, with nothing observed there yet`);
  }
 } catch (error) {
  toast.error(`Could not add to the site map: ${error instanceof Error ? error.message : String(error)}`);
 }
};

 const copyUrl = async (exchange: Exchange) => {
  await copyToClipboard(exchangeUrl(exchange));
  toast.success("URL copied");
 };

 const copyCurl = async (exchange: Exchange) => {
  try {
   const raw = await fetchRaw(exchange.request);
   await copyToClipboard(rawToCurl(raw, exchangeUrl(exchange)));
   toast.success("curl command copied");
  } catch (error) {
   toast.error(`Could not build curl: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 const filterByHost = (exchange: Exchange) => {
  setHistoryQuery(`host = ${exchange.host}`);
  setRoute("history");
 };

 const addToScope = async (exchange: Exchange) => {
  try {
   await api<unknown>("/api/scope", json("POST", { action: "include", pattern: exchange.host }));
   // The status bar's rule count and the Scope page read this key; without the refresh they kept
   // saying "0 rules" after the add succeeded.
   void queryClient.invalidateQueries({ queryKey: ["scope"] });
   toast.success(`${exchange.host} added to scope`);
  } catch (error) {
   toast.error(`Could not scope ${exchange.host}: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 const addHostsToScope = async (hosts: string[]) => {
  const failed: string[] = [];
  // Sequential, not parallel: the scope store is one ordered rule list, and N concurrent writes
  // to it would race for the order an operator then reads back on the Scope page.
  for (const host of hosts) {
   try {
    await api<unknown>("/api/scope", json("POST", { action: "include", pattern: host }));
   } catch {
    failed.push(host);
   }
  }
  void queryClient.invalidateQueries({ queryKey: ["scope"] });
  const added = hosts.length - failed.length;
  if (failed.length === 0) toast.success(hosts.length === 1 ? `${hosts[0]} added to scope` : `${added} hosts added to scope: ${hosts.join(", ")}`);
  else if (added === 0) toast.error(`Could not scope ${failed.join(", ")}`);
  else toast.warning(`${added} of ${hosts.length} hosts added to scope; refused: ${failed.join(", ")}`);
 };

 const compareTwo = async (a: Exchange, b: Exchange) => {
  try {
   const [left, right] = await Promise.all([fetchRaw(a.request), fetchRaw(b.request)]);
   setComparerSlot("a", left);
   setComparerSlot("b", right);
   setRoute("comparer");
   toast.success(`#${a.id} loaded into A and #${b.id} into B`);
  } catch (error) {
   toast.error(`Could not load request bytes: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 const copyUrls = async (exchanges: Exchange[]) => {
  await copyToClipboard(exchanges.map((exchange) => exchangeUrl(exchange)).join("\n"));
  toast.success(`Copied ${exchanges.length} URL${exchanges.length === 1 ? "" : "s"}`);
 };

 const addAllToOrganizer = async (exchanges: Exchange[]) => {
  let added = 0;
  const failed: number[] = [];
  for (const exchange of exchanges) {
   try {
    await api<unknown>("/api/tools/organizer", { method: "POST", body: JSON.stringify({ exchange: exchange.id }) });
    added += 1;
   } catch {
    failed.push(exchange.id);
   }
  }
  void queryClient.invalidateQueries({ queryKey: ["organizer"] });
  if (failed.length === 0) toast.success(`${added} exchanges added to Organizer`);
  else toast.warning(`${added} of ${exchanges.length} added to Organizer; refused: ${failed.map((id) => `#${id}`).join(", ")}`);
 };

 const menuMany = (exchanges: Exchange[], extra: MenuGroup[] = []): MenuGroup[] =>
  manyMenuGroups(
   exchanges,
   {
    compare: (a, b) => void compareTwo(a, b),
    copyUrls: (list) => void copyUrls(list),
    addHostsToScope: (hosts) => void addHostsToScope(hosts),
    addAllToOrganizer: (list) => void addAllToOrganizer(list),
   },
   extra,
  );

 const auditExchange = async (exchange: Exchange) => {
  try {
   await api<unknown>(`/api/audit/${exchange.id}`, json("POST", {}));
   toast.success(`Active audit queued for exchange #${exchange.id}`);
  } catch (error) {
   toast.error(`Could not start the audit: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

const auditSelection = async (exchange: Exchange, spans: [number, number][]) => {
  try {
   await api<unknown>(`/api/audit/${exchange.id}`, json("POST", { insertion_spans: spans }));
   toast.success(`Active audit queued for the marked span on exchange #${exchange.id}`);
  } catch (error) {
   toast.error(`Could not start the audit: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 const sendToDecoder = async (exchange: Exchange) => {
  try {
   const raw = await fetchRaw(exchange.request);
   setDecoderSeed({ label: `#${exchange.id} ${exchange.method} ${exchange.path}`, input: raw });
   setRoute("decoder");
  } catch (error) {
   toast.error(`Could not load request bytes: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 /** Download the request to a file — clipboard cannot carry it to a terminal or a test harness. */
 const copyRequestToFile = async (exchange: Exchange) => {
  try {
   const raw = await fetchRaw(exchange.request);
   const blob = new Blob([raw], { type: "text/plain" });
   const anchor = document.createElement("a");
   anchor.href = URL.createObjectURL(blob);
   anchor.download = `${exchange.method}-${exchange.host}${exchange.path}`.replace(/[^a-z0-9.\-/]+/gi, "_").slice(0, 80) + ".txt";
   anchor.click();
   URL.revokeObjectURL(anchor.href);
   toast.success("Request downloaded");
  } catch (error) {
   toast.error(`Could not load request bytes: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 const copyLinks = async (exchange: Exchange) => {
  if (exchange.response === null) {
   toast.error(`Exchange #${exchange.id} has no response to harvest links from`);
   return;
  }
  try {
   const raw = await fetchRaw(exchange.response);
   const links = extractLinks(raw);
   if (!links.length) {
    toast.error(`No links found in the response of #${exchange.id}`);
    return;
   }
   await copyToClipboard(links.join("\n"));
   toast.success(`Copied ${links.length} link${links.length === 1 ? "" : "s"} from #${exchange.id}`);
  } catch (error) {
   toast.error(`Could not load response bytes: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 /**
  * Burp's "Save items" for one exchange (burpsy-react-ui-57t): request and response together
  * in a single labelled file, which is what gets attached to a report. "Copy request to
  * file" stays request-only beside it - the two are different actions, as in Burp. A
  * missing response still saves (labelled as missing) rather than refusing: the request
  * half is the evidence being kept.
  */
 const saveItems = async (exchange: Exchange) => {
  try {
   const request = await fetchRaw(exchange.request);
   const response = exchange.response === null ? null : await fetchRaw(exchange.response, "response");
   const name = `${exchange.method}-${exchange.host}${exchange.path}`.replace(/[^a-z0-9.\-/]+/gi, "_").slice(0, 80);
   downloadText(
    `${name}-exchange.txt`,
    ["=============== REQUEST ===============", request, "=============== RESPONSE ===============", response ?? "(no response was captured for this exchange)"].join("\n"),
   );
   toast.success(`Exchange #${exchange.id} saved with its response`);
  } catch (error) {
   toast.error(`Could not load exchange bytes: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 /**
  * Open the target in the burpsy browser (bufa): Chromium routed through burpsy's proxy, so what
  * the operator does there is captured. A refused launch is shown verbatim and offers the
  * operator's own browser instead, saying that it is not proxied.
  */
 const requestInBrowser = (exchange: Exchange) => void openUrlInBrowser(exchangeUrl(exchange));

/**
 * Burp's "Show response in browser" (burpsy-react-ui-js5y): the operator's own browser opens
 * a URL that serves THIS exchange's stored response verbatim — relative links resolve, and
 * the page renders as the target produced it. Unlike Open URL, nothing is re-fetched: what
 * the browser shows is what burpsy holds, which is the point in an access-control test.
 */
const showResponseInBrowser = (exchange: Exchange) => {
 window.open(`/api/exchange/in-browser/${exchange.id}`, "_blank", "noopener");
 toast.info(`Serving the stored response of #${exchange.id} — relative links resolve against this console's origin`);
};

 /** Flip GET/POST on a copy and hand it to Repeater; history rows stay immutable. */
 const changeRequestMethod = async (exchange: Exchange) => {
  try {
   const raw = await fetchRaw(exchange.request);
   const nextMethod = ((raw.match(/^([A-Z]+)/)?.[1] ?? "GET") === "GET" ? "POST" : "GET") as string;
   openRepeaterTab({
    name: `#${exchange.id} ${nextMethod} ${exchange.path}`.slice(0, 42),
    target: exchangeAuthority(exchange),
    protocol: schemeOf(exchange),
    request: toggleRequestMethod(raw),
    fromExchange: exchange.id,
   });
   setRoute("repeater");
   toast.success(`Method flipped to ${nextMethod} in a new Repeater tab`);
  } catch (error) {
   toast.error(`Could not load request bytes: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 /**
  * Toggle chunked framing on a copy and hand it to Repeater.
  *
  * This used to be labelled "Change body encoding", which is the name Burp gives a different
  * operation — converting the body between form, multipart and JSON (burpsy-react-ui-wv5). That
  * conversion is now `convertBodyEncoding` below, and this keeps the framing name it always
  * described.
  */
 const toggleChunkedFraming = async (exchange: Exchange) => {
  try {
   const raw = await fetchRaw(exchange.request);
   const next = isChunked(raw) ? dechunkBody(raw) : chunkBody(raw);
   if (next === raw) {
    toast.info("Nothing to change: the request has no body to reframe");
    return;
   }
   openRepeaterTab({
    name: `#${exchange.id} ${isChunked(raw) ? "dechunked" : "chunked"}`.slice(0, 42),
    target: exchangeAuthority(exchange),
    protocol: schemeOf(exchange),
    request: next,
    fromExchange: exchange.id,
   });
   setRoute("repeater");
   toast.success(isChunked(raw) ? "Body dechunked in a new Repeater tab" : "Body reframed as chunked in a new Repeater tab");
  } catch (error) {
   toast.error(`Could not load request bytes: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 /**
  * Burp's "Change body encoding" (burpsy-react-ui-wv5): re-encode the request body as form
  * URL-encoding, multipart or JSON and open the result as a Repeater tab to edit and send.
  *
  * The refusal is a toast carrying the transform's own reason, not a generic failure. A
  * conversion this cannot make faithfully — a file part, a nested JSON member, a repeated
  * parameter on the way to a JSON object — produces no tab at all, because a half-converted
  * request that still looks sendable teaches the operator something false about the server.
  *
  * The three targets are all offered unconditionally rather than greying out the one the body is
  * already in: this menu is built from the row synchronously and the bytes only arrive from
  * `fetchRaw` afterwards, so "which encoding is this?" is not knowable at render time. Picking
  * the current one answers with the refusal that says so. The Repeater editor's copy of this
  * menu, where `active.request` is in hand, does disable it.
  */
 const convertBodyEncoding = async (exchange: Exchange, target: BodyEncoding) => {
  try {
   const raw = await fetchRaw(exchange.request);
   const result = convertBody(raw, target);
   if (!result.ok) {
    toast.error(`Could not re-encode the body as ${BODY_ENCODING_LABELS[target]}: ${result.reason}`);
    return;
   }
   openRepeaterTab({
    name: `#${exchange.id} as ${BODY_ENCODING_LABELS[target]}`.slice(0, 42),
    target: exchangeAuthority(exchange),
    protocol: schemeOf(exchange),
    request: result.raw,
    fromExchange: exchange.id,
   });
   setRoute("repeater");
   toast.success(`Body re-encoded as ${BODY_ENCODING_LABELS[target]} in a new Repeater tab`);
  } catch (error) {
   toast.error(`Could not load request bytes: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 /**
  * Crawl scoped by the query grammar's honest limits: seeds start at this exchange's URL, and
  * retention follows only paths still containing the branch prefix (trailing slash included,
  * because `path ~ "/v2"` would also keep `/v22`). The toast names the scope actually used.
  */
 const crawlFrom = async (exchange: Exchange, scope: "branch" | "host") => {
  const url = exchangeUrl(exchange);
  const retention =
   scope === "host" ? `host = ${exchange.host}` : `path ~ "${exchange.path.replace(/\/[^/]*$/, "")}/"`;
  try {
   await api<{ task_id: number }>("/api/crawl", json("POST", { seeds: [url], retention_query: retention }));
   toast.success(`${scope === "branch" ? "Branch" : "Host"} crawl started — retained where ${retention}`);
   setRoute("dashboard");
  } catch (error) {
   toast.error(`Could not start the crawl: ${error instanceof Error ? error.message : String(error)}`);
  }
 };

 const generateCSRF = (exchange: Exchange) => {
  // Opens the PoC dialog (burpsy-react-ui-0z10) instead of a blob page: a blob URL inherits
  // the console's origin, and a generated PoC — attacker-shaped HTML built from captured
  // bytes — is the one thing that must never run there. The dialog shows the HTML and the
  // technique choice, and its "Test in browser" opens the one-shot URL the server mints on
  // the PoC host's own port.
  useCsrfPoc.getState().open(exchange);
 };

 /**
  * Burp's "Highlight". `""` is the wire's "no highlight", which is why the picker's `none`
  * sentinel is translated here rather than stored — see the `highlight` field's own comment in
  * types.ts. Fired straight at the mutation with no confirmation: it is one PATCH, it is visible
  * in the row the instant it lands, and setting it again to a different colour is the undo.
  */
 const setHighlight = (exchange: Exchange, colour: string) => {
  annotate.mutate(
   { id: exchange.id, highlight: colour },
   {
    onError: (error) =>
     toast.error(`Could not highlight #${exchange.id}: ${error instanceof Error ? error.message : String(error)}`),
   },
  );
 };

 /**
  * Burp's "Add comment", seeded with whatever note the row already carries so the menu entry
  * edits rather than replaces.
  *
  * Through the shell's themed prompt (lib/dialogs.ts, bea3), not window.prompt: the menu factory
  * is a plain function with no React subtree of its own, which is exactly what promptDialog is
  * for — it awaits an answer from the one host mounted in the shell. The detail pane's textarea
  * stays the place for a multi-line note. Cancel resolves null and is left alone; clearing the box
  * to empty is a deliberate "remove the note" and is sent as null, which is what the PATCH
  * endpoint takes for "unset".
  */
 const addComment = (exchange: Exchange) => {
  const existing = exchange.notes ?? "";
  void promptDialog({
   title: existing ? `Edit comment on exchange #${exchange.id}` : `Comment on exchange #${exchange.id}`,
   description: `${exchange.method} ${exchange.host}${exchange.path}. An empty comment removes it.`,
   label: "Comment",
   initial: existing,
   confirmLabel: "Save comment",
   allowEmpty: true,
  }).then((next) => {
   if (next === null) return;
   const trimmed = next.trim();
   if (trimmed === existing) return;
   annotate.mutate(
    { id: exchange.id, notes: trimmed === "" ? null : trimmed },
    {
     onSuccess: () => toast.success(trimmed === "" ? `Comment cleared on #${exchange.id}` : `Comment saved on #${exchange.id}`),
     onError: (error) =>
      toast.error(`Could not save the comment: ${error instanceof Error ? error.message : String(error)}`),
    },
   );
  });
 };

 // Record an issue (burpsy-react-ui-4qqz): Burp's "Record an issue" context-menu action. The
 // operator names and grades the finding; the exchange they invoked the menu on is attached as
 // the occurrence, so the issue is jumpable to the bytes that demonstrate it.
 //
 // One form, not the three chained window.prompt calls it used to be (bea3). The severity was a
 // free-text box then, and the server folds anything it does not recognise to Informational
 // (core.ParseSeverity) — so a typo like "hihg" silently recorded an informational issue. A select
 // over the server's own five values makes that impossible.
 const recordIssue = (exchange: Exchange) => {
  void formDialog({
   title: "Record an issue",
   description: `Against exchange #${exchange.id}: ${exchange.method} ${exchange.host}${exchange.path}`,
   confirmLabel: "Record issue",
   fields: [
    { id: "name", label: "Name", kind: "text", required: true, hint: "The report heading" },
    { id: "description", label: "Description", kind: "textarea" },
    {
     id: "severity",
     label: "Severity",
     kind: "select",
     initial: "low",
     options: [
      { value: "critical", label: "Critical" },
      { value: "high", label: "High" },
      { value: "medium", label: "Medium" },
      { value: "low", label: "Low" },
      { value: "info", label: "Information" },
     ],
    },
   ],
  }).then((values) => {
   if (values === null) return;
   record.mutate(
    {
     name: (values.name ?? "").trim(),
     description: (values.description ?? "").trim(),
     severity: values.severity ?? "low",
     exchange_id: exchange.id,
    },
    {
     onSuccess: (result) => toast.success(`Issue #${result.id} recorded against #${exchange.id}`),
     onError: (cause) => toast.error(`Could not record the issue: ${cause instanceof Error ? cause.message : String(cause)}`),
    },
   );
  });
 };

 const menu = (exchange: Exchange, extra: MenuGroup[] = []): MenuGroup[] => [
  {
   id: "send",
   actions: [
    { id: "repeater", label: "Send to Repeater", icon: Repeat2, shortcut: "R", onSelect: () => void sendToRepeater(exchange) },
    { id: "intruder", label: "Send to Intruder", icon: Crosshair, shortcut: "I", onSelect: () => sendToIntruder(exchange) },
    { id: "sequencer", label: "Send to Sequencer", icon: Activity, shortcut: "Q", onSelect: () => void sendToSequencer(exchange) },
    { id: "compare-a", label: "Send to Comparer (A)", icon: Combine, onSelect: () => void sendToComparer(exchange, "a") },
    { id: "compare-b", label: "Send to Comparer (B)", icon: ArrowRightLeft, onSelect: () => void sendToComparer(exchange, "b") },
    // Decoder is a client-side transform pipeline, so this is a seed hand-off, not a wire call.
    { id: "decoder", label: "Send to Decoder", icon: FileOutput, onSelect: () => void sendToDecoder(exchange) },
   ],
  },
  {
   id: "request-edits",
   title: "Edit a copy in Repeater",
   actions: [
    { id: "flip-method", label: "Change request method (GET/POST)", onSelect: () => void changeRequestMethod(exchange) },
    {
     id: "body-encoding",
     label: "Change body encoding",
     // A submenu, like the highlight picker: the operation is "convert to X", and three
     // sibling rows named after the three encodings say that better than one row that
     // cycles through them in an order the operator cannot see.
     submenu: [
      {
       id: "encodings",
       actions: BODY_ENCODINGS.map((encoding) => ({
        id: encoding,
        label: BODY_ENCODING_LABELS[encoding],
        onSelect: () => void convertBodyEncoding(exchange, encoding),
       })),
      },
     ],
     onSelect: () => undefined,
    },
    { id: "chunked-framing", label: "Toggle chunked transfer framing", onSelect: () => void toggleChunkedFraming(exchange) },
   ],
  },
  {
   id: "copy",
   actions: [
    { id: "url", label: "Copy URL", icon: Link2, onSelect: () => void copyUrl(exchange) },
    { id: "curl", label: "Copy as curl", icon: Terminal, onSelect: () => void copyCurl(exchange) },
    { id: "id", label: `Copy exchange id (#${exchange.id})`, icon: Copy, onSelect: () => void copyToClipboard(String(exchange.id)) },
    { id: "to-file", label: "Copy request to file", icon: FileCode2, onSelect: () => void copyRequestToFile(exchange) },
    { id: "links", label: "Copy links", icon: Globe, onSelect: () => void copyLinks(exchange) },
    { id: "save-items", label: "Save request and response", icon: Download, onSelect: () => void saveItems(exchange) },
   ],
  },
  {
   // Burp's universal annotate pair, on the selection rather than in a detail pane: annotate
   // then filter by annotation is a first-class triage loop, and `highlight` and `notes` are
   // both queryable DSL fields, so a row that cannot be marked cannot be found again.
   id: "annotate",
   actions: [
    {
     id: "highlight",
     label: "Highlight",
     icon: Highlighter,
     // A submenu, as Burp's colour picker is. The current colour is disabled rather than
     // hidden: an operator looking for "which one is set" should find it in the list.
     submenu: [
      {
       id: "colours",
       actions: HIGHLIGHTS.map((name) => {
        const wire = name === "none" ? "" : name;
        return {
         id: name,
         label: name === "none" ? "Clear highlight" : name.charAt(0).toUpperCase() + name.slice(1),
         icon: HIGHLIGHT_ICONS[name],
         disabled: (exchange.highlight ?? "") === wire,
         onSelect: () => setHighlight(exchange, wire),
        };
       }),
      },
     ],
     onSelect: () => { },
    },
    {
     id: "comment",
     label: exchange.notes ? "Edit comment" : "Add comment",
     icon: MessageSquarePlus,
     onSelect: () => addComment(exchange),
    },
   ],
  },
  {
   id: "organise",
   actions: [
    { id: "organizer", label: "Add to Organizer", icon: NotebookPen, onSelect: () => void addToOrganizer(exchange) },
    { id: "site-map", label: "Add to site map", icon: Map, onSelect: () => void addToSiteMap(exchange) },
    // Burp's "Show details in new window" (wvcl). In the ORGANISE group because that is where Burp
    // puts window-level actions, and because the ones above it all move the item somewhere else
    // rather than opening a second view of the item already selected.
    {
     id: "detail-window",
     label: "Show details in new window",
     icon: ExternalLink,
     onSelect: () => {
      // Synchronous and no `void`: window.open is one of the few browser calls that only counts as
      // a user gesture inside the call stack that started it, so an await before it is the
      // difference between a window and a blocked popup.
      openDetailWindow(exchange);
     },
    },
    { id: "host", label: `Filter history by ${exchange.host}`, icon: FolderTree, onSelect: () => filterByHost(exchange) },
    { id: "browser", label: "Open URL in browser", icon: Globe, onSelect: () => requestInBrowser(exchange) },
    {
     id: "response-in-browser",
     label: "Show response in browser",
     icon: Globe,
     onSelect: () => showResponseInBrowser(exchange),
    },
   ],
  },
  {
   id: "scope-scan",
   actions: [
    { id: "scope", label: `Add ${exchange.host} to scope`, icon: ShieldCheck, onSelect: () => void addToScope(exchange) },
    { id: "audit", label: `Audit exchange #${exchange.id}`, icon: Radar, onSelect: () => void auditExchange(exchange) },
    // Burp's Param Miner "Guess params" (burpsy-react-ui-wlz8): opens the app-level dialog, which
    // picks the kinds and starts the run. A blind tunnel has no request to add names to.
    ...(exchange.request === null
     ? []
     : [{ id: "guess-inputs", label: "Guess hidden inputs…", icon: KeyRound, onSelect: () => setHiddenInputsTarget(exchange) }]),
    { id: "crawl-branch", label: "Actively scan this branch (crawl)", icon: Waypoints, onSelect: () => void crawlFrom(exchange, "branch") },
    { id: "crawl-host", label: "Actively scan this host (crawl)", icon: ScanSearch, onSelect: () => void crawlFrom(exchange, "host") },
   ],
  },
  {
   id: "engage",
   title: "Engagement tools",
   actions: [
    { id: "record-issue", label: "Record an issue", icon: FlagTriangleRight, onSelect: () => recordIssue(exchange) },
    { id: "csrf", label: "Generate CSRF PoC", icon: FileCode2, onSelect: () => void generateCSRF(exchange) },
   ],
  },
  ...extra,
 ];

 return {
  recordIssue,
  sendToRepeater,
  sendToIntruder,
  sendToSequencer,
  sendToComparer,
  addToOrganizer,
  addToSiteMap,
  copyUrl,
  copyCurl,
  filterByHost,
  addToScope,
  auditExchange,
  auditSelection,
  sendToDecoder,
  copyRequestToFile,
  copyLinks,
  saveItems,
  requestInBrowser,
 showResponseInBrowser,
  changeRequestMethod,
  toggleChunkedFraming,
  convertBodyEncoding,
  crawlFrom,
  setHighlight,
  addComment,
  menu,
  menuMany,
  addHostsToScope,
 };
}

/**
 * The row send-to chords, installed from the keymap registry.
 *
 * # Why this is a hook rather than three `useHotkeys` calls per page
 *
 * These were hardcoded literals in history.tsx, which made two separate defects. The chords in
 * Settings -> Hotkeys are real, persisted, duplicate-checked state that nothing read, so
 * rebinding Send to Repeater reported success and changed nothing; and the bindings existed only
 * on that one page, so on Site map, Logger and WebSockets history ctrl+R reached the browser and
 * reloaded the console — losing the operator's filter and selection to reach a page that has
 * meant "send to Repeater" for a Burp user for twenty years. `send.organizer` was worse still:
 * advertised in the shortcut modal and the Settings table, installed nowhere.
 *
 * One hook fixes all three at once, and — the point — makes it impossible to add a fourth row
 * table that quietly omits them.
 *
 * The claim is unconditional (bc2 holes 2 and 3): preventDefault fires on every table page
 * whether or not a row is selected, and even when focus is in a form field — because the two
 * guard shapes that "left the key to the browser" are precisely how the browser's reload ate
 * the operator's page state. Nothing selected on a fresh page load: first Ctrl+R reloaded the
 * console. Hands in the DSL query box or a column filter: the handler never ran at all. Both
 * holes survive a selected-row-only fix, so the chord is claimed on every table page and the
 * no-row case answers with a toast — a swallowed key that says nothing is a dead key, which is
 * a different bad outcome. enableOnFormTags: true follows the in-repo precedent (intercept.tsx's
 * proxy.forward), and F5 remains the deliberate reload path.
 */
export function useSendShortcuts(exchange: Exchange | null | undefined): void {
 const actions = useExchangeActions();
 const repeaterChord = useChord("send.repeater");
 const intruderChord = useChord("send.intruder");
 const organizerChord = useChord("send.organizer");

 useHotkeys(
  repeaterChord,
  (event) => {
   event.preventDefault();
   if (!exchange) {
    toast.info("Select a row to send it to Repeater");
    return;
   }
   void actions.sendToRepeater(exchange);
  },
  { enableOnFormTags: true, enableOnContentEditable: true },
  [repeaterChord, exchange, actions],
 );
 useHotkeys(
  intruderChord,
  (event) => {
   event.preventDefault();
   if (!exchange) {
    toast.info("Select a row to send it to Intruder");
    return;
   }
   actions.sendToIntruder(exchange);
  },
  { enableOnFormTags: true, enableOnContentEditable: true },
  [intruderChord, exchange, actions],
 );
 useHotkeys(
  organizerChord,
  (event) => {
   event.preventDefault();
   if (!exchange) {
    toast.info("Select a row to send it to Organizer");
    return;
   }
   void actions.addToOrganizer(exchange);
  },
  { enableOnFormTags: true, enableOnContentEditable: true },
  [organizerChord, exchange, actions],
 );
}
