import {
  ArrowRightLeft,
  Combine,
  Copy,
  Crosshair,
  FileCode2,
  FileOutput,
  FolderTree,
  Globe,
  Link2,
  NotebookPen,
  Radar,
  Repeat2,
  ScanSearch,
  ShieldCheck,
  Terminal,
  Waypoints,
} from "lucide-react";
import { toast } from "sonner";
import { api, copyToClipboard, json } from "./api";
import { useApp } from "./store";
import type { Exchange, MessageView } from "./types";
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

async function fetchRaw(messageId: number): Promise<string> {
  const message = await api<MessageView>(`/api/message/${messageId}`);
  return message.text ?? "";
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
  for (;;) {
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
  sendToComparer: (exchange: Exchange, slot: "a" | "b") => Promise<void>;
  addToOrganizer: (exchange: Exchange) => Promise<void>;
  copyUrl: (exchange: Exchange) => Promise<void>;
  copyCurl: (exchange: Exchange) => Promise<void>;
  filterByHost: (exchange: Exchange) => void;
  addToScope: (exchange: Exchange) => Promise<void>;
  auditExchange: (exchange: Exchange) => Promise<void>;
  sendToDecoder: (exchange: Exchange) => Promise<void>;
  copyRequestToFile: (exchange: Exchange) => Promise<void>;
  requestInBrowser: (exchange: Exchange) => void;
  changeRequestMethod: (exchange: Exchange) => Promise<void>;
  changeBodyEncoding: (exchange: Exchange) => Promise<void>;
  crawlFrom: (exchange: Exchange, scope: "branch" | "host") => Promise<void>;
  menu: (exchange: Exchange, extra?: MenuGroup[]) => MenuGroup[];
} {
  const openRepeaterTab = useApp((state) => state.openRepeaterTab);
  const setRoute = useApp((state) => state.setRoute);
  const setIntruderSeed = useApp((state) => state.setIntruderSeed);
  const setComparerSlot = useApp((state) => state.setComparerSlot);
  const setHistoryQuery = useApp((state) => state.setHistoryQuery);
  const setDecoderSeed = useApp((state) => state.setDecoderSeed);

  const sendToRepeater = async (exchange: Exchange) => {
    try {
      const raw = await fetchRaw(exchange.request);
      openRepeaterTab({
        name: `#${exchange.id} ${exchange.method} ${exchange.path}`.slice(0, 42),
        target: exchangeAuthority(exchange),
        protocol: schemeOf(exchange),
        request: raw,
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
      toast.success(`${exchange.host} added to scope`);
    } catch (error) {
      toast.error(`Could not scope ${exchange.host}: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const auditExchange = async (exchange: Exchange) => {
    try {
      await api<unknown>(`/api/audit/${exchange.id}`, json("POST", {}));
      toast.success(`Active audit queued for exchange #${exchange.id}`);
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

  /**
   * Open the target in a browser tab. Capture only happens if the operator's browser routes
   * through burpsy's proxy, so the toast says that instead of implying burpsy fetched anything.
   */
  const requestInBrowser = (exchange: Exchange) => {
    window.open(exchangeUrl(exchange), "_blank", "noopener");
    toast.info("Opened in your browser — it is captured only if that browser uses burpsy's proxy");
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

  /** Toggle chunked framing on a copy and hand it to Repeater. */
  const changeBodyEncoding = async (exchange: Exchange) => {
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

  const generateCSRF = async (exchange: Exchange) => {
    try {
      const view = await api<{ html: string; notes: string[] }>(`/api/exchange/${exchange.id}/csrf`);
      // Opened as a blob page rather than copied to the clipboard: the PoC IS an auto-submitting
      // page, so rendering it is both the review surface and the proof.
      const blob = new Blob([view.html], { type: "text/html" });
      window.open(URL.createObjectURL(blob), "_blank", "noopener");
      for (const note of view.notes ?? []) toast.info(note);
    } catch (error) {
      toast.error(`Could not generate the CSRF PoC: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const menu = (exchange: Exchange, extra: MenuGroup[] = []): MenuGroup[] => [
    {
      id: "send",
      actions: [
        { id: "repeater", label: "Send to Repeater", icon: Repeat2, shortcut: "R", onSelect: () => void sendToRepeater(exchange) },
        { id: "intruder", label: "Send to Intruder", icon: Crosshair, shortcut: "I", onSelect: () => sendToIntruder(exchange) },
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
        { id: "body-encoding", label: "Change body encoding (chunked)", onSelect: () => void changeBodyEncoding(exchange) },
      ],
    },
    {
      id: "copy",
      actions: [
        { id: "url", label: "Copy URL", icon: Link2, onSelect: () => void copyUrl(exchange) },
        { id: "curl", label: "Copy as curl", icon: Terminal, onSelect: () => void copyCurl(exchange) },
        { id: "id", label: `Copy exchange id (#${exchange.id})`, icon: Copy, onSelect: () => void copyToClipboard(String(exchange.id)) },
        { id: "to-file", label: "Copy request to file", icon: FileCode2, onSelect: () => void copyRequestToFile(exchange) },
      ],
    },
    {
      id: "organise",
      actions: [
        { id: "organizer", label: "Add to Organizer", icon: NotebookPen, onSelect: () => void addToOrganizer(exchange) },
        { id: "host", label: `Filter history by ${exchange.host}`, icon: FolderTree, onSelect: () => filterByHost(exchange) },
        { id: "browser", label: "Open URL in browser", icon: Globe, onSelect: () => requestInBrowser(exchange) },
      ],
    },
    {
      id: "scope-scan",
      actions: [
        { id: "scope", label: `Add ${exchange.host} to scope`, icon: ShieldCheck, onSelect: () => void addToScope(exchange) },
        { id: "audit", label: `Audit exchange #${exchange.id}`, icon: Radar, onSelect: () => void auditExchange(exchange) },
        { id: "crawl-branch", label: "Actively scan this branch (crawl)", icon: Waypoints, onSelect: () => void crawlFrom(exchange, "branch") },
        { id: "crawl-host", label: "Actively scan this host (crawl)", icon: ScanSearch, onSelect: () => void crawlFrom(exchange, "host") },
      ],
    },
    {
      id: "engage",
      title: "Engagement tools",
      actions: [{ id: "csrf", label: "Generate CSRF PoC", icon: FileCode2, onSelect: () => void generateCSRF(exchange) }],
    },
    ...extra,
  ];

  return {
    sendToRepeater,
    sendToIntruder,
    sendToComparer,
    addToOrganizer,
    copyUrl,
    copyCurl,
    filterByHost,
    addToScope,
    auditExchange,
    sendToDecoder,
    copyRequestToFile,
    requestInBrowser,
    changeRequestMethod,
    changeBodyEncoding,
    crawlFrom,
    menu,
  };
}
