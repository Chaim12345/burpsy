import {
  ArrowRightLeft,
  Combine,
  Copy,
  Crosshair,
  FolderTree,
  Link2,
  NotebookPen,
  Repeat2,
  Terminal,
} from "lucide-react";
import { toast } from "sonner";
import { api, copyToClipboard } from "./api";
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
  menu: (exchange: Exchange, extra?: MenuGroup[]) => MenuGroup[];
} {
  const openRepeaterTab = useApp((state) => state.openRepeaterTab);
  const setRoute = useApp((state) => state.setRoute);
  const setIntruderSeed = useApp((state) => state.setIntruderSeed);
  const setComparerSlot = useApp((state) => state.setComparerSlot);
  const setHistoryQuery = useApp((state) => state.setHistoryQuery);

  const sendToRepeater = async (exchange: Exchange) => {
    try {
      const raw = await fetchRaw(exchange.request);
      openRepeaterTab({
        name: `#${exchange.id} ${exchange.method} ${exchange.path}`.slice(0, 42),
        target: exchangeAuthority(exchange),
        protocol: schemeOf(exchange),
        request: raw,
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

  const menu = (exchange: Exchange, extra: MenuGroup[] = []): MenuGroup[] => [
    {
      id: "send",
      actions: [
        { id: "repeater", label: "Send to Repeater", icon: Repeat2, shortcut: "R", onSelect: () => void sendToRepeater(exchange) },
        { id: "intruder", label: "Send to Intruder", icon: Crosshair, shortcut: "I", onSelect: () => sendToIntruder(exchange) },
        { id: "compare-a", label: "Send to Comparer (A)", icon: Combine, onSelect: () => void sendToComparer(exchange, "a") },
        { id: "compare-b", label: "Send to Comparer (B)", icon: ArrowRightLeft, onSelect: () => void sendToComparer(exchange, "b") },
      ],
    },
    {
      id: "copy",
      actions: [
        { id: "url", label: "Copy URL", icon: Link2, onSelect: () => void copyUrl(exchange) },
        { id: "curl", label: "Copy as curl", icon: Terminal, onSelect: () => void copyCurl(exchange) },
        { id: "id", label: `Copy exchange id (#${exchange.id})`, icon: Copy, onSelect: () => void copyToClipboard(String(exchange.id)) },
      ],
    },
    {
      id: "organise",
      actions: [
        { id: "organizer", label: "Add to Organizer", icon: NotebookPen, onSelect: () => void addToOrganizer(exchange) },
        { id: "host", label: `Filter history by ${exchange.host}`, icon: FolderTree, onSelect: () => filterByHost(exchange) },
      ],
    },
    ...extra,
  ];

  return { sendToRepeater, sendToIntruder, sendToComparer, addToOrganizer, copyUrl, copyCurl, filterByHost, menu };
}
