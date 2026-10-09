/**
 * The trailing "<Tool> documentation" entry on table and editor context menus (u9zz).
 *
 * Burp ends its menus with one: Zr2s.java adds `new Zu2h("Proxy history documentation",
 * Zx10.DESKTOP_TOOLS_PROXY_HISTORY, …)` after a separator, Zs7j.java "Repeater documentation".
 * Burp's opens PortSwigger's site. burpsy serves no documentation route and links nowhere
 * outbound (lib/reference.ts says why), so the entry opens the in-app reference — the Discover
 * page — at that tool's own panel, which lists what each menu item does.
 *
 * `null` is a deliberate "this menu has no documentation entry" (the menu bar's tool tabs, which
 * Burp does not give one either); ContextMenu requires every call site to choose.
 */
import { useApp } from "./store";

export type DocTopic =
  | "tables"
  | "proxy-history"
  | "websockets"
  | "site-map"
  | "scope"
  | "intercept"
  | "logger"
  | "organizer"
  | "issues"
  | "intruder"
  | "repeater"
  | "message-editor";

/** The tool name the entry reads as ("Proxy history documentation") and the panel it opens. */
export const DOC_TOPICS: Record<DocTopic, { title: string; panelId: string }> = {
  tables: { title: "Tables", panelId: "tool-tables" },
  "proxy-history": { title: "Proxy history", panelId: "tool-proxy-history" },
  websockets: { title: "WebSockets history", panelId: "tool-websockets" },
  "site-map": { title: "Site map", panelId: "tool-site-map" },
  scope: { title: "Scope", panelId: "tool-scope" },
  intercept: { title: "Intercept", panelId: "tool-intercept" },
  logger: { title: "Logger", panelId: "tool-logger" },
  organizer: { title: "Organizer", panelId: "tool-organizer" },
  issues: { title: "Issues", panelId: "tool-issues" },
  intruder: { title: "Intruder", panelId: "tool-intruder" },
  repeater: { title: "Repeater", panelId: "tool-repeater" },
  "message-editor": { title: "Message editor", panelId: "tool-message-editor" },
};

export function docEntryLabel(topic: DocTopic): string {
  return `${DOC_TOPICS[topic].title} documentation`;
}

// The panel Discover should scroll to when it next renders. A module value with a listener set
// (lib/keymap.ts's shape), because the request comes from a menu factory with no React state.
let pending: string | null = null;
const listeners = new Set<() => void>();

/** Open Discover at a topic's panel. */
export function openDocs(topic: DocTopic): void {
  pending = DOC_TOPICS[topic].panelId;
  for (const listener of listeners) listener();
  useApp.getState().setRoute("discover");
}

/** The panel waiting to be shown, if any. Discover reads it, scrolls, and clears it. */
export function pendingDocPanel(): string | null {
  return pending;
}

export function clearPendingDocPanel(): void {
  pending = null;
}

export function subscribeDocs(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
