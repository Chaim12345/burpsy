// Which connection a Repeater WebSocket tab sends on (burpsy-react-ui-wuwf).
//
// Burp: "You can clone or attach to any open connection, create a new connection, or reconnect a
// closed connection." A ws tab opened from WebSockets history knows the connection it came from
// (its WebSocket ID), so it can:
//   - attach — write the frame into that very socket while the proxy still holds it, toward the
//     server or toward the client; the replies are the browser's own conversation;
//   - clone — open a NEW connection with that connection's captured handshake (its cookies,
//     Origin, Authorization, subprotocol), so the target sees the same client;
//   - new — open a new connection with a minimal handshake to the tab's Target, the only mode a
//     tab started by hand has.
//
// Pure over the tab and the connection's live flag, so the decision of what is offered and what
// is sent is pinned by a unit test without a browser.

export type WsConnectionMode = "new" | "clone" | "attach";

/** The fields of a Repeater tab this module reads. */
export interface WsTabLike {
 target: string;
 wsPayload?: string;
 wsOpcode?: string;
 wsDirection?: "server" | "client";
 /** The WebSocket ID (handshake exchange) the tab was opened from; absent for a hand-made tab. */
 wsSocket?: number;
 /** The connection's path, sent with a new-connection send so it reaches the same endpoint. */
 wsPath?: string;
 wsMode?: WsConnectionMode;
}

/**
 * The mode a tab opened from a frame starts in: attach when the proxy still holds the connection
 * (Burp's own default for an open connection), clone when it has closed, new when the tab names
 * no connection at all.
 */
export function defaultWsMode(socket: number | undefined, live: boolean): WsConnectionMode {
 if (socket === undefined) return "new";
 return live ? "attach" : "clone";
}

/** The mode a tab is actually in. A tab persisted before modes existed reads as "new". */
export function effectiveWsMode(tab: WsTabLike): WsConnectionMode {
 if (tab.wsSocket === undefined) return "new";
 return tab.wsMode ?? "new";
}

export interface WsModeOption {
 value: WsConnectionMode;
 label: string;
 /** Set when the option cannot run now; the reason is what the control says instead of hiding it. */
 disabledReason?: string;
}

/**
 * The connection chooser's options. Every mode is listed, and one that cannot run says why —
 * a chooser that silently dropped "attach" would read as a tool that cannot attach at all.
 */
export function wsModeOptions(socket: number | undefined, live: boolean): WsModeOption[] {
 const noSocket = "This tab was not opened from a captured connection";
 return [
  { value: "new", label: "New connection (to Target)" },
  {
   value: "clone",
   label: socket === undefined ? "Clone a connection" : `Clone WebSocket #${socket} (same handshake)`,
   ...(socket === undefined ? { disabledReason: noSocket } : {}),
  },
  {
   value: "attach",
   label: socket === undefined ? "Attach to a live connection" : `Attach to live WebSocket #${socket}`,
   ...(socket === undefined
    ? { disabledReason: noSocket }
    : live
      ? {}
      : { disabledReason: `WebSocket #${socket} is no longer open through the proxy — clone it instead` }),
  },
 ];
}

export type WsSendPlan =
 | { route: "/api/repeater/ws-send"; body: Record<string, unknown> }
 | { route: "/api/repeater/ws-attach"; body: Record<string, unknown> };

/**
 * What a ws tab's Send posts. Liveness is NOT decided here: the connection may close between the
 * last poll and the click, and the server's registry is the authority — it answers a closed
 * connection with its reason, which the pane shows.
 *
 * to_client rides every mode. On attach it is a real direction; on new and clone the server
 * refuses it with the reason (a fresh connection has no client), which is shown rather than the
 * choice being hidden.
 */
export function planWsSend(tab: WsTabLike): WsSendPlan {
 const opcode = tab.wsOpcode ?? "text";
 const payload = tab.wsPayload ?? "";
 const toClient = (tab.wsDirection ?? "server") === "client" ? { to_client: true } : {};
 const mode = effectiveWsMode(tab);
 if (mode === "attach" && tab.wsSocket !== undefined) {
  return { route: "/api/repeater/ws-attach", body: { socket: tab.wsSocket, opcode, payload, ...toClient } };
 }
 if (mode === "clone" && tab.wsSocket !== undefined) {
  return { route: "/api/repeater/ws-send", body: { clone: true, socket: tab.wsSocket, opcode, payload, ...toClient } };
 }
 return {
  route: "/api/repeater/ws-send",
  body: { target: tab.target, ...(tab.wsPath ? { path: tab.wsPath } : {}), opcode, payload, ...toClient },
 };
}

/** The Target a tab opened from a connection shows: the ws spelling the send understands. */
export function wsTargetOf(conn: { host: string; port: number; tls?: boolean }): string {
 const host = conn.host.includes(":") && !conn.host.startsWith("[") ? `[${conn.host}]` : conn.host;
 return `${conn.tls ? "wss" : "ws"}://${host}:${conn.port}`;
}

/** Whether the direction "to client" can actually run in a mode. */
export function toClientRuns(mode: WsConnectionMode): boolean {
 return mode === "attach";
}

/** The fields of a WebSockets-history frame row this module reads. */
export interface WsFrameRowLike {
 id: number;
 exchange: number;
 opcode: string;
 url?: string;
 tls?: boolean;
}

/** The connection row a frame belongs to, as /api/ws/connections reports it. */
export interface WsConnLike {
 exchange: number;
 host: string;
 port: number;
 tls?: boolean;
 path: string;
 live?: boolean;
}

/**
 * The Repeater tab "Send to Repeater" opens from a WebSockets-history frame (wuwf). A ws tab, not
 * an HTTP one: it carries the frame's payload and opcode, the connection it came from (so it can
 * attach or clone), and that connection's target and path (so "new connection" reaches the same
 * endpoint). It starts attached when the proxy still holds the connection.
 *
 * payload is the frame's text when the detail has loaded, null when it has not — the tab then opens
 * with an empty editor rather than a guessed payload.
 */
export function wsTabSeedFromFrame(row: WsFrameRowLike, conn: WsConnLike | null, payload: string | null) {
 const live = conn?.live === true;
 let target = "";
 let path: string | undefined;
 if (conn) {
  target = wsTargetOf(conn);
  path = conn.path || undefined;
 } else if (row.url) {
  // The frame's own URL, when its connection row is not in the list (paged out): same facts.
  try {
   const url = new URL(row.url);
   const port = url.port || (url.protocol === "https:" ? "443" : "80");
   target = `${url.protocol === "https:" ? "wss" : "ws"}://${url.hostname}:${port}`;
   path = `${url.pathname}${url.search}` || undefined;
  } catch {
   target = "";
  }
 }
 return {
  name: `WS #${row.exchange} frame #${row.id}`.slice(0, 42),
  target,
  protocol: conn?.tls || row.tls ? "https" : "http",
  request: "",
  kind: "ws" as const,
  wsPayload: payload ?? "",
  wsOpcode: row.opcode === "binary" ? "binary" : "text",
  wsSocket: row.exchange,
  ...(path ? { wsPath: path } : {}),
  wsMode: defaultWsMode(row.exchange, live),
 };
}
