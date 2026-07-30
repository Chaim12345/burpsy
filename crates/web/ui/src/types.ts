// Shared response shapes, mirrored from the serde structs in crates/core and crates/web/src.
// Feature-specific shapes (sitemap nodes, findings, tool-log entries, ...) live in their own
// module rather than here, so no two feature files ever need to touch this one.

export interface Exchange {
  id: number;
  request: number;
  response: number | null;
  host: string;
  port: number;
  tls: boolean;
  method: string;
  path: string;
  status: number | null;
  response_len: number;
  started_ms: number;
  duration_ms: number;
  notes: string | null;
  related: unknown[];
  protocol: "Http1" | "Http2";
}

export interface MessageView {
  id: number;
  len: number;
  text: string;
}

export interface Stats {
  exchanges: number;
  messages: number;
  stored_bytes: number;
}

export interface ScopeInfo {
  allow_all: boolean;
  rules: unknown[];
  empty: boolean;
}

/** Cross-tab handoff events, emitted via `emit()` in common.ts and consumed by the target tab. */
export const EVT_SEND_TO_REPEATER = "send-to-repeater";
export const EVT_SEND_TO_INTRUDER = "send-to-intruder";
export const EVT_SEND_TO_COMPARER = "send-to-comparer";
export const EVT_SHOW_EXCHANGE = "show-exchange";

export interface SendToRepeaterDetail {
  target: string;
  raw: string;
  protocol: "Http1" | "Http2";
}

export interface SendToIntruderDetail {
  msgId: number;
  target: string;
}

export interface SendToComparerDetail {
  /** Which comparer slot to fill. */
  side: "a" | "b";
  msgId: number;
  label: string;
}

export interface ShowExchangeDetail {
  exchangeId: number;
}
