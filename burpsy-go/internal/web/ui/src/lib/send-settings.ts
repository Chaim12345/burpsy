import type { IntruderConfig } from "./store";

/**
 * The send settings Intruder and Repeater put on the wire (burpsy-react-ui-xixe.1, Phase 1).
 *
 * Pure functions, out of the page, so the step that turns what is on screen into request fields is
 * testable without rendering the page — the same reason delayVariationFields lives in its own file.
 * Every field here is omitted when the operator left it at "the standing behaviour", because an
 * absent field and an explicit default must not become two wire shapes for "I did not choose".
 */

/**
 * A typed response timeout in milliseconds, or undefined for "the standing read timeout".
 *
 * Blank, zero, negative and non-numbers are all undefined: the server refuses a zero or negative
 * response_timeout_ms (it cannot mean a bound), and a field that sent one would turn a cleared input
 * into a refused launch rather than into the standing behaviour the empty field shows.
 */
export function parseResponseTimeoutMS(text: string): number | undefined {
  const trimmed = text.trim();
  if (trimmed === "") return undefined;
  const value = Number(trimmed);
  if (!Number.isFinite(value) || value <= 0) return undefined;
  return Math.floor(value);
}

/** The Intruder settings this module owns, as the run request's fields. */
export type IntruderSendSettings = Pick<
  IntruderConfig,
  "responseTimeoutMS" | "http1ConnectionReuse" | "httpVersion" | "setConnectionClose"
>;

/**
 * Whether HTTP/1 connection reuse is actually requested. Set Connection header wins: every request
 * then says Connection: close, which the server never reuses, and it refuses the pair outright —
 * so the control is shown off and nothing is sent, rather than a launch that fails.
 */
export function reuseRequested(config: Pick<IntruderSendSettings, "http1ConnectionReuse" | "setConnectionClose">): boolean {
  return config.http1ConnectionReuse !== false && !config.setConnectionClose;
}

export function intruderSendSettingsFields(config: IntruderSendSettings): Record<string, unknown> {
  const fields: Record<string, unknown> = {};
  const responseTimeout = parseResponseTimeoutMS(config.responseTimeoutMS ?? "");
  if (responseTimeout !== undefined) fields.response_timeout_ms = responseTimeout;
  // Sent only when on: an absent field is the server's "one connection per request".
  if (reuseRequested(config)) fields.http1_connection_reuse = true;
  if (config.httpVersion === "http1" || config.httpVersion === "http2") fields.http_version = config.httpVersion;
  return fields;
}

/**
 * The report's connection counts as one line, or null when the attack did not count them (reuse was
 * off, or an older server). Null is not zero: "every request had its own connection" and "reuse was
 * on and never happened" are different findings about the target.
 */
export function connectionReuseSummary(view: { connections_opened?: number | null; connections_reused?: number | null }): string | null {
  const opened = view.connections_opened;
  const reused = view.connections_reused;
  if (typeof opened !== "number" || typeof reused !== "number") return null;
  return `${opened} opened, ${reused} ${reused === 1 ? "request" : "requests"} on a reused connection`;
}
