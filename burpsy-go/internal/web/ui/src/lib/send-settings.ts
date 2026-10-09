import type { IntruderConfig } from "./store";
import type { RepeaterSendOptions } from "./types";

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
/**
 * A Repeater tab's streaming-response window as typed (of0z): blank is "not set" (the network
 * settings' window applies), 0 is Burp's "no cutoff", a positive number is milliseconds. Anything
 * else is "not set" rather than a value the server would refuse.
 */
export function parseStreamingTimeoutMS(text: string): number | undefined {
  const trimmed = text.trim();
  if (trimmed === "") return undefined;
  const value = Number(trimmed);
  if (!Number.isFinite(value) || value < 0) return undefined;
  return Math.floor(value);
}

/**
 * A tab's send options with a patch applied and every "standing behaviour" value removed, so the
 * wire carries only what the operator chose. Empty strings and false are the defaults for every
 * field but one: unpack_responses defaults to ON (Burp's default), so it is `true` that is dropped
 * and an explicit `false` that is kept. 0 is kept — for streaming_timeout_ms it means "no cutoff".
 */
export function mergeRepeaterOptions(current: RepeaterSendOptions | undefined, patch: Partial<RepeaterSendOptions>): RepeaterSendOptions {
  const merged: RepeaterSendOptions = { ...(current ?? {}), ...patch };
  for (const key of Object.keys(merged) as (keyof RepeaterSendOptions)[]) {
    const value = merged[key];
    const standing = key === "unpack_responses" ? value === true : value === false;
    if (value === undefined || value === "" || standing) delete merged[key];
  }
  return merged;
}

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
  "responseTimeoutMS" | "http1ConnectionReuse" | "httpVersion" | "setConnectionClose" | "updateHostHeader"
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
  // Sent only when on: an absent field is the server's "leave the Host header as captured". `!== false`
  // so an attack persisted before the setting existed gets Burp's default rather than nothing.
  if (config.updateHostHeader !== false) fields.update_host_header = true;
  return fields;
}

/**
 * What the report says Update Host header to match target did NOT do, as result caveats: the whole
 * setting stood aside (a position covers Host, or the base request does not carry exactly one), or
 * some requests kept the Host header a payload gave them. Empty when there is nothing to say.
 */
export function hostHeaderCaveats(view: { host_header_skipped?: string; host_header_untouched?: number }): string[] {
  const out: string[] = [];
  if (view.host_header_skipped) out.push(`Host header not updated to match the target: ${view.host_header_skipped}.`);
  const untouched = view.host_header_untouched ?? 0;
  if (untouched > 0) {
    out.push(
      `${untouched} request${untouched === 1 ? "" : "s"} kept the Host header the payload produced (not exactly one Host header, so none was rewritten).`,
    );
  }
  return out;
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
