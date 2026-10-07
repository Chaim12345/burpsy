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
export type IntruderSendSettings = Pick<IntruderConfig, "responseTimeoutMS">;

export function intruderSendSettingsFields(config: IntruderSendSettings): Record<string, unknown> {
  const fields: Record<string, unknown> = {};
  const responseTimeout = parseResponseTimeoutMS(config.responseTimeoutMS ?? "");
  if (responseTimeout !== undefined) fields.response_timeout_ms = responseTimeout;
  return fields;
}
