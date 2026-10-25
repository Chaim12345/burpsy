import type { IntruderConfig } from "./store";
import type { CaptureFilterSpec } from "./types.tools";

/**
 * Burp's Intruder results capture filter (burpsy-react-ui-ip2b): "Choose which items Intruder captures
 * during the attack to control resource usage" — Discard items without responses, Capture by search term
 * (regex, case sensitive, negative search) and Capture by status code. Distinct from the Results tab's
 * view filter, which only hides rows that were captured: a discarded item leaves no row and no stored
 * request or response, and cannot be brought back. Its counts survive — Sent, Failed, the buckets, and
 * the report's `discarded`.
 */

export const STATUS_CLASSES = ["2xx", "3xx", "4xx", "5xx"] as const;
export type StatusClassName = (typeof STATUS_CLASSES)[number];

export type StorageConfig = Pick<IntruderConfig, "storeRequests" | "storeResponses">;

/**
 * Burp's "Store requests" / "Store responses" (burpsy-react-ui-nqww) as run-request fields. Each is sent
 * only when switched off: absent is the server's (and Burp's) "store", and an attack persisted before
 * the switches existed keeps storing.
 */
export function storageFields(config: StorageConfig): { store_requests?: false; store_responses?: false } {
  return {
    ...(config.storeRequests === false ? { store_requests: false as const } : {}),
    ...(config.storeResponses === false ? { store_responses: false as const } : {}),
  };
}

/** Why a row has no request or response to act on, when the attack itself chose not to store it. */
export const NOT_STORED = "Not stored (attack setting): this attack ran with storage switched off in Settings.";

/**
 * The reason a result row carries no stored request or response: the attack setting when it was off,
 * otherwise the row-specific fallback the caller gives (a failed send, a row that did not open its bucket).
 */
export function missingReason(stored: boolean | undefined, fallback: string): string {
  return stored === false ? NOT_STORED : fallback;
}

export type CaptureConfig = Pick<
  IntruderConfig,
  | "captureFilterEnabled"
  | "captureDiscardNoResponse"
  | "captureTerm"
  | "captureRegex"
  | "captureCaseSensitive"
  | "captureNegate"
  | "captureStatuses"
>;

/**
 * The run request's capture_filter, or nothing when the filter is off. Off sends nothing at all rather
 * than an all-capturing object, so "I did not set a filter" stays one wire shape. Statuses are sent only
 * when some class is unticked: all four is the server's default, and a list naming all four would be a
 * second spelling of it.
 */
export function captureFilterField(config: CaptureConfig): { capture_filter?: CaptureFilterSpec } {
  if (!config.captureFilterEnabled) return {};
  const statuses = STATUS_CLASSES.filter((c) => (config.captureStatuses ?? [...STATUS_CLASSES]).includes(c));
  return {
    capture_filter: {
      discard_no_response: config.captureDiscardNoResponse === true,
      term: config.captureTerm ?? "",
      regex: config.captureRegex === true,
      case_sensitive: config.captureCaseSensitive === true,
      negate: config.captureNegate === true,
      ...(statuses.length < STATUS_CLASSES.length ? { statuses } : {}),
    },
  };
}

/**
 * The filter as one line, in the words of Burp's filter bar (Zx1y): what is discarded and what is
 * captured, or "Capturing all items".
 */
export function describeCaptureFilter(spec: CaptureFilterSpec | null | undefined): string {
  if (!spec) return "Capturing all items";
  const parts: string[] = [];
  if (spec.discard_no_response) parts.push("discarding items without responses");
  const statuses = spec.statuses ?? [...STATUS_CLASSES];
  const dropped = STATUS_CLASSES.filter((c) => !statuses.includes(c));
  if (dropped.length) parts.push(`discarding ${dropped.join(", ")}`);
  if (spec.term) {
    parts.push(`${spec.negate ? "not " : ""}matching ${spec.regex ? "regex" : "expression"} ${spec.term}${spec.case_sensitive ? " (case sensitive)" : ""}`);
  }
  if (!parts.length) return "Capturing all items";
  const text = parts.join("; ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}
