import type { IntruderConfig } from "./store";
import type { PointView } from "./types.tools";

/**
 * Burp's "Automatic payload placement" (burpsy-react-ui-1krs): "Replace base parameter value" or
 * "Append to base parameter value".
 *
 * Pure functions, out of the page, because the one property that matters is checkable without
 * rendering anything: /points (the positions the page shows) and /run (the positions the attack
 * splices) must be asked with the SAME placement. If they disagree the page shows append markers while
 * the attack replaces values — so both requests take their field from this one function.
 */

export type PayloadPlacement = IntruderConfig["payloadPlacement"];

export const PAYLOAD_PLACEMENTS: { value: PayloadPlacement; label: string; detail: string }[] = [
 {
  value: "replace",
  label: "Replace base parameter value",
  detail: "Each payload overwrites the parameter's value.",
 },
 {
  value: "append",
  label: "Append to base parameter value",
  detail:
   "Each payload is added after the parameter's value, which is sent as captured. Applies to parameter values only — names, paths, headers and the whole body still replace.",
 },
];

/**
 * The placement as request fields, for /points and /run alike. "replace" is omitted rather than sent,
 * because an absent field is the server's replace and the two must not be two wire shapes for "I did
 * not choose"; anything that is not exactly "append" (an older persisted attack with no field at all)
 * is replace.
 */
export function placementFields(placement: PayloadPlacement | undefined): { payload_placement?: "append" } {
 return placement === "append" ? { payload_placement: "append" } : {};
}

/**
 * How a discovered position reads in the list: what the payload does to which value. An appended
 * position names the value it is added to, never "(empty)" — the zero-length span is where the payload
 * goes, not what the parameter holds.
 */
export function describePoint(point: Pick<PointView, "kind" | "offset" | "current" | "placement">): string {
 const value = point.current === "" ? "(empty)" : point.current;
 if (point.placement === "append") return `${point.kind} · offset ${point.offset} · appends to ${value}`;
 return `${point.kind} · offset ${point.offset} · ${value}`;
}
