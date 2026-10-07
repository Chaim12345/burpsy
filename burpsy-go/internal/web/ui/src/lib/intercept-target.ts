/**
 * The destination an operator points a held request at (burpsy-react-ui-akv).
 *
 * Burp's intercept header bar carries an "Edit target" pencil beside the authority label
 * (BurpClass9694.java: proxyInterceptEditTargetButton, tooltip "Click to modify"), which lets the
 * operator send the item they are holding somewhere other than where the client asked. burpsy's wire
 * carried no destination at all before this, so the capability was missing end to end rather than
 * merely unrendered.
 *
 * The three parts travel together or not at all. The Go side refuses a partial destination rather
 * than completing it from the hold, because a caller that sent only a port would silently inherit the
 * old host and produce a destination nobody typed (see api_intercept.go). This module is the other
 * end of that contract: it builds all three or reports why it cannot.
 *
 * Kept out of the page so the two things that are easy to get wrong — a port that is not a number a
 * socket can take, and a host that is blank — are decided in one place and testable without a server.
 */

export interface InterceptTarget {
  host: string;
  /** 1..65535. Never 0: a retarget to port 0 dials nothing and reads as an engine failure. */
  port: number;
  /**
   * Whether this request goes out over TLS — a property of the destination, not of the connection it
   * arrived on. A request delivered by a client over plain HTTP can be retargeted to an https origin
   * and the proxy will dial TLS for it.
   */
  tls: boolean;
}

/**
 * The authority as the held-message table spells it, deliberately: the row an operator clicked and
 * the header bar above the editor must name the same destination the same way, or a retarget looks
 * like it moved something it did not.
 */
export function describeTarget(target: InterceptTarget): string {
  return `${target.host}:${target.port}${target.tls ? " (tls)" : ""}`;
}

/** The scheme a retarget would use, for the tooltip that spells out what "(tls)" means. */
export function targetScheme(target: InterceptTarget): string {
  return target.tls ? "https" : "http";
}

/**
 * Whether two targets are the same destination.
 *
 * Used to tell "the operator opened the editor and left it alone" from "the operator changed where
 * this goes", which the page reports in the header bar. The engine collapses the unchanged case to no
 * target itself, so an editor merely opened and closed costs nothing on the wire.
 */
export function sameTarget(a: InterceptTarget, b: InterceptTarget): boolean {
  return a.host === b.host && a.port === b.port && a.tls === b.tls;
}

export type TargetDraftResult =
  | { ok: true; target: InterceptTarget }
  | { ok: false; error: string };

/**
 * Read the editor's three fields into a target, or say what is wrong with them.
 *
 * Refusals are stated as what would go wrong rather than as which field failed a test: "the port must
 * be a whole number in 1..65535" tells the operator what a port is, and the engine would refuse the
 * same values with its own sentence, so the page and the wire agree about what a usable destination
 * is instead of one accepting what the other rejects.
 */
export function targetFromDraft(hostRaw: string, portRaw: string, tls: boolean): TargetDraftResult {
  const host = hostRaw.trim();
  if (host === "") {
    return { ok: false, error: "A target needs a host — a blank one would dial the local machine." };
  }
  // A host with a slash or whitespace inside it is a URL pasted into the wrong field; passing it
  // through would send the request line's path as part of the Host header, which resolves to a name
  // nobody owns and is answered as a DNS failure rather than as the mistake it is.
  if (/\s/.test(host) || host.includes("/")) {
    return { ok: false, error: "A host cannot contain spaces or a path — put the path in the request line." };
  }
  const portText = portRaw.trim();
  if (portText === "") {
    return { ok: false, error: "A target needs a port: 443 for https, 80 for http." };
  }
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: "The port must be a whole number in 1..65535." };
  }
  return { ok: true, target: { host, port, tls } };
}

/**
 * The destination a held row already has, as a draft to start editing from.
 *
 * A function rather than an inline object literal so a caller cannot accidentally omit `tls` and
 * retarget an https request to plain HTTP by opening the editor and pressing Forward.
 */
export function targetOf(row: { host: string; port: number; tls: boolean }): InterceptTarget {
  return { host: row.host, port: row.port, tls: row.tls };
}
