/**
 * The proxy-listener row's draft state and the prose that describes what a listener actually
 * does (burpsy-react-ui-pfeg).
 *
 * Pure, and separate from the page, for two reasons. The validation here mirrors the Go
 * refusals in api_proxylistener.go so a typo is answered in the form rather than as a round
 * trip — but it is deliberately NOT the authority: the server refuses the same values and the
 * page shows its message, because a bind can only really be judged by trying it. And
 * describeListener is the answer to "what is this row doing", which a table of five columns
 * cannot give: a listener with no redirect and no force-TLS is an ordinary proxy and should
 * say so rather than leave the operator to infer it from four empty cells.
 */
import type { ProxyListenerBody, ProxyListenerRow } from "./data.proxylistener";

/** Invisible proxying is a tri-state on the wire (null = inherit); the form spells it out. */
export type InvisibleChoice = "inherit" | "on" | "off";

export interface ListenerDraft {
  bind: string;
  redirectHost: string;
  redirectPort: string;
  forceTLS: boolean;
  invisible: InvisibleChoice;
  /** "Support HTTP/2" (34rd). On unless the operator turns it off. */
  supportHTTP2: boolean;
}

export function emptyListenerDraft(): ListenerDraft {
  return { bind: "", redirectHost: "", redirectPort: "", forceTLS: false, invisible: "inherit", supportHTTP2: true };
}

export function draftFromListener(row: ProxyListenerRow): ListenerDraft {
  return {
    bind: row.bind,
    redirectHost: row.redirect_host,
    redirectPort: row.redirect_port ? String(row.redirect_port) : "",
    forceTLS: row.force_tls,
    invisible: row.invisible === null ? "inherit" : row.invisible ? "on" : "off",
    supportHTTP2: row.support_http2 !== false,
  };
}

export type DraftResult = { ok: true; body: ProxyListenerBody } | { ok: false; error: string };

/**
 * Turn a form into a request body, or say why it cannot be one. Every refusal names the field
 * and what a good value looks like — an operator who mistypes a port should not have to guess
 * which of five inputs the server disliked.
 */
export function listenerDraftToBody(draft: ListenerDraft): DraftResult {
  const bind = draft.bind.trim();
  if (!bind) return { ok: false, error: "A bind address is required, in host:port form — for example 127.0.0.1:8081." };
  const bindPort = bind.slice(bind.lastIndexOf(":") + 1);
  if (!bind.includes(":") || bind.lastIndexOf(":") === bind.length - 1) {
    return { ok: false, error: "The bind address needs a port: host:port, for example 127.0.0.1:8081." };
  }
  if (bind.startsWith(":")) {
    return { ok: false, error: 'The bind address needs a host: "" binds nothing; use 0.0.0.0 for every interface.' };
  }
  if (!/^\d+$/.test(bindPort) || Number(bindPort) > 65535) {
    return { ok: false, error: "The bind port must be a number between 0 and 65535; 0 picks an ephemeral port." };
  }

  const redirectHost = draft.redirectHost.trim();
  if (redirectHost.includes("://")) {
    return { ok: false, error: "The redirect host is a hostname or IP, not a URL — drop the scheme." };
  }
  if (/[/?# ]/.test(redirectHost)) {
    return { ok: false, error: "The redirect host is a hostname or IP: no path, query or spaces." };
  }
  if (!redirectHost.startsWith("[") && (redirectHost.match(/:/g) ?? []).length === 1) {
    return { ok: false, error: "The redirect host carries a port — put the port in the redirect-port field instead." };
  }

  const rawPort = draft.redirectPort.trim();
  let redirectPort = 0;
  if (rawPort) {
    if (!/^\d+$/.test(rawPort) || Number(rawPort) > 65535) {
      return { ok: false, error: "The redirect port must be a number between 0 and 65535; leave it blank to keep the port the client asked for." };
    }
    redirectPort = Number(rawPort);
  }

  return {
    ok: true,
    body: {
      bind,
      redirect_host: redirectHost,
      redirect_port: redirectPort,
      force_tls: draft.forceTLS,
      invisible: draft.invisible === "inherit" ? null : draft.invisible === "on",
      // Sent only when off, so a listener the operator never touched keeps the default on the wire.
      ...(draft.supportHTTP2 ? {} : { support_http2: false }),
    },
  };
}

/**
 * One sentence saying what this listener does to the traffic it accepts, with the
 * invisible-proxying tri-state resolved against the process-wide switch — the effective
 * behaviour, not the stored value, because a tick that reads "inherit" tells an operator
 * nothing about what their client will get.
 */
export function describeListener(row: ProxyListenerRow, globalInvisible: boolean): string {
  const parts: string[] = [];
  if (row.redirect_host && row.redirect_port) {
    parts.push(`sends every request to ${row.redirect_host}:${row.redirect_port} instead of the host the client named`);
  } else if (row.redirect_host) {
    parts.push(`sends every request to ${row.redirect_host}, keeping the port the client asked for`);
  } else if (row.redirect_port) {
    parts.push(`sends every request to port ${row.redirect_port}, keeping the host the client asked for`);
  }
  if (row.force_tls) {
    parts.push("reaches the destination over TLS whatever the client used to get here");
  }
  if (row.support_http2 === false) {
    parts.push("holds clients to HTTP/1.1, never offering HTTP/2");
  }
  const invisible = row.invisible === null ? globalInvisible : row.invisible;
  parts.push(
    invisible
      ? `accepts origin-form requests from clients that were never told about a proxy${row.invisible === null ? " (inherited from the switch below)" : ""}`
      : `refuses an origin-form request it cannot attribute${row.invisible === null ? " (inherited from the switch below)" : ""}`,
  );
  if (parts.length === 1 && !row.redirect_host && !row.redirect_port && !row.force_tls && row.support_http2 !== false) {
    return `An ordinary proxy listener: it ${parts[0]}, and forwards everything else to the destination the client named.`;
  }
  return `This listener ${parts.join(", and ")}.`;
}

/** The recorded-traffic caveat, stated once and shown next to any redirecting listener. */
export const REDIRECT_CAVEAT =
  "A redirect moves the destination, not the Host header: the origin still sees the name the client asked for, which is what makes a vhost on the redirect target answer. Scope, the out-of-scope fence and the recorded exchange all follow the redirect, so history shows where the bytes actually went.";
