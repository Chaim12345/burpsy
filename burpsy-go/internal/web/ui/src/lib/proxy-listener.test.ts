import { describe, expect, test } from "bun:test";
import type { ProxyListenerRow } from "./data.proxylistener";
import { describeListener, draftFromListener, emptyListenerDraft, listenerDraftToBody } from "./proxy-listener";

const row = (over: Partial<ProxyListenerRow> = {}): ProxyListenerRow => ({
  id: "listener-1",
  bind: "127.0.0.1:8081",
  bound_addr: "127.0.0.1:8081",
  redirect_host: "",
  redirect_port: 0,
  force_tls: false,
  invisible: null,
  removable: true,
  ...over,
});

describe("listenerDraftToBody", () => {
  test("a blank bind is refused before a round trip", () => {
    const got = listenerDraftToBody(emptyListenerDraft());
    expect(got.ok).toBe(false);
    if (!got.ok) expect(got.error).toContain("host:port");
  });

  test("the bind must carry a host and a real port", () => {
    for (const bind of ["8081", "127.0.0.1", ":8081", "127.0.0.1:70000", "127.0.0.1:"]) {
      const got = listenerDraftToBody({ ...emptyListenerDraft(), bind });
      expect(got.ok).toBe(false);
    }
    expect(listenerDraftToBody({ ...emptyListenerDraft(), bind: "127.0.0.1:0" }).ok).toBe(true);
  });

  test("a redirect host is a hostname, not a URL and not host:port", () => {
    const scheme = listenerDraftToBody({ ...emptyListenerDraft(), bind: "127.0.0.1:8081", redirectHost: "http://a.test" });
    expect(scheme.ok).toBe(false);
    if (!scheme.ok) expect(scheme.error).toContain("scheme");

    const withPort = listenerDraftToBody({ ...emptyListenerDraft(), bind: "127.0.0.1:8081", redirectHost: "a.test:8443" });
    expect(withPort.ok).toBe(false);
    if (!withPort.ok) expect(withPort.error).toContain("redirect-port");

    // A bracketed IPv6 literal is an address, not a host:port, and is accepted.
    expect(listenerDraftToBody({ ...emptyListenerDraft(), bind: "127.0.0.1:8081", redirectHost: "[::1]" }).ok).toBe(true);
  });

  test("a blank redirect port means keep the client's port, and 0 is what the wire carries", () => {
    const got = listenerDraftToBody({ ...emptyListenerDraft(), bind: "127.0.0.1:8081", redirectHost: "a.test" });
    expect(got.ok).toBe(true);
    if (got.ok) expect(got.body.redirect_port).toBe(0);

    const bad = listenerDraftToBody({ ...emptyListenerDraft(), bind: "127.0.0.1:8081", redirectPort: "nope" });
    expect(bad.ok).toBe(false);
  });

  test("the invisible tri-state reaches the wire as null / true / false", () => {
    const base = { ...emptyListenerDraft(), bind: "127.0.0.1:8081" };
    const inherit = listenerDraftToBody(base);
    const on = listenerDraftToBody({ ...base, invisible: "on" });
    const off = listenerDraftToBody({ ...base, invisible: "off" });
    expect(inherit.ok && inherit.body.invisible).toBe(null);
    expect(on.ok && on.body.invisible).toBe(true);
    expect(off.ok && off.body.invisible).toBe(false);
  });

  test("a row round-trips through the edit form unchanged", () => {
    const original = row({ redirect_host: "10.0.0.5", redirect_port: 8443, force_tls: true, invisible: false });
    const got = listenerDraftToBody(draftFromListener(original));
    expect(got.ok).toBe(true);
    if (got.ok) {
      expect(got.body).toEqual({
        bind: "127.0.0.1:8081",
        redirect_host: "10.0.0.5",
        redirect_port: 8443,
        force_tls: true,
        invisible: false,
      });
    }
  });
});

describe("describeListener", () => {
  test("a plain listener says it is a plain listener", () => {
    expect(describeListener(row(), true)).toContain("An ordinary proxy listener");
  });

  test("both halves of a redirect are described, and each half alone says what it keeps", () => {
    expect(describeListener(row({ redirect_host: "a.test", redirect_port: 8443 }), true)).toContain("a.test:8443");
    expect(describeListener(row({ redirect_host: "a.test" }), true)).toContain("keeping the port the client asked for");
    expect(describeListener(row({ redirect_port: 8443 }), true)).toContain("keeping the host the client asked for");
  });

  test("force TLS is described as what it changes: the leg to the destination", () => {
    expect(describeListener(row({ force_tls: true }), true)).toContain("over TLS whatever the client used");
  });

  test("invisible proxying is described as the effective behaviour, and inheritance is named", () => {
    expect(describeListener(row({ invisible: null }), true)).toContain("inherited from the switch below");
    expect(describeListener(row({ invisible: null }), false)).toContain("refuses an origin-form request");
    // An explicit tick overrides the global switch in both directions, and does not claim to inherit.
    expect(describeListener(row({ invisible: false }), true)).toContain("refuses an origin-form request");
    expect(describeListener(row({ invisible: false }), true)).not.toContain("inherited");
    expect(describeListener(row({ invisible: true }), false)).toContain("accepts origin-form requests");
  });
});
