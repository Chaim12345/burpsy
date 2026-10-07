import { describe, expect, test } from "bun:test";
import { connectionReuseSummary, intruderSendSettingsFields, parseResponseTimeoutMS } from "./send-settings";
import { emptyIntruderConfig, mergePersistedWorkspace } from "./store";

// ---- what the send-settings controls put on the wire (burpsy-react-ui-xixe.1, Phase 1) ------------

describe("response timeout (mmca)", () => {
  test("a positive number is sent, as whole milliseconds", () => {
    expect(parseResponseTimeoutMS("2500")).toBe(2500);
    expect(parseResponseTimeoutMS(" 20000 ")).toBe(20000);
    expect(intruderSendSettingsFields({ ...emptyIntruderConfig(), responseTimeoutMS: "20000" })).toMatchObject({
      response_timeout_ms: 20000,
    });
  });

  test("blank, zero and nonsense mean the standing read timeout, and send nothing", () => {
    for (const text of ["", "  ", "0", "-5", "abc"]) {
      expect(parseResponseTimeoutMS(text)).toBeUndefined();
      expect(intruderSendSettingsFields({ ...emptyIntruderConfig(), responseTimeoutMS: text })).not.toHaveProperty(
        "response_timeout_ms",
      );
    }
  });
});

describe("HTTP/1 connection reuse and the HTTP version (xhqr)", () => {
  test("a fresh attack asks for reuse — Burp's default — and pins no version", () => {
    const fields = intruderSendSettingsFields(emptyIntruderConfig());
    expect(fields.http1_connection_reuse).toBe(true);
    expect(fields).not.toHaveProperty("http_version");
  });

  test("reuse off sends nothing, so the server keeps one connection per request", () => {
    expect(intruderSendSettingsFields({ ...emptyIntruderConfig(), http1ConnectionReuse: false })).not.toHaveProperty(
      "http1_connection_reuse",
    );
  });

  test("Set Connection header switches reuse off rather than sending the pair the server refuses", () => {
    const fields = intruderSendSettingsFields({ ...emptyIntruderConfig(), setConnectionClose: true });
    expect(fields).not.toHaveProperty("http1_connection_reuse");
  });

  test("a version pin is sent as written", () => {
    expect(intruderSendSettingsFields({ ...emptyIntruderConfig(), httpVersion: "http1" }).http_version).toBe("http1");
    expect(intruderSendSettingsFields({ ...emptyIntruderConfig(), httpVersion: "http2" }).http_version).toBe("http2");
  });

  test("the report's counts read as a line, and null is not zero", () => {
    expect(connectionReuseSummary({ connections_opened: 3, connections_reused: 9 })).toBe(
      "3 opened, 9 requests on a reused connection",
    );
    expect(connectionReuseSummary({ connections_opened: 4, connections_reused: 0 })).toBe(
      "4 opened, 0 requests on a reused connection",
    );
    expect(connectionReuseSummary({ connections_opened: null, connections_reused: null })).toBeNull();
    expect(connectionReuseSummary({})).toBeNull();
  });
});

describe("a persisted attack from before a setting existed", () => {
  test("hydrates the missing setting with its default rather than with undefined", () => {
    const current = { intruder: emptyIntruderConfig(), other: 1 };
    const old = { ...emptyIntruderConfig(), msgId: "9" } as Record<string, unknown>;
    delete old.responseTimeoutMS;
    delete old.http1ConnectionReuse;
    delete old.httpVersion;
    const merged = mergePersistedWorkspace({ intruder: old }, current);
    expect(merged.intruder.msgId).toBe("9");
    expect(merged.intruder.responseTimeoutMS).toBe("");
    // A true default must come back true, not undefined-and-therefore-off.
    expect(merged.intruder.http1ConnectionReuse).toBe(true);
    expect(merged.intruder.httpVersion).toBe("");
    expect(merged.other).toBe(1);
  });
});
