import { describe, expect, test } from "bun:test";
import { intruderSendSettingsFields, parseResponseTimeoutMS } from "./send-settings";
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

describe("a persisted attack from before a setting existed", () => {
  test("hydrates the missing setting with its default rather than with undefined", () => {
    const current = { intruder: emptyIntruderConfig(), other: 1 };
    const old = { ...emptyIntruderConfig(), msgId: "9" } as Record<string, unknown>;
    delete old.responseTimeoutMS;
    const merged = mergePersistedWorkspace({ intruder: old }, current);
    expect(merged.intruder.msgId).toBe("9");
    expect(merged.intruder.responseTimeoutMS).toBe("");
    expect(merged.other).toBe(1);
  });
});
