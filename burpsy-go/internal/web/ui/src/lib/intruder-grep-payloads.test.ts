import { describe, expect, test } from "bun:test";
import { grepPayloadsField, reflectionColumnLabels } from "./intruder-grep-payloads";
import { emptyIntruderConfig } from "./store";

describe("Grep - Payloads (7qc3)", () => {
  test("a new attack sends Burp's defaults with matching on", () => {
    expect(grepPayloadsField(emptyIntruderConfig())).toEqual({
      grep_payloads: { enabled: true, case_sensitive: false, exclude_headers: false, match_pre_url_encoded: true },
    });
  });

  test("every switch reaches the request", () => {
    const config = {
      ...emptyIntruderConfig(),
      grepPayloadsEnabled: false,
      grepPayloadsCaseSensitive: true,
      grepPayloadsExcludeHeaders: true,
      grepPayloadsMatchPreEncoded: false,
    };
    expect(grepPayloadsField(config)).toEqual({
      grep_payloads: { enabled: false, case_sensitive: true, exclude_headers: true, match_pre_url_encoded: false },
    });
  });

  test("one count column per payload set, none when the check was off or unreported", () => {
    const on = { grep_payloads: { enabled: true, case_sensitive: false, exclude_headers: false, match_pre_url_encoded: true } };
    expect(reflectionColumnLabels(on, 1)).toEqual(["Payload reflections"]);
    expect(reflectionColumnLabels(on, 3)).toEqual(["Set 1 reflections", "Set 2 reflections", "Set 3 reflections"]);
    expect(reflectionColumnLabels({ grep_payloads: { ...on.grep_payloads, enabled: false } }, 2)).toEqual([]);
    expect(reflectionColumnLabels({}, 2)).toEqual([]);
  });
});
