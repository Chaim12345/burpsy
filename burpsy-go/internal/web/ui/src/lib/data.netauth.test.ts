import { describe, expect, test } from "bun:test";
import { ruleSchemeFor } from "./data.netauth";

describe("ruleSchemeFor", () => {
  test("maps a challenged scheme to the rule scheme that answers it", () => {
    expect(ruleSchemeFor("Basic")).toBe("basic");
    expect(ruleSchemeFor("Digest")).toBe("digest");
    expect(ruleSchemeFor("NTLM")).toBe("ntlmv2");
  });
  test("a scheme this build cannot answer has no rule scheme", () => {
    expect(ruleSchemeFor("Negotiate")).toBeNull();
  });
});
