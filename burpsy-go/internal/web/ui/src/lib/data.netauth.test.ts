import { describe, expect, test } from "bun:test";
import { ruleSchemeFor } from "./data.netauth";

describe("ruleSchemeFor", () => {
 test("maps a challenged scheme to the rule scheme that answers it", () => {
  expect(ruleSchemeFor("Basic")).toBe("basic");
  expect(ruleSchemeFor("Digest")).toBe("digest");
  expect(ruleSchemeFor("NTLM")).toBe("ntlmv2");
  // Negotiate is answered with raw NTLM inside it, by an ntlmv2 rule (burpsy-react-ui-sel6).
  expect(ruleSchemeFor("Negotiate")).toBe("ntlmv2");
 });
 test("a prompt never proposes the weak NTLMv1 downgrade", () => {
  for (const challenged of ["NTLM", "Negotiate", "ntlm"]) expect(ruleSchemeFor(challenged)).not.toBe("ntlmv1" as never);
 });
 test("a scheme this build cannot answer has no rule scheme", () => {
  expect(ruleSchemeFor("Bearer")).toBeNull();
  expect(ruleSchemeFor("Kerberos")).toBeNull();
 });
});
