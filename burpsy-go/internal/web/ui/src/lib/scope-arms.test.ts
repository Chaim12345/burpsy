import { describe, expect, test } from "bun:test";
import {
  decodeHostArm,
  decodePathArm,
  encodeHostArm,
  encodePathArm,
  hostArmProblem,
  pathArmProblem,
  RANGE_ARM_TAG,
  REGEX_ARM_TAG,
} from "./scope-arms";

// The arms ride inside the pattern and path strings, which are also the rule's identity on remove,
// toggle and edit. So the pair that matters is encode/decode: an encode the decode cannot read is a
// rule an operator can create and then never edit or delete from the table.

describe("encoding and decoding an arm", () => {
 test("every mode survives the round trip it is stored in", () => {
  const cases: [Parameters<typeof encodeHostArm>[0], string][] = [
   ["wildcard", "*.example.com"],
   ["regex", "^api[0-9]+\\.example\\.test$"],
   ["range", "10.0.0.0/8"],
  ];
  for (const [mode, value] of cases) {
   expect(decodeHostArm(encodeHostArm(mode, value))).toEqual({ mode, value });
  }
  expect(decodePathArm(encodePathArm("prefix", "/admin"))).toEqual({ mode: "prefix", value: "/admin" });
  expect(decodePathArm(encodePathArm("regex", "/v[0-9]+/.*"))).toEqual({ mode: "regex", value: "/v[0-9]+/.*" });
 });

 test("a rule stored before the arms existed decodes as the wildcard and prefix it is", () => {
  // The regression that matters on this page: every rule already in a project was written with no
  // tag, and reading one as anything but a glob would change what it authorises.
  expect(decodeHostArm("*.example.com")).toEqual({ mode: "wildcard", value: "*.example.com" });
  expect(decodePathArm("/admin")).toEqual({ mode: "prefix", value: "/admin" });
  expect(decodePathArm(null)).toEqual({ mode: "prefix", value: "" });
 });

 test("an empty path body is no path arm at all, not an empty one", () => {
  // A rule with no path arm covers the whole host; a rule with an empty one would be a different
  // tuple, and the table identifies rules by that tuple.
  expect(encodePathArm("prefix", "  ")).toBe("");
  expect(encodePathArm("regex", "")).toBe("");
 });
});

describe("refusing an arm the server would refuse", () => {
 test("a blank expression is refused rather than sent as match-anything", () => {
  expect(hostArmProblem("regex", "  ")).toContain("blank");
  expect(pathArmProblem("regex", "")).toBeNull(); // an empty path field is simply no path arm
 });

 test("an expression that does not compile is named before it is sent", () => {
  expect(hostArmProblem("regex", "api[0-9")).toContain("does not compile");
  expect(pathArmProblem("regex", "(")).toContain("does not compile");
  expect(hostArmProblem("regex", "^api[0-9]+$")).toBeNull();
 });

 test("a tag typed into a literal field is refused with the mode to use instead", () => {
  // Otherwise the page sends an arm the form is not showing: the operator sees a wildcard field and
  // a regex rule is stored.
  expect(hostArmProblem("wildcard", `${REGEX_ARM_TAG}^a$`)).toContain("Regular expression mode");
  expect(hostArmProblem("wildcard", `${RANGE_ARM_TAG}10.0.0.0/8`)).toContain("IP range mode");
  expect(pathArmProblem("prefix", `${REGEX_ARM_TAG}/a`)).toContain("Regular expression mode");
 });

 test("a path prefix must start with a slash, because a request path does", () => {
  expect(pathArmProblem("prefix", "admin")).toContain("must start with /");
  expect(pathArmProblem("prefix", "/admin")).toBeNull();
  expect(pathArmProblem("prefix", "")).toBeNull();
 });

 test("an IP range with host bits set names both rules the operator might have meant", () => {
  // 10.0.0.5/8 is either sixteen million addresses or one, and picking for them is picking the size
  // of an authorised network.
  const problem = hostArmProblem("range", "10.0.0.5/8");
  expect(problem).toContain("10.0.0.0/8");
  expect(problem).toContain("10.0.0.5");
 });

 test("a range that is not a range is refused, and a real one is not", () => {
  expect(hostArmProblem("range", "not-an-address")).toContain("not an IPv4 address");
  expect(hostArmProblem("range", "10.0.0.0/33")).toContain("prefix length");
  expect(hostArmProblem("range", "999.1.1.1")).toContain("not an IPv4 address");
  expect(hostArmProblem("range", "10.0.0.0/8")).toBeNull();
  expect(hostArmProblem("range", "192.168.1.5")).toBeNull();
  // IPv6 is left to the server rather than half-parsed here, and that is deliberate, not an
  // oversight: a partial parser that refused a valid address would block work the server allows.
  expect(hostArmProblem("range", "2001:db8::/32")).toBeNull();
 });

 test("a wildcard host is still required, as it always was", () => {
  expect(hostArmProblem("wildcard", "  ")).toContain("required");
  expect(hostArmProblem("wildcard", "*.example.com")).toBeNull();
 });
});
