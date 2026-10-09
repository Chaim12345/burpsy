import { describe, expect, test } from "bun:test";
import { dropRulesFrom, dropRulesInclude } from "./drop-scope";

describe("dropRulesFrom", () => {
 test("keeps every arm of a reported rule, so a re-send does not widen it", () => {
  expect(
   dropRulesFrom([
    { kind: "Include", host: "api.shop.test", port: 8443, protocol: "https", enabled: true },
    { kind: "Exclude", host: "api.shop.test", path: "/admin", enabled: false },
   ]),
  ).toEqual([
   { action: "include", pattern: "api.shop.test", port: 8443, protocol: "https", enabled: true },
   { action: "exclude", pattern: "api.shop.test", path: "/admin", enabled: false },
  ]);
 });
});

describe("dropRulesInclude", () => {
 test("an exclude-only or disabled-include scope admits nothing the server would accept", () => {
  expect(dropRulesInclude([{ action: "exclude", pattern: "a.test" }])).toBe(false);
  expect(dropRulesInclude([{ action: "include", pattern: "a.test", enabled: false }])).toBe(false);
  expect(dropRulesInclude([{ action: "include", pattern: "a.test" }])).toBe(true);
 });
});
