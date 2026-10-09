import { describe, expect, test } from "bun:test";
import { scopeAllowsEverything, scopeBadge } from "./scope-state";

describe("scope state", () => {
 test("an emptied scope allows everything — not 'restricted'", () => {
  expect(scopeAllowsEverything({ allow_all: false, rules: [] })).toBe(true);
  expect(scopeBadge({ allow_all: false, rules: [] })).toEqual({ label: "everything in scope", tone: "warn" });
 });
 test("exclude-only still lets every other host through", () => {
  const s = { allow_all: false, rules: [{ include: false }] };
  expect(scopeAllowsEverything(s)).toBe(true);
  expect(scopeBadge(s).label).toBe("everything not excluded is in scope");
 });
 test("one include rule restricts, whichever field spells it", () => {
  expect(scopeBadge({ allow_all: false, rules: [{ include: true }] })).toEqual({ label: "restricted", tone: "good" });
  expect(scopeAllowsEverything({ allow_all: false, rules: [{ kind: "Include" }] })).toBe(false);
 });
 test("a disabled include rule restricts nothing", () => {
  expect(scopeAllowsEverything({ allow_all: false, rules: [{ kind: "Include", enabled: false }] })).toBe(true);
 });
 test("allow_all wins", () => {
  expect(scopeAllowsEverything({ allow_all: true, rules: [{ include: true }] })).toBe(true);
 });
});
