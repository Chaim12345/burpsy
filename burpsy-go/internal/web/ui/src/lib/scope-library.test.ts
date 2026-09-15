import { describe, expect, test } from "bun:test";
import {
 describeScopeLibraryAge,
 describeScopeLibraryDelete,
 describeScopeLibraryLoad,
 describeScopeLibraryLoaded,
 describeScopeLibrarySaved,
 isScopeLibraryDamaged,
 SCOPE_LIBRARY_DAMAGED,
} from "./scope-library";
import type { ScopeLibraryEntry } from "./data.policy";

const entry = (over: Partial<ScopeLibraryEntry> = {}): ScopeLibraryEntry => ({
 name: "friday",
 rules: 4,
 saved_at: 1_700_000_000_000,
 ...over,
});

// The issue this page closes asked for the merge-vs-replace semantics to be *stated*, not left to
// the implementation. These tests are that statement: the sentence the operator reads before they
// load has to say the current rules go away, and say how many of them there are.

describe("the sentence shown before a library is loaded", () => {
 test("it says the load replaces the current rules, and names both counts", () => {
  const text = describeScopeLibraryLoad(entry({ rules: 6 }), 3);
  expect(text).toContain("Replaces");
  expect(text).toContain("3 rules");
  expect(text).toContain("6 rules");
  expect(text).toContain("friday");
  // The half an operator is most likely to be wrong about: rules they added since the save.
  expect(text).toContain("removed");
 });

 test("one rule reads as one rule, so the warning does not look machine-generated", () => {
  expect(describeScopeLibraryLoad(entry({ rules: 1 }), 1)).toContain("the 1 rule in your scope now");
 });

 test("loading into an empty scope says the scope is empty rather than claiming a replacement", () => {
  // Nothing is replaced, and the state being left behind is default-allow, which is the one thing
  // worth saying out loud on this page.
  const text = describeScopeLibraryLoad(entry({ rules: 2 }), 0);
  expect(text).not.toContain("Replaces");
  expect(text).toContain("allows every host");
 });

 test("a library the server could not read is described as unloadable, not as an empty rule set", () => {
  // The failure this guards: -1 rendering as "0 rules", and an operator loading what they read as
  // an empty scope — which allows everything — believing they restored a restriction.
  const damaged = entry({ rules: SCOPE_LIBRARY_DAMAGED });
  expect(isScopeLibraryDamaged(damaged)).toBe(true);
  const text = describeScopeLibraryLoad(damaged, 3);
  expect(text).toContain("cannot be read");
  expect(text).not.toContain("0 rules");
  expect(text).toContain("untouched");
 });
});

describe("the confirmation shown before a library is deleted", () => {
 test("it names the library and says the current scope is not affected", () => {
  const text = describeScopeLibraryDelete(entry({ rules: 4 }));
  expect(text).toContain("friday");
  expect(text).toContain("4 rules");
  expect(text).toContain("cannot be recovered");
  // Deleting a library must not read as deleting the scope: they are one click apart on this page.
  expect(text).toContain("current scope is not changed");
 });
});

describe("what the operator is told after a save", () => {
 test("an overwrite is reported as an overwrite, not as a plain save", () => {
  // A save that replaced yesterday's rule set and said only "Saved" is how a scope is lost with
  // nobody noticing until they try to load it back.
  expect(describeScopeLibrarySaved("friday", { replaced: true, rules: 4 })).toContain("Replaced");
  expect(describeScopeLibrarySaved("friday", { replaced: false, rules: 4 })).toContain("Saved 4 rules");
 });

 test("a load reports what is now in scope rather than that a button worked", () => {
  expect(describeScopeLibraryLoaded("friday", { loaded: true, rules: 6 })).toContain("6 rules now in scope");
 });
});

describe("when a library was saved", () => {
 const base = 1_700_000_000_000;
 test("recent saves read relatively, because the picker's real question is which one is the newer", () => {
  expect(describeScopeLibraryAge(base, base + 10_000)).toBe("just now");
  expect(describeScopeLibraryAge(base, base + 20 * 60_000)).toBe("20 min ago");
  expect(describeScopeLibraryAge(base, base + 5 * 3_600_000)).toBe("5 h ago");
 });

 test("anything older than a day reads as a date, where a relative count stops helping", () => {
  expect(describeScopeLibraryAge(base, base + 9 * 86_400_000)).toBe(new Date(base).toLocaleDateString());
 });

 test("a missing timestamp says so instead of claiming 1970", () => {
  expect(describeScopeLibraryAge(0)).toBe("saved at an unknown time");
 });
});
