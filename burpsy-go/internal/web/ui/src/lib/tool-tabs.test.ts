/**
 * Tests for the hidden-tab preference (burpsy-react-ui-lje3). Run with `bun run test:lib`.
 *
 * The rule under test is the reader's refusal posture: a preference that cannot be read must mean
 * "show every tab", never "hide what you cannot find". The View menu writes what the operator
 * hid; a corrupted or truncated value must not be able to take a tool off the strip, because a
 * hidden tab is only findable again through the menu that hid it.
 */

import { afterEach, describe, expect, test } from "bun:test";
import {
 TOOL_TABS_STORAGE_KEY,
 clearHiddenToolTabs,
 neighbourTab,
 orderToolTabs,
 readHiddenToolTabs,
 writeHiddenToolTabs,
} from "./tool-tabs";

const store = new Map<string, string>();

// The same minimal localStorage stand-in lib/palette-recency.test.ts installs, for the same
// reason: the libs read through window.localStorage, which does not exist in the bun test
// environment. Installed through an EXISTING window when there is one — defining window from
// scratch clobbers the environment other test files in the same run depend on.
const fakeStorage = {
 getItem: (key: string) => store.get(key) ?? null,
 setItem: (key: string, value: string) => void store.set(key, value),
 removeItem: (key: string) => void store.delete(key),
 clear: () => store.clear(),
};
const existingWindow = (globalThis as Record<string, unknown>).window as (Record<string, unknown> & { localStorage?: Storage }) | undefined;
if (existingWindow) {
 existingWindow.localStorage = fakeStorage as unknown as Storage;
} else {
 (globalThis as Record<string, unknown>).window = {
  localStorage: fakeStorage,
  addEventListener: () => {},
  removeEventListener: () => {},
 };
}

afterEach(() => store.clear());

describe("hidden tool tabs", () => {
 test("nothing stored shows every tab", () => {
  expect(readHiddenToolTabs()).toEqual([]);
 });

 test("what was written is what a reload reads back", () => {
  writeHiddenToolTabs(["organizer", "session"]);
  expect(readHiddenToolTabs()).toEqual(["organizer", "session"]);
 });

 test("a repeated id is stored once", () => {
  store.set(TOOL_TABS_STORAGE_KEY, JSON.stringify(["scope", "scope", "scope"]));
  expect(readHiddenToolTabs()).toEqual(["scope"]);
 });

 test("a value that is not a list of ids hides nothing", () => {
  // Each of these is a shape a truncated write, a hand-edit or a future format could leave
  // behind. All of them must read as "nothing is hidden": the alternative would take tabs off
  // the strip with the only way to restore them being a menu the operator may not think to open.
  for (const value of ['{"organizer":true}', "null", "42", '"organizer"', "not json"]) {
   store.set(TOOL_TABS_STORAGE_KEY, value);
   expect(readHiddenToolTabs(), `stored ${value}`).toEqual([]);
  }
 });

 test("entries that are not ids are dropped, and the real ids survive", () => {
  // The distinction matters: a value that is not a list at all means "hide nothing" (above),
  // while a list whose junk entries a later format added still carries the operator's real
  // choices. Dropping only the junk keeps the preference they actually made.
  store.set(TOOL_TABS_STORAGE_KEY, JSON.stringify(["organizer", 7, null, { id: "scope" }]));
  expect(readHiddenToolTabs()).toEqual(["organizer"]);
 });

 test("an empty id is ignored rather than hiding a nameless tab", () => {
  store.set(TOOL_TABS_STORAGE_KEY, JSON.stringify(["", "organizer"]));
  expect(readHiddenToolTabs()).toEqual(["organizer"]);
 });

 test("clearing restores the default layout", () => {
  writeHiddenToolTabs(["logger"]);
  clearHiddenToolTabs();
  expect(readHiddenToolTabs()).toEqual([]);
 });

 test("a storage that throws does not throw back", () => {
  // A private window, cleared site data or a browser set to block storage all throw on access.
  const throwing = {
   getItem: () => {
    throw new Error("denied");
   },
   setItem: () => {
    throw new Error("denied");
   },
   removeItem: () => {
    throw new Error("denied");
   },
   clear: () => {},
  } as unknown as Storage;
  const target = (globalThis as Record<string, unknown>).window as { localStorage: Storage };
  const previous = target.localStorage;
  target.localStorage = throwing;
  try {
   expect(readHiddenToolTabs()).toEqual([]);
   expect(() => writeHiddenToolTabs(["organizer"])).not.toThrow();
   expect(() => clearHiddenToolTabs()).not.toThrow();
  } finally {
   target.localStorage = previous;
  }
 });
});

describe("neighbourTab (next/previous-tab chords follow the saved order)", () => {
 const tabs = [{ id: "a" }, { id: "b" }, { id: "c" }];
 const dragged = orderToolTabs(tabs, ["c", "a", "b"]);
 test("walks the order it is given, not the default one", () => {
  expect(neighbourTab(dragged, "c", 1)?.id).toBe("a");
  expect(neighbourTab(dragged, "a", 1)?.id).toBe("b");
  expect(neighbourTab(tabs, "c", 1)?.id).toBe("a");
  expect(neighbourTab(tabs, "a", 1)?.id).toBe("b");
  expect(neighbourTab(dragged, "a", -1)?.id).toBe("c");
 });
 test("wraps both ways and says nothing for an unknown tab", () => {
  expect(neighbourTab(dragged, "b", 1)?.id).toBe("c");
  expect(neighbourTab(dragged, "c", -1)?.id).toBe("b");
  expect(neighbourTab(dragged, "zzz", 1)).toBeNull();
  expect(neighbourTab([], "a", 1)).toBeNull();
 });
});
