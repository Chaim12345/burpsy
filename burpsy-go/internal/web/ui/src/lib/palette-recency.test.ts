/**
 * Tests for the palette's recency ledger (burpsy-react-ui-daj4). Run with `bun run test:lib`.
 *
 * The rule under test: the ledger records the order commands were last run in, and reads back
 * newest-first. Two readers consume it. The palette's "Recently used" group is built from
 * `recentActionIds` and is the whole of what the empty query orders by; a *typed* query still
 * sorts by text rank first and uses recency only to break a tie, so a genuinely better match
 * wins over a recently-run worse one. That sort lives in palette.tsx and cannot run without
 * mounting; these tests pin the ledger's contract that both readers consume.
 */

import { afterEach, describe, expect, test } from "bun:test";
import { paletteRecency, recentActionIds, recordPaletteUse } from "./palette-recency";

const store = new Map<string, string>();

// A minimal localStorage stand-in: the lib reads/writes through window.localStorage, which
// does not exist in the bun test environment.
const fakeStorage = {
 getItem: (key: string) => store.get(key) ?? null,
 setItem: (key: string, value: string) => void store.set(key, value),
 removeItem: (key: string) => void store.delete(key),
 clear: () => store.clear(),
};
// Installed through an EXISTING window when one is present. Defining window from scratch would
// clobber the environment for every other test file in the run (react-hotkeys-hook installs
// document/window listeners at import time; a bare object broke them — two files failed with
// "window.addEventListener is not a function"). Only the storage surface this lib touches is added.
const existingWindow = (globalThis as Record<string, unknown>).window as (Record<string, unknown> & { localStorage?: Storage }) | undefined;
if (existingWindow) {
 existingWindow.localStorage = fakeStorage as unknown as Storage;
} else {
 // The stand-in carries no-op listener methods because bun test files share one globalThis:
 // installing window mid-run makes react-hotkeys-hook's `typeof window < "u"` guard (already
 // imported by lib/actions through pages/history) start acting on THIS object, and a window
 // without addEventListener failed the other files' tests with
 // "window.addEventListener is not a function". A no-op listener set keeps those imports inert.
 (globalThis as Record<string, unknown>).window = {
  localStorage: fakeStorage,
  addEventListener: () => {},
  removeEventListener: () => {},
 };
}

afterEach(() => store.clear());

describe("palette recency", () => {
 test("the most recently run command has the highest sequence number", () => {
  recordPaletteUse("nav.history");
  recordPaletteUse("nav.palette");
  recordPaletteUse("nav.history");
  const ledger = paletteRecency();
  expect(ledger["nav.history"] ?? 0).toBeGreaterThan(ledger["nav.palette"] ?? -1);
 });

 test("recording survives a reload-shaped re-read from storage", () => {
  recordPaletteUse("send.repeater");
  // Simulate the page reload: storage contents are re-read into a fresh ledger.
  const afterReload = paletteRecency();
  expect(afterReload["send.repeater"]).toBeGreaterThan(0);
 });

 test("a corrupt ledger reads as empty instead of throwing", () => {
  store.set("burpsy.palette-recency", "{not json");
  expect(paletteRecency()).toEqual({});
  // And recording after corruption still works — the ledger is rebuilt, not wedged.
  recordPaletteUse("view.toggleTheme");
  expect(paletteRecency()["view.toggleTheme"]).toBeGreaterThan(0);
 });

 test("the ledger stays bounded so an unrepeating operator's storage does not grow forever", () => {
  for (let i = 0; i < 80; i += 1) recordPaletteUse(`action-${i}`);
  const ledger = paletteRecency();
  expect(Object.keys(ledger).length).toBeLessThanOrEqual(64);
  // The oldest entries are the ones dropped, the newest retained.
  expect(ledger["action-79"] ?? 0).toBeGreaterThan(0);
  expect(ledger["action-0"]).toBeUndefined();
 });
});

describe("the Recently used reader", () => {
 test("ids come back newest first, which is the order Burp's palette shows them in", () => {
  recordPaletteUse("nav.history");
  recordPaletteUse("nav.repeater");
  recordPaletteUse("nav.history");
  expect(
   recentActionIds(paletteRecency(), ["nav.history", "nav.repeater"], 5),
   "a reader that returned storage order would hand the palette a Recents group ordered by first use, so a command run every minute would sit below one run once an hour ago",
  ).toEqual(["nav.history", "nav.repeater"]);
 });

 test("an id the palette no longer offers is dropped rather than listed", () => {
  recordPaletteUse("nav.retired");
  recordPaletteUse("nav.history");
  expect(
   recentActionIds(paletteRecency(), ["nav.history"], 5),
   "the ledger survives upgrades, so a command deleted in a later build is still in an operator's storage: listing it would put a row in the palette with nothing behind it to run",
  ).toEqual(["nav.history"]);
 });

 test("the reader honours its limit, so the Recents group cannot grow into a second command list", () => {
  const ids = ["a", "b", "c", "d"];
  for (const id of ids) recordPaletteUse(id);
  expect(
   recentActionIds(paletteRecency(), ids, 2),
   "an unbounded Recents block pushes the rest of the palette below the fold on every open",
  ).toEqual(["d", "c"]);
 });

 test("a zero or negative limit asks for nothing and gets nothing, instead of the whole ledger", () => {
  recordPaletteUse("nav.history");
  expect(
   recentActionIds(paletteRecency(), ["nav.history"], 0),
   "a slice with a negative or zero count is the classic way to accidentally return the entire array",
  ).toEqual([]);
 });
});
