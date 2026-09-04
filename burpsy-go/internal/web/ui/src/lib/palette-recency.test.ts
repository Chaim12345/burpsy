/**
 * Tests for the palette's recency ledger (burpsy-react-ui-daj4). Run with `bun run test:lib`.
 *
 * The rule under test: on an equal text rank (the empty query ranks every action 1), the
 * most-recently-run command floats to the top; a genuinely better text match still wins over a
 * recently-run worse one. The DOM sort lives in palette.tsx and cannot run without mounting;
 * these tests pin the ledger's contract that the sort consumes.
 */

import { afterEach, describe, expect, test } from "bun:test";
import { paletteRecency, recordPaletteUse } from "./palette-recency";

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
const existingWindow = (globalThis as Record<string, unknown>).window as
  | (Record<string, unknown> & { localStorage?: Storage })
  | undefined;
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
