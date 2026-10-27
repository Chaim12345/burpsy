/**
 * The invariant the Settings hotkey table depends on: every row it offers to rebind is actually
 * installed against the registry.
 *
 * # Why this reads source text instead of rendering components
 *
 * The defect this pins (burpsy-react-ui-9td, burpsy-react-ui-zy6) was not a wrong value anywhere —
 * every unit involved worked. `setChord` wrote, the listener broadcast, the table re-rendered and
 * reported success. The bug was that five of the ten rebindable actions were installed as
 * hardcoded literals (`useHotkeys("mod+r", …)`) that never read the map, and one — `send.organizer`
 * — was installed nowhere at all while being advertised in both the modal and the Settings table.
 *
 * No unit test of any single module can see that: the missing wire is *between* modules. What can
 * see it is the shape of the call sites, so that is what this asserts. It is a structural test, and
 * it is deliberately strict about the exact call form `useChord("<id>")` — a binding reached
 * through an indirection this regex cannot follow is a binding a reader cannot follow either.
 *
 * A rebindable row with no `useChord` for it is the exact state this project shipped once and
 * called done, which is why the failure message says what to do rather than only what is wrong.
 */
import { expect, test, describe } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { REBINDABLE, SHORTCUT_ACTIONS } from "./shortcuts";

const SRC = join(import.meta.dir, "..");

function sourceFiles(dir: string): string[] {
 const out: string[] = [];
 for (const entry of readdirSync(dir)) {
  const full = join(dir, entry);
  if (statSync(full).isDirectory()) {
   out.push(...sourceFiles(full));
  } else if ((entry.endsWith(".ts") || entry.endsWith(".tsx")) && !entry.endsWith(".test.ts")) {
   out.push(full);
  }
 }
 return out;
}

const CORPUS = sourceFiles(SRC)
 .map((file) => readFileSync(file, "utf8"))
 .join("\n");

/** Every id passed to `useChord("…")` anywhere in the app. */
const INSTALLED = new Set(
 // useCommandChord("id") (lib/keymap.ts) binds the chord to the command bridge; it reads the
 // registry through useChord itself, so it is the same wire in a second spelling.
 [...CORPUS.matchAll(/(?:useChord|useCommandChord)\(\s*"([^"]+)"\s*\)/g)].map((match) => match[1] as string),
);

describe("the rebindable registry and the installed bindings agree", () => {
 test("the corpus was actually read", () => {
  // A positive control. An empty or mis-rooted corpus would make every assertion below pass by
  // finding nothing to contradict it, which is the failure mode a grep-shaped test has.
  expect(CORPUS.length).toBeGreaterThan(10_000);
  expect(INSTALLED.size).toBeGreaterThan(0);
 });

 test.each(REBINDABLE.map((action) => [action.id, action.label] as const))("%s is installed via useChord", (id) => {
  expect(INSTALLED.has(id)).toBe(true);
 });

 test("nothing is installed that the registry does not declare", () => {
  // The other direction: a useChord for an id no longer in SHORTCUT_ACTIONS resolves to no
  // chord and silently never fires, and nothing in the UI would ever mention it.
  const declared = new Set(SHORTCUT_ACTIONS.map((action) => action.id));
  const orphans = [...INSTALLED].filter((id) => !declared.has(id));
  expect(orphans).toEqual([]);
 });

 test("every installed id is one the registry marks rebindable", () => {
  // The inverse of the file's own docstring: a fixed row reached through useChord would be
  // offered no editor in Settings while still being dispatched from the map.
  const rebindable = new Set(REBINDABLE.map((action) => action.id));
  const fixed = [...INSTALLED].filter((id) => !rebindable.has(id));
  expect(fixed).toEqual([]);
 });
});

describe("no rebindable chord is installed as a literal", () => {
 /**
  * The five literals that were the defect. Each is asserted absent from a `useHotkeys` first
  * argument, which is the only place it could re-appear and quietly win over the keymap again.
  */
 const RETIRED_LITERALS = ["mod+r", "mod+i", "mod+o", "mod+f", "alt+t", "mod+enter"];

 test.each(RETIRED_LITERALS)("%s is not passed to useHotkeys as a literal", (literal) => {
  const pattern = new RegExp(`useHotkeys\\(\\s*"${literal.replace(/\+/g, "\\+")}"`);
  expect(pattern.test(CORPUS)).toBe(false);
 });
});
