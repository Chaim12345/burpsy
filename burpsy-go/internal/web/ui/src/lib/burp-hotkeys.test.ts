// Burp's 50 shipped hotkeys, each with exactly one disposition (2czi). This is the acceptance
// criterion as data: a row that is bound must be bound to what it says, an alternative must say why
// and be a chord the registry accepts, and nothing may silently share a chord.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { BURP_HOTKEYS, burpChordToChord, sameChord } from "./burp-hotkeys";
import { chordFor, chordKeys, shortcutAction, validateChord } from "./shortcuts";

describe("Burp's shipped hotkey table", () => {
 test("is all 50 rows of UserDefaults.json, in Burp's own ids and chords", () => {
  // FRAGILE (vln1): the reference file lives outside the repo (/root/burp-re, not readable from CI or
  // from the sandbox this was reviewed in), so on every machine without it this comparison is skipped
  // and only the table's own shape is checked: it can silently verify nothing. Freezing the 50 rows
  // into an in-repo data file needs the file itself; it was not obtainable, so this is left as is.
  // The source file is read directly when it is on this machine, so a drift in Burp's defaults
  // (or a typo here) fails rather than passing on a copied list. Skipped, saying so, elsewhere.
  expect(BURP_HOTKEYS.length).toBe(50);
  let shipped: { action: string; hotkey: string }[] | null = null;
  try {
   const defaults = JSON.parse(readFileSync("/root/burp-re/in/extract/resources/Preferences/UserDefaults.json", "utf8"));
   shipped = defaults.user_options.misc.hotkeys;
  } catch {
   console.warn("UserDefaults.json not present on this machine; checking the table's shape only");
  }
  if (shipped) {
   // As a set: the table groups the three declined Burp AI rows at the end, where Burp's file
   // has explain_this fourth.
   const ours = BURP_HOTKEYS.map((row) => `${row.action} ${row.burpChord}`).sort();
   expect(ours).toEqual(shipped.map((row) => `${row.action} ${row.hotkey}`).sort());
  }
 });

 test("every Burp action appears once", () => {
  const actions = BURP_HOTKEYS.map((row) => row.action);
  expect(new Set(actions).size).toBe(actions.length);
 });

 test("every row has a reason", () => {
  for (const row of BURP_HOTKEYS) expect(row.reason.trim(), row.action).not.toBe("");
 });

 test("a 'same' row binds Burp's chord", () => {
  for (const row of BURP_HOTKEYS.filter((r) => r.disposition === "same")) {
   expect(row.chord, row.action).not.toBeNull();
   expect(sameChord(row.chord!, burpChordToChord(row.burpChord)), `${row.action}: ${row.chord} vs ${row.burpChord}`).toBe(true);
  }
 });

 test("an 'alternative' row binds a different, valid chord", () => {
  for (const row of BURP_HOTKEYS.filter((r) => r.disposition === "alternative")) {
   expect(row.chord, row.action).not.toBeNull();
   expect(sameChord(row.chord!, burpChordToChord(row.burpChord)), row.action).toBe(false);
   expect("chord" in validateChord(row.chord!), `${row.action}: ${row.chord}`).toBe(true);
  }
 });

 test("a 'declined' row binds nothing", () => {
  for (const row of BURP_HOTKEYS.filter((r) => r.disposition === "declined")) {
   expect(row.chord, row.action).toBeNull();
   expect(row.burpsyId, row.action).toBeNull();
  }
 });

 test("the bound rows' chords are what the registry actually installs", () => {
  // The wire, not just the label: a row that says "same" while the registry ships something
  // else is the 'reports success and changes nothing' defect this registry exists to prevent.
  for (const row of BURP_HOTKEYS.filter((r) => r.burpsyId !== null && r.burpsyId !== "native")) {
   const action = shortcutAction(row.burpsyId!);
   expect(action, `${row.action} names ${row.burpsyId}, which is not in the registry`).toBeDefined();
   if (row.burpsyId === "nav.tools") {
    // The alt+digit family: alt+2 is Target, alt+4 is Intruder (nav.ts hotkey fields).
    expect(row.chord).toMatch(/^alt\+\d$/);
    continue;
   }
   if (action!.rebindable) {
    expect(
     sameChord(chordFor({}, action!.id, "web")!, row.chord!),
     `${row.action}: registry ships ${chordFor({}, action!.id, "web")}`,
    ).toBe(true);
   } else if (row.burpsyId === "editor.paragraphUp" || row.burpsyId === "editor.paragraphDown") {
    // One fixed row covers the plain and the Shift-extend chord.
    expect(sameChord(row.chord!.replace("shift+", ""), chordKeys(action!, {}).join("+").toLowerCase())).toBe(true);
   } else {
    expect(
     sameChord(chordKeys(action!, {}).join("+").toLowerCase(), row.chord!),
     `${row.action}: registry displays ${chordKeys(action!, {}).join("+")}`,
    ).toBe(true);
   }
  }
 });

 test("an alternative's desktop chord is Burp's own", () => {
  for (const row of BURP_HOTKEYS.filter((r) => r.disposition === "alternative" && r.burpsyId !== "nav.tools")) {
   const action = shortcutAction(row.burpsyId!)!;
   expect(sameChord(chordFor({}, action.id, "desktop")!, burpChordToChord(row.burpChord)), row.action).toBe(true);
  }
  for (const id of ["nav.switchTarget", "nav.switchIntruder"]) {
   const burp = BURP_HOTKEYS.find((row) => shortcutAction(id)!.burp === `SHOW_${row.action.replace("switch_to_", "").toUpperCase()}`);
   expect(sameChord(chordFor({}, id, "desktop")!, burpChordToChord(burp!.burpChord)), id).toBe(true);
  }
 });

 test("no two rows bind the same chord", () => {
  const chords = BURP_HOTKEYS.filter((row) => row.chord !== null).map((row) => burpChordToChord(row.chord!));
  const seen = new Map<string, number>();
  for (const chord of chords) seen.set(chord, (seen.get(chord) ?? 0) + 1);
  expect([...seen].filter(([, n]) => n > 1)).toEqual([]);
 });

 test("burpChordToChord speaks the registry's vocabulary", () => {
  expect(burpChordToChord("Ctrl+Shift+D")).toBe("mod+shift+d");
  expect(burpChordToChord("Ctrl+Equals")).toBe("mod+equal");
  expect(burpChordToChord("Ctrl+Space")).toBe("mod+space");
  expect(sameChord("ctrl+space", "mod+space")).toBe(true);
 });
});
