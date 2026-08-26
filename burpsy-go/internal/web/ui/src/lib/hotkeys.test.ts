// The hotkey registry's two rules that decide whether a rebind is accepted, tested as
// functions. Both are refusals, and a refusal that silently passes is worse than one that
// blocks: an unusable chord stored is a shortcut that never fires and never says why.
import { expect, test, describe } from "bun:test";
import { actionForChord, chordFor, validateChord, SHORTCUT_ACTIONS, REBINDABLE } from "./shortcuts";

describe("validateChord", () => {
  test("accepts a mod chord and normalises modifier order", () => {
    expect(validateChord("mod+k")).toEqual({ chord: "mod+k" });
    expect(validateChord("shift+alt+mod+p")).toEqual({ chord: "mod+alt+shift+p" });
    expect(validateChord("MOD+K")).toEqual({ chord: "mod+k" });
  });

  test("accepts alt without mod, because this build ships alt bindings", () => {
    // alt+T and alt+1..0 exist precisely because browsers reserve Burp's mod combinations.
    // Refusing alt would refuse bindings already in the product.
    expect(validateChord("alt+t")).toEqual({ chord: "alt+t" });
  });

  test("refuses a bare key — it would fire while typing", () => {
    const got = validateChord("k");
    expect("error" in got).toBe(true);
  });

  test("refuses a modifier with no key", () => {
    expect("error" in validateChord("mod")).toBe(true);
    expect("error" in validateChord("mod+shift")).toBe(true);
  });

  test("refuses two non-modifier keys", () => {
    expect("error" in validateChord("mod+k+j")).toBe(true);
  });

  test("refuses empty input", () => {
    expect("error" in validateChord("   ")).toBe(true);
  });
});

describe("duplicate detection", () => {
  test("names the action already holding a chord", () => {
    const held = actionForChord({}, "mod+k");
    expect(held?.id).toBe("nav.palette");
  });

  test("does not report a row as clashing with itself", () => {
    expect(actionForChord({}, "mod+k", "nav.palette")).toBeNull();
  });

  test("sees an override, not just the default", () => {
    // After rebinding the theme toggle onto the palette's key, the palette must be reported
    // as free and the theme toggle as the holder.
    const keymap = { "view.toggleTheme": "mod+j" };
    expect(actionForChord(keymap, "mod+j")?.id).toBe("view.toggleTheme");
    expect(actionForChord(keymap, "mod+shift+l")).toBeNull();
  });
});

describe("the registry itself", () => {
  test("every action id is unique", () => {
    const ids = SHORTCUT_ACTIONS.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("no two rebindable actions ship with the same default", () => {
    // The thing that would make the table unusable on first load.
    const chords = REBINDABLE.map((a) => a.defaultChord).filter((c): c is string => c !== null);
    expect(new Set(chords).size).toBe(chords.length);
  });

  test("a non-rebindable action always explains itself", () => {
    for (const action of SHORTCUT_ACTIONS.filter((a) => !a.rebindable)) {
      expect(action.note, `${action.id} is fixed but says no why`).toBeTruthy();
    }
  });

  test("chordFor prefers an override and falls back to the default", () => {
    expect(chordFor({}, "nav.palette")).toBe("mod+k");
    expect(chordFor({ "nav.palette": "mod+j" }, "nav.palette")).toBe("mod+j");
    expect(chordFor({ "nav.palette": null }, "nav.palette")).toBeNull();
  });
});
