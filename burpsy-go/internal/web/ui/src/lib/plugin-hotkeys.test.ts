// The chord normaliser (burpsy-react-ui-wsu4). It is the single translation between the
// spelling a plugin declares (Burp's Settings format, "Ctrl+Shift+K") and the one the
// console's keymap installs (mod/alt/shift + key), and these tests pin the three properties
// that keep it honest:
//
//   1. AGREEMENT WITH THE HOST. The Go side (extension.NormaliseChord) refuses a hotkey
//      registration whose chord it cannot spell, at load, before the registration ever reaches
//      the wire. If this side disagreed about any spelling, a chord the host accepted would
//      arrive here and silently not install — a binding that looks registered and never fires,
//      the worst outcome this project names. Every accepted spelling here must therefore be
//      one the host accepts too, and the refused ones must overlap at least on the classes a
//      plugin is likely to try (meta, bare keys, function keys).
//
//   2. BURP'S LENIENCY. Burp's format allows case, separator and order variation, and the
//      Montoya doc says only "the same format as within Burp's Settings". A plugin that
//      declares "ctrl SHIFT k" means what "Ctrl+Shift+K" means, and reading it otherwise
//      would punish a spelling the documented format allows.
//
//   3. THE ONE-MODIFIER RULE. mod (Ctrl/Cmd) or alt must be present — a bare key would fire
//      while the operator types — and exactly one non-modifier key, and the output is in the
//      console's canonical modifier order so two plugins asking for the same binding in
//      different spellings install as one chord.
import { describe, expect, test } from "bun:test";
import { installedPluginHotkeys, normalisePluginChord } from "./plugin-hotkeys";
import type { ExtensionList } from "./types.extensions";

describe("normalisePluginChord spells Burp's format in the console's", () => {
  test("Burp's canonical spelling installs as the canonical chord", () => {
    expect(normalisePluginChord("Ctrl+Shift+K")).toBe("mod+shift+k");
    expect(normalisePluginChord("Ctrl+K")).toBe("mod+k");
    expect(normalisePluginChord("Alt+T")).toBe("alt+t");
    expect(normalisePluginChord("Ctrl+Alt+R")).toBe("mod+alt+r");
  });

  test("the documented format's leniency — case, separators, order, glued — all spell one binding", () => {
    expect(normalisePluginChord("ctrl SHIFT k")).toBe("mod+shift+k");
    expect(normalisePluginChord("ctrl-shift-k")).toBe("mod+shift+k");
    expect(normalisePluginChord("ctrlshiftk")).toBe("mod+shift+k");
    // Modifier order is canonicalised, not required: the console's order is the only order.
    expect(normalisePluginChord("Shift+Ctrl+K")).toBe("mod+shift+k");
    // mac spellings mean the same thing as their windows twins
    expect(normalisePluginChord("Cmd+K")).toBe("mod+k");
    expect(normalisePluginChord("Option+T")).toBe("alt+t");
  });

  test("a chord that would never fire is refused, not installed", () => {
    // meta: mod is already the platform's primary modifier; a meta chord would look bound and
    // never fire.
    expect(normalisePluginChord("Meta+K")).toBeNull();
    expect(normalisePluginChord("Super+K")).toBeNull();
    // A bare key fires while the operator types.
    expect(normalisePluginChord("K")).toBeNull();
    // A modifier with no key is not a shortcut.
    expect(normalisePluginChord("Ctrl")).toBeNull();
    expect(normalisePluginChord("Ctrl+Shift")).toBeNull();
    // Function keys belong to the browser and the OS.
    expect(normalisePluginChord("Ctrl+F5")).toBeNull();
    expect(normalisePluginChord("Ctrl+F12")).toBeNull();
  });
});

describe("installedPluginHotkeys installs only what the host accepted", () => {
  const hotkey = (id: string, chord: string) => ({
    id,
    kind: "hotkey" as const,
    label: `action ${id}`,
    chord,
  });

  test("a loaded plugin's hotkey registrations arrive normalised with their identity", () => {
    const list: ExtensionList = {
      allowlisted: 1,
      policy: { admission: "allowlist", max_output_bytes: 1, call_timeout_ms: 1 },
      extensions: [
        {
          name: "probe",
          state: "loaded",
          registrations: [hotkey("key", "Ctrl+Shift+K"), hotkey("plain", "Ctrl+P")],
          registrations_refused: 0,
        },
      ],
    } as unknown as ExtensionList;
    const bindings = installedPluginHotkeys(list);
    expect(bindings).toEqual([
      { chord: "mod+shift+k", plugin: "probe", registration: "key", label: "action key" },
      { chord: "mod+p", plugin: "probe", registration: "plain", label: "action plain" },
    ]);
  });

  test("a registration whose chord this side cannot spell does not install rather than throwing inside the keymap", () => {
    // The host refuses these at load, so the wire should never carry one — but the two
    // normalisers are separate code, and a disagreement must surface as a silently
    // uninstalled binding, not a runtime error.
    const list: ExtensionList = {
      allowlisted: 1,
      policy: { admission: "allowlist", max_output_bytes: 1, call_timeout_ms: 1 },
      extensions: [
        { name: "probe", state: "loaded", registrations: [hotkey("meta", "Meta+K")], registrations_refused: 0 },
      ],
    } as unknown as ExtensionList;
    expect(installedPluginHotkeys(list)).toEqual([]);
  });

  test("an unloaded plugin's hotkey installs nothing", () => {
    // pluginInvocations already refuses unloaded plugins; the hotkey walk inherits that rule,
    // and this pins it: a binding whose plugin is not running could only ever fail.
    const list: ExtensionList = {
      allowlisted: 1,
      policy: { admission: "allowlist", max_output_bytes: 1, call_timeout_ms: 1 },
      extensions: [{ name: "probe", state: "unloaded", registrations: [hotkey("key", "Ctrl+K")], registrations_refused: 0 }],
    } as unknown as ExtensionList;
    expect(installedPluginHotkeys(list)).toEqual([]);
  });
});
