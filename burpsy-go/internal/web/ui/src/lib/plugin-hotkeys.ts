// The hotkey registration point (burpsy-react-ui-wsu4): where a plugin's declared chord
// becomes a live binding in this console.
//
// The protocol half lives in internal/extension/protocol.go — KindHotKey, the chord field on
// Registration, and hotkey.invoke. This module is the UI half, and its whole job is one honest
// translation: the plugin declared its chord in Burp's Settings spelling ("Ctrl+Shift+K",
// burp.api.montoya.ui.hotkey.HotKey's documented format), and the console's keymap vocabulary
// is mod/alt/shift plus one key. Two spellings of one binding that disagreed would mean a
// chord that looks registered and never fires — the exact defect this project treats as
// worse than absence — so the normaliser here is the single spelling the installer consumes,
// and it mirrors NormaliseChord on the Go side: the host refuses a chord it cannot spell at
// load, and this side must agree, or a chord the host accepted would arrive here and die.
import { useHotkeys } from "react-hotkeys-hook";
import { toast } from "sonner";
import { useExtensions, useInvokeExtension } from "./data.extensions";
import { pluginInvocations } from "./plugin-registrations";
import type { ExtensionList } from "./types.extensions";

/**
 * Spell a Burp-Settings chord in this console's vocabulary, or null for a binding this console
 * cannot install.
 *
 * The rules are validateChord's, applied to Burp's spelling: mod (Ctrl/Cmd) or alt must be
 * present — a bare key would fire while the operator types — plus any amount of shift, plus
 * exactly one non-modifier key. meta/super are refused (mod is already the platform's primary
 * modifier; a meta chord would silently never fire), and so are function keys, which the
 * browser and the OS own.
 *
 * Burp's spelling is lenient about case, separators (+, -, space or none) and modifier order,
 * so this reads modifiers by prefix rather than by splitting: "ctrlshiftk" and "Ctrl+Shift+K"
 * are the same binding, and "ctrlk" is ctrl+k rather than some key called "ctrlk".
 */
export function normalisePluginChord(burp: string): string | null {
 let rest = burp.trim().toLowerCase();
 if (rest === "") return null;
 const mods: string[] = [];
 let key = "";
 while (rest !== "") {
  if (rest.startsWith("ctrl") || rest.startsWith("control")) {
   rest = rest.slice(rest.startsWith("control") ? 7 : 4);
   if (!mods.includes("mod")) mods.push("mod");
  } else if (rest.startsWith("cmd")) {
   rest = rest.slice(3);
   if (!mods.includes("mod")) mods.push("mod");
  } else if (rest.startsWith("shift")) {
   rest = rest.slice(5);
   if (!mods.includes("shift")) mods.push("shift");
  } else if (rest.startsWith("alt")) {
   rest = rest.slice(3);
   if (!mods.includes("alt")) mods.push("alt");
  } else if (rest.startsWith("option")) {
   rest = rest.slice(6);
   if (!mods.includes("alt")) mods.push("alt");
  } else if (rest.startsWith("meta") || rest.startsWith("super") || rest.startsWith("windows")) {
   return null;
  } else {
   const sep = rest.search(/[+-\s]/);
   if (sep === 0) {
    rest = rest.slice(1);
    continue;
   }
   if (sep < 0) {
    key = rest;
    rest = "";
   } else {
    key = rest.slice(0, sep);
    rest = rest.slice(sep);
   }
  }
 }
 if (key === "") return null;
 if (["ctrl", "cmd", "control", "shift", "alt", "option", "meta", "super", "windows"].includes(key)) return null;
 if (/^f([1-9]|1[0-2])$/.test(key)) return null;
 if (!mods.includes("mod") && !mods.includes("alt")) return null;
 const ordered = ["mod", "alt", "shift"].filter((m) => mods.includes(m));
 return [...ordered, key].join("+");
}

/** One installed binding: the chord in this console's vocabulary, and what it runs. */
export interface InstalledPluginHotkey {
 chord: string;
 plugin: string;
 registration: string;
 label: string;
}

/**
 * The loaded plugins' hotkey registrations, normalised and ready to install.
 *
 * Refusals cannot happen here in practice — the host refuses a hotkey registration whose
 * chord it cannot spell at load, and the two normalisers agree — but the filter is still
 * load-bearing: if the two spellings ever disagree, the disagreement surfaces as a
 * registration that simply does not install, not as a runtime error inside the keymap. The
 * honest thing either side can do with a chord it cannot honour is to not bind it.
 */
export function installedPluginHotkeys(list: ExtensionList | undefined): InstalledPluginHotkey[] {
 const out: InstalledPluginHotkey[] = [];
 for (const invocation of pluginInvocations(list, "hotkey")) {
  const chord = normalisePluginChord(invocation.registration.chord ?? "");
  if (chord === null) continue;
  out.push({ chord, plugin: invocation.plugin, registration: invocation.registration.id, label: invocation.registration.label });
 }
 return out;
}

/**
 * Install every loaded plugin's hotkey chord, suite-wide.
 *
 * One useHotkeys call over the joined chord list rather than one per registration, because
 * react-hotkeys-hook's bindings are global to the tree either way and the joined form keeps
 * the dependency array one item long: a plugin loading or unloading re-runs the whole
 * install, which is the only moment a binding's meaning can change.
 *
 * The handler is the palette's, not a new one: a hotkey is a standalone command, exactly what
 * menu.invoke serves, and the toast tells the operator which piece of plugin code just ran —
 * the same "Decode: ran" the palette prints, because from the operator's side these are the
 * same event reached by a different muscle.
 *
 * Burp's five HotKeyContexts (message editor, Proxy history, Intruder results, Organizer,
 * Site map) are deliberately not modelled: a DOM keydown cannot be scoped to one table's rows
 * without every surface opting in, and a binding that fires only on some pages — or fires on
 * the page the operator did not mean — is worse than one that fires everywhere. A plugin
 * hotkey here is suite-wide, which is also what Burp's context-less overload means: "it will
 * fire for any supported context."
 */
export function usePluginHotkeys(): void {
 const extensions = useExtensions();
 const invoke = useInvokeExtension();
 const bindings = installedPluginHotkeys(extensions.data);
 const chord = bindings.map((b) => b.chord).join(",");
 useHotkeys(
  chord,
  (event, handler) => {
   const pressed = handler.keys?.join("+");
   const binding = bindings.find((b) => b.chord === pressed);
   if (!binding) return;
   event.preventDefault();
   invoke.mutate(
    { name: binding.plugin, registration: binding.registration },
    {
     onSuccess: (answer) => {
      const said = answer.result.text ?? answer.result.output;
      toast.success(said ? `${binding.label}: ${said}` : `${binding.label} ran`);
     },
     onError: (failure: unknown) =>
      toast.error(failure instanceof Error ? `${binding.label}: ${failure.message}` : `${binding.label} failed`),
    },
   );
  },
  { enableOnFormTags: true, enableOnContentEditable: true },
  [chord, bindings, invoke],
 );
}
