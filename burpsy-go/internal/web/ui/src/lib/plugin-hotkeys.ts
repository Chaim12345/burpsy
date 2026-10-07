// The hotkey registration point (burpsy-react-ui-wsu4): where a plugin's declared chord
// becomes a live binding in this console.
//
// The protocol half lives in internal/extension/protocol.go — KindHotKey, the chord field on
// Registration, and hotkey.invoke. This module is the UI half, and its whole job is to install
// the binding the host computed: the host's NormaliseChord is the single source of truth, and
// the UI installs Registration.Binding verbatim. No second normaliser, no disagreement
// possible — a chord the host accepted is a chord the UI can bind.
import { useHotkeys } from "react-hotkeys-hook";
import { toast } from "sonner";
import { useExtensions, useInvokeExtension } from "./data.extensions";
import { pluginInvocations } from "./plugin-registrations";
import type { ExtensionList } from "./types.extensions";

/** One installed binding: the chord in this console's vocabulary, and what it runs. */
export interface InstalledPluginHotkey {
  chord: string;
  plugin: string;
  registration: string;
  label: string;
}

/**
 * The loaded plugins' hotkey registrations, with the host's normalised binding.
 *
 * The host refuses a hotkey registration whose chord it cannot spell at load, so every
 * hotkey registration that reaches this point has a Binding field set by NormaliseChord.
 * The UI installs that field verbatim — no second normaliser, no disagreement possible.
 */
export function installedPluginHotkeys(list: ExtensionList | undefined): InstalledPluginHotkey[] {
  const out: InstalledPluginHotkey[] = [];
  for (const invocation of pluginInvocations(list, "hotkey")) {
    // Optional on the wire: absent is how a non-hotkey registration, and a hotkey the host
    // refused, both arrive. Absent means "do not bind it", which is the honest reading either way.
    const chord = invocation.registration.binding;
    if (!chord) continue;
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
      if (event.repeat) return;
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
