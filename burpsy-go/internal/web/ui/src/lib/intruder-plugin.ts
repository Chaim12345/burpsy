// Plugin payload generators and processors in the Intruder UI (burpsy-react-ui-0qwh).
//
// The providers come from the extensions view: a loaded plugin's registrations of kind
// payload-generator (a payload source) or payload-processor (a processing rule). An unloaded
// plugin offers none, for the reason plugin-registrations.ts gives: the server refuses it.
import { pluginInvocations } from "./plugin-registrations";
import type { RegistrationKind } from "./types.extensions";
import type { ExtensionList } from "./types.extensions";
import type { PluginRef } from "./types.tools";

export interface PluginProvider {
 /** The select value: both ids, so two plugins that reuse a registration id stay distinct. */
 value: string;
 label: string;
 ref: PluginRef;
}

const SEP = "\u0000";

export function refValue(ref: PluginRef): string {
 return `${ref.plugin}${SEP}${ref.registration}`;
}

export function refFromValue(value: string): PluginRef | undefined {
 const at = value.indexOf(SEP);
 if (at < 0) return undefined;
 return { plugin: value.slice(0, at), registration: value.slice(at + 1) };
}

/** The loaded plugins' registrations of one payload kind, labelled with the plugin's own words. */
export function pluginProviders(
 list: ExtensionList | undefined,
 kind: Extract<RegistrationKind, "payload-generator" | "payload-processor">,
): PluginProvider[] {
 return pluginInvocations(list, kind).map(({ plugin, registration }) => {
  const ref = { plugin, registration: registration.id };
  return { value: refValue(ref), label: `${registration.label} (${plugin})`, ref };
 });
}
