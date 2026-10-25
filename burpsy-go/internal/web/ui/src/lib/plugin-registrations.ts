// Where a loaded plugin's registrations become controls in the console (burpsy-react-ui-ww5).
//
// The host has three registration points with an honest web analogue — context-menu, menu and
// editor-tab (see internal/extension/views.go for the wire shapes and internal/web/api_extensions.go
// for the route that invokes one). This module is the part of surfacing them that is worth testing
// without a DOM: which registrations a loaded-plugin list offers for one kind, what a tab is keyed
// by, and the context-menu group they are arranged into.
//
// Two rules are deliberate rather than incidental:
//
//   - Only loaded plugins are offered. A registration exists for the lifetime of the process that
//     declared it, and the invoke route refuses a plugin that is not loaded, so a row built from an
//     unloaded plugin would be a control that can only fail. Loading is what makes an item real.
//   - The plugin's own words are the label. `label` is what the plugin declared over the handshake;
//     renaming it here would make this the second implementation of a fact the host published.
import { Plug } from "lucide-react";
import type { ExtensionList, Registration, RegistrationKind } from "./types.extensions";
import type { MenuGroup } from "../ui/menu";

/** One registration together with the allowlist key of the plugin that declared it. */
export interface PluginInvocation {
 plugin: string;
 registration: Registration;
}

/** What an invocation is about. Both ids are optional and are sent as given: 0 is a real id here. */
export interface PluginTarget {
 exchange?: number;
 message?: number;
 /** The bytes the plugin's handler is called for. Sent only when the caller already holds them. */
 raw?: string;
}

/**
 * A loaded plugin's registrations of one kind, in load order.
 *
 * Order is the plugin list's own order, then the order the plugin declared them: a menu that
 * reshuffled itself between two right-clicks would be a menu an operator cannot learn.
 */
export function pluginInvocations(list: ExtensionList | undefined, kind: RegistrationKind): PluginInvocation[] {
 const found: PluginInvocation[] = [];
 for (const plugin of list?.extensions ?? []) {
  if (plugin.state !== "loaded") continue;
  for (const registration of plugin.registrations) {
   if (registration.kind === kind) found.push({ plugin: plugin.name, registration });
  }
 }
 return found;
}

/**
 * The identity of one plugin tab for one message.
 *
 * It carries the message id because a plugin's view is *of a message*: the same registration over a
 * different message is a different view, and keying on the registration alone would keep showing a
 * stale render when the operator selects another row.
 */
export function pluginTabKey(messageId: number, invocation: PluginInvocation): string {
 return `${messageId}\u0000${invocation.plugin}\u0000${invocation.registration.id}`;
}

/** The id of the context-menu group this module contributes. Stable so a caller can find it. */
export const PLUGIN_MENU_ID = "plugin-context-menu";

/**
 * The same group as a list, which is what a menu spread wants.
 *
 * Kept separate so the null case stays explicit: a menu that always carries an empty "Extensions"
 * heading is a row that opens onto nothing.
 */
export function pluginMenuItems(
 list: ExtensionList | undefined,
 exchangeId: number,
 invoke: (call: PluginInvocation, target: PluginTarget) => void,
): MenuGroup[] {
 const group = pluginMenuGroup(list, exchangeId, invoke);
 return group ? [group] : [];
}

/**
 * The context-menu group for one exchange, or null when no loaded plugin declares an item.
 *
 * One row per plugin, each a submenu of what that plugin registered, because the row has to name
 * what will run: two plugins offering "Decode" are two different pieces of code, and a flat list
 * would hide which one an operator is about to invoke.
 *
 * `invoke` is called on selection rather than here, so building the group stays free of side
 * effects — and it takes the exchange id, which is what the route dispatches on.
 */
export function pluginMenuGroup(
 list: ExtensionList | undefined,
 exchangeId: number,
 invoke: (call: PluginInvocation, target: PluginTarget) => void,
): MenuGroup | null {
 const byPlugin = new Map<string, PluginInvocation[]>();
 for (const invocation of pluginInvocations(list, "context-menu")) {
  const existing = byPlugin.get(invocation.plugin);
  if (existing) existing.push(invocation);
  else byPlugin.set(invocation.plugin, [invocation]);
 }
 if (byPlugin.size === 0) return null;

 return {
  id: PLUGIN_MENU_ID,
  title: "Extensions",
  actions: [...byPlugin].map(([plugin, invocations]) => ({
   id: `${PLUGIN_MENU_ID}:${plugin}`,
   label: plugin,
   icon: Plug,
   // A submenu trigger's own onSelect is never called (see ui/menu.tsx renderItems) — the item
   // is a way into the registrations below it, and there is nothing to run for the parent.
   onSelect: () => {},
   submenu: [
    {
     id: `${PLUGIN_MENU_ID}:${plugin}:items`,
     actions: invocations.map((invocation) => ({
      id: `${PLUGIN_MENU_ID}:${plugin}:${invocation.registration.id}`,
      label: invocation.registration.label,
      onSelect: () => invoke(invocation, { exchange: exchangeId }),
     })),
    },
   ],
  })),
 };
}
