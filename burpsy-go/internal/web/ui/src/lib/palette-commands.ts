// The palette groups that are built from data rather than written out (burpsy-react-ui-1wrb).
//
// Burp's palette (tools/command-palette.html) lists recently used commands at the top, treats
// encoding data as a core command, and includes commands registered by extensions. All three
// are enumerations of something the console already knows — the recency ledger, the editor's
// codec table, the host's registration list — so all three belong here, built from the source
// of truth, rather than as a hand-written list beside it that the next encoder would not reach.
//
// Kept free of React and of the DOM so the rules are testable: the palette passes in what it
// resolved (the ledger, the selection choice, the extension list) and gets rows back.
import { Binary, Plug } from "lucide-react";
import type { ComponentType } from "react";
import { recentActionIds } from "./palette-recency";
import { SELECTION_CODECS, type SelectionCodec } from "./selection-codecs";
import { pluginInvocations, type PluginInvocation } from "./plugin-registrations";
import type { ExtensionList } from "./types.extensions";
import { chordFor, type Keymap, type ShortcutAction } from "./shortcuts";

/** What `ui/palette.tsx` consumes: the shape of a `PaletteAction`, restated so lib stays a leaf. */
export interface PaletteCommand {
 id: string;
 label: string;
 group: string;
 hint?: string;
 shortcut?: string;
 keywords?: string;
 icon?: ComponentType<{ size?: number }>;
 /** Offered but not runnable right now. The palette shows the row and refuses the commit. */
 disabled?: boolean;
 /** Why it cannot run, for a place that shows the row away from the heading carrying the reason. */
 disabledReason?: string;
 run: () => void;
}

/** The heading Burp's "recently used commands" become here. */
export const RECENTS_GROUP = "Recently used";

/**
 * How many recent commands the palette floats to the top.
 *
 * Small on purpose: Recents is a shortcut past the list, and a Recents group long enough to
 * need scrolling past is just the list again in a different order. Burp shows a short block.
 */
export const RECENTS_LIMIT = 6;

/**
 * The recently-run commands, newest first, as the same action objects the rest of the list holds.
 *
 * The same object rather than a copy: a Recents row has to run the command it names and has to
 * record *that* command's id when it does, or the ledger would start tracking a second, parallel
 * notion of "recent" that drifts from the one it already ranks by.
 */
export function recentCommands<T extends { id: string }>(actions: T[], ledger: Record<string, number>, limit: number = RECENTS_LIMIT): T[] {
 const byId = new Map(actions.map((action) => [action.id, action]));
 const recent: T[] = [];
 for (const id of recentActionIds(ledger, byId.keys(), limit)) {
  const action = byId.get(id);
  if (action) recent.push(action);
 }
 return recent;
}

/**
 * One palette entry per transform the editor's selection menu offers.
 *
 * `note` and `runnable` are passed in rather than decided here because they are facts about the
 * page — which editor holds a selection, and whether its message can be written to — and the
 * caller is the only one that can see them.
 *
 * The note goes on the group heading rather than on every row, which is where the editor's own
 * menu puts it ("Convert selection (select text first)"): seventeen rows each repeating the same
 * sentence would bury the labels the operator came to read. It is carried on the row as well, in
 * `disabledReason`, because the Recently used group prints a row under its own heading — and a
 * disabled row that has been lifted away from the heading explaining it is a row that looks
 * ordinary and then does nothing.
 */
export function codecCommands(run: (codec: SelectionCodec) => void, state: { runnable: boolean; note?: string }): PaletteCommand[] {
 return SELECTION_CODECS.map((codec) => ({
  id: `convert:${codec.id}`,
  label: codec.label,
  group: state.note ? `${codec.group} (${state.note})` : codec.group,
  shortcut: codec.shortcut || undefined,
  // "encode"/"decode" both, on every row: an operator reaching for "decode base64" and one
  // reaching for "encode base64" are typing about the same menu, and Burp files the whole
  // family under "encoding data".
  keywords: `encode decode encoding convert selection ${codec.id.replace(/-/g, " ")}`,
  icon: Binary,
  disabled: !state.runnable,
  disabledReason: state.runnable ? undefined : state.note,
  run: () => run(codec),
 }));
}

/**
 * One palette entry per `menu` registration a loaded plugin declared.
 *
 * `menu` and not `context-menu`: a context-menu registration is invoked *about* an exchange the
 * operator right-clicked, and the palette has no exchange to hand it — the registration would be
 * a row that runs against nothing. A menu registration is the host's own notion of a standalone
 * command, which is exactly what a palette entry is.
 *
 * Only loaded plugins reach this list, because `pluginInvocations` already refuses the rest: the
 * invoke route rejects a plugin that is not running, so an unloaded plugin's row could only fail.
 */
export function extensionCommands(list: ExtensionList | undefined, invoke: (call: PluginInvocation) => void): PaletteCommand[] {
 return pluginInvocations(list, "menu").map((invocation) => ({
  id: `extension:${invocation.plugin}:${invocation.registration.id}`,
  // The plugin's own words, and the plugin's name beside them: two plugins may both register
  // "Decode", and the row has to say which piece of code is about to run.
  label: invocation.registration.label,
  group: "Extensions",
  hint: invocation.registration.hint ?? `registered by ${invocation.plugin}`,
  keywords: `extension plugin ${invocation.plugin}`,
  icon: Plug,
  run: () => invoke(invocation),
 }));
}

/**
 * One palette row per registry action flagged `palette` (2czi): Burp's action catalogue, reachable
 * from the palette as Burp's own is ("all commands … through the command palette",
 * desktop/settings/ui/hotkeys.html).
 *
 * `available` and `run` come from lib/commands.ts. An action with no mounted handler is listed
 * disabled with the registry's `where` as the reason, never hidden: an operator searching for
 * "drop all" from Repeater should learn where it lives, not conclude it does not exist.
 */
export function catalogueCommands(
 actions: readonly ShortcutAction[],
 keymap: Keymap,
 available: (id: string) => boolean,
 run: (id: string) => void,
 /** The owner's own "cannot run now" reason, when it registered one (lib/commands.ts). */
 reasonFor: (id: string) => string | undefined = () => undefined,
): PaletteCommand[] {
 return actions
  .filter((action) => action.palette)
  .map((action) => {
   const can = available(action.id);
   const chord = chordFor(keymap, action.id);
   const why = can ? undefined : (reasonFor(action.id) ?? `Available in ${action.where ?? "another tool"}`);
   return {
    id: `action:${action.id}`,
    label: action.label,
    group: action.group,
    shortcut: chord ?? undefined,
    keywords: [action.burp?.toLowerCase().replace(/_/g, " "), action.where].filter(Boolean).join(" "),
    disabled: !can,
    disabledReason: why,
    hint: why,
    run: () => run(action.id),
   };
  });
}
