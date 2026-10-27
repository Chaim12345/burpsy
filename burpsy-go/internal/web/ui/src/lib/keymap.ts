/**
 * The operator's hotkey overrides, and the hook every rebindable binding installs through.
 *
 * # Why a subscription rather than component state
 *
 * A binding lives in app.tsx, another in history.tsx, another in intercept.tsx. Editing one
 * in Settings has to change the binding those components installed, and they do not share a
 * React ancestor with the editor. So the map lives in a module-level store with a listener
 * set: the Settings table writes, everyone re-renders, and `useHotkeys` is re-registered with
 * the new chord. A context provider would have worked too and would have meant threading a
 * provider through app.tsx, which is the file another unit is most likely to be editing.
 *
 * localStorage is the persistence, matching `burpsy.split.*` and `burpsy.logger.columns`.
 * Every read and write is wrapped: a private window, cleared site data or a browser set to
 * block storage all throw on access, and a hotkey table is not worth a blank page.
 */
import { useEffect, useState } from "react";
import { useHotkeys } from "react-hotkeys-hook";
import { hasCommand, runCommand } from "./commands";
import { KEYMAP_STORAGE_KEY, chordFor, type Chord, type Keymap } from "./shortcuts";

let current: Keymap = load();
const listeners = new Set<() => void>();

function load(): Keymap {
 try {
  const raw = localStorage.getItem(KEYMAP_STORAGE_KEY);
  if (raw === null) return {};
  const parsed: unknown = JSON.parse(raw);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  // Only string-or-null values survive. A stored map that has drifted into another shape is
  // discarded per-entry rather than wholesale, so one bad row cannot cost every binding.
  const out: Keymap = {};
  for (const [id, value] of Object.entries(parsed as Record<string, unknown>)) {
   if (value === null || typeof value === "string") out[id] = value;
  }
  return out;
 } catch {
  return {};
 }
}

function persist(next: Keymap): void {
 try {
  localStorage.setItem(KEYMAP_STORAGE_KEY, JSON.stringify(next));
 } catch {
  // Non-fatal by design: the override still applies for this session, and the Settings table
  // says so rather than pretending the write succeeded.
 }
}

function announce(): void {
 for (const listener of listeners) listener();
}

/** Read the map without subscribing. For one-shot reads outside React. */
export function keymapSnapshot(): Keymap {
 return current;
}

/** Assign a chord to an action, or null to unbind it. */
export function setChord(id: string, chord: Chord | null): void {
 current = { ...current, [id]: chord };
 persist(current);
 announce();
}

/** Drop an override so the action returns to its shipped default. */
export function resetChord(id: string): void {
 const next = { ...current };
 delete next[id];
 current = next;
 persist(current);
 announce();
}

/** Drop every override. */
export function resetAllChords(): void {
 current = {};
 persist(current);
 announce();
}

/** Subscribe to the map. Returns the live map, re-rendering on every change. */
export function useKeymap(): Keymap {
 const [, bump] = useState(0);
 useEffect(() => {
  const listener = () => bump((n) => n + 1);
  listeners.add(listener);
  return () => {
   listeners.delete(listener);
  };
 }, []);
 return current;
}

/**
 * The chord in force for one action, as a subscribed value.
 *
 * Returns react-hotkeys-hook's own "no binding" spelling for an unbound action: the empty
 * string, which it accepts and never matches. Returning undefined would make the caller
 * choose, and one caller choosing `"mod+k"` as a fallback is how an unbound action silently
 * keeps its old key.
 */
export function useChord(id: string): Chord {
 const keymap = useKeymap();
 return chordFor(keymap, id) ?? "";
}

/** Whether the operator has overridden this action. Drives the per-row Reset control. */
export function useIsOverridden(id: string): boolean {
 const keymap = useKeymap();
 return Object.prototype.hasOwnProperty.call(keymap, id);
}

/** Read a keystroke off a keydown event as a chord this registry can store. */
export function chordFromEvent(event: KeyboardEvent | React.KeyboardEvent): string {
 const parts: string[] = [];
 if (event.ctrlKey || event.metaKey) parts.push("mod");
 if (event.altKey) parts.push("alt");
 if (event.shiftKey) parts.push("shift");
 const key = event.key;
 // Modifier-only presses produce no key part, which validateChord then refuses with a
 // readable reason rather than storing a chord that can never fire.
 if (!["Control", "Meta", "Alt", "Shift"].includes(key)) {
  parts.push(key.length === 1 ? key.toLowerCase() : key.toLowerCase());
 }
 return parts.join("+");
}

/**
 * Bind an action's chord to whichever component registered a handler for it (lib/commands.ts).
 *
 * Installed once, in the shell, for every catalogue action; the pages only register handlers.
 * The key is claimed (preventDefault) only when a handler exists, so a chord whose action is not
 * available here — Close tab outside Repeater — still reaches the browser instead of dying.
 */
export function useCommandChord(id: string): void {
 const chord = useChord(id);
 useHotkeys(
  chord,
  (event) => {
   if (!hasCommand(id)) return;
   event.preventDefault();
   runCommand(id);
  },
  { enableOnFormTags: true, enableOnContentEditable: true },
  [chord, id],
 );
}

/** A stable no-op, for binding an action whose handler is not on this page. */
export const noopHandler = (): void => {};

export { chordFor };
