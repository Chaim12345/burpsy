import { useEffect, useRef } from "react";

/**
 * The bridge between a named action and whichever mounted component can perform it (2czi).
 *
 * Burp's action catalogue (Zipf.java) is one flat list reachable from the hotkey table and the
 * command palette. In burpsy most of those actions live inside a page: Forward all is
 * intercept.tsx's, Close tab is repeater.tsx's, Toggle line wrap belongs to whichever message
 * editor was used last. The palette lives in the shell and cannot reach into them.
 *
 * So a component that can perform an action registers a handler under the registry id while it
 * is mounted (useActionHotkey in lib/keymap.ts does this alongside binding the chord), and the
 * palette runs the id. When nothing is registered the palette shows the row disabled with the
 * registry's `where` as the reason. The row is never dead and never pretends to work.
 *
 * Handlers stack: the most recent registration wins, and unregistering exposes the previous one.
 * That is what makes "the editor you used last" work: an editor re-registers on focus, which
 * moves it to the top.
 */

type Handler = () => void;

interface Entry {
 token: number;
 /** Absent when the registering component is mounted but cannot run the action right now. */
 handler?: Handler;
 /** Why it cannot run right now, when `handler` is absent. */
 reason?: string;
}

const stacks = new Map<string, Entry[]>();
const listeners = new Set<() => void>();
let nextToken = 0;
let version = 0;

function announce(): void {
 version += 1;
 for (const listener of listeners) listener();
}

/** Register `handler` for `id`. Returns the unregister function. Registering moves it to the top. */
export function registerCommand(id: string, handler: Handler): () => void {
 return register(id, { handler });
}

/**
 * Register "this component owns `id`, and it cannot run now, because `reason`". The palette shows
 * the reason in place of the registry's generic "Available in …", which would be false when the
 * operator is already there (Go back, on a tab's first send).
 */
export function registerUnavailable(id: string, reason: string): () => void {
 return register(id, { reason });
}

function register(id: string, body: Omit<Entry, "token">): () => void {
 const token = ++nextToken;
 const stack = stacks.get(id) ?? [];
 stack.push({ token, ...body });
 stacks.set(id, stack);
 announce();
 return () => {
  const current = stacks.get(id);
  if (!current) return;
  const at = current.findIndex((entry) => entry.token === token);
  if (at < 0) return;
  current.splice(at, 1);
  if (current.length === 0) stacks.delete(id);
  announce();
 };
}

/** Whether some mounted component can run `id` right now. */
export function hasCommand(id: string): boolean {
 const stack = stacks.get(id);
 return Boolean(stack?.[stack.length - 1]?.handler);
}

/** Why `id` cannot run, when its owner said so; undefined when it can, or when nothing owns it. */
export function unavailableReason(id: string): string | undefined {
 const stack = stacks.get(id);
 const top = stack?.[stack.length - 1];
 return top && !top.handler ? top.reason : undefined;
}

/** Run the most recently registered handler for `id`. False when there is none. */
export function runCommand(id: string): boolean {
 const stack = stacks.get(id);
 const top = stack?.[stack.length - 1];
 if (!top?.handler) return false;
 top.handler();
 return true;
}

/** Subscribe to registration changes (for the palette's enabled state). */
export function subscribeCommands(listener: () => void): () => void {
 listeners.add(listener);
 return () => {
  listeners.delete(listener);
 };
}

/** A number that changes whenever the registered set does. useSyncExternalStore's snapshot. */
export function commandsVersion(): number {
 return version;
}

/**
 * Register a handler for `id` while the calling component is mounted. Pass a string instead when
 * the action cannot run right now — "Nothing is held", "Already at the first send": the palette
 * shows that reason on the disabled row, and the chord is left to the browser rather than
 * swallowed.
 */
export function useCommandHandler(id: string, handler: Handler | string): void {
 const ref = useRef(handler);
 ref.current = handler;
 const reason = typeof handler === "string" ? handler : null;
 useEffect(() => {
  if (reason !== null) return registerUnavailable(id, reason);
  return registerCommand(id, () => {
   const current = ref.current;
   if (typeof current === "function") current();
  });
 }, [id, reason]);
}
