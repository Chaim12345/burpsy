// What the operator's screen shows when a plugin hotkey fires (burpsy-react-ui-gqvg).
//
// A hotkey plugin gets the highlighted rows and the message open in the editor, and nothing else:
// the invoke route never reads the traffic store, so the console is the only party that knows what
// was on screen. Pages publish what they show into two slots, and the chord handler reads both at
// the moment the key is pressed. A page clears its slot when it unmounts, so a plugin never receives
// rows from a page the operator has left.
//
// Exchange id 0 is a real row. Every check here is `=== undefined`, never truthiness.
import { useEffect } from "react";

/** The wire shape of one highlighted row (extension.SelectedExchange). */
export interface HotkeySelectedRow {
 exchange: number;
 raw?: string;
}

/** The wire shape of the open editor message (extension.EditorMessage). */
export interface HotkeyEditorMessage {
 message?: number;
 raw?: string;
}

/** What the server accepts at most (extension.MaxHotkeySelection). Over it the route answers 400. */
export const MAX_HOTKEY_SELECTION = 100;

const slots: { rows: HotkeySelectedRow[] | null; editor: HotkeyEditorMessage | null } = { rows: null, editor: null };

export function publishHotkeyRows(rows: HotkeySelectedRow[] | null): void {
 slots.rows = rows && rows.length > 0 ? rows : null;
}

export function publishHotkeyEditor(editor: HotkeyEditorMessage | null): void {
 slots.editor = editor && (editor.message !== undefined || editor.raw !== undefined) ? editor : null;
}

/**
 * The fields to add to a hotkey invocation. Empty when nothing is on screen, so a chord pressed on
 * a page with no table and no editor posts exactly what it did before this existed. An oversized
 * selection is sent as it is: the route refuses it with a message the toast shows, and cutting it
 * here would hand the plugin a different selection than the one highlighted.
 */
export function hotkeyContextFields(): { selected?: HotkeySelectedRow[]; editor?: HotkeyEditorMessage } {
 return {
  ...(slots.rows ? { selected: slots.rows } : {}),
  ...(slots.editor ? { editor: slots.editor } : {}),
 };
}

/** Publish the highlighted rows while this component is mounted. */
export function usePublishHotkeyRows(rows: HotkeySelectedRow[] | null): void {
 const key = rows === null ? "" : JSON.stringify(rows);
 // biome-ignore lint/correctness/useExhaustiveDependencies: key is the rows' content.
 useEffect(() => {
  publishHotkeyRows(rows);
  return () => publishHotkeyRows(null);
 }, [key]);
}

/** Publish the open editor's message while this component is mounted. */
export function usePublishHotkeyEditor(editor: HotkeyEditorMessage | null): void {
 const key = editor === null ? "" : JSON.stringify(editor);
 // biome-ignore lint/correctness/useExhaustiveDependencies: key is the editor's content.
 useEffect(() => {
  publishHotkeyEditor(editor);
  return () => publishHotkeyEditor(null);
 }, [key]);
}
