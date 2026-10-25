/**
 * Column visibility rules for VirtualTable (burpsy-react-ui-bae7).
 *
 * Burp (desktop/burps-layout/customize-tables.html): "Hide columns - Right-click the column header,
 * then select Hide column", "Show hidden columns - Click the options menu > Table layout", and
 * "Burp remembers your preferences, so you don't need to reorganize your tables every time you
 * start Burp". So hiding is a header gesture, showing is the column menu, and the choice persists.
 *
 * The state is TanStack's VisibilityState: `false` means hidden, absent or `true` means shown.
 */

export type Visibility = Record<string, boolean>;

/** The columns of `ids` currently shown. */
export function visibleColumnIds(ids: readonly string[], visibility: Visibility): string[] {
 return ids.filter((id) => visibility[id] !== false);
}

/**
 * Whether `id` may be hidden. A table with no visible column is a table with no way back to its
 * own header menu — Burp greys "Hide column" out on the last one, and so does this.
 */
export function canHideColumn(ids: readonly string[], visibility: Visibility, id: string): boolean {
 if (visibility[id] === false) return false;
 return visibleColumnIds(ids, visibility).length > 1;
}

/**
 * A stored visibility map, trusted only for the column ids this table renders now: unknown ids are
 * dropped (a renamed or removed column), non-boolean values are dropped, and a map that would hide
 * every column is discarded whole rather than restoring an empty table.
 */
export function reconcileVisibility(stored: unknown, ids: readonly string[]): Visibility {
 if (stored === null || typeof stored !== "object" || Array.isArray(stored)) return {};
 const known = new Set(ids);
 const out: Visibility = {};
 for (const [id, value] of Object.entries(stored as Record<string, unknown>)) {
  if (known.has(id) && typeof value === "boolean") out[id] = value;
 }
 return visibleColumnIds(ids, out).length === 0 ? {} : out;
}

/** The localStorage key for a table shape — the same fingerprint VirtualTable's column order uses. */
export function visibilityStorageKey(ids: readonly string[]): string {
 return `burpsy.table-column-visibility.${[...ids].sort().join("|")}`;
}
