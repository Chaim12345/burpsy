/**
 * Client-side row filtering for the sortable result tables (burpsy-react-ui-4rd).
 *
 * Burp's results filtering is free-text against the values a row shows. This
 * matcher runs against one row value at a time — with TanStack's global filter,
 * the row passes when any column's value matches — and flattens each value into
 * the text an operator could plausibly type to find it:
 *
 * - strings match as themselves, case-insensitively;
 * - numbers match their string form ("404", not a formatted variant — the raw
 *   value is the data, and formatted widths like "1.2 kB" are presentation);
 * - booleans match both the word and the badge text they render as ("true",
 *   "yes", "no"), since yes/no is what the table shows;
 * - null and undefined are skipped: an empty cell is nothing to search, not a
 *   "null" to search for;
 * - arrays and plain objects (payload parts, drop reasons) flatten recursively,
 *   depth-capped so a self-referential value cannot hang the table.
 *
 * The query is a literal substring, never a regex: an operator pasting "a.c"
 * is looking for that text, and a parse error (or a silently wrong match) is
 * the kind of dishonesty the filter must not add.
 */

// Type-only: the result tables' column definitions (ui/table.tsx re-exports the TanStack alias).
import type { Column } from "../ui/table";

const MAX_DEPTH = 4;

export function flattenRowText(value: unknown, depth = 0): string[] {
  if (value === null || value === undefined) return [];
  if (typeof value === "string") return value === "" ? [] : [value];
  if (typeof value === "number") return Number.isFinite(value) ? [String(value)] : [];
  if (typeof value === "boolean") return [String(value), value ? "yes" : "no"];
  if (depth >= MAX_DEPTH) return [];
  if (Array.isArray(value)) return value.flatMap((item) => flattenRowText(item, depth + 1));
  if (typeof value === "object") {
    return Object.values(value as Record<string, unknown>).flatMap((item) => flattenRowText(item, depth + 1));
  }
  return [];
}

export function tableRowMatches(value: unknown, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (needle === "") return true;
  return flattenRowText(value).some((text) => text.toLowerCase().includes(needle));
}

/**
 * The rows of a result table that survive a filter query.
 *
 * A column contributes its accessor value — `accessorFn` where the column
 * defines one, otherwise the `accessorKey` property of the row — because that
 * is the same value the cell renders from and sorts by. A row passes when any
 * column's value matches; columns without an accessor (a pure render cell)
 * contribute nothing, which is also what TanStack would see for them.
 *
 * Takes the result tables' own column type (the `Column` alias in ui/table.tsx)
 * so pages pass their defs straight in and a drift in either definition fails
 * to compile.
 */
export function filterTableRows<T>(rows: T[], columns: Column<T>[], query: string): T[] {
  if (query.trim() === "") return rows;
  return rows.filter((row, index) =>
    columns.some((column) => {
      // The column union hides which accessor a def carries; `in` narrows to
      // the members that actually declare one, matching TanStack's own
      // accessor resolution.
      const value =
        "accessorFn" in column
          ? column.accessorFn(row, index)
          : "accessorKey" in column
            ? (row as Record<string, unknown>)[column.accessorKey as string]
            : undefined;
      return tableRowMatches(value, query);
    }),
  );
}

