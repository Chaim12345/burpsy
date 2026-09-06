import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type Row,
  type SortingState,
  type VisibilityState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp, Columns3, Copy } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { copyToClipboard } from "../lib/api";
import { cn } from "../lib/cn";
import { useApp } from "../lib/store";
import { ColumnVisibilityMenu } from "./column-visibility-menu";
import { ContextMenu, type MenuGroup } from "./menu";
import { Spinner } from "./primitives";

// Re-exported so a page wiring `columnVisibility`/`onColumnVisibilityChange` does
// not need its own dependency on @tanstack/react-table just for this one type.
export type { VisibilityState };

// TanStack's ColumnDef is invariant in its value type; `any` is the documented
// escape hatch for heterogeneous column collections.
/* eslint-disable @typescript-eslint/no-explicit-any */
export type Column<T> = ColumnDef<T, any>;

/** Fallbacks only; the real height is measured from the CSS token below. */
const ROW_HEIGHT_FALLBACK = { comfortable: 30, compact: 24 } as const;

/**
 * Row height comes from a fluid CSS token, but the virtualizer needs a number in
 * pixels to compute offsets. Reading a custom property gives back the unresolved
 * `clamp(...)` expression, so an off-screen probe styled with the same token is
 * measured instead, and re-measured whenever the viewport changes.
 */
function useFluidRowHeight(density: "comfortable" | "compact"): [number, (node: HTMLDivElement | null) => void] {
  const [height, setHeight] = useState<number>(ROW_HEIGHT_FALLBACK[density]);
  const probe = useRef<HTMLDivElement | null>(null);

  const setProbe = useCallback((node: HTMLDivElement | null) => {
    probe.current = node;
  }, []);

  useEffect(() => {
    const measure = () => {
      const measured = probe.current?.getBoundingClientRect().height ?? 0;
      if (measured > 0) setHeight(Math.round(measured));
    };
    measure();
    window.addEventListener("resize", measure);
    window.addEventListener("orientationchange", measure);
    return () => {
      window.removeEventListener("resize", measure);
      window.removeEventListener("orientationchange", measure);
    };
  }, [density]);

  return [height, setProbe];
}

/**
 * The column-visibility menu needs a plain string per column. Every column in
 * this app declares a string `header` (see history.tsx, sitemap.tsx, logger.tsx,
 * wshistory.tsx) — the fallback to the column id only covers a future column
 * whose header is a rendered node.
 */
function columnLabel(header: unknown, id: string): string {
  return typeof header === "string" ? header : id;
}

export interface VirtualTableProps<T> {
  data: T[];
  columns: Column<T>[];
  getRowId: (row: T) => string;
  ariaLabel: string;
  selectedId?: string | null;
  onSelect?: (row: T) => void;
  /** Enter or double-click. Falls back to onSelect when omitted. */
  onActivate?: (row: T) => void;
  menuGroups?: (row: T) => MenuGroup[];
  rowClassName?: (row: T) => string | undefined;
  loading?: boolean;
  empty?: ReactNode;
  density?: "comfortable" | "compact";
  /** CSS height for the scroll viewport. Must be bounded for virtualization. */
  height?: string;
  initialSort?: SortingState;
  /**
   * Shows the column show/hide trigger in the header. Off by default so a table
   * that never opts in behaves exactly as before — no button, no menu, no
   * change to `columns.length`-based layout.
   *
   * Mark a column non-removable with TanStack's own `enableHiding: false` on its
   * `ColumnDef`, not a parallel prop.
   */
  enableColumnVisibility?: boolean;
  /**
   * Controlled column-visibility state, in TanStack's own shape (`false` means
   * hidden; omitted or `true` means visible). Pass this with
   * `onColumnVisibilityChange` when a page wants to read and persist which
   * columns are hidden (e.g. to `localStorage`). Omit both to let the table
   * manage the state itself.
   */
  columnVisibility?: VisibilityState;
  onColumnVisibilityChange?: (next: VisibilityState) => void;
  /**
   * Pin the viewport to the last row whenever rows are appended. Off by default: a table
   * that yanks the viewport out from under an operator reading older rows is the failure
   * this flag exists to avoid, so following is always opt-in per table (burpsy-react-ui-c13).
   */
  followNewRows?: boolean;
}

export function VirtualTable<T>({
  data,
  columns,
  getRowId,
  ariaLabel,
  selectedId,
  onSelect,
  onActivate,
  menuGroups,
  rowClassName,
  loading = false,
  empty,
  density: densityProp,
  height = "100%",
  initialSort = [],
  enableColumnVisibility = false,
  columnVisibility: controlledVisibility,
  onColumnVisibilityChange,
  followNewRows = false,
}: VirtualTableProps<T>): JSX.Element {
  // The operator's density preference is the default when a page does not name
  // one — the store is the single source of truth for it, so a table that never
  // opts in still honours the Settings/palette/View-menu toggle instead of
  // silently rendering at the component default forever. The store read is
  // unconditional (a hook must not sit on the right of `??`, or it would run only
  // when no prop is passed), and an explicit prop still wins when a page supplies one.
  const storeDensity = useApp((state) => state.density);
  const density = densityProp ?? storeDensity;
  const [sorting, setSorting] = useState<SortingState>(initialSort);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Controlled when a page supplies `columnVisibility`, uncontrolled otherwise —
  // the same split `Field`-adjacent components in this codebase use, so a table
  // that never opts in stays on the internal `{}` (every column visible) and a
  // page that wants to persist the choice can own the state instead.
  const [internalVisibility, setInternalVisibility] = useState<VisibilityState>({});
  const visibility = controlledVisibility ?? internalVisibility;
  const setVisibility = useCallback(
    (next: VisibilityState) => {
      onColumnVisibilityChange?.(next);
      if (!controlledVisibility) setInternalVisibility(next);
    },
    [controlledVisibility, onColumnVisibilityChange],
  );

  const [columnMenuOpen, setColumnMenuOpen] = useState(false);
  const columnMenuTriggerRef = useRef<HTMLButtonElement>(null);
  const columnMenuPanelRef = useRef<HTMLDivElement>(null);

  const table = useReactTable({
    data,
    columns,
    state: { sorting, columnVisibility: visibility },
    onSortingChange: setSorting,
    onColumnVisibilityChange: (updater) => {
      setVisibility(typeof updater === "function" ? updater(visibility) : updater);
    },
    getRowId,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    columnResizeMode: "onChange",
  });

  // Escape closes the menu and returns focus to the trigger that opened it;
  // clicking anywhere outside the panel and trigger closes it too, matching the
  // rest of this app's popovers (ContextMenu, DropdownMenu are Radix and get this
  // for free — this one is plain markup so checkboxes stay in normal tab order,
  // which is the requirement, rather than Radix's roving-tabindex menu keys).
  useEffect(() => {
    if (!columnMenuOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setColumnMenuOpen(false);
        columnMenuTriggerRef.current?.focus();
      }
    };
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (columnMenuPanelRef.current?.contains(target) || columnMenuTriggerRef.current?.contains(target)) return;
      setColumnMenuOpen(false);
    };
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("pointerdown", onPointerDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("pointerdown", onPointerDown);
    };
  }, [columnMenuOpen]);

  const hideableColumns = useMemo(
    () =>
      enableColumnVisibility
        ? table.getAllLeafColumns().filter((column) => column.getCanHide())
        : [],
    // table identity is stable per render pass; visibility changes are what should
    // recompute the checked state, columns changes are what should recompute the set.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [enableColumnVisibility, columns, visibility],
  );

  const rows = table.getRowModel().rows;
  const [rowHeight, setProbe] = useFluidRowHeight(density);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: 14,
  });

  const virtualRows = virtualizer.getVirtualItems();
  const totalSize = virtualizer.getTotalSize();
  const paddingTop = virtualRows.length ? (virtualRows[0]?.start ?? 0) : 0;
  const paddingBottom = virtualRows.length ? totalSize - (virtualRows.at(-1)?.end ?? 0) : 0;

  const selectedIndex = useMemo(
    () => (selectedId ? rows.findIndex((row) => row.id === selectedId) : -1),
    [rows, selectedId],
  );

  // Keep the selected row in view when selection moves from outside the table
  // (keyboard shortcuts, send-to handoffs, a jump from another page).
  useEffect(() => {
    if (selectedIndex >= 0) virtualizer.scrollToIndex(selectedIndex, { align: "auto" });
    // virtualizer identity is stable per scroll element; re-running on it would loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIndex]);

  // burpsy-react-ui-c13: follow appended rows while enabled. Growth-only (a filter narrowing
  // the list must never fling the viewport), and bottom-of-current-order rather than
  // newest-by-id: under a descending sort the last row is the oldest, and claiming otherwise
  // would be the same dishonesty as a fabricated count. Selection scroll above still wins on
  // its own trigger; the two do not fight because this one only fires when the row count grew.
  const rowCountRef = useRef(rows.length);
  useEffect(() => {
    const grew = rows.length > rowCountRef.current;
    rowCountRef.current = rows.length;
    if (followNewRows && grew && rows.length > 0) {
      virtualizer.scrollToIndex(rows.length - 1, { align: "end" });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows.length, followNewRows]);

  const move = useCallback(
    (delta: number | "start" | "end") => {
      if (!rows.length || !onSelect) return;
      let next: number;
      if (delta === "start") next = 0;
      else if (delta === "end") next = rows.length - 1;
      else next = Math.min(rows.length - 1, Math.max(0, (selectedIndex < 0 ? -1 : selectedIndex) + delta));
      const row = rows[next];
      if (row) onSelect(row.original);
    },
    [rows, onSelect, selectedIndex],
  );

  const onKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault();
        move(1);
        break;
      case "ArrowUp":
        event.preventDefault();
        move(-1);
        break;
      case "PageDown":
        event.preventDefault();
        move(12);
        break;
      case "PageUp":
        event.preventDefault();
        move(-12);
        break;
      case "Home":
        event.preventDefault();
        move("start");
        break;
      case "End":
        event.preventDefault();
        move("end");
        break;
      case "Enter": {
        const row = rows[selectedIndex];
        if (row) {
          event.preventDefault();
          (onActivate ?? onSelect)?.(row.original);
        }
        break;
      }
      default:
        break;
    }
  };

  const showEmpty = !loading && rows.length === 0;
  const visibleColumnCount = table.getVisibleLeafColumns().length;

  return (
    <div className={cn("table-frame", `density-${density}`)}>
      <div
        ref={setProbe}
        aria-hidden="true"
        className="row-height-probe"
        style={{ height: density === "compact" ? "var(--row-h-compact)" : "var(--row-h)" }}
      />
      {enableColumnVisibility ? (
        <div className="column-menu-anchor">
          <button
            ref={columnMenuTriggerRef}
            type="button"
            className="column-menu-trigger"
            aria-haspopup="menu"
            aria-expanded={columnMenuOpen}
            aria-label="Show or hide columns"
            title="Show or hide columns"
            onClick={() => setColumnMenuOpen((open) => !open)}
          >
            <Columns3 size={12} />
          </button>
          {columnMenuOpen ? (
            <ColumnVisibilityMenu
              ref={columnMenuPanelRef}
              columns={hideableColumns.map((column) => ({
                id: column.id,
                label: columnLabel(column.columnDef.header, column.id),
                visible: column.getIsVisible(),
              }))}
              onToggle={(id, visible) => table.getColumn(id)?.toggleVisibility(visible)}
              onReset={() => table.resetColumnVisibility()}
            />
          ) : null}
        </div>
      ) : null}
      <div
        className="table-scroll"
        ref={scrollRef}
        style={{ height }}
        tabIndex={0}
        role="group"
        aria-label={ariaLabel}
        onKeyDown={onKeyDown}
      >
        {/* Column sizes are the floor; with table-layout:fixed the browser shares any
            leftover width across them so the grid still spans the viewport. */}
        <table style={{ width: "100%", minWidth: table.getCenterTotalSize() }}>
          <thead>
            {table.getHeaderGroups().map((group) => (
              <tr key={group.id}>
                {group.headers.map((header) => {
                  const sorted = header.column.getIsSorted();
                  const canSort = header.column.getCanSort();
                  // Burp's "Copy column" (burpsy-react-ui-3gr3): the underlying values of every
                  // loaded row, not just the rendered window - copying only the virtualised
                  // viewport would silently drop rows. Raw values, not badge text ("pending",
                  // "HTML", "—" are presentation); the data is what a wordlist wants.
                  const rawHeader = header.column.columnDef.header;
                  const columnLabel = typeof rawHeader === "string" ? rawHeader : header.column.id;
                  const copyColumn = () => {
                    if (!rows.length) {
                      toast.error("No rows to copy");
                      return;
                    }
                    const lines = rows.map((row) => {
                      const value: unknown = row.getValue(header.column.id);
                      return value === null || value === undefined ? "" : String(value);
                    });
                    void copyToClipboard(lines.join("\n"));
                    toast.success(`Copied ${lines.length} ${columnLabel} values`);
                  };
                  const label = canSort ? (
                    <button type="button" className="th-sort" onClick={header.column.getToggleSortingHandler()}>
                      {flexRender(header.column.columnDef.header, header.getContext())}
                      {sorted === "asc" ? <ArrowUp size={11} /> : sorted === "desc" ? <ArrowDown size={11} /> : null}
                    </button>
                  ) : (
                    <span className="th-label">{flexRender(header.column.columnDef.header, header.getContext())}</span>
                  );
                  return (
                    <th key={header.id} style={{ width: header.getSize() }} aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}>
                      <ContextMenu
                        groups={[
                          {
                            id: "column",
                            actions: [{ id: "copy-column", label: `Copy ${columnLabel} column`, icon: Copy, onSelect: copyColumn }],
                          },
                        ]}
                      >
                        {label}
                      </ContextMenu>
                      {header.column.getCanResize() ? (
                        <span
                          role="presentation"
                          className={cn("col-resize", header.column.getIsResizing() && "col-resizing")}
                          onMouseDown={header.getResizeHandler()}
                          onTouchStart={header.getResizeHandler()}
                          onDoubleClick={() => header.column.resetSize()}
                        />
                      ) : null}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {paddingTop > 0 ? (
              <tr aria-hidden="true" style={{ height: paddingTop }}>
                <td colSpan={visibleColumnCount} />
              </tr>
            ) : null}
            {virtualRows.map((virtualRow) => {
              const row = rows[virtualRow.index];
              if (!row) return null;
              return (
                <TableRow
                  key={row.id}
                  row={row}
                  height={rowHeight}
                  selected={row.id === selectedId}
                  className={rowClassName?.(row.original)}
                  onSelect={onSelect}
                  onActivate={onActivate}
                  menuGroups={menuGroups}
                />
              );
            })}
            {paddingBottom > 0 ? (
              <tr aria-hidden="true" style={{ height: paddingBottom }}>
                <td colSpan={visibleColumnCount} />
              </tr>
            ) : null}
          </tbody>
        </table>
        {loading && rows.length === 0 ? (
          <div className="table-overlay">
            <Spinner />
          </div>
        ) : null}
        {showEmpty ? <div className="table-overlay">{empty}</div> : null}
      </div>
    </div>
  );
}

function TableRow<T>({
  row,
  height,
  selected,
  className,
  onSelect,
  onActivate,
  menuGroups,
}: {
  row: Row<T>;
  height: number;
  selected: boolean;
  className?: string;
  onSelect?: (row: T) => void;
  onActivate?: (row: T) => void;
  menuGroups?: (row: T) => MenuGroup[];
}): JSX.Element {
  const element = (
    <tr
      style={{ height }}
      aria-selected={selected}
      className={cn("data-row", selected && "selected-row", onSelect && "clickable", className)}
      onClick={() => onSelect?.(row.original)}
      onDoubleClick={() => (onActivate ?? onSelect)?.(row.original)}
      // Right-clicking a row should act on that row, matching desktop tools.
      onContextMenu={() => onSelect?.(row.original)}
    >
      {row.getVisibleCells().map((cell) => (
        <td key={cell.id} style={{ width: cell.column.getSize() }}>
          {flexRender(cell.column.columnDef.cell, cell.getContext())}
        </td>
      ))}
    </tr>
  );
  if (!menuGroups) return element;
  return <ContextMenu groups={menuGroups(row.original)}>{element}</ContextMenu>;
}

/**
 * A `SimpleTable` row with a right-click menu.
 *
 * # Why this is a component and not a `menuGroups` prop on SimpleTable
 *
 * `SimpleTable` takes its rows as `children`, so it never sees a row object to hand to a menu
 * factory — the page builds the `<tr>`s itself. That leaves two options, and one of them is a
 * trap: wrapping the page's `<tr>` in a `<ContextMenu>` inside the `.map()` callback moves the
 * React key onto a child of the mapped element, which leaves the list keyless. That was tried
 * here and reverted.
 *
 * This is the other option. `MenuRow` *is* the mapped element, so the key goes on it, and the
 * `<tr>` it renders is the Radix trigger via `asChild` — no wrapper element, so the table markup
 * stays valid. Every prop other than `groups` is forwarded to the `<tr>`, so a page converts a
 * row by renaming the tag and adding one prop.
 */
export function MenuRow({
  groups,
  children,
  ...rowProps
}: { groups: MenuGroup[]; children: ReactNode } & React.HTMLAttributes<HTMLTableRowElement>): JSX.Element {
  return (
    <ContextMenu groups={groups}>
      <tr {...rowProps}>{children}</tr>
    </ContextMenu>
  );
}

/**
 * A sortable table for bounded row sets (burpsy-react-ui-4rd).
 *
 * VirtualTable carries selection, virtualization and context menus for the
 * traffic tables; Intruder's result tables are report-shaped — fixed columns,
 * every row rendered, no row semantics — and SimpleTable gave them nothing but
 * static headers. This keeps SimpleTable's footprint (table-frame, density,
 * plain rows) and adds click-to-sort headers over raw accessor values, which
 * Burp's results documentation treats as the way to read an attack: "click on
 * the column header to sort the results".
 *
 * Filtering is deliberately not in here: the page filters the rows it passes
 * (lib/table-filter.ts's filterTableRows) so the count it prints next to the
 * filter box is computed from the same rows the table renders, by construction,
 * rather than two implementations that could drift.
 */
export function SortableTable<T>({
  data,
  columns,
  getRowId,
  ariaLabel,
  initialSort = [],
  rowClassName,
  density: densityProp,
}: {
  data: T[];
  columns: Column<T>[];
  getRowId: (row: T) => string;
  ariaLabel: string;
  initialSort?: SortingState;
  rowClassName?: (row: T) => string | undefined;
  density?: "comfortable" | "compact";
}): JSX.Element {
  const storeDensity = useApp((state) => state.density);
  const density = densityProp ?? storeDensity;
  const [sorting, setSorting] = useState<SortingState>(initialSort);
  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId,
  });

  return (
    <div className={cn("table-frame", `density-${density}`)} role="group" aria-label={ariaLabel}>
      <div className="table-scroll">
        <table>
          <thead>
            {table.getHeaderGroups().map((group) => (
              <tr key={group.id}>
                {group.headers.map((header) => {
                  const sorted = header.column.getIsSorted();
                  const canSort = header.column.getCanSort();
                  return (
                    <th
                      key={header.id}
                      aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
                    >
                      {canSort ? (
                        <button type="button" className="th-sort" onClick={header.column.getToggleSortingHandler()}>
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {sorted === "asc" ? (
                            <ArrowUp size={11} />
                          ) : sorted === "desc" ? (
                            <ArrowDown size={11} />
                          ) : null}
                        </button>
                      ) : (
                        <span className="th-label">
                          {flexRender(header.column.columnDef.header, header.getContext())}
                        </span>
                      )}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr key={row.id} className={rowClassName?.(row.original)}>
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** Static table for short, non-virtualized lists where a scroll viewport would be wrong. */
export function SimpleTable({
  headers,
  children,
  className,
  density: densityProp,
}: {
  headers: string[];
  children: ReactNode;
  className?: string;
  density?: "comfortable" | "compact";
}): JSX.Element {
  // Same store fallback as VirtualTable: density is a preference set in one
  // place and consumed here, and the crossing must not silently stop working.
  const storeDensity = useApp((state) => state.density);
  const density = densityProp ?? storeDensity;
  return (
    <div className={cn("table-frame", "density-" + density, className)}>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              {headers.map((header) => (
                <th key={header}>{header}</th>
              ))}
            </tr>
          </thead>
          <tbody>{children}</tbody>
        </table>
      </div>
    </div>
  );
}
