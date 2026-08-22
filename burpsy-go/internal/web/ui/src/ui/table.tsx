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
import { ArrowDown, ArrowUp, Columns3 } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { cn } from "../lib/cn";
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
  density = "comfortable",
  height = "100%",
  initialSort = [],
  enableColumnVisibility = false,
  columnVisibility: controlledVisibility,
  onColumnVisibilityChange,
}: VirtualTableProps<T>): JSX.Element {
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
                  return (
                    <th key={header.id} style={{ width: header.getSize() }} aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}>
                      {canSort ? (
                        <button
                          type="button"
                          className="th-sort"
                          onClick={header.column.getToggleSortingHandler()}
                          title={
                            sorted === "asc"
                              ? "Sorted ascending. Click to sort descending."
                              : sorted === "desc"
                                ? "Sorted descending. Click to clear sort."
                                : "Click to sort ascending."
                          }
                        >
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {sorted === "asc" ? <ArrowUp size={11} /> : sorted === "desc" ? <ArrowDown size={11} /> : null}
                        </button>
                      ) : (
                        flexRender(header.column.columnDef.header, header.getContext())
                      )}
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

/** Static table for short, non-virtualized lists where a scroll viewport would be wrong. */
export function SimpleTable({ headers, children, className }: { headers: string[]; children: ReactNode; className?: string }): JSX.Element {
  return (
    <div className={cn("table-frame", className)}>
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
