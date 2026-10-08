import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type ColumnOrderState,
  type Row,
  type SortingState,
  type VisibilityState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp, Columns3, Copy, EyeOff, GripVertical, RotateCcw } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { copyToClipboard } from "../lib/api";
import { cn } from "../lib/cn";
import { useApp } from "../lib/store";
import { canHideColumn, reconcileVisibility, visibilityStorageKey } from "../lib/table-columns";
import { clickAction, contextKeepsSelection, reduceSelection, sameIds, type SelectionAction, type SelectionState } from "../lib/table-selection";
import { ColumnVisibilityMenu } from "./column-visibility-menu";
import { ContextMenu, type MenuGroup } from "./menu";
import type { DocTopic } from "../lib/docs";
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

// --- column order (burpsy-react-ui-mem3) ---------------------------------------------------------
//
// Burp: "Move columns - Drag and drop the column header to a new location", on every table it
// shows. VirtualTable had sizing and visibility but no order at all — the columns array's own
// order was the only order a page could ever see.

/** The id TanStack itself would derive for a column def that names no explicit `id`. */
function columnKey<T>(def: Column<T>, index: number): string {
  if (def.id) return def.id;
  const accessorKey = (def as { accessorKey?: string }).accessorKey;
  return accessorKey ?? `column-${index}`;
}

/**
 * A stored order is only trusted for the id set it was written for — filtered down to ids still
 * present, then whatever is new in `fallback` (a page's own column addition, or simply a
 * first-ever visit) is appended in the page's own order. A stored order for a different table
 * shape entirely (found via key collision, or hand-edited storage) degrades to the fallback rather
 * than reordering columns it was never told about.
 */
function reconcileOrder(order: string[], fallback: string[]): string[] {
  const known = new Set(fallback);
  const kept = order.filter((id) => known.has(id));
  const missing = fallback.filter((id) => !kept.includes(id));
  return [...kept, ...missing];
}

function readStoredOrder(key: string, fallback: string[]): ColumnOrderState {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed) || !parsed.every((id) => typeof id === "string")) return fallback;
    return reconcileOrder(parsed, fallback);
  } catch {
    return fallback;
  }
}

/**
 * Column order, persisted per table shape rather than per page.
 *
 * `ariaLabel` was the obvious storage key and is wrong: Site map hands VirtualTable a fresh one
 * per node (`Requests under ${path}`), so keying on it would forget the operator's arrangement
 * the moment they clicked a different folder. The column *id set* a page renders does not change
 * between those clicks, and does differ between actually different tables (History's ids are not
 * Site map's), which makes it a fingerprint for "this kind of table" good enough to persist
 * against — with no prop and no change required in any of VirtualTable's callers.
 */
function useColumnOrder(defaultOrder: string[]): [ColumnOrderState, (updater: ColumnOrderState | ((current: ColumnOrderState) => ColumnOrderState)) => void] {
  const fingerprint = [...defaultOrder].sort().join("|");
  const storageKey = `burpsy.table-column-order.${fingerprint}`;

  const [order, setOrderState] = useState<ColumnOrderState>(() => readStoredOrder(storageKey, defaultOrder));

  // The column set itself changing (a page adds/removes a column, or this is a different table
  // reusing the hook) reconciles rather than resets, for the reason readStoredOrder does.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    setOrderState((current) => {
      const next = reconcileOrder(current, defaultOrder);
      // Same sequence already: bail out so this cannot loop against the persist effect below just
      // because `defaultOrder` is a fresh array reference on every render.
      return next.length === current.length && next.every((id, i) => id === current[i]) ? current : next;
    });
  }, [fingerprint]);

  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(order));
    } catch {
      // A private window or cleared site data: the order still holds for this session.
    }
  }, [storageKey, order]);

  const setOrder = useCallback(
    (updater: ColumnOrderState | ((current: ColumnOrderState) => ColumnOrderState)) => {
      setOrderState((current) => (typeof updater === "function" ? updater(current) : updater));
    },
    [],
  );

  return [order, setOrder];
}

/**
 * Uncontrolled column visibility, persisted per table shape (bae7) — the same fingerprint, and the
 * same reasoning, as useColumnOrder. A page that owns the state (History, Logger) passes it in and
 * this hook is bypassed; every other table now remembers what the operator hid, as Burp does.
 */
function usePersistedVisibility(ids: string[]): [VisibilityState, (next: VisibilityState) => void] {
  const storageKey = visibilityStorageKey(ids);
  const read = (): VisibilityState => {
    try {
      const raw = localStorage.getItem(storageKey);
      return raw ? reconcileVisibility(JSON.parse(raw), ids) : {};
    } catch {
      return {};
    }
  };
  const [visibility, setVisibility] = useState<VisibilityState>(read);
  // A different table shape reusing the hook (Site map's table across node clicks keeps its shape;
  // a page adding a column changes it) re-reads rather than carrying the old map over.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => setVisibility(read()), [storageKey]);
  const write = useCallback(
    (next: VisibilityState) => {
      setVisibility(next);
      try {
        localStorage.setItem(storageKey, JSON.stringify(next));
      } catch {
        // Private window or blocked storage: the choice still holds for this session.
      }
    },
    [storageKey],
  );
  return [visibility, write];
}

/** Move `moving` to sit immediately before `target` in `order`. A `target` no longer present
 *  (dropped between drag-start and drop, or a stale event) is a no-op rather than a silent drop
 *  of the moved column off the end. */
function moveColumnBefore(order: readonly string[], moving: string, target: string): string[] {
  const without = order.filter((id) => id !== moving);
  const at = without.indexOf(target);
  if (at < 0) return [...order];
  return [...without.slice(0, at), moving, ...without.slice(at)];
}

export interface VirtualTableProps<T> {
  data: T[];
  columns: Column<T>[];
  getRowId: (row: T) => string;
  ariaLabel: string;
  selectedId?: string | null;
  onSelect?: (row: T) => void;
  /** Enter or double-click. Falls back to onSelect when omitted. */
  /**
   * Double-click ONLY, and distinct from onActivate on purpose.
   *
   * onActivate is Enter-or-double-click, so an operator who has bound Enter to "send to Repeater"
   * must keep it: taking the double-click away from that would make the only way to open a detached
   * window a gesture, and the keyboard path would then have no gesture left to share it with. A
   * double-click that means one thing on one page and another on the next is worse than a missing
   * affordance, which is why the split is here rather than in each page.
   */
  onDoubleActivate?: (row: T) => void;
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
   * Shows the column show/hide trigger in the header and the header's "Hide column" item. On by
   * default (bae7): Burp offers both on every table it lets you customise, and a table that opts
   * out should have a reason. Uncontrolled tables persist the choice per table shape.
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
  /**
   * Multi-row selection (burpsy-react-ui-fe16): click, Ctrl/Cmd-click, Shift-click, Shift+arrows
   * and Ctrl+A, as Burp's JTables do. Opt-in per table, because a table that turns it on changes
   * what its right-click menu acts on. `selectedId` stays the focus row — the one the detail pane
   * shows — and the selection is the set of rows a multi-row menu acts on.
   */
  multiSelect?: boolean;
  /** Controlled selection, as row ids. Omit both to let the table hold the selection itself. */
  selectedIds?: readonly string[];
  onSelectionChange?: (ids: string[]) => void;
  /**
   * The menu for a right-click inside a selection of two or more rows, given those rows in
   * displayed order. Burp builds a different menu for N rows (Zr2s.java: "Delete selected items",
   * "Copy URLs", a multi "Send to Comparer"); a table without one falls back to `menuGroups` for
   * the clicked row.
   */
  menuGroupsMany?: (rows: T[]) => MenuGroup[];
  /**
   * The documentation topic the row menu's trailing "<Tool> documentation" entry opens (u9zz,
   * lib/docs.ts). Defaults to the generic Tables panel; a tool's own table names its tool.
   */
  docTopic?: DocTopic;
}

export function VirtualTable<T>({
  data,
  columns,
  getRowId,
  ariaLabel,
  selectedId,
  onSelect,
  onActivate,
  onDoubleActivate,
  menuGroups,
  rowClassName,
  loading = false,
  empty,
  density: densityProp,
  height = "100%",
  initialSort = [],
  enableColumnVisibility = true,
  columnVisibility: controlledVisibility,
  onColumnVisibilityChange,
  followNewRows = false,
  multiSelect = false,
  selectedIds: controlledIds,
  onSelectionChange,
  menuGroupsMany,
  docTopic = "tables",
}: VirtualTableProps<T>): JSX.Element {
  // The operator's density preference is the default when a page does not name
  // one — the store is the single source of truth for it, so a table that never
  // opts in still honours the Settings/palette/View-menu toggle instead of
  // silently rendering at the component default forever. The store read is
  // unconditional (a hook must not sit on the right of `??`, or it would run only
  // when no prop is passed), and an explicit prop still wins when a page supplies one.
  const storeDensity = useApp((state) => state.density);
  const density = densityProp ?? storeDensity;
  // Zebra striping (69p0), Burp's table_appearance.zebra_striping. Applied per row from the
  // virtual index, never :nth-child — the virtualizer's padding row and its windowing would flip
  // the parity as the table scrolls, and the stripes would swap under the operator.
  const stripes = useApp((state) => state.tableStripes);
  const [sorting, setSorting] = useState<SortingState>(initialSort);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Controlled when a page supplies `columnVisibility`, uncontrolled otherwise —
  // the same split `Field`-adjacent components in this codebase use, so a table
  // that never opts in stays on the internal `{}` (every column visible) and a
  // page that wants to persist the choice can own the state instead.
  const columnIds = useMemo(() => columns.map((def, index) => columnKey(def, index)), [columns]);
  const [internalVisibility, setInternalVisibility] = usePersistedVisibility(columnIds);
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

  // Drag-to-reorder (burpsy-react-ui-mem3): always on, unlike visibility, because every page gets
  // it for free — see useColumnOrder for why persistence needs no prop from the caller either.
  const defaultColumnOrder = columnIds;
  const [columnOrder, setColumnOrder] = useColumnOrder(defaultColumnOrder);
  // Which column's header is mid-drag, purely to know what a drop on another header should move.
  // Not persisted itself — only the resulting order is.
  const [draggingColumn, setDraggingColumn] = useState<string | null>(null);

  const table = useReactTable({
    data,
    columns,
    state: { sorting, columnVisibility: visibility, columnOrder },
    onSortingChange: setSorting,
    onColumnVisibilityChange: (updater) => {
      setVisibility(typeof updater === "function" ? updater(visibility) : updater);
    },
    onColumnOrderChange: setColumnOrder,
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

  // The sticky header sits inside the scroll element, above row 0, and the virtualizer knows nothing
  // of it: its row offsets start at 0 while the real rows start a header's height lower. Scrolling a
  // row into view from below therefore stopped one header short and left the row hidden under the
  // bottom edge — found when Go to entry (vfu2) "selected" #30 out of sight. Telling the virtualizer
  // the header's height as end padding makes "in view" mean in view.
  const theadRef = useRef<HTMLTableSectionElement>(null);
  const [headerHeight, setHeaderHeight] = useState(0);
  useEffect(() => {
    const head = theadRef.current;
    if (!head) return;
    const measure = () => setHeaderHeight(Math.round(head.getBoundingClientRect().height));
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(head);
    return () => observer.disconnect();
  }, []);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: 14,
    scrollPaddingEnd: headerHeight,
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

  // --- multi-row selection (fe16) ---------------------------------------------------------------
  // The displayed order is the one every range is computed over (lib/table-selection.ts says why).
  const order = useMemo(() => rows.map((row) => row.id), [rows]);
  const rowById = useMemo(() => new Map(rows.map((row) => [row.id, row])), [rows]);
  const [internalIds, setInternalIds] = useState<string[]>([]);
  const selectionIds: readonly string[] = multiSelect ? (controlledIds ?? internalIds) : selectedId ? [selectedId] : [];
  const selectedSet = useMemo(() => new Set(selectionIds), [selectionIds]);
  const anchorRef = useRef<string | null>(null);
  // The focus this table last asked the page to show, so an outside change to `selectedId` (a jump
  // from another page, Go to entry) can be told apart from one the table made itself.
  const ownFocusRef = useRef<string | null>(null);

  const writeIds = useCallback(
    (ids: string[]) => {
      onSelectionChange?.(ids);
      if (!controlledIds) setInternalIds(ids);
    },
    [controlledIds, onSelectionChange],
  );

  const dispatchSelection = (action: SelectionAction) => {
    const current: SelectionState = { ids: [...selectionIds], anchor: anchorRef.current, focus: selectedId ?? null };
    const next = reduceSelection(current, action, order);
    anchorRef.current = next.anchor;
    if (!sameIds(next.ids, selectionIds)) writeIds(next.ids);
    if (next.focus !== null && next.focus !== selectedId) {
      const row = rowById.get(next.focus);
      if (row) {
        ownFocusRef.current = next.focus;
        onSelect?.(row.original);
      }
    }
  };

  // A row selected from outside becomes the selection, so the menu and the detail pane agree.
  useEffect(() => {
    if (!multiSelect || !selectedId || selectedId === ownFocusRef.current) return;
    ownFocusRef.current = selectedId;
    if (!(selectionIds.length === 1 && selectionIds[0] === selectedId) && order.includes(selectedId)) {
      anchorRef.current = selectedId;
      writeIds([selectedId]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, multiSelect]);

  // Prune rows the filter no longer shows. Not while loading: an empty interim row model would
  // otherwise clear a selection the reload is about to show again.
  useEffect(() => {
    if (!multiSelect || loading) return;
    const kept = selectionIds.filter((id) => rowById.has(id));
    if (kept.length !== selectionIds.length) writeIds(order.filter((id) => kept.includes(id)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [order, multiSelect, loading]);

  const selectedRows = useMemo(
    () => (multiSelect ? order.filter((id) => selectedSet.has(id)).map((id) => rowById.get(id)!.original) : []),
    [multiSelect, order, selectedSet, rowById],
  );
  // Built once per render rather than per row: every selected row on screen shares one menu.
  const manyGroups = useMemo(
    () => (multiSelect && menuGroupsMany && selectedRows.length > 1 ? menuGroupsMany(selectedRows) : null),
    [multiSelect, menuGroupsMany, selectedRows],
  );
  const menuFor = menuGroups || manyGroups
    ? (row: Row<T>): MenuGroup[] =>
        manyGroups && selectedSet.has(row.id) ? manyGroups : (menuGroups?.(row.original) ?? [])
    : undefined;

  const onRowClick = (row: Row<T>, event: React.MouseEvent) => {
    if (!multiSelect) {
      onSelect?.(row.original);
      return;
    }
    dispatchSelection(clickAction(row.id, { shift: event.shiftKey, mod: event.ctrlKey || event.metaKey }));
  };

  const onRowContextMenu = (row: Row<T>) => {
    if (!multiSelect) {
      onSelect?.(row.original);
      return;
    }
    const current: SelectionState = { ids: [...selectionIds], anchor: anchorRef.current, focus: selectedId ?? null };
    if (!contextKeepsSelection(current, row.id)) dispatchSelection({ type: "only", id: row.id });
  };

  const step = (delta: number | "start" | "end", extend: boolean) => {
    if (!multiSelect) {
      move(delta);
      return;
    }
    dispatchSelection(extend ? { type: "extend", delta } : { type: "move", delta });
  };

  const onKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    // React bubbles events through the component tree, not the DOM, so a key pressed in a row's
    // context menu — rendered in a portal, but a React child of the row — arrives here too. Enter
    // on a menu item then also "activated" the selected row (History: sent it to Repeater), and
    // arrows moving through the menu moved the table's selection behind it. Pre-existing; found
    // in the u9zz live drive, where choosing "Proxy history documentation" with Enter opened a
    // Repeater tab. Only keys aimed at the table itself are the table's.
    if (!event.currentTarget.contains(event.target as Node)) return;
    const extend = event.shiftKey;
    // Ctrl/Cmd+A on the table itself only: inside a cell's own control it keeps its meaning.
    if (multiSelect && (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "a" && event.target === event.currentTarget) {
      event.preventDefault();
      dispatchSelection({ type: "all" });
      return;
    }
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault();
        step(1, extend);
        break;
      case "ArrowUp":
        event.preventDefault();
        step(-1, extend);
        break;
      case "PageDown":
        event.preventDefault();
        step(12, extend);
        break;
      case "PageUp":
        event.preventDefault();
        step(-12, extend);
        break;
      case "Home":
        event.preventDefault();
        step("start", extend);
        break;
      case "End":
        event.preventDefault();
        step("end", extend);
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
    <div className={cn("table-frame", `density-${density}`, stripes && "table-stripes")}>
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
        <table
          style={{ width: "100%", minWidth: table.getCenterTotalSize() }}
          // aria-multiselectable is only valid on a grid (or listbox/tree/tablist), not on a plain
          // table or the group around it, so a multi-select table is announced as a grid.
          role={multiSelect ? "grid" : undefined}
          aria-multiselectable={multiSelect ? true : undefined}
          aria-label={multiSelect ? ariaLabel : undefined}
        >
          <thead ref={theadRef}>
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
                  // A column declared with no header text — the row-select checkbox, a grip-only
                  // column, an actions column — still needs an accessible name, and axe is right to
                  // say so (#history, burpsy-react-ui-wj9k): an empty <th> tells a screen-reader user
                  // that this column exists and nothing about what it holds, which is exactly the
                  // column whose purpose the cells underneath it do not reveal.
                  //
                  // The column id is the name because it is the one identifier here already unique,
                  // already declared, and already what a caller passes back as the "path" argument —
                  // so the accessible name and the name in the transcript are the same string. Carried
                  // as clipped text rather than only aria-label on the cell, because text content also
                  // names the column to a table-navigation cursor, and .sr-only costs no layout.
                  const headerText = typeof rawHeader === "string" ? rawHeader.trim() : "";
                  const cellName = headerText === "" ? header.column.id : undefined;
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
                    <th
                      key={header.id}
                      style={{ width: header.getSize() }}
                      aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
                      className={cn(draggingColumn && draggingColumn !== header.column.id && "th-drop-target")}
                      // The drop target is the whole header, not just the grip: Burp's own drag
                      // and drop lands wherever the header is released, not on a fixed-size handle.
                      onDragOver={(event) => {
                        if (draggingColumn && draggingColumn !== header.column.id) event.preventDefault();
                      }}
                      onDrop={(event) => {
                        event.preventDefault();
                        if (!draggingColumn || draggingColumn === header.column.id) return;
                        setColumnOrder((current) => moveColumnBefore(current, draggingColumn, header.column.id));
                        setDraggingColumn(null);
                      }}
                      aria-label={cellName}
                    >
                      {cellName ? <span className="sr-only">{cellName}</span> : null}
                      <span
                        className="col-drag-handle"
                        aria-hidden="true"
                        title="Drag to reorder this column"
                        draggable
                        onDragStart={(event) => {
                          event.dataTransfer.effectAllowed = "move";
                          // Firefox refuses to start a drag with no data set on it at all.
                          event.dataTransfer.setData("text/plain", header.column.id);
                          setDraggingColumn(header.column.id);
                        }}
                        onDragEnd={() => setDraggingColumn(null)}
                      >
                        <GripVertical size={11} />
                      </span>
                      <ContextMenu
                        docTopic="tables"
                        groups={[
                          {
                            id: "column",
                            actions: [
                              { id: "copy-column", label: `Copy ${columnLabel} column`, icon: Copy, onSelect: copyColumn },
                              // Burp's "Hide column" (customize-tables.html). Absent on a column the page
                              // marked enableHiding:false (History's tick column); disabled, with the
                              // reason, on the last visible one, because hiding it would leave no header
                              // to bring anything back from.
                              ...(enableColumnVisibility && header.column.getCanHide()
                                ? [
                                    {
                                      id: "hide-column",
                                      label: `Hide ${columnLabel} column`,
                                      icon: EyeOff,
                                      disabled: !canHideColumn(columnIds, visibility, header.column.id),
                                      hint: canHideColumn(columnIds, visibility, header.column.id)
                                        ? "Show it again from the columns button at the right of the header"
                                        : "The last visible column cannot be hidden",
                                      onSelect: () => header.column.toggleVisibility(false),
                                    },
                                  ]
                                : []),
                            ],
                          },
                          ...(enableColumnVisibility
                            ? [
                                {
                                  id: "layout",
                                  actions: [
                                    {
                                      // Burp's "Restore default table": every column shown, in the
                                      // page's own order.
                                      id: "restore-table",
                                      label: "Restore default table layout",
                                      icon: RotateCcw,
                                      onSelect: () => {
                                        table.resetColumnVisibility();
                                        setVisibility({});
                                        setColumnOrder(columnIds);
                                      },
                                    },
                                  ],
                                },
                              ]
                            : []),
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
                  selected={multiSelect ? selectedSet.has(row.id) : row.id === selectedId}
                  focused={multiSelect && row.id === selectedId}
                  striped={virtualRow.index % 2 === 1}
                  className={rowClassName?.(row.original)}
                  clickable={Boolean(onSelect) || multiSelect}
                  onRowClick={onRowClick}
                  onRowContextMenu={onRowContextMenu}
                  shiftSelects={multiSelect}
                  onSelect={onSelect}
                  onActivate={onActivate}
                  onDoubleActivate={onDoubleActivate}
                  menuFor={menuFor}
                  docTopic={docTopic}
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
  focused,
  className,
  clickable,
  onRowClick,
  onRowContextMenu,
  shiftSelects,
  onSelect,
  onActivate,
  onDoubleActivate,
  menuFor,
  docTopic,
  striped,
}: {
  row: Row<T>;
  height: number;
  selected: boolean;
  focused: boolean;
  striped: boolean;
  className?: string;
  clickable: boolean;
  onRowClick: (row: Row<T>, event: React.MouseEvent) => void;
  onRowContextMenu: (row: Row<T>) => void;
  shiftSelects: boolean;
  onSelect?: (row: T) => void;
  onActivate?: (row: T) => void;
  onDoubleActivate?: (row: T) => void;
  menuFor?: (row: Row<T>) => MenuGroup[];
  docTopic: DocTopic;
}): JSX.Element {
  const element = (
    <tr
      style={{ height }}
      aria-selected={selected}
      className={cn("data-row", striped && "row-stripe", selected && "selected-row", focused && "focus-row", clickable && "clickable", className)}
      // Shift-click is a range select here, not a text selection: without this the browser also
      // paints a text selection across every row between the two clicks.
      onMouseDown={(event) => {
        if (shiftSelects && event.shiftKey) event.preventDefault();
      }}
      onClick={(event) => onRowClick(row, event)}
      // Double-click prefers the dedicated handler, then onActivate, then plain selection — so a
      // table that was not given one behaves exactly as it always did, and one that was gets the
      // gesture it asked for without losing the other two.
      onDoubleClick={() => (onDoubleActivate ?? onActivate ?? onSelect)?.(row.original)}
      // Right-clicking a row should act on that row, matching desktop tools — or, inside a
      // multi-row selection, on the whole selection (onRowContextMenu decides which).
      onContextMenu={() => onRowContextMenu(row)}
    >
      {row.getVisibleCells().map((cell) => (
        <td key={cell.id} style={{ width: cell.column.getSize() }}>
          {flexRender(cell.column.columnDef.cell, cell.getContext())}
        </td>
      ))}
    </tr>
  );
  if (!menuFor) return element;
  return (
    <ContextMenu groups={menuFor(row)} docTopic={docTopic}>
      {element}
    </ContextMenu>
  );
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
  docTopic = "tables",
  children,
  ...rowProps
}: { groups: MenuGroup[]; docTopic?: DocTopic; children: ReactNode } & React.HTMLAttributes<HTMLTableRowElement>): JSX.Element {
  return (
    <ContextMenu groups={groups} docTopic={docTopic}>
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
 *
 * `menuGroups` is the same right-click contract VirtualTable carries, and it is
 * here for the same reason it is there: a row an operator can read but cannot
 * act on is a dead end. Intruder's results were exactly that until
 * burpsy-react-ui-79u. Omit it and the rows render as plain `<tr>`s, which is
 * what every other caller still gets.
 */
export function SortableTable<T>({
  data,
  columns,
  getRowId,
  ariaLabel,
  initialSort = [],
  rowClassName,
  menuGroups,
  density: densityProp,
  docTopic = "tables",
}: {
  data: T[];
  columns: Column<T>[];
  getRowId: (row: T) => string;
  ariaLabel: string;
  initialSort?: SortingState;
  rowClassName?: (row: T) => string | undefined;
  menuGroups?: (row: T) => MenuGroup[];
  density?: "comfortable" | "compact";
  /** See VirtualTable's `docTopic`. */
  docTopic?: DocTopic;
}): JSX.Element {
  const storeDensity = useApp((state) => state.density);
  const density = densityProp ?? storeDensity;
  const stripes = useApp((state) => state.tableStripes);
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
    <div className={cn("table-frame", `density-${density}`, stripes && "table-stripes")} role="group" aria-label={ariaLabel}>
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
            {table.getRowModel().rows.map((row, index) => (
              <SortableRow
                key={row.id}
                row={row}
                className={cn(index % 2 === 1 && "row-stripe", rowClassName?.(row.original))}
                menuGroups={menuGroups}
                docTopic={docTopic}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * One `SortableTable` row, optionally wrapped in its right-click menu.
 *
 * This is a component and not an inline `.map()` body for the reason `MenuRow` above spells out:
 * wrapping the `<tr>` inside the callback moves the key onto a child of the mapped element and
 * leaves the list keyless. `SortableRow` *is* the mapped element, so the key lands on it either
 * way, and the `<tr>` stays the direct child of `<tbody>`.
 */
function SortableRow<T>({
  row,
  className,
  menuGroups,
  docTopic,
}: {
  row: Row<T>;
  className?: string;
  menuGroups?: (row: T) => MenuGroup[];
  docTopic: DocTopic;
}): JSX.Element {
  const element = (
    <tr className={className}>
      {row.getVisibleCells().map((cell) => (
        <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
      ))}
    </tr>
  );
  if (!menuGroups) return element;
  return (
    <ContextMenu groups={menuGroups(row.original)} docTopic={docTopic}>
      {element}
    </ContextMenu>
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
  const stripes = useApp((state) => state.tableStripes);
  return (
    // SimpleTable renders every row with no padding rows, so :nth-child parity is stable here and
    // the page's own <tr>s need no class (styles.css, .simple-stripes).
    <div className={cn("table-frame", "density-" + density, stripes && "table-stripes simple-stripes", className)}>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              {headers.map((header, index) => {
                // A header declared "" is this tree's convention for the per-row action column, and
                // ~15 call sites do it (#proxysettings, #auditqueue, #extenderapis and others all
                // carried an unnamed <th> before this, burpsy-react-ui-wj9k). The cell is still a
                // column, and an unnamed column tells a screen-reader user that something is there
                // and nothing about what it is.
                //
                // Named by POSITION, because SimpleTable takes a bare string[] with no id to borrow
                // and "Actions" would be a claim this component cannot make: one caller's trailing
                // column is a note field, another's is a menu, and the component sees only a string.
                //
                // Keyed by index in the empty case, which also fixes a live React bug — settings.tsx
                // passes ["Name","Source","Keys set","",""] and two headers of "" were both keyed "",
                // so the browser logged "Encountered two children with the same key".
                const empty = header.trim() === "";
                const name = `Column ${index + 1}`;
                return (
                  <th key={empty ? `empty-${index}` : header} scope="col" aria-label={empty ? name : undefined}>
                    {empty ? <span className="sr-only">{name}</span> : header}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>{children}</tbody>
        </table>
      </div>
    </div>
  );
}
