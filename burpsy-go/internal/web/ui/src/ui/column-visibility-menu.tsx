import { forwardRef, useEffect, useRef, useState } from "react";
import { Checkbox } from "./primitives";

/** One row in the menu: a hideable column and whether it is currently shown. */
export interface HideableColumn {
 id: string;
 label: string;
 visible: boolean;
}

/**
 * The column show/hide popover — design/jsx/menu-column-visibility.jsx.
 *
 * Purely presentational: `VirtualTable` owns the TanStack column-visibility state
 * and open/close/focus behaviour, and hands this component plain data plus two
 * callbacks. `Checkbox` (primitives.tsx) renders the visible label per row, so a
 * screen reader announces "Method, checkbox, checked" rather than an unlabelled box.
 */
export const ColumnVisibilityMenu = forwardRef<
 HTMLDivElement,
 {
  columns: HideableColumn[];
  onToggle: (id: string, visible: boolean) => void;
  onReset: () => void;
 }
>(function ColumnVisibilityMenu({ columns, onToggle, onReset }, ref) {
 return (
  <div ref={ref} className="column-menu-panel" role="menu" aria-label="Show or hide columns">
   {columns.map((column) => (
    <Checkbox
     key={column.id}
     checked={column.visible}
     onCheckedChange={(checked) => onToggle(column.id, checked)}
     label={column.label}
     className="column-menu-row"
    />
   ))}
   <div className="column-menu-divider" role="separator" />
   <button type="button" className="column-menu-reset" onClick={onReset}>
    Reset columns
   </button>
  </div>
 );
});

/**
 * One multi-bucket filter control (burpsy-react-ui-9my): a button naming its count plus a
 * checkbox popover in the same anchored-panel shape as the column-visibility menu, so
 * checkboxes stay in normal tab order with Escape/outside-click to dismiss.
 */
export function BucketMenu({
 label,
 buckets,
 selected,
 onToggle,
 onReset,
}: {
 label: string;
 buckets: { value: string; label: string }[];
 selected: string[];
 onToggle: (value: string) => void;
 onReset: () => void;
}): JSX.Element {
 const [open, setOpen] = useState(false);
 const triggerRef = useRef<HTMLButtonElement>(null);
 const panelRef = useRef<HTMLDivElement>(null);
 useEffect(() => {
  if (!open) return;
  const onKeyDown = (event: KeyboardEvent) => {
   if (event.key === "Escape") {
    event.preventDefault();
    setOpen(false);
    triggerRef.current?.focus();
   }
  };
  const onPointerDown = (event: PointerEvent) => {
   if (panelRef.current?.contains(event.target as Node) || triggerRef.current?.contains(event.target as Node)) return;
   setOpen(false);
  };
  document.addEventListener("keydown", onKeyDown);
  document.addEventListener("pointerdown", onPointerDown);
  return () => {
   document.removeEventListener("keydown", onKeyDown);
   document.removeEventListener("pointerdown", onPointerDown);
  };
 }, [open]);
 return (
  <div className="column-menu-anchor">
   <button
    ref={triggerRef}
    type="button"
    className="column-menu-trigger"
    aria-haspopup="menu"
    aria-expanded={open}
    aria-label={`${label} filter${selected.length ? `, ${selected.length} selected` : ""}`}
    onClick={() => setOpen((current) => !current)}
   >
    {label}
    {selected.length > 0 ? ` (${selected.length})` : ""}
   </button>
   {open ? (
    <div ref={panelRef} className="column-menu-panel" role="menu" aria-label={`${label} buckets`}>
     {buckets.map((bucket) => (
      <Checkbox
       key={bucket.value}
       checked={selected.includes(bucket.value)}
       onCheckedChange={() => onToggle(bucket.value)}
       label={bucket.label}
       className="column-menu-row"
      />
     ))}
     <div className="column-menu-divider" role="separator" />
     <button type="button" className="column-menu-reset" onClick={() => { onReset(); setOpen(false); }}>
      Reset {label.toLowerCase()}
     </button>
    </div>
   ) : null}
  </div>
 );
}

