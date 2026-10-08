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
 *
 * `role="group"`, not `role="menu"`: the rows are ordinary checkboxes in normal tab order with
 * Escape/outside-click to dismiss. A menu role promises `menuitem` children and arrow-key
 * navigation, and axe fails an open panel with `aria-required-children` (critical) when it does
 * not get them — which it never did, because this panel is a disclosure, not a menu. The trigger
 * therefore carries `aria-expanded` with no `aria-haspopup`, which is the disclosure pattern.
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
  <div ref={ref} className="column-menu-panel" role="group" aria-label="Show or hide columns">
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
 *
 * It is an INLINE toolbar control, and deliberately not built on `.column-menu-anchor` /
 * `.column-menu-trigger` — those are the table header's overlay (absolute at the header's
 * top-right, icon-sized). Reusing them here put a labelled chip in a row that has no
 * positioned ancestor, so `right: 0` resolved against the viewport and pinned it to the
 * window's top-right corner: on #sitemap and #history the two chips landed on the same 24×24
 * square over the menubar, one of them unreachable by mouse, and the label's 22px of overflow
 * past the icon-sized box dragged the whole document sideways. `.bucket-menu` is the chip's
 * own positioning context, sized to its content like the FilterToggle beside it.
 *
 * The popover is a `group` for the same reason the column menu's is — see that component's note.
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
  <div className="bucket-menu">
   {/* `data-active` is shown, not just announced: an active bucket filter is otherwise only a
       muted " (2)" in the row, which is the one thing about this control a glance has to
       recover. */}
   <button
    ref={triggerRef}
    type="button"
    className="bucket-menu-trigger"
    aria-expanded={open}
    aria-label={`${label} filter${selected.length ? `, ${selected.length} selected` : ""}`}
    data-active={selected.length > 0 ? "true" : undefined}
    onClick={() => setOpen((current) => !current)}
   >
    {label}
    {selected.length > 0 ? ` (${selected.length})` : ""}
   </button>
   {open ? (
    <div ref={panelRef} className="column-menu-panel" role="group" aria-label={`${label} buckets`}>
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
