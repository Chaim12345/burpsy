import { forwardRef } from "react";
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
