import type { CSSProperties } from "react";
import { cn } from "../lib/cn";
import { Spinner } from "./primitives";

/**
 * The "loading" leg of DESIGN.md's three data states: a view that is still
 * fetching keeps its column headers (a loading table is still a table) and
 * fills the body with these two components. Neither is wired into a page here
 * — that is a later task's job — so treat this file as the palette, not the
 * plumbing.
 */

/** Bar widths measured from `design/jsx/skeleton-row.jsx`, in px, left to right. */
const SKELETON_BAR_WIDTHS = [28, 44, 110, 78, 36, 52];

/**
 * Six bars per row at the widths above, fading down the list across four
 * steps (`--skeleton-1` brightest → `--skeleton-4` dimmest) before repeating.
 * The fade is the pattern, not decoration: it is what reads as a list of rows
 * rather than a single grey block. See `skeleton-row.jsx`.
 */
export function SkeletonRows({ count = 6, label = "Loading" }: { count?: number; label?: string }): JSX.Element {
 return (
  <div className="skeleton-rows" role="status" aria-busy="true" aria-label={label}>
   {Array.from({ length: count }, (_, rowIndex) => (
    <div key={rowIndex} className="skeleton-row" style={{ "--row-skeleton": `var(--skeleton-${(rowIndex % 4) + 1})` } as CSSProperties}>
     {SKELETON_BAR_WIDTHS.map((width, barIndex) => (
      <span key={barIndex} className="skeleton-bar" style={{ width }} />
     ))}
    </div>
   ))}
  </div>
 );
}

/**
 * The centred "still working" state from `design/jsx/state-loading.jsx`: an
 * accent ring, a bold title, a detail line. The ring reuses `Spinner` rather
 * than redrawing it — same stroke, same animation, same `role="status"` — so
 * there is one spinner implementation in the app, not two that can drift.
 */
export function LoadingState({ title, detail }: { title: string; detail?: string }): JSX.Element {
 return (
  <div className={cn("loading-state")} aria-busy="true">
   <Spinner label={detail ?? title} />
   <strong>{title}</strong>
   {detail ? <p>{detail}</p> : null}
  </div>
 );
}
