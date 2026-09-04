import type { ComponentType, CSSProperties } from "react";
import { HIGHLIGHTS } from "../lib/types";

/**
 * The row-highlight colours as MenuAction icons.
 *
 * `MenuAction.icon` is a component, not a colour, so the Highlight submenu needs one small
 * component per colour rather than a style computed at render time. They are built once here
 * instead of inside the menu factory: the factory runs on every right-click, and a fresh
 * component identity per open would remount the chip each time for no benefit.
 *
 * The colour itself comes from the same `--highlight-*` custom properties the detail pane's
 * HighlightPicker uses, so the swatch in the menu and the swatch in the pane cannot drift.
 */
export const HIGHLIGHT_ICONS: Record<string, ComponentType<{ size?: number }>> = Object.fromEntries(
  HIGHLIGHTS.map((name) => {
    const isNone = name === "none";
    const Swatch = (): JSX.Element => (
      <span
        className={isNone ? "menu-swatch menu-swatch-none" : "menu-swatch"}
        style={isNone ? undefined : ({ "--swatch-color": `var(--highlight-${name})` } as CSSProperties)}
      />
    );
    Swatch.displayName = `HighlightIcon(${name})`;
    return [name, Swatch];
  }),
);
