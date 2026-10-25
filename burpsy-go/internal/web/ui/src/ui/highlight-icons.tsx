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

/**
 * The colours a Repeater tab can carry (burpsy-react-ui-fkj).
 *
 * The same palette the row highlights use, deliberately: a tab colour and a row highlight are the
 * operator marking the same kind of thing — "this one, for now" — and two vocabularies would let
 * "red" on a tab and "red" on a row be different colours. The value is the CSS custom property's
 * name, resolved by the tab's own border, so changing the theme changes both together.
 */
export const TAB_COLOURS: { value: string; label: string; icon: ComponentType<{ size?: number }> }[] = [
 { value: "", label: "No colour", icon: HIGHLIGHT_ICONS.none as ComponentType<{ size?: number }> },
 ...HIGHLIGHTS.filter((name) => name !== "none").map((name) => ({
  value: name,
  label: name.charAt(0).toUpperCase() + name.slice(1),
  icon: HIGHLIGHT_ICONS[name] as ComponentType<{ size?: number }>,
 })),
];
