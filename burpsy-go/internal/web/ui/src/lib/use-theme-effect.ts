import { useEffect } from "react";
import { THEME_SLOTS, themeTokenVars } from "./theme-import";
import { editorFontStack, resolveTheme, uiScaleFactor, useApp } from "./store";

/** The preferences that live on <html>: theme attribute, text scales, editor font, imported theme. */
export function useThemeEffect(): void {
 const theme = useApp((state) => state.theme);
 const uiScale = useApp((state) => state.uiScale);
 const editorFont = useApp((state) => state.editorFont);
 const editorFontFamily = useApp((state) => state.editorFontFamily);
 const customTheme = useApp((state) => state.customTheme);
 const themePreview = useApp((state) => state.themePreview);
 useEffect(() => {
  const apply = () => document.documentElement.setAttribute("data-theme", resolveTheme(theme));
  apply();
  if (theme !== "system") return;
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  media.addEventListener("change", apply);
  return () => media.removeEventListener("change", apply);
 }, [theme]);
 // The two text scales (burpsy-react-ui-7bd) ride the same attribute pattern as the
 // theme: one place on <html>, everything downstream reads the custom property.
 useEffect(() => {
  document.documentElement.style.setProperty("--ui-scale", uiScaleFactor(uiScale));
 }, [uiScale]);
 useEffect(() => {
  document.documentElement.style.setProperty("--editor-font-size", editorFont);
 }, [editorFont]);
 // The editor font family (burpsy-react-ui-mqrn): a non-default choice sets --editor-font-family,
 // which the editor's CodeMirror theme reads; "default" removes the property so the editor falls
 // back to the stylesheet's --font-mono. Family and size are separate custom properties so one can
 // change without disturbing the other.
 useEffect(() => {
  const stack = editorFontStack(editorFontFamily);
  if (stack) document.documentElement.style.setProperty("--editor-font-family", stack);
  else document.documentElement.style.removeProperty("--editor-font-family");
 }, [editorFontFamily]);
 // The imported theme (burpsy-react-ui-fpew): set an inline override on <html> for every slot the
 // theme names (an inline property beats semantic.css's :root rule), and remove every other slot the
 // theme could have named so a reverted or narrowed theme falls back to the Penpot default instead of
 // keeping a stale override. Walking THEME_SLOTS rather than a remembered key set means the cleanup is
 // correct even across a reload where the previous overrides were never in this document's inline style.
 useEffect(() => {
  const style = document.documentElement.style;
  // A live preview overlays the kept theme (themePreview ?? customTheme): previewing shows the file
  // before it is kept, and a preview that read badly is escaped by a reload because themePreview is
  // not persisted. themeTokenVars tolerates a corrupted persisted theme (an object without tokens)
  // rather than letting Object.entries throw and take the whole app down on load.
  const active = themePreview ?? customTheme;
  const vars = active ? themeTokenVars(active) : {};
  for (const slot of THEME_SLOTS) {
   const prop = `--${slot}`;
   const value = vars[prop];
   if (value !== undefined) style.setProperty(prop, value);
   else style.removeProperty(prop);
  }
 }, [customTheme, themePreview]);
}
