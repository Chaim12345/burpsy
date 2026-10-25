/**
 * burpsy-react-ui-vln1 (replaces the app.tsx and store.ts source pins in lib/editor-font.test.ts):
 * the editor font family travels store -> <html> custom property, and survives a reload. The hook
 * the app mounts is rendered here through a tiny host component.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { act, cleanup, render } from "@testing-library/react";
import { useThemeEffect } from "../lib/use-theme-effect";
import { editorFontStack, useApp } from "../lib/store";

function Host(): null {
 useThemeEffect();
 return null;
}

const root = () => document.documentElement.style;

beforeEach(() => {
 window.localStorage.clear();
 root().removeProperty("--editor-font-family");
 useApp.setState({ editorFontFamily: "default" });
});
afterEach(cleanup);

describe("the editor font family reaches the document", () => {
 test("a chosen face sets --editor-font-family to its stack", () => {
  render(<Host />);
  act(() => useApp.getState().setEditorFontFamily("menlo"));
  expect(root().getPropertyValue("--editor-font-family")).toBe(editorFontStack("menlo"));
  expect(root().getPropertyValue("--editor-font-family")).not.toBe("");
 });

 test("going back to the default removes the property, so the stylesheet's --font-mono applies", () => {
  render(<Host />);
  act(() => useApp.getState().setEditorFontFamily("menlo"));
  act(() => useApp.getState().setEditorFontFamily("default"));
  expect(root().getPropertyValue("--editor-font-family")).toBe("");
 });

 test("the choice is persisted, so a chosen face survives a reload", () => {
  act(() => useApp.getState().setEditorFontFamily("consolas"));
  const saved = JSON.parse(window.localStorage.getItem("burpsy.workspace") ?? "{}") as { state?: { editorFontFamily?: string } };
  expect(saved.state?.editorFontFamily).toBe("consolas");
 });
});

describe("an imported theme (fpew)", () => {
 const kept = { name: "kept", tokens: { paper: "#101010" } };
 const preview = { name: "preview", tokens: { paper: "#fafafa" } };

 test("a kept theme sets its slots on <html>, and clearing it removes them", () => {
  render(<Host />);
  act(() => useApp.getState().setCustomTheme(kept));
  expect(root().getPropertyValue("--paper")).toBe("#101010");
  act(() => useApp.getState().setCustomTheme(null));
  expect(root().getPropertyValue("--paper")).toBe("");
 });

 test("a live preview overlays the kept theme, and dropping it returns to the kept one", () => {
  render(<Host />);
  act(() => useApp.getState().setCustomTheme(kept));
  act(() => useApp.getState().setThemePreview(preview));
  expect(root().getPropertyValue("--paper")).toBe("#fafafa");
  act(() => useApp.getState().setThemePreview(null));
  expect(root().getPropertyValue("--paper")).toBe("#101010");
 });

 test("the kept theme survives a reload but a preview does not, so an unreadable preview is escaped by reloading", () => {
  act(() => {
   useApp.getState().setCustomTheme(kept);
   useApp.getState().setThemePreview(preview);
  });
  const saved = JSON.parse(window.localStorage.getItem("burpsy.workspace") ?? "{}") as { state?: Record<string, unknown> };
  expect(saved.state?.customTheme).toEqual(kept);
  expect("themePreview" in (saved.state ?? {})).toBe(false);
 });
});
