import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { editorFontStack } from "./store";

// burpsy-react-ui-mqrn: the message editor's font family, Burp's http_message_display.font_name.
// editorFontStack turns a stored preference into the CSS --editor-font-family; the model rules are
// worth pinning without a mounted console because they decide whether the editor can render the
// bytes in the operator's chosen face at all.
describe("editorFontStack", () => {
 const named = ["ibm-plex-mono", "cascadia-code", "jetbrains-mono", "sf-mono", "consolas", "menlo", "courier-new"];

 test("every named family ends in a generic monospace fallback", () => {
  // A machine without the chosen face must still read the HTTP bytes in a monospace font rather
  // than the body sans — so every stack keeps `monospace` as its last resort.
  for (const family of named) {
   expect(editorFontStack(family), `${family} must fall back to monospace`).toMatch(/\bmonospace$/);
  }
 });

 test('"default" is the empty string, so the editor keeps the stylesheet\'s --font-mono', () => {
  // Empty means "leave --editor-font-family unset": app.tsx removes the property, and the editor's
  // var(--editor-font-family, var(--font-mono)) fallback supplies the canonical stack.
  expect(editorFontStack("default")).toBe("");
 });

 test("a corrupted preference is the default, not an empty family", () => {
  expect(editorFontStack("")).toBe("");
  expect(editorFontStack("Comic Sans")).toBe("");
 });
});

describe("the editor font family is wired end to end", () => {
 // Structural, the ui-scale.test.ts style: the preference travels store → app.tsx custom property →
 // editor theme, and no unit test of editorFontStack can see that wire.
 const app = readFileSync(join(import.meta.dir, "..", "app.tsx"), "utf8");
 const editor = readFileSync(join(import.meta.dir, "..", "ui", "editor.tsx"), "utf8");
 const store = readFileSync(join(import.meta.dir, "store.ts"), "utf8");

 test("app.tsx sets --editor-font-family from the stack, and removes it for the default", () => {
  expect(app).toMatch(/setProperty\("--editor-font-family"/);
  expect(app).toMatch(/removeProperty\("--editor-font-family"\)/);
 });

 test("the editor theme reads --editor-font-family with the --font-mono fallback", () => {
  expect(editor).toMatch(/var\(--editor-font-family, var\(--font-mono\)\)/);
 });

 test("the store persists the preference, so a chosen face survives a reload", () => {
  expect(store).toMatch(/editorFontFamily: state\.editorFontFamily/);
 });
});
