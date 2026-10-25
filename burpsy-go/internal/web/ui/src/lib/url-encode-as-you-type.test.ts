// URL-encode as you type (burpsy-react-ui-js1) — what the editor wire is, and what the
// persisted toggle changes.
//
// The DOM half (typing & and seeing %26 land under the cursor) needs a mounted console and is
// driven live; what is worth pinning without one is the wire — the filter exists, is gated on
// the persisted preference, and the toggle the operator presses both exists and persists. The
// key-character set itself is the transforms module's own (already tested there) — the point
// here is that the editor reuses it rather than inventing a second set.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { urlEncodeKeyChars } from "./transforms";

const editor = readFileSync(join(import.meta.dir, "..", "ui", "editor.tsx"), "utf8");
const store = readFileSync(join(import.meta.dir, "store.ts"), "utf8");

describe("the URL-encode-as-you-type editor wire", () => {
 // The mode lives in lib/url-encode-as-you-type.ts (factored so its whole logic is
 // testable against a real EditorState); the editor installs it while the toggle is on.
 const module_ = readFileSync(join(import.meta.dir, "url-encode-as-you-type.ts"), "utf8");

 test("a transaction filter rewrites the typed insert before the document changes", () => {
  expect(module_, "the mode must be a filter, not an onChange rewrite — onChange would fight the cursor after every keystroke").toMatch(
   /transactionFilter\.of/,
  );
 });

 test("only keystrokes are encoded: input.type, never paste or programmatic changes", () => {
  expect(module_).toMatch(/Transaction\.userEvent\) !== "input\.type"/);
 });

 test("the encoding goes through urlEncodeKeyChars — Burp's key-character set, not a second one", () => {
  expect(module_).toMatch(/urlEncodeKeyChars\(inserted\.toString\(\)\)/);
 });

 test("the editor installs the filter only while the toggle is on", () => {
  expect(editor).toMatch(/if \(urlEncodeAsYouType\)/);
  expect(editor).toMatch(/urlEncodeAsYouTypeExtension\(\)/);
 });

 test("the preference is persisted — a typing preference survives a reload like the font does", () => {
  expect(store).toMatch(/urlEncodeAsYouType: state\.urlEncodeAsYouType/);
 });

 test("the toggle is a pressed-state control on the text views", () => {
  expect(editor).toMatch(/aria-pressed=\{urlEncodeAsYouType\}/);
  expect(editor).toMatch(/"URL-encode as you type"/);
 });
});

describe("the key-character set the mode reuses", () => {
 test("encodes the characters that change a request's structure, and leaves prose readable", () => {
  expect(urlEncodeKeyChars("a=b&c")).toBe("a%3Db%26c");
  expect(urlEncodeKeyChars("hello world")).toBe("hello%20world");
  expect(urlEncodeKeyChars("/api/v2/users")).toBe("%2Fapi%2Fv2%2Fusers");
 });

 test("the percent itself is a key character — typing %41 encodes the % so the literal survives", () => {
  expect(urlEncodeKeyChars("%41")).toBe("%2541");
 });
});
