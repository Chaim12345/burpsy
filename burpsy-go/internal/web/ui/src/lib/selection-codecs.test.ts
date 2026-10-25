// The palette's codec table, and the guard that keeps it honest (burpsy-react-ui-1wrb).
//
// The claim under test is not "the table has seventeen rows". It is that the table is the same
// set of transforms `ui/editor.tsx` offers on its selection menu — because the palette's whole
// justification is reaching the editor's codecs from mod+K, and a palette that offers sixteen of
// them is a palette an operator cannot trust to be complete.
//
// The editor does not import this table (that edit belongs to the file's owner), so the test
// reads the editor's source and compares. A source read is a blunt instrument; it is also the
// only instrument that fails when someone adds a codec to the menu and not to the palette.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { SELECTION_CODECS } from "./selection-codecs";

const editorSource = readFileSync(new URL("../ui/editor.tsx", import.meta.url), "utf8");

/** The `codec("id", "label", …)` rows the editor's Convert-selection group is built from. */
function editorCodecRows(): { id: string; label: string }[] {
 const rows: { id: string; label: string }[] = [];
 const pattern = /codec\(\s*"([^"]+)"\s*,\s*"((?:[^"\\]|\\.)*)"/g;
 for (const found of editorSource.matchAll(pattern)) {
  rows.push({ id: found[1] ?? "", label: (found[2] ?? "").replace(/\\u00a7/g, "§") });
 }
 return rows;
}

/** The Construct-string dialects, which the editor maps into `construct-<dialect>` ids. */
function editorConstructRows(): { id: string; label: string }[] {
 const block = editorSource.match(/CONSTRUCT_DIALECTS: Record<ConstructDialect, string> = \{([^}]*)\}/);
 const rows: { id: string; label: string }[] = [];
 for (const found of (block?.[1] ?? "").matchAll(/(\w+):\s*"([^"]*)"/g)) {
  rows.push({ id: `construct-${found[1]}`, label: found[2] ?? "" });
 }
 return rows;
}

describe("the palette's copy of the editor's selection codecs", () => {
 test("the editor's source really does declare codec rows, so an empty parse can never pass this file", () => {
  expect(
   editorCodecRows().length,
   "the parse found no codec(...) rows in ui/editor.tsx: either the menu was rewritten in a shape this guard no longer recognises, or the file moved — until the parse is fixed every comparison below is vacuously true",
  ).toBeGreaterThan(5);
  expect(
   editorConstructRows().length,
   "the parse found no CONSTRUCT_DIALECTS entries in ui/editor.tsx, so the construct-string half of the comparison is checking nothing",
  ).toBeGreaterThan(0);
 });

 test("every transform on the editor's selection menu has a palette entry", () => {
  const expected = [...editorCodecRows(), ...editorConstructRows()].map((row) => row.id).sort();
  const offered = SELECTION_CODECS.map((codec) => codec.id).sort();
  expect(
   offered,
   "the palette's codec table and the editor's menu list different transforms: whichever one is missing is a codec an operator can reach one way and not the other, which is exactly the gap this table exists to close",
  ).toEqual(expected);
 });

 test("a palette entry is spelled the way the editor spells it, so the two read as one command", () => {
  const editorLabels = new Map([...editorCodecRows(), ...editorConstructRows()].map((row) => [row.id, row.label]));
  const mismatched = SELECTION_CODECS.filter((codec) => editorLabels.get(codec.id) !== codec.label).map(
   (codec) => `${codec.id}: palette "${codec.label}" vs editor "${editorLabels.get(codec.id) ?? "(absent)"}"`,
  );
  expect(
   mismatched,
   "a row whose wording differs between the palette and the context menu reads as two different commands, and an operator who learned one will not find the other by name",
  ).toEqual([]);
 });

 test("no id appears twice, because a duplicate would render as two palette rows doing one thing", () => {
  const ids = SELECTION_CODECS.map((codec) => codec.id);
  expect(
   ids.filter((id, index) => ids.indexOf(id) !== index),
   "a duplicated codec id means two identical palette rows and one React key collision, and the recency ledger would count them as one command while the list shows two",
  ).toEqual([]);
 });

 test("each entry carries a transform that actually transforms, not a placeholder", () => {
  const byId = new Map(SELECTION_CODECS.map((codec) => [codec.id, codec]));
  expect(byId.get("url-encode")?.transform("a b&c"), "URL-encode must escape the key characters Burp escapes").toBe("a%20b%26c");
  expect(byId.get("url-decode")?.transform("a%20b"), "URL-decode must undo what URL-encode wrote").toBe("a b");
  expect(byId.get("b64-encode")?.transform("hi"), "Base64-encode must produce base64, not echo its input").toBe("aGk=");
  expect(byId.get("html-encode")?.transform("<a>"), "HTML-encode must escape the markup characters").toBe("&lt;a&gt;");
  expect(
   byId.get("construct-js_double")?.transform("hi"),
   "a construct-string entry must build a quoted literal in its own dialect, which is the only thing that tells the five dialects apart",
  ).toBe('"hi"');
 });

 test("every entry declares a group the palette can print as a heading", () => {
  const ungrouped = SELECTION_CODECS.filter((codec) => !codec.group.trim() || !codec.label.trim());
  expect(
   ungrouped.map((codec) => codec.id),
   "an entry with no group or no label renders as a blank palette row under a blank heading",
  ).toEqual([]);
 });
});
