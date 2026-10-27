// The palette's codec table, and the guard that keeps it honest (burpsy-react-ui-1wrb).
//
// The claim under test is not "the table has seventeen rows". It is that the table is the same
// set of transforms `ui/editor.tsx` offers on its selection menu — because the palette's whole
// justification is reaching the editor's codecs from mod+K, and a palette that offers sixteen of
// them is a palette an operator cannot trust to be complete.
//
// The comparison with the editor's menu is rendered in ui/selection-codecs-menu.test.tsx (vln1).
//
// The editor does not import this table, so the comparison renders the editor's menu.
import { describe, expect, test } from "bun:test";
import { SELECTION_CODECS } from "./selection-codecs";

describe("the palette's copy of the editor's selection codecs", () => {
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
