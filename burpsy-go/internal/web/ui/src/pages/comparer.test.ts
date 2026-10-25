import { describe, expect, test } from "bun:test";
import { buildHexRows, MAX_HEX_BYTES } from "./comparer";
import type { CompareOp } from "../lib/types.workbench";

/**
 * burpsy-react-ui-ufn: the Comparer had no hex view, so a whitespace-only or non-printable-byte
 * difference — the class of difference a byte-level diff is best placed to find — rendered as
 * nothing or as the GAP_CHAR padding glyph, itself indistinguishable from a real middot in the
 * data. buildHexRows is the pure function behind the new Hex toggle: built straight from the
 * diff ops and each side's own encoded bytes, not from the text pane's padded strings, so these
 * tests assert on real byte values rather than on rendered markup.
 */
function equalOp(offset: number, len: number): CompareOp {
 return { kind: "equal", a_offset: offset, a_len: len, b_offset: offset, b_len: len };
}

describe("buildHexRows", () => {
 test("an all-equal comparison renders one plain group per row, wrapping every 16 bytes", () => {
  const text = "ABCDEFGHIJKLMNOPQ"; // 17 bytes: a full row plus one more
  const bytes = new TextEncoder().encode(text);
  const { rows, shown, total } = buildHexRows([equalOp(0, bytes.length)], bytes, "a");

  expect(shown).toBe(17);
  expect(total).toBe(17);
  expect(rows).toHaveLength(2);
  expect(rows[0]!.groups).toHaveLength(1);
  expect(rows[0]!.groups[0]!.kind).toBe("equal");
  expect(rows[0]!.groups[0]!.hunk).toBeNull();
  expect(rows[0]!.groups[0]!.hex).toBe("41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50");
  expect(rows[0]!.groups[0]!.ascii).toBe("ABCDEFGHIJKLMNOP");
  expect(rows[0]!.padCells).toBe(0);
  expect(rows[1]!.groups[0]!.hex).toBe("51");
  expect(rows[1]!.padCells).toBe(15);
 });

 test("a whitespace-only difference is a different byte in hex, on both sides, in the same hunk", () => {
  // "a\tb" vs "a b": byte 1 is a tab on one side and a space on the other — a text render that
  // shows both as blank space would hide exactly the difference this view exists to surface.
  const aBytes = new TextEncoder().encode("a\tb");
  const bBytes = new TextEncoder().encode("a b");
  const ops: CompareOp[] = [equalOp(0, 1), { kind: "replace", a_offset: 1, a_len: 1, b_offset: 1, b_len: 1 }, equalOp(2, 1)];

  const a = buildHexRows(ops, aBytes, "a");
  const b = buildHexRows(ops, bBytes, "b");
  const aReplaced = a.rows[0]!.groups.find((g) => g.kind === "replace");
  const bReplaced = b.rows[0]!.groups.find((g) => g.kind === "replace");

  expect(aReplaced?.hex).toBe("09");
  expect(bReplaced?.hex).toBe("20");
  expect(aReplaced?.hunk).toBe(0);
  expect(aReplaced?.hunk).toBe(bReplaced?.hunk);
 });

 test("an insert contributes zero bytes to side A and its real bytes to side B", () => {
  const aBytes = new TextEncoder().encode("ac");
  const bBytes = new TextEncoder().encode("abc");
  const ops: CompareOp[] = [
   equalOp(0, 1),
   { kind: "insert", a_offset: 1, a_len: 0, b_offset: 1, b_len: 1 },
   { kind: "equal", a_offset: 1, a_len: 1, b_offset: 2, b_len: 1 },
  ];

  const a = buildHexRows(ops, aBytes, "a");
  const b = buildHexRows(ops, bBytes, "b");

  expect(a.shown).toBe(2);
  expect(b.shown).toBe(3);
  expect(a.rows[0]!.groups.some((g) => g.kind === "insert")).toBe(false);
  expect(b.rows[0]!.groups.find((g) => g.kind === "insert")?.hex).toBe("62");
 });

 test("caps what it dumps at MAX_HEX_BYTES but still reports the true total, like Decoder's hexDump", () => {
  const text = "x".repeat(MAX_HEX_BYTES + 100);
  const bytes = new TextEncoder().encode(text);
  const { shown, total } = buildHexRows([equalOp(0, bytes.length)], bytes, "a");

  expect(total).toBe(MAX_HEX_BYTES + 100);
  expect(shown).toBe(MAX_HEX_BYTES);
 });
});
