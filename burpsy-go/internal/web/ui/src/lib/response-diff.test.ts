import { describe, expect, test } from "bun:test";
import { byteOffsetsToUtf16, changeMarksFor, valuePosToDocPos, type CompareOp } from "./response-diff";

const utf8 = (text: string) => new TextEncoder().encode(text);

describe("byte offsets to UTF-16 (burpsy-react-ui-b4gt)", () => {
 test("ASCII maps one to one", () => {
  expect(byteOffsetsToUtf16("hello", [0, 2, 5, 9])).toEqual([0, 2, 5, 5]);
 });

 test("é is two bytes and one unit, so every later offset shifts by one", () => {
  const text = "café latte";
  const latte = utf8(text).indexOf(utf8("latte")[0]!, 4);
  expect(latte).toBe(6);
  expect(byteOffsetsToUtf16(text, [latte])).toEqual([text.indexOf("latte")]);
 });

 test("an emoji is four bytes and two units", () => {
  const text = "a😀b";
  // bytes: a=0, 😀=1..4, b=5. units: a=0, 😀=1..2, b=3.
  expect(byteOffsetsToUtf16(text, [5, 1, 0])).toEqual([3, 1, 0]);
 });

 test("an offset inside a multibyte character snaps to its start rather than splitting it", () => {
  expect(byteOffsetsToUtf16("é", [1])).toEqual([0]);
 });
});

describe("message positions to CodeMirror positions", () => {
 test("every CRLF before the position is one unit shorter in the document", () => {
  const value = "A\r\nB\r\nC";
  expect(valuePosToDocPos(value, value.indexOf("C"))).toBe(4);
  expect(valuePosToDocPos(value, 0)).toBe(0);
  expect(valuePosToDocPos("A\nB", 2)).toBe(2);
 });
});

describe("changeMarksFor", () => {
 test("a replaced word after multibyte text and CRLFs lands exactly on the new word", () => {
  const b = "HTTP/1.1 200 OK\r\nX: é😀\r\n\r\nhello NEW world";
  const at = utf8(b).length - utf8("NEW world").length;
  const ops: CompareOp[] = [
   { kind: "equal", a_offset: 0, a_len: at, b_offset: 0, b_len: at },
   { kind: "replace", a_offset: at, a_len: 3, b_offset: at, b_len: 3 },
   { kind: "equal", a_offset: at + 3, a_len: 6, b_offset: at + 3, b_len: 6 },
  ];
  const { marks } = changeMarksFor(b, ops);
  expect(marks).toHaveLength(1);
  expect(b.slice(marks[0]!.from, marks[0]!.to)).toBe("NEW");
 });

 test("a delete is a point mark, and an uninteresting op is counted, not painted", () => {
  const b = "abc";
  const { marks, discounted } = changeMarksFor(b, [
   { kind: "delete", a_offset: 1, a_len: 2, b_offset: 1, b_len: 0 },
   { kind: "insert", a_offset: 0, a_len: 0, b_offset: 2, b_len: 1, uninteresting: true },
  ]);
  expect(marks).toEqual([{ from: 1, to: 1, kind: "deleted" }]);
  expect(discounted).toBe(1);
 });

 test("identical messages give no marks", () => {
  expect(changeMarksFor("same", [{ kind: "equal", a_offset: 0, a_len: 4, b_offset: 0, b_len: 4 }]).marks).toEqual([]);
 });
});
