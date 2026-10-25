// Go to entry (vfu2): the entry number parses as an operator types it, and each of the four
// outcomes is distinguished — a hidden row is not reported as a missing one.
import { describe, expect, test } from "bun:test";
import { classifyEntry, parseEntryNumber } from "./go-to-entry";

describe("parseEntryNumber", () => {
 test("accepts the forms a ticket uses", () => {
  expect(parseEntryNumber("1843")).toBe(1843);
  expect(parseEntryNumber(" #1843 ")).toBe(1843);
  expect(parseEntryNumber("# 7")).toBe(7);
  expect(parseEntryNumber("0")).toBe(0);
 });

 test("refuses what is not one entry number", () => {
  for (const raw of ["", "abc", "12a", "-3", "1.5", "1843 1844", "#"]) expect(parseEntryNumber(raw), raw).toBeNull();
 });
});

describe("classifyEntry", () => {
 const displayed = new Set([10, 11, 12]);
 test("a displayed row is shown, whatever else is true", () => {
  expect(classifyEntry({ id: 11, displayed, exists: true, filtered: true })).toBe("shown");
 });
 test("an id the store does not have is missing", () => {
  expect(classifyEntry({ id: 99, displayed, exists: false, filtered: true })).toBe("missing");
 });
 test("an existing row hidden while a filter is on is filtered", () => {
  expect(classifyEntry({ id: 3, displayed, exists: true, filtered: true })).toBe("filtered");
 });
 test("an existing row with no filter on is beyond the loaded rows", () => {
  expect(classifyEntry({ id: 3, displayed, exists: true, filtered: false })).toBe("beyond-limit");
 });
});
