import { describe, expect, test } from "bun:test";
import { parseSeeds } from "./parse-seeds";

// The one seed parser both launchers share (f3k). The contract is Burp's "URLs to scan":
// many URLs, one box — and the two launchers must never disagree about what a box means.

describe("parseSeeds", () => {
 test("splits on newlines, commas and mixes of both", () => {
  expect(parseSeeds("https://a.test/\nhttps://b.test/")).toEqual(["https://a.test/", "https://b.test/"]);
  expect(parseSeeds("https://a.test/, https://b.test/")).toEqual(["https://a.test/", "https://b.test/"]);
  expect(parseSeeds("https://a.test/,\nhttps://b.test/")).toEqual(["https://a.test/", "https://b.test/"]);
 });

 test("trims surrounding whitespace and drops blank entries", () => {
  expect(parseSeeds("  https://a.test/  \n\n  \nhttps://b.test/")).toEqual(["https://a.test/", "https://b.test/"]);
 });

 test("an empty box is an empty list, never a one-empty-string list", () => {
  expect(parseSeeds("")).toEqual([]);
  expect(parseSeeds("   \n , \n")).toEqual([]);
 });
});
