/**
 * Tests for link harvesting (burpsy-react-ui-4d4). Run with `bun run test:lib`.
 *
 * The rule under test: quoted attributes and bare absolute URLs are collected in
 * first-seen order without repeats, while fragments, javascript:/mailto:/data: URLs
 * and trailing sentence punctuation never reach the clipboard. A harvest that invents
 * URLs (resolving relatives) or duplicates entries would poison the crawl seeds it feeds.
 */

import { describe, expect, test } from "bun:test";
import { extractLinks } from "./actions";

describe("extractLinks harvests what is there and nothing else", () => {
 test("quoted attributes come first, in order, without repeats", () => {
  expect(
   extractLinks(
    '<a href="/login">in</a><img src="https://cdn.x/y.png"><a href="/login">again</a>',
   ),
  ).toEqual(["/login", "https://cdn.x/y.png"]);
 });

 test("bare absolute URLs in JS and CSS are harvested", () => {
  expect(extractLinks('fetch("https://api.x/v1?q=1"), url(/static/a.css)')).toEqual([
   "https://api.x/v1?q=1",
   "/static/a.css",
  ]);
 });

 test("fragments, javascript:, mailto: and data: never reach the clipboard", () => {
  expect(
   extractLinks('<a href="#top">t</a><a href="javascript:void(0)">j</a><a href="mailto:a@b.c">m</a><img src="data:image/png;base64,AAA">'),
  ).toEqual([]);
 });

 test("trailing sentence punctuation is stripped, not seeded", () => {
  expect(extractLinks("see https://x.example/y, and https://x.example/z.")).toEqual([
   "https://x.example/y",
   "https://x.example/z",
  ]);
 });

 test("an unlinking response harvests nothing", () => {
  expect(extractLinks("<html><body>no links here</body></html>")).toEqual([]);
 });
});
