/**
 * Tests for the sortable-table row filter (burpsy-react-ui-4rd). Run with `bun run test:lib`.
 *
 * The matcher backs Intruder's result-table filter boxes. A filter that missed
 * values an operator can see, or that pretended an empty cell read "null", would
 * quietly hide the one error row being hunted; these pin the flattening rules
 * against the row shapes this page actually renders.
 */

import { describe, expect, test } from "bun:test";
import { filterTableRows, flattenRowText, tableRowMatches } from "./table-filter";
import type { Column } from "../ui/table";
import type { Attempt, ErrorBucket, ResultBucket } from "./types.tools";

describe("flattenRowText flattens what the tables render", () => {
 test("strings pass through, empty strings are nothing", () => {
  expect(flattenRowText("conn refused")).toEqual(["conn refused"]);
  expect(flattenRowText("")).toEqual([]);
 });

 test("numbers become their raw string form", () => {
  expect(flattenRowText(404)).toEqual(["404"]);
  expect(flattenRowText(1234)).toEqual(["1234"]);
 });

 test("booleans match both the word and the badge text", () => {
  expect(flattenRowText(true)).toEqual(["true", "yes"]);
  expect(flattenRowText(false)).toEqual(["false", "no"]);
 });

 test("null and undefined are nothing to search", () => {
  expect(flattenRowText(null)).toEqual([]);
  expect(flattenRowText(undefined)).toEqual([]);
 });

 test("arrays and objects flatten, depth-capped", () => {
  expect(flattenRowText([{ reason: "max_count", count: 3 }])).toEqual(["max_count", "3"]);
  const deep = { a: { b: { c: { d: { e: "too deep" } } } } };
  expect(flattenRowText(deep)).toEqual([]);
  expect(flattenRowText({ a: { b: { c: { d: "just in" } } } })).toEqual(["just in"]);
 });

 test("non-finite numbers and bare primitives contribute nothing", () => {
  expect(flattenRowText(Number.NaN)).toEqual([]);
  expect(flattenRowText(Number.POSITIVE_INFINITY)).toEqual([]);
 });
});

describe("tableRowMatches matches any flattened value, literally", () => {
 const bucket: ResultBucket = {
  status: 500,
  response_len: 1234,
  reflected: true,
  count: 7,
  first_ordinal: 11,
  example_request_id: null, example_response_id: 90,
  grep_matches: 2,
  grep_extract: "token=[abc]",
  grep_match_totals: [],
 };

 test("case-insensitive substring", () => {
  expect(tableRowMatches(bucket, "REFUSED")).toBe(false);
  expect(tableRowMatches(bucket, "ABC")).toBe(true);
 });

 test("the empty query matches everything, including empty rows", () => {
  expect(tableRowMatches(bucket, "")).toBe(true);
  expect(tableRowMatches(bucket, "   ")).toBe(true);
  expect(tableRowMatches(null, "")).toBe(true);
 });

 test("numbers match raw values, not presentation", () => {
  expect(tableRowMatches(bucket, "500")).toBe(true);
  expect(tableRowMatches(bucket, "1234")).toBe(true);
  // "1.2 kB" is formatBytes presentation; the filter is over the data.
  expect(tableRowMatches(bucket, "1.2 kB")).toBe(false);
 });

 test("booleans answer to yes/no and true/false", () => {
  expect(tableRowMatches(bucket, "yes")).toBe(true);
  expect(tableRowMatches(bucket, "no")).toBe(false);
 });

 test("regex metacharacters are literals, not a pattern", () => {
  expect(tableRowMatches("a.c", "a.c")).toBe(true);
  expect(tableRowMatches("abc", "a.c")).toBe(false);
  expect(tableRowMatches("x(1)", "(")).toBe(true);
 });

 test("an error row matches its message and its null-safe ordinal", () => {
  const error: ErrorBucket = { error: "connection reset by peer", count: 4, first_ordinal: null };
  expect(tableRowMatches(error, "reset")).toBe(true);
  expect(tableRowMatches(error, "null")).toBe(false);
 });
});

describe("tableRowMatches over the attempt rows it will filter", () => {
 const attempt: Attempt = {
  ordinal: 18,
  status: null,
  response_len: 0,
  duration_ms: 1200,
  reflected: false,
  request_id: null, response_id: null,
  error: "dial tcp: connection refused",
  grep_matched: false,
  grep_extract: null,
  grep_match_counts: [],
  time_of_day: "2026-01-01T00:00:00.000Z",
  cookies: [],
  timeout: false,
 };

 test("an error row is findable by its message", () => {
  expect(tableRowMatches(attempt, "refused")).toBe(true);
 });

 test("a failed attempt is findable without the status being a number", () => {
  expect(tableRowMatches(attempt, "404")).toBe(false);
  expect(tableRowMatches(attempt, "1200")).toBe(true);
 });

 test("an unmatching query is an honest no", () => {
  expect(tableRowMatches(attempt, "404")).toBe(false);
 });
});

describe("filterTableRows keeps the count and the table in agreement", () => {
 const buckets: ResultBucket[] = [
  {
   status: 200,
   response_len: 1200,
   reflected: true,
   count: 3,
   first_ordinal: 0,
   example_request_id: null, example_response_id: 1,
   grep_matches: 0,
   grep_extract: null,
   grep_match_totals: [],
  },
  {
   status: 404,
   response_len: 900,
   reflected: false,
   count: 1,
   first_ordinal: 3,
   example_request_id: null, example_response_id: null,
   grep_matches: 2,
   grep_extract: "token=[x]",
   grep_match_totals: [],
  },
  {
   status: null,
   response_len: 0,
   reflected: false,
   count: 1,
   first_ordinal: 4,
   example_request_id: null, example_response_id: null,
   grep_matches: 0,
   grep_extract: null,
   grep_match_totals: [],
  },
 ];

 test("an empty query returns the rows untouched", () => {
  expect(filterTableRows(buckets, [{ accessorKey: "count" }], "")).toBe(buckets);
  expect(filterTableRows(buckets, [{ accessorKey: "count" }], "   ")).toBe(buckets);
 });

 test("accessorFn columns are searched by their computed value", () => {
  const columns: Column<ResultBucket>[] = [{ accessorFn: (bucket) => (bucket.reflected ? "yes" : "no"), id: "reflected", header: "Reflected" }];
  expect(filterTableRows(buckets, columns, "yes").map((bucket) => bucket.status)).toEqual([200]);
  expect(filterTableRows(buckets, columns, "no").map((bucket) => bucket.status)).toEqual([404, null]);
 });

 test("accessorKey columns read the raw row property", () => {
  expect(filterTableRows(buckets, [{ accessorKey: "status", header: "Status" }], "404").map((bucket) => bucket.first_ordinal)).toEqual([3]);
 });

 test("a row passes when any column matches", () => {
  const columns: Column<ResultBucket>[] = [
   { accessorKey: "status", header: "Status" },
   { accessorKey: "grep_extract", header: "Grep" },
  ];
  expect(filterTableRows(buckets, columns, "token").map((bucket) => bucket.status)).toEqual([404]);
 });

 test("columns with no accessor contribute nothing rather than matching everything", () => {
  expect(filterTableRows(buckets, [{ header: "Nothing" }], "200")).toEqual([]);
 });

 test("the same query that finds rows also finds the flattened shape", () => {
  const columns: Column<ResultBucket>[] = [{ accessorFn: (bucket) => bucket.status ?? undefined, id: "status", header: "Status" }];
  expect(filterTableRows(buckets, columns, "error")).toEqual([]);
  expect(filterTableRows(buckets, columns, "200").length).toBe(1);
 });
});
