// Per-column filters compose into the DSL box (burpsy-react-ui-8sa).
//
// The point of testing these as functions is that the interesting property is a SEQUENCE property.
// Any single call looks obviously right; what can go wrong is what happens as an operator types,
// which no screenshot and no single assertion would catch.
import { expect, test, describe } from "bun:test";
import { COLUMN_FILTERS, columnClause, rewriteClause } from "../pages/history";

describe("columnClause", () => {
 test("builds a DSL clause with a quoted value", () => {
  expect(columnClause("host", "~", "api.example")).toBe('host ~ "api.example"');
  expect(columnClause("path", "~", "/admin")).toBe('path ~ "/admin"');
 });

 test("an empty or whitespace-only input contributes nothing", () => {
  // Not `host ~ ""`, which would be a real clause the server has to evaluate — and which matches
  // everything, so the operator would see no change and conclude the filter is broken.
  expect(columnClause("host", "~", "")).toBe("");
  expect(columnClause("host", "~", "   ")).toBe("");
 });

 test("escapes a value that would otherwise break out of the string literal", () => {
  // A path really can contain a quote, and an unescaped one would produce a query the server
  // rejects — reported to the operator as a syntax error in text they never typed.
  expect(columnClause("path", "~", 'a"b')).toBe('path ~ "a\\"b"');
  expect(columnClause("path", "~", "a\\b")).toBe('path ~ "a\\\\b"');
 });

 test("every declared column filter names a field the query grammar knows", () => {
  // internal/query/query.go:444. A filter on a field the DSL cannot parse would send a query the
  // server rejects, and the panel exists precisely because not every column is expressible.
  const known = new Set(["host", "method", "path", "mime", "status", "body"]);
  for (const spec of COLUMN_FILTERS) {
   expect(known.has(spec.field)).toBe(true);
  }
 });
});

describe("rewriteClause", () => {
 test("typing one character at a time leaves exactly one clause", () => {
  // The bug this exists for. Without stripping the previous clause the box would accumulate one
  // clause per keystroke, ANDed together, so the query would match only rows containing every
  // prefix — which is every row containing the final value, i.e. right by accident, in an
  // unreadable box that gets slower with each character.
  let term = "";
  let previous = "";
  for (const value of ["a", "ap", "api"]) {
   const next = columnClause("host", "~", value);
   term = rewriteClause(term, previous, next);
   previous = next;
  }
  expect(term).toBe('host ~ "api"');
 });

 test("clearing an input removes its clause and nothing else", () => {
  const hostClause = columnClause("host", "~", "api");
  const pathClause = columnClause("path", "~", "/admin");

  let term = rewriteClause("", "", hostClause);
  term = rewriteClause(term, "", pathClause);
  expect(term).toBe('host ~ "api" AND path ~ "/admin"');

  term = rewriteClause(term, hostClause, "");
  expect(term).toBe('path ~ "/admin"');

  term = rewriteClause(term, pathClause, "");
  expect(term).toBe("");
 });

 test("two column filters compose rather than replace each other", () => {
  const host = columnClause("host", "~", "api");
  const body = columnClause("body", "~", "token");
  let term = rewriteClause("", "", host);
  term = rewriteClause(term, "", body);
  expect(term).toBe('host ~ "api" AND body ~ "token"');
 });

 test("a clause the operator has hand-edited away is not mangled", () => {
  // stripFragment is best-effort by design: the box is meant to be editable, and the design's
  // stated intent is that the operator "can see what it did and learn the language". If the old
  // clause is gone because they rewrote the query, the new one is appended to THEIR text rather
  // than the function trying to patch a string it no longer recognises.
  const stale = columnClause("host", "~", "api");
  const term = 'status >= 400 OR mime = "application/json"';
  const next = columnClause("host", "~", "cdn");
  expect(rewriteClause(term, stale, next)).toBe(`${term} AND host ~ "cdn"`);
 });

 test("a filter applied to an existing hand-written query is ANDed onto it", () => {
  const term = "status >= 500";
  const next = columnClause("path", "~", "/api");
  expect(rewriteClause(term, "", next)).toBe('status >= 500 AND path ~ "/api"');
 });

 test("an empty next clause on an empty term stays empty rather than becoming whitespace", () => {
  // A box holding " " is not an empty box: the page sends it, and the server has to parse it.
  expect(rewriteClause("", "", "")).toBe("");
 });
});
