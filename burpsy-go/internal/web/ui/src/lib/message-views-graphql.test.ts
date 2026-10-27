import { describe, expect, test } from "bun:test";
import { detectGraphQL, graphQLPercentDecode, looksLikeGraphQLDocument } from "./message-views";

// The console half of the 4xqt.3 review fixes: the list the console shows is the list the
// edit-apply route indexes, in the route's carrier precedence - the URL query parameter
// first, then the JSON body - and the document filter is the one predicate both sides share.

const JSON_POST = (body: string) =>
 `POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`;

describe("the GraphQL document filter", () => {
 test("a batch entry whose query is not a document is not an operation", () => {
  const doc = detectGraphQL(JSON_POST(`[{"query":"not graphql"},{"query":"{b}"}]`));
  expect(doc?.operations.map((op) => op.query)).toEqual(["{b}"]);
 });

 test("an anonymous operation and a JSON object share the opener; only one parses as JSON", () => {
  expect(looksLikeGraphQLDocument("{ a }")).toBe(true);
  expect(looksLikeGraphQLDocument('{"a":1}')).toBe(false);
  expect(looksLikeGraphQLDocument("# a comment\nquery Q { a }")).toBe(true);
  expect(looksLikeGraphQLDocument("querystring { a }")).toBe(false);
 });
});

describe("the document filter is one predicate on both sides", () => {
 // The same probe table as TestLooksLikeGraphQLDocumentMatchesTheConsolePredicate in Go.
 const probes: [string, boolean][] = [
  ["{ a }", true],
  ['{"a":1}', false],
  ["query Q { a }", true],
  ["mutation M { a }", true],
  ["subscription S { a }", true],
  ["fragment F on T { a }", true],
  ["# a comment\nquery Q { a }", true],
  ["# a comment without a newline", false],
  ["", false],
  ["   ", false],
  ["https://example.test/graphql", false],
  ["query$bad", true],
  ["queryé", true],
  ["queryx", false],
  ["query_2", false],
  ["query2", false],
  ["\ufeff{a}", true],
  ["\u0085{a}", false],
  ["\u00a0{a}", true],
 ];
 test("every shared probe reads the same as the Go predicate", () => {
  for (const [input, want] of probes) {
   expect(looksLikeGraphQLDocument(input)).toBe(want);
  }
 });
});

describe("the URL carrier is read with the server's decode", () => {
 test("'+' is data, not a space", () => {
  const doc = detectGraphQL(
   "POST /graphql?query=query+%7Ba%7D HTTP/1.1\r\nHost: shop.example\r\n\r\n",
  );
  expect(doc?.source).toBe("query string");
  expect(doc?.operations[0]?.query).toBe("query+{a}");
 });

 test("a partial escape decodes its valid prefix or survives, Sscanf semantics", () => {
  const doc = detectGraphQL(
   "POST /graphql?query=%7Ba%7D%2 HTTP/1.1\r\nHost: shop.example\r\n\r\n",
  );
  expect(doc?.operations[0]?.query).toBe("{a}%2");
 });

 test("an encoded parameter name is not the carrier", () => {
  const doc = detectGraphQL(
   "POST /graphql?%71uery=%7Ba%7D HTTP/1.1\r\nHost: shop.example\r\n\r\n",
  );
  expect(doc).toBeNull();
 });

 test("the first query= pair wins", () => {
  const doc = detectGraphQL(
   "POST /graphql?query=%7Ba%7D&query=%7Bb%7D HTTP/1.1\r\nHost: shop.example\r\n\r\n",
  );
  expect(doc?.operations[0]?.query).toBe("{a}");
 });
});

describe("the percent codec matches the server byte-for-byte", () => {
 // The same edge table as TestGraphQLPercentDecodeSscanfAndUTF8Edges in Go, probed against
 // the server: Sscanf window semantics, per-byte U+FFFD granularity, BOM kept, UTF-8 runs.
 const rows: [string, string][] = [
  // the original seven
  ["% 2", "\x02"],
  ["%\t2", "\x02"],
  ["%2 ", "\x02"],
  ["%2G", "\x02"],
  ["%G2", "%G2"],
  ["%C3%A9", "é"],
  ["%FF", "\uFFFD"],
  // the class rows: whitespace shapes - newline, NBSP and NEL break the scan
  ["%\n2", "%\n2"],
  ["%\r2", "\x02"],
  ["%\v2", "\x02"],
  ["%\f2", "\x02"],
  ["%\u00a02", "%\u00a02"],
  ["%\u00852", "%\u00852"],
  // UTF-8 shapes: non-BMP, BOM, NUL, overlong, lone continuation, truncated, mixed
  ["%F0%9F%98%80", "😀"],
  ["😀", "😀"], // a literal non-BMP char is one rune's bytes, not two replacements
  ["%EF%BB%BF", "\uFEFF"],
  ["%00", "\x00"],
  ["%C0%80", "\uFFFD\uFFFD"], // overlong: per-BYTE granularity, like Go's range
  ["%A9", "\uFFFD"], // a lone continuation byte
  ["%E2%82", "\uFFFD\uFFFD"], // a truncated prefix is two U+FFFD, not one
  ["%C3%A9%FF%41", "é\uFFFDA"], // valid + invalid + valid
  ["query+%C3%A9+{a}", "query+é+{a}"],
 ];
 test("every edge row reads as the server reads it", () => {
  for (const [input, want] of rows) {
   expect(graphQLPercentDecode(input)).toBe(want);
  }
 });
 test("T1 negative control: an unterminated or hex-less escape never decodes", () => {
  expect(graphQLPercentDecode("%")).toBe("%");
  expect(graphQLPercentDecode("%2")).toBe("%2");
  expect(graphQLPercentDecode("%zz")).toBe("%zz");
  expect(graphQLPercentDecode("100%")).toBe("100%");
 });
});

describe("carrier precedence is the server's edit precedence", () => {
 test("the URL query parameter wins over the JSON body", () => {
  const doc = detectGraphQL(
   `POST /graphql?query=%7B%20fromParam%20%7D HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{"query":"{ fromBody }"}`,
  );
  expect(doc?.source).toBe("query string");
  expect(doc?.operations[0]?.query).toBe("{ fromParam }");
 });

 test("a URL parameter that is not a document falls through to the JSON body", () => {
  const doc = detectGraphQL(
   `POST /graphql?query=notgraphql HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{"query":"{a}"}`,
  );
  expect(doc?.source).toBe("JSON body");
  expect(doc?.operations[0]?.query).toBe("{a}");
 });

 test("the form and application/graphql carriers are still read, after the editable ones", () => {
  const form = detectGraphQL(
   "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 12\r\n\r\nquery=%7Ba%7D",
  );
  expect(form?.source).toBe("urlencoded body");
  const raw = detectGraphQL(
   "POST /graphql HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/graphql\r\nContent-Length: 3\r\n\r\n{a}",
  );
  expect(raw?.source).toBe("application/graphql body");
 });
});
