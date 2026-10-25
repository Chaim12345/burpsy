import { describe, expect, test } from "bun:test";
import { detectGraphQL, looksLikeGraphQLDocument } from "./message-views";

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
