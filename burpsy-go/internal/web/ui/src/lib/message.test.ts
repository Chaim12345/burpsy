/**
 * Tests for message.ts's inverse operations — the writers the editable Inspector
 * goes through. Run with `bun run test:lib` from internal/web/ui.
 *
 * Almost every assertion here is on the WHOLE message rather than on a parsed
 * field, and that is the point. An Inspector edit becomes bytes that go over the
 * wire, so "the header now reads X" is not the claim worth checking — "every
 * other byte, the CRLFs included, is exactly what it was" is. A writer that
 * normalised line endings, or reflowed a body, or moved a header, would pass a
 * field-level check and quietly change what the operator is testing.
 */

import { describe, expect, test } from "bun:test";
import {
 addBodyParam,
 addCookie,
 addHeader,
 addQueryParam,
 bodyParamSpans,
 bodyParamsEditable,
 bodyParamsOf,
 compactMessage,
 cookieSpans,
 cookiesOf,
 eolOf,
 fixContentLength,
 headerSpans,
 jsonMemberSpans,
 parseMessage,
 pairSpans,
 parsePairs,
 queryOf,
 querySpans,
 removeBodyParamAt,
 removeCookieAt,
 removeHeaderAt,
 removeQueryParamAt,
 setBody,
 prettyMessage,
 setBodyParamAt,
 setCookieAt,
 setHeaderAt,
 setQueryParamAt,
 setStartLineTail,
 setStartLineToken,
 startLineSpans,
} from "./message";

/**
 * A CRLF request with a form body, which is the shape most of these act on.
 *
 * Its Content-Length is the body's real byte count. That matters: a fixture that
 * declared the wrong length would make every `fixContentLength` assertion below
 * pass for the wrong reason — the writer would look like it had corrected the
 * length when all it had done was correct the fixture.
 */
const FORM = [
 "POST /login?next=%2Fhome&debug=1 HTTP/1.1",
 "Host: shop.example",
 "Cookie: session=abc; theme=dark",
 "Content-Type: application/x-www-form-urlencoded",
 "Content-Length: 26",
 "",
 "user=admin&pass=hunter+two",
].join("\r\n");

const GET = ["GET /a HTTP/1.1", "Host: shop.example", "Accept: */*", "", ""].join("\r\n");

const RESPONSE = [
 "HTTP/1.1 404 Not Found",
 "Content-Type: text/html",
 "Set-Cookie: a=1; Path=/",
 "Content-Length: 4",
 "",
 "gone",
].join("\r\n");

describe("reading is unchanged by the span rewrite", () => {
 test("CRLF, LF and separator-less messages parse the same as before", () => {
  expect(parseMessage(FORM).startLine).toBe("POST /login?next=%2Fhome&debug=1 HTTP/1.1");
  expect(parseMessage(FORM).headers).toEqual([
   ["Host", "shop.example"],
   ["Cookie", "session=abc; theme=dark"],
   ["Content-Type", "application/x-www-form-urlencoded"],
   ["Content-Length", "26"],
  ]);
  expect(parseMessage(FORM).body).toBe("user=admin&pass=hunter+two");

  const lf = "GET / HTTP/1.1\nHost: h\n\nbody";
  expect(parseMessage(lf).headers).toEqual([["Host", "h"]]);
  expect(parseMessage(lf).body).toBe("body");

  const bare = "GET / HTTP/1.1\r\nHost: h";
  expect(parseMessage(bare).headers).toEqual([["Host", "h"]]);
  expect(parseMessage(bare).body).toBe("");

  expect(parseMessage("").headers).toEqual([]);
  expect(parseMessage("\r\n\r\nbody").startLine).toBe("");
 });

 test("a line with no colon is not a header, and the spans skip it too", () => {
  const odd = "GET / HTTP/1.1\r\nHost: h\r\nnonsense\r\n: novalue\r\nX: 1\r\n\r\n";
  expect(parseMessage(odd).headers).toEqual([
   ["Host", "h"],
   ["X", "1"],
  ]);
  // Index-for-index with parseMessage: the whole reason headerSpans exists.
  expect(headerSpans(odd).map((s) => [s.name, s.value])).toEqual(parseMessage(odd).headers);
 });

 test("header spans point at exactly their own line", () => {
  for (const span of headerSpans(FORM)) {
   expect(FORM.slice(span.start, span.end)).toBe(`${span.name}: ${span.value}`);
  }
 });

 test("eolOf reports the message's own line ending", () => {
  expect(eolOf(FORM)).toBe("\r\n");
  expect(eolOf("GET / HTTP/1.1\nHost: h\n\n")).toBe("\n");
  expect(eolOf("GET / HTTP/1.1")).toBe("\r\n");
 });
});

describe("headers", () => {
 test("setting one header changes that line and nothing else", () => {
  const next = setHeaderAt(FORM, 0, "Host", "other.example");
  expect(next).toBe(FORM.replace("Host: shop.example", "Host: other.example"));
  // The rest of the message is byte-identical, CRLFs included.
  expect(next.split("\r\n").length).toBe(FORM.split("\r\n").length);
  expect(parseMessage(next).body).toBe(parseMessage(FORM).body);
 });

 test("a CR or LF in a value cannot inject a second header", () => {
  const next = setHeaderAt(GET, 1, "Accept", "*/*\r\nX-Injected: yes");
  expect(parseMessage(next).headers).toEqual([
   ["Host", "shop.example"],
   ["Accept", "*/*X-Injected: yes"],
  ]);
 });

 test("removing a header keeps the head/body boundary intact at any position", () => {
  // First, middle and last, because each one takes a different line ending with it.
  expect(removeHeaderAt(FORM, 0)).toBe(FORM.replace("Host: shop.example\r\n", ""));
  expect(removeHeaderAt(FORM, 1)).toBe(FORM.replace("Cookie: session=abc; theme=dark\r\n", ""));

  const last = removeHeaderAt(FORM, 3);
  expect(last).toBe(FORM.replace("\r\nContent-Length: 26", ""));
  expect(parseMessage(last).body).toBe(parseMessage(FORM).body);
  expect(parseMessage(last).headers).toHaveLength(3);
 });

 test("an added header lands at the end of the head with the message's own line ending", () => {
  expect(addHeader(FORM, "X-Trace", "1")).toBe(
   FORM.replace("Content-Length: 26\r\n\r\n", "Content-Length: 26\r\nX-Trace: 1\r\n\r\n"),
  );
  const lf = "GET / HTTP/1.1\nHost: h\n\nbody";
  expect(addHeader(lf, "X", "1")).toBe("GET / HTTP/1.1\nHost: h\nX: 1\n\nbody");
 });

 test("an out-of-range index is a no-op rather than a corrupted message", () => {
  expect(setHeaderAt(FORM, 99, "X", "1")).toBe(FORM);
  expect(removeHeaderAt(FORM, -1)).toBe(FORM);
 });
});

describe("Content-Length follows the body", () => {
 test("an existing header is corrected", () => {
  const next = setBody(FORM, "user=admin");
  expect(parseMessage(next).body).toBe("user=admin");
  expect(parseMessage(next).headers).toContainEqual(["Content-Length", "10"]);
  // The head is otherwise untouched: same headers, same order.
  expect(parseMessage(next).headers.map(([name]) => name)).toEqual(parseMessage(FORM).headers.map(([name]) => name));
 });

 test("a body arriving at a message that declared none gets a header", () => {
  const next = setBody(GET, "hello");
  expect(parseMessage(next).headers).toContainEqual(["Content-Length", "5"]);
  expect(next.startsWith("GET /a HTTP/1.1\r\nHost: shop.example\r\nAccept: */*\r\n")).toBe(true);
 });

 test("the length counts BYTES, not characters", () => {
  // "é" is two bytes in UTF-8. A length in characters would understate it by one
  // and the peer would read one byte short of the body.
  expect(parseMessage(setBody(GET, "é")).headers).toContainEqual(["Content-Length", "2"]);
 });

 test("an emptied body reports zero rather than losing the header", () => {
  expect(parseMessage(setBody(FORM, "")).headers).toContainEqual(["Content-Length", "0"]);
 });

 test("Transfer-Encoding owns the framing, so no Content-Length is written beside it", () => {
  const chunked = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
  expect(fixContentLength(chunked)).toBe(chunked);
  expect(parseMessage(setBody(chunked, "x")).headers).toEqual(parseMessage(chunked).headers);
 });

 test("a message with no body and no header is left alone", () => {
  expect(fixContentLength(GET)).toBe(GET);
 });
});

describe("query parameters", () => {
 test("the spans agree with queryOf, and each covers its own pair", () => {
  expect(querySpans(FORM).map((s) => [s.name, s.value])).toEqual(queryOf(parseMessage(FORM).startLine.split(" ")[1]!));
  expect(querySpans(FORM).map((s) => FORM.slice(s.start, s.end))).toEqual(["next=%2Fhome", "debug=1"]);
 });

 test("setting one parameter re-encodes only that one", () => {
  const next = setQueryParamAt(FORM, 1, "debug", "0");
  expect(next.split("\r\n")[0]).toBe("POST /login?next=%2Fhome&debug=0 HTTP/1.1");

  // The value is percent-encoded on the way in, so a "&" cannot smuggle a parameter.
  const smuggled = setQueryParamAt(FORM, 1, "debug", "1&admin=true");
  expect(queryOf(smuggled.split(" ")[1]!)).toEqual([
   ["next", "/home"],
   ["debug", "1&admin=true"],
  ]);
 });

 test("removing a parameter takes its separator, at either end", () => {
  expect(removeQueryParamAt(FORM, 0).split("\r\n")[0]).toBe("POST /login?debug=1 HTTP/1.1");
  expect(removeQueryParamAt(FORM, 1).split("\r\n")[0]).toBe("POST /login?next=%2Fhome HTTP/1.1");
 });

 test("removing the last parameter takes the question mark too", () => {
  const one = "GET /x?a=1 HTTP/1.1\r\nHost: h\r\n\r\n";
  expect(removeQueryParamAt(one, 0).split("\r\n")[0]).toBe("GET /x HTTP/1.1");
 });

 test("adding a parameter introduces a query string when there is none", () => {
  expect(addQueryParam(GET, "q", "a b").split("\r\n")[0]).toBe("GET /a?q=a%20b HTTP/1.1");
  expect(addQueryParam(FORM, "q", "1").split("\r\n")[0]).toBe("POST /login?next=%2Fhome&debug=1&q=1 HTTP/1.1");
 });

 test("a fragment stays a fragment", () => {
  const fragment = "GET /x#top HTTP/1.1\r\nHost: h\r\n\r\n";
  expect(addQueryParam(fragment, "a", "1").split("\r\n")[0]).toBe("GET /x?a=1#top HTTP/1.1");
  const both = "GET /x?a=1#top HTTP/1.1\r\nHost: h\r\n\r\n";
  expect(querySpans(both).map((s) => [s.name, s.value])).toEqual([["a", "1"]]);
  expect(setQueryParamAt(both, 0, "a", "2").split("\r\n")[0]).toBe("GET /x?a=2#top HTTP/1.1");
 });
});

describe("request cookies", () => {
 test("the spans agree with cookiesOf on every shape it filters", () => {
  for (const jar of ["session=abc; theme=dark", " a=1 ;; b = 2 ", "=novalue; c=3", "flag", "; ; "]) {
   const raw = `GET / HTTP/1.1\r\nHost: h\r\nCookie: ${jar}\r\n\r\n`;
   expect(cookieSpans(raw).map((s) => [s.name, s.value])).toEqual(cookiesOf(parseMessage(raw).headers, false));
  }
 });

 test("setting one cookie leaves its neighbours' spacing alone", () => {
  expect(setCookieAt(FORM, 1, "theme", "light")).toBe(FORM.replace("theme=dark", "theme=light"));
  // A ";" in a value would split one cookie into two, so it is dropped.
  expect(setCookieAt(FORM, 0, "session", "a;admin=1")).toBe(FORM.replace("session=abc", "session=aadmin=1"));
 });

 test("removing a cookie takes its separator; removing the last takes the header", () => {
  expect(removeCookieAt(FORM, 1)).toBe(FORM.replace("Cookie: session=abc; theme=dark", "Cookie: session=abc"));
  expect(removeCookieAt(FORM, 0)).toBe(FORM.replace("Cookie: session=abc; theme=dark", "Cookie: theme=dark"));

  const one = "GET / HTTP/1.1\r\nHost: h\r\nCookie: only=1\r\nAccept: */*\r\n\r\n";
  expect(removeCookieAt(one, 0)).toBe("GET / HTTP/1.1\r\nHost: h\r\nAccept: */*\r\n\r\n");
 });

 test("adding a cookie appends to the jar, or writes the header when there is none", () => {
  expect(addCookie(FORM, "tz", "UTC")).toBe(FORM.replace("theme=dark", "theme=dark; tz=UTC"));
  expect(parseMessage(addCookie(GET, "a", "1")).headers).toContainEqual(["Cookie", "a=1"]);
  // An empty jar is a header with nothing in it, not a missing header.
  const empty = "GET / HTTP/1.1\r\nHost: h\r\nCookie: \r\n\r\n";
  expect(parseMessage(addCookie(empty, "a", "1")).headers).toContainEqual(["Cookie", "a=1"]);
 });
});

describe("body parameters — urlencoded", () => {
 test("the spans agree with bodyParamsOf", () => {
  expect(bodyParamSpans(FORM).map((s) => [s.name, s.value])).toEqual(
   bodyParamsOf(parseMessage(FORM).body, "application/x-www-form-urlencoded"),
  );
  expect(bodyParamsOf(parseMessage(FORM).body, "application/x-www-form-urlencoded")).toEqual([
   ["user", "admin"],
   ["pass", "hunter two"],
  ]);
 });

 test("an edit corrects Content-Length in the same operation", () => {
  const next = setBodyParamAt(FORM, 0, "user", "root");
  expect(parseMessage(next).body).toBe("user=root&pass=hunter+two");
  expect(parseMessage(next).headers).toContainEqual(["Content-Length", "25"]);

  const longer = setBodyParamAt(FORM, 0, "user", "administrator");
  expect(parseMessage(longer).headers).toContainEqual(["Content-Length", "34"]);
  expect(parseMessage(longer).body).toBe("user=administrator&pass=hunter+two");
 });

 test("removing and adding keep the body well formed and the length honest", () => {
  const removed = removeBodyParamAt(FORM, 0);
  expect(parseMessage(removed).body).toBe("pass=hunter+two");
  expect(parseMessage(removed).headers).toContainEqual(["Content-Length", "15"]);

  const added = addBodyParam(FORM, "csrf", "t o k");
  expect(parseMessage(added).body).toBe("user=admin&pass=hunter+two&csrf=t%20o%20k");
  expect(parseMessage(added).headers).toContainEqual(["Content-Length", "41"]);
 });

 test("adding to a form message with no body writes the body", () => {
  const empty = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n";
  const next = addBodyParam(empty, "a", "1");
  expect(parseMessage(next).body).toBe("a=1");
  expect(parseMessage(next).headers).toContainEqual(["Content-Length", "3"]);
 });
});

describe("body parameters — JSON", () => {
 const json = [
  "POST /api HTTP/1.1",
  "Host: h",
  "Content-Type: application/json",
  "Content-Length: 66",
  "",
  '{\n  "2": "second",\n  "name": "ann",\n  "age": 30,\n  "tags": ["a"]\n}',
 ].join("\r\n");

 test("members come back in source order, not Object.entries order", () => {
  // Object.entries would put "2" first for any key order, so a row index taken
  // from it and a span taken from the text would disagree about which member is
  // which — the drift bodyParamSpans exists to make impossible.
  expect(bodyParamSpans(json).map((s) => s.name)).toEqual(["2", "name", "age", "tags"]);
  expect(bodyParamSpans(json).map((s) => s.value)).toEqual(["second", "ann", "30", '["a"]']);
 });

 test("each span covers exactly its own member", () => {
  expect(bodyParamSpans(json).map((s) => json.slice(s.start, s.end))).toEqual([
   '"2": "second"',
   '"name": "ann"',
   '"age": 30',
   '"tags": ["a"]',
  ]);
 });

 test("editing one member leaves the indentation and every other member alone", () => {
  const next = setBodyParamAt(json, 1, "name", "bob");
  expect(parseMessage(next).body).toBe('{\n  "2": "second",\n  "name": "bob",\n  "age": 30,\n  "tags": ["a"]\n}');
  // "ann" and "bob" are the same width, so the length is left where it was
  // rather than rewritten to the same number — the newlines and two-space
  // indentation all survive, which is what "splice, never reflow" buys.
  expect(parseMessage(next).headers).toContainEqual(["Content-Length", "66"]);
 });

 test("a number stays a number and a string stays a string", () => {
  expect(parseMessage(setBodyParamAt(json, 2, "age", "31")).body).toContain('"age": 31');
  // Not valid JSON, so it can only go in as a string — and says so in the bytes.
  expect(parseMessage(setBodyParamAt(json, 2, "age", "thirty")).body).toContain('"age": "thirty"');
  // A string member does NOT silently become a number.
  expect(parseMessage(setBodyParamAt(json, 1, "name", "42")).body).toContain('"name": "42"');
 });

 test("a nested value can be replaced wholesale", () => {
  expect(parseMessage(setBodyParamAt(json, 3, "tags", '["a","b"]')).body).toContain('"tags": ["a","b"]');
 });

 test("renaming a key rewrites only the key", () => {
  expect(parseMessage(setBodyParamAt(json, 1, "user", "ann")).body).toContain('"user": "ann"');
 });

 test("removing a member takes the comma with it, at either end", () => {
  // Removing the first member takes the comma AFTER it, so the "{\n  " that
  // preceded it stays exactly as written. Reaching back to the brace instead
  // would silently restyle a body the operator did not ask to restyle.
  expect(parseMessage(removeBodyParamAt(json, 0)).body).toBe('{\n  "name": "ann",\n  "age": 30,\n  "tags": ["a"]\n}');
  expect(parseMessage(removeBodyParamAt(json, 3)).body).toBe('{\n  "2": "second",\n  "name": "ann",\n  "age": 30\n}');
  expect(parseMessage(removeBodyParamAt(json, 1)).body).toBe('{\n  "2": "second",\n  "age": 30,\n  "tags": ["a"]\n}');
 });

 test("adding a member appends, and Content-Length follows", () => {
  const next = addBodyParam(json, "role", "admin");
  expect(parseMessage(next).body).toContain('"tags": ["a"], "role": "admin"');
  expect(parseMessage(next).headers).toContainEqual([
   "Content-Length",
   String(new TextEncoder().encode(parseMessage(next).body).length),
  ]);
 });

 test("an empty object gets its first member", () => {
  const empty = "POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{}";
  expect(parseMessage(addBodyParam(empty, "a", "1")).body).toBe('{"a": "1"}');
 });

 test("a body that is not a well-formed object yields no rows rather than wrong ones", () => {
  for (const body of ['["a","b"]', "42", '{"a": ', '{"a" 1}', "not json at all"]) {
   const raw = `POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n${body}`;
   expect(bodyParamSpans(raw)).toEqual([]);
  }
 });

 test("the scanner survives braces, commas and escapes inside strings", () => {
  const tricky = '{"a": "}, \\"quoted\\" {", "b": 1}';
  expect(jsonMemberSpans(tricky).map((m) => [m.name, m.source])).toEqual([
   ["a", '"}, \\"quoted\\" {"'],
   ["b", "1"],
  ]);
 });

 test("bodyParamsEditable names the bodies that can be written", () => {
  expect(bodyParamsEditable(FORM)).toBe(true);
  expect(bodyParamsEditable(json)).toBe(true);
  expect(bodyParamsEditable("POST /a HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\nx")).toBe(false);
  expect(bodyParamsEditable(GET)).toBe(false);
 });
});

describe("the start line", () => {
 test("tokens are spans, so the original spacing survives an edit", () => {
  const spaced = "GET   /x   HTTP/1.1\r\nHost: h\r\n\r\n";
  expect(startLineSpans(spaced).map((s) => spaced.slice(s.start, s.end))).toEqual(["GET", "/x", "HTTP/1.1"]);
  expect(setStartLineToken(spaced, 0, "POST").split("\r\n")[0]).toBe("POST   /x   HTTP/1.1");
 });

 test("the method, the target and the version each write independently", () => {
  expect(setStartLineToken(FORM, 0, "PUT").split("\r\n")[0]).toBe("PUT /login?next=%2Fhome&debug=1 HTTP/1.1");
  expect(setStartLineToken(FORM, 1, "/other").split("\r\n")[0]).toBe("POST /other HTTP/1.1");
  expect(setStartLineToken(FORM, 2, "HTTP/2").split("\r\n")[0]).toBe("POST /login?next=%2Fhome&debug=1 HTTP/2");
  // Switching the version leaves the headers and body untouched.
  expect(parseMessage(setStartLineToken(FORM, 2, "HTTP/2")).headers).toEqual(parseMessage(FORM).headers);
 });

 test("a version can be added to a start line that has none", () => {
  const short = "GET /x\r\nHost: h\r\n\r\n";
  expect(setStartLineToken(short, 2, "HTTP/1.1").split("\r\n")[0]).toBe("GET /x HTTP/1.1");
 });

 test("a response's status and reason are writable, spaces included", () => {
  expect(setStartLineToken(RESPONSE, 1, "500").split("\r\n")[0]).toBe("HTTP/1.1 500 Not Found");
  expect(setStartLineTail(RESPONSE, 2, "Server Error").split("\r\n")[0]).toBe("HTTP/1.1 404 Server Error");
  const bare = "HTTP/1.1 204\r\nX: 1\r\n\r\n";
  expect(setStartLineTail(bare, 2, "No Content").split("\r\n")[0]).toBe("HTTP/1.1 204 No Content");
 });
});

describe("the writers compose", () => {
 test("a chain of edits reads back as the chain of edits", () => {
  let raw = FORM;
  raw = setStartLineToken(raw, 0, "PUT");
  raw = setHeaderAt(raw, 0, "Host", "api.example");
  raw = addHeader(raw, "X-Trace", "abc");
  raw = setCookieAt(raw, 0, "session", "zzz");
  raw = addQueryParam(raw, "v", "2");
  raw = setBodyParamAt(raw, 1, "pass", "s3cret");
  // Index 2 is Content-Type: the appended X-Trace went to the END of the head,
  // so it did not shift the headers that were already there.
  raw = removeHeaderAt(raw, 2);

  const parsed = parseMessage(raw);
  expect(parsed.startLine).toBe("PUT /login?next=%2Fhome&debug=1&v=2 HTTP/1.1");
  expect(parsed.headers).toEqual([
   ["Host", "api.example"],
   // Editing cookie 0 by name and value rewrote only cookie 0; theme survived.
   ["Cookie", "session=zzz; theme=dark"],
   ["Content-Length", "22"],
   ["X-Trace", "abc"],
  ]);
  expect(parsed.body).toBe("user=admin&pass=s3cret");
 });

 test("parsePairs and pairSpans skip the same empty chunks", () => {
  for (const input of ["", "a=1", "&a=1&&b=2&", "a", "=1", "a=1=2", "a=1&&&b=2"]) {
   const spans = pairSpans(input);
   expect(spans.map(({ name, value }) => [name, value])).toEqual(parsePairs(input));
   // And every span really points at the chunk it claims, so the row an
   // operator edits and the bytes that get spliced are the same chunk.
   for (const span of spans) {
    const chunk = input.slice(span.start, span.end);
    expect(chunk).not.toContain("&");
    expect(chunk.length).toBeGreaterThan(0);
   }
  }
 });
});

describe("compactMessage — the Pretty write-back (burpsy-react-ui-dmf)", () => {
 // A minified JSON request — the shape an operator is forced to edit on one
 // unwrapped line in Raw without dmf's Pretty editing.
 const JSON_REQ = [
  "POST /api HTTP/1.1",
  "Host: h",
  "Content-Type: application/json",
  "Content-Length: 43",
  "",
  '{"name":"ann","tags":["a","b"],"nested":{"k":1}}',
 ].join("\r\n");

 test("a Pretty edit round-trips to the minified bytes the wire carried", () => {
  const pretty = prettyMessage(JSON_REQ);
  // The premise: Pretty actually reformatted, so this exercises a real
  // write-back and not an identity.
  expect(pretty).not.toBe(JSON_REQ);
  // An edit made in the readable form comes back as the message with only
  // that edit — and the wire bytes stay minified, not pretty-printed.
  const edited = pretty.replace('"ann"', '"bob"');
  expect(compactMessage(edited)).toBe(JSON_REQ.replace('"ann"', '"bob"'));
 });

 test("the head of an edited Pretty view is kept exactly as the operator left it", () => {
  const edited = prettyMessage(JSON_REQ).replace("Host: h", "Host: other.example");
  const parsed = parseMessage(compactMessage(edited));
  expect(parsed.startLine).toBe("POST /api HTTP/1.1");
  expect(parsed.headers).toEqual([
   ["Host", "other.example"],
   ["Content-Type", "application/json"],
   ["Content-Length", "43"],
  ]);
 });

 test("mid-edit JSON passes through unchanged so Raw shows exactly what was typed", () => {
  const pretty = prettyMessage(JSON_REQ);
  // A body cut in half mid-edit is not valid JSON; the operator's text must
  // survive byte-identically rather than be mangled by a guess.
  const halfEdited = pretty.slice(0, pretty.indexOf('"tags"'));
  expect(compactMessage(halfEdited)).toBe(halfEdited);
 });

 test("pure-tag markup round-trips byte-identically", () => {
  // Minified HTML — the common shape an operator meets on the wire. Every
  // newline in the Pretty view is one prettyMarkup inserted, so the write-back
  // can restore the exact original body.
  const HTML = [
   "HTTP/1.1 200 OK",
   "Content-Type: text/html",
   "",
   "<html><body><p>hi</p><br><a href=\"/x\">y</a></body></html>",
  ].join("\r\n");
  const pretty = prettyMessage(HTML);
  expect(pretty).not.toBe(HTML);
  expect(compactMessage(pretty)).toBe(HTML);
 });

 test("markup write-back collapses only the breaks prettyMarkup inserted", () => {
  // A text node that spans lines: prettyMarkup re-indented its continuation
  // lines, and that indentation is unrecoverable — the write-back leaves the
  // node's own newlines and words exactly as the Pretty view showed rather than
  // eating them with the tag breaks.
  const HTML = [
   "HTTP/1.1 200 OK",
   "Content-Type: text/html",
   "",
   "<html><body>hello\nworld</body></html>",
  ].join("\r\n");
  const pretty = prettyMessage(HTML);
  const compacted = compactMessage(pretty);
  // Tag breaks collapsed back to the minified framing…
  expect(parseMessage(compacted).body).toBe("<html><body>hello\n  world</body></html>");
  // …and re-prettifying the write-back is a fixed point, so editing in Pretty
  // never drifts further with each view switch.
  expect(prettyMessage(compacted)).toBe(pretty);
 });

 test("a body with nothing formattable passes through untouched", () => {
  expect(compactMessage(FORM)).toBe(FORM);
 });
});
