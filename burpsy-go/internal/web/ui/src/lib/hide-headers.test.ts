// Burp's eye button (burpsy-react-ui-whr): the message editor hides the headers named in two
// editable lists, in Pretty only.
//
// The DOM half (pressing the eye and watching a header leave the pane) needs a mounted console
// and is driven live; what is worth pinning without one is the transform itself, the list parser
// the settings textarea and the stored list share, and the editor/Store wiring that decides which
// list applies to which direction. A wrong filter would hide a header an operator needed, which is
// worse than no filter at all — that is the risk these tests exist for.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_HIDE_REQUEST_HEADERS, DEFAULT_HIDE_RESPONSE_HEADERS, hideHeadersIn, parseHeaderNames } from "./message";

const REQUEST = "GET /a HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nAccept-Language: en\r\nX-App-Token: live\r\n\r\nbody";

describe("hideHeadersIn", () => {
 test("removes the named lines and leaves every other byte exactly as captured", () => {
  const out = hideHeadersIn(REQUEST, ["accept", "accept-language"]);
  expect(out, "the start line, the surviving headers and the body must survive byte for byte").toBe(
   "GET /a HTTP/1.1\r\nHost: app.test\r\nX-App-Token: live\r\n\r\nbody",
  );
 });

 test("is case-insensitive on the header name, because header names fold", () => {
  const out = hideHeadersIn("HTTP/1.1 200 OK\r\nACCEPT-LANGUAGE: en\r\nX-Live: 1\r\n\r\nb", ["Accept-Language"]);
  expect(out).toBe("HTTP/1.1 200 OK\r\nX-Live: 1\r\n\r\nb");
 });

 test("hides a name that appears twice, because both lines are the same header", () => {
  const out = hideHeadersIn("HTTP/1.1 200 OK\r\nVary: A\r\nX-Live: 1\r\nVary: B\r\n\r\nb", ["vary"]);
  expect(out).toBe("HTTP/1.1 200 OK\r\nX-Live: 1\r\n\r\nb");
 });

 test("takes a folded continuation line with its header, rather than folding it onto the previous one", () => {
  const raw = "GET /a HTTP/1.1\r\nX-Long: one\r\n two\r\nX-Live: 1\r\n\r\nb";
  const out = hideHeadersIn(raw, ["x-long"]);
  expect(out, "an orphaned continuation would become part of X-Live's value, silently changing a header that was never on the list").toBe(
   "GET /a HTTP/1.1\r\nX-Live: 1\r\n\r\nb",
  );
 });

 test("filters an LF-only message too: the line ending is the message's, not an assumption", () => {
  const out = hideHeadersIn("GET /a HTTP/1.1\nServer: x\nX-Live: 1\n\nbody", ["server"]);
  expect(out).toBe("GET /a HTTP/1.1\nX-Live: 1\n\nbody");
 });

 test("an empty list, an all-match list and a name that is not there all behave", () => {
  expect(hideHeadersIn(REQUEST, [])).toBe(REQUEST);
  expect(hideHeadersIn(REQUEST, ["x-absent"])).toBe(REQUEST);
  expect(hideHeadersIn("GET / HTTP/1.1\r\n\r\nb", ["host"])).toBe("GET / HTTP/1.1\r\n\r\nb");
 });

 test("never touches the bytes the editor edits: the input survives the call", () => {
  const copy = REQUEST;
  hideHeadersIn(REQUEST, ["accept"]);
  expect(REQUEST).toBe(copy);
 });

 test("a header whose whole value spans lines keeps the body boundary intact", () => {
  const out = hideHeadersIn('GET / HTTP/1.1\r\nHost: h\r\nServer: x\r\n\r\n{"a":1}', ["server"]);
  expect(out).toBe('GET / HTTP/1.1\r\nHost: h\r\n\r\n{"a":1}');
 });
});

describe("parseHeaderNames", () => {
 test("one name per line, folded to lower case and de-duplicated", () => {
  expect(parseHeaderNames("Date\ndate\nServer\n")).toEqual(["date", "server"]);
 });

 test("a pasted whole header line is tolerated, because that is how the line reads in a message", () => {
  expect(parseHeaderNames("Cache-Control: no-store, no-cache")).toEqual(["cache-control"]);
 });

 test("blank lines and padding do not become header names", () => {
  expect(parseHeaderNames("\n  \n Server \n")).toEqual(["server"]);
 });
});

describe("the defaults", () => {
 test("the response list is the protocol-level noise and not a findings-relevant header", () => {
  // Set-Cookie can BE the finding (a rotated or fixated token), Content-Type/Length are how a
  // reader checks a mislabelled or truncated body, and the security headers are the signal. A
  // default that hides any of them would hide the answer.
  for (const kept of ["set-cookie", "content-type", "content-length", "strict-transport-security", "x-frame-options"]) {
   expect(DEFAULT_HIDE_RESPONSE_HEADERS, `${kept} must not be hidden out of the box`).not.toContain(kept);
  }
  expect(DEFAULT_HIDE_RESPONSE_HEADERS).toContain("date");
  expect(DEFAULT_HIDE_RESPONSE_HEADERS).toContain("server");
 });

 test("every default is already in the stored form the parser produces", () => {
  expect(parseHeaderNames(DEFAULT_HIDE_REQUEST_HEADERS.join("\n"))).toEqual(DEFAULT_HIDE_REQUEST_HEADERS);
  expect(parseHeaderNames(DEFAULT_HIDE_RESPONSE_HEADERS.join("\n"))).toEqual(DEFAULT_HIDE_RESPONSE_HEADERS);
 });
});

// The wiring the DOM half depends on: which list reaches which pane, and that the two settings
// sections (the editor's hide lists and the Comparer's dim list) stay separate features. Mirrors
// url-encode-as-you-type.test.ts's approach — the reader of a mounted console is the live pass.
const editor = readFileSync(join(import.meta.dir, "..", "ui", "editor.tsx"), "utf8");
const store = readFileSync(join(import.meta.dir, "store.ts"), "utf8");
const settings = readFileSync(join(import.meta.dir, "..", "pages", "settings.tsx"), "utf8");
const sections = readFileSync(join(import.meta.dir, "settings-sections.ts"), "utf8");

describe("the editor wire", () => {
 test("the pane's own direction picks the list", () => {
  expect(editor, "a request pane must read the request list and a response pane the response list").toMatch(
   /isResponse\(value\) \? hideResponseHeaders : hideRequestHeaders/,
  );
 });

 test("the eye is offered only in Pretty, and only when the list has something to hide", () => {
  expect(editor).toMatch(/active === "pretty" && hideList\.length > 0/);
 });

 test("the filter feeds the Pretty render and the clipboard, and nothing else", () => {
  expect(editor).toMatch(/hideHeadersIn\(prettied, hideList\)/g);
  expect(editor.replace(/\n/g, " ")).not.toMatch(/hideHeadersIn\((?!prettied)/);
 });

 test("editing is off while the eye is on, so an edit cannot be written back against a filtered head", () => {
  expect(editor).toMatch(/editable && !charsetActive && !hiding/);
  expect(editor, "the operator must be told why the pane stopped accepting edits").toMatch(/Press the eye again to edit/);
 });

 test("an unpressed eye follows the Settings default; a pressed one wins for the life of the pane", () => {
  expect(editor).toMatch(/hidePicked \?\? hideHeadersByDefault/);
  expect(editor).toMatch(/useState<boolean \| null>\(null\)/);
 });

 test("both lists and the default toggle are persisted, like the editor's other prefs", () => {
  for (const key of ["hideRequestHeaders", "hideResponseHeaders", "hideHeadersByDefault"]) {
   expect(store, `${key} must survive a reload`).toMatch(new RegExp(`${key}: state\\.${key}`));
  }
 });
});

describe("the two sections cannot be read for one another", () => {
 test("the editor's section is its own registry entry, next to the Comparer's", () => {
  expect(sections).toMatch(/id: "message-editor"/);
  expect(sections).toMatch(/title: "Comparer: uninteresting headers"/);
  const order = [...sections.matchAll(/id: "([a-z-]+)"/g)].map((m) => m[1]);
  expect(order.indexOf("message-editor"), "the two must sit together so the summaries are read as a pair").toBe(
   order.indexOf("uninteresting-headers") - 1,
  );
 });

 test("the editor's card renders the registry's title and says what it is not", () => {
  expect(settings).toMatch(/title="Message editor"/);
  expect(settings, "the card must name the Comparer list it is not").toMatch(/Comparer: uninteresting headers/);
  expect(settings, "the Comparer card must point back").toMatch(/Not the message editor&rsquo;s hide-headers lists/);
 });
});
