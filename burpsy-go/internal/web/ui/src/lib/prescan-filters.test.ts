// The pre-scan filter step (burpsy-react-ui-a13): the query the dialog composes, and the counts it
// predicts. The DOM half needs a mounted console and is driven live; what is worth pinning without
// one is the composition, because a wrong clause here is a filter that removes the wrong items — the
// failure an operator cannot see, since the sweep still runs and still reports counts.
import { describe, expect, test } from "bun:test";
import {
 BURP_DEFAULT_HIDDEN_EXTENSIONS,
 DEFAULT_PRESCAN_FILTERS,
 countFiltered,
 normaliseExtension,
 parseExtensions,
 pathExtensionOf,
 prescanExclude,
 queryParamCountOf,
} from "./prescan-filters";

describe("prescanExclude", () => {
 test("no filters is no query at all, not a query that matches nothing", () => {
  expect(
   prescanExclude({ removeNoParameters: false, hiddenExtensions: [], removeDuplicates: false }),
   "an empty string is what the server reads as keep-everything; a match-nothing clause would silently empty every sweep",
  ).toBe("");
 });

 test("Burp's shipped extension list becomes a disjunction the parenthesises", () => {
  const query = prescanExclude({ ...DEFAULT_PRESCAN_FILTERS, hiddenExtensions: ["js", "png"] });
  expect(query).toBe('not (extension = "js" or extension = "png")');
  // The parentheses are load-bearing: without them `not extension = "js" or extension = "png"`
  // would keep every .js and drop every .png, which is the opposite filter.
  expect(query.startsWith("not (")).toBe(true);
 });

 test("a second clause is ANDed under the one not, so both are kept", () => {
  const query = prescanExclude({ removeNoParameters: true, hiddenExtensions: ["png"], removeDuplicates: false });
  expect(query).toBe('not (params = 0 and (extension = "png"))');
 });

 test("extensions are folded and dot-prefixes stripped, because a URL names LOGO.PNG as logo.png", () => {
  expect(prescanExclude({ removeNoParameters: false, hiddenExtensions: [".PNG", " Js "], removeDuplicates: false })).toBe(
   'not (extension = "png" or extension = "js")',
  );
 });

 test("an empty extension list is no extension clause, so remove-no-parameters still works alone", () => {
  expect(prescanExclude({ removeNoParameters: true, hiddenExtensions: [""], removeDuplicates: false })).toBe(
   "not params = 0",
  );
 });
});

describe("parseExtensions", () => {
 test("reads the wizard's comma list and an operator's pasted line, dropping what cannot be a value", () => {
  expect(parseExtensions("js, gif,png ico, woff2")).toEqual(["js", "gif", "png", "ico", "woff2"]);
 });

 test("duplicates fold to one, so a list typed twice does not double-count in the dialog", () => {
  expect(parseExtensions("png,png,.PNG")).toEqual(["png"]);
 });

 test("an entry carrying a quote cannot be a field value and is dropped rather than quoted into a query", () => {
  expect(parseExtensions('ok, "bad"')).toEqual(["ok"]);
 });

 test("a space separates entries, because an operator pastes a newline-separated list", () => {
  expect(parseExtensions("also\nbad")).toEqual(["also", "bad"]);
 });
});

describe("the shipped defaults", () => {
 test("are Burp's list verbatim", () => {
  expect([...BURP_DEFAULT_HIDDEN_EXTENSIONS]).toEqual([
   "js", "gif", "jpg", "png", "ico", "css", "woff", "woff2", "ttf", "svg",
  ]);
 });
});

describe("pathExtensionOf", () => {
 test("reads the last segment, folded, and ignores the query string", () => {
  expect(pathExtensionOf("/static/LOGO.PNG")).toBe("png");
  expect(pathExtensionOf("/a/b.js?v=2")).toBe("js");
 });

 test("an extensionless path has no extension, which is not the empty extension", () => {
  expect(pathExtensionOf("/app/page")).toBeNull();
  expect(pathExtensionOf("/app/page?x=.png")).toBeNull();
  // A dotfile is a name, not an extension — otherwise `.gitignore` would be a "gitignore" file.
  expect(pathExtensionOf("/.gitignore")).toBeNull();
  expect(pathExtensionOf("/trailing.")).toBeNull();
 });
});

describe("queryParamCountOf", () => {
 test("counts query parameters, which is what the grammar's params field means", () => {
  expect(queryParamCountOf("/a")).toBe(0);
  expect(queryParamCountOf("/a?")).toBe(0);
  expect(queryParamCountOf("/a?x=1")).toBe(1);
  expect(queryParamCountOf("/a?x=1&y=2&z=3")).toBe(3);
  // Empty pairs are separators, not parameters.
  expect(queryParamCountOf("/a?x=1&&y=2&")).toBe(2);
 });
});

describe("countFiltered", () => {
 const items = [
  { path: "/app/page" },
  { path: "/app/search?q=burp" },
  { path: "/static/app.js" },
  { path: "/static/logo.png" },
 ];

 test("counts each filter separately, so the dialog can say what each one removes", () => {
  const counts = countFiltered(items, { ...DEFAULT_PRESCAN_FILTERS, removeNoParameters: true });
  expect(counts.extensions, "the two static assets").toBe(2);
  expect(counts.noParameters, "the paths with no query string").toBe(3);
 });

 test("an exchange removed by both filters is counted under each, because the dialog answers two "
  + "questions, and the total is the sum of the two lists rather than the size of their union", () => {
   const counts = countFiltered([{ path: "/static/app.js" }], { ...DEFAULT_PRESCAN_FILTERS, removeNoParameters: true });
   expect(counts.extensions).toBe(1);
   expect(counts.noParameters).toBe(1);
   expect(counts.total).toBe(2);
  });

 test("a filter that is off counts nothing, so the dialog never states a number for a filter nobody asked for", () => {
  const off = countFiltered(items, DEFAULT_PRESCAN_FILTERS);
  expect(off.noParameters, "remove-no-parameters is off by default, like Burp's checkbox").toBe(0);
  const on = countFiltered(items, { ...DEFAULT_PRESCAN_FILTERS, removeNoParameters: true });
  expect(on.noParameters).toBe(3);
 });

 test("no filters removes nothing", () => {
  expect(countFiltered(items, { removeNoParameters: false, hiddenExtensions: [], removeDuplicates: false }).total).toBe(0);
 });
});

describe("normaliseExtension", () => {
 test("folds case and drops a leading dot", () => {
  expect(normaliseExtension(" .PNG ")).toBe("png");
 });
});
