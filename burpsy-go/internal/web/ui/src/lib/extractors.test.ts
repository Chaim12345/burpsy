// The history extractor draft<->wire mapping and client validation (burpsy-react-ui-28n8).
//
// The wire shape is the contract the Go handler validates (sessionExtractDto in
// internal/web/api_session.go), so these assert the exact JSON an operator's form choices produce,
// not just that a round trip is lossless — a shape that round-trips through this file but is not what
// the server decodes would still fail in the browser.
import { describe, expect, test } from "bun:test";
import {
 draftToExtractor,
 emptyExtractorDraft,
 extractorColumnId,
 extractorSignature,
 extractorToDraft,
 MAX_HISTORY_EXTRACTORS,
 validateDrafts,
 type ExtractorDraft,
 type HistoryExtractor,
} from "./extractors";

describe("draftToExtractor produces the wire shape the server decodes", () => {
 test("body + regex with a capture group", () => {
  const draft: ExtractorDraft = { name: "csrf", fromKind: "body", header: "", how: "regex", pattern: 'value="([^"]+)"', group: "1" };
  expect(draftToExtractor(draft)).toEqual({ name: "csrf", from: "body", how: { regex: { pattern: 'value="([^"]+)"', group: 1 } } });
 });

 test("a header source becomes { header }", () => {
  const draft: ExtractorDraft = { name: "token", fromKind: "header", header: "X-Token", how: "whole", pattern: "", group: "1" };
  expect(draftToExtractor(draft)).toEqual({ name: "token", from: { header: "X-Token" }, how: "whole" });
 });

 test("a JSON path becomes { json_path }", () => {
  const draft: ExtractorDraft = { name: "uid", fromKind: "body", header: "", how: "json_path", pattern: "data.user.id", group: "1" };
  expect(draftToExtractor(draft)).toEqual({ name: "uid", from: "body", how: { json_path: "data.user.id" } });
 });

 test("group 0 is honoured (not coerced to the default 1)", () => {
  const draft: ExtractorDraft = { name: "whole-match", fromKind: "body", header: "", how: "regex", pattern: "\\d+", group: "0" };
  expect(draftToExtractor(draft).how).toEqual({ regex: { pattern: "\\d+", group: 0 } });
 });

 test("a blank or negative group falls back to the server default of 1", () => {
  for (const group of ["", "   ", "-2", "abc"]) {
   const draft: ExtractorDraft = { name: "g", fromKind: "body", header: "", how: "regex", pattern: "x", group };
   expect(draftToExtractor(draft).how).toEqual({ regex: { pattern: "x", group: 1 } });
  }
 });

 test("the name and header name are trimmed, so a stray space cannot split one column into two", () => {
  const draft: ExtractorDraft = { name: "  csrf ", fromKind: "header", header: "  X-Token  ", how: "whole", pattern: "", group: "1" };
  expect(draftToExtractor(draft)).toEqual({ name: "csrf", from: { header: "X-Token" }, how: "whole" });
 });
});

describe("extractorToDraft is the inverse", () => {
 const cases: HistoryExtractor[] = [
  { name: "csrf", from: "body", how: { regex: { pattern: "a(b)c", group: 2 } } },
  { name: "token", from: { header: "X-Token" }, how: "whole" },
  { name: "uid", from: "body", how: { json_path: "data.id" } },
  // `from` absent means the body, matching the optional field on the wire.
  { name: "nofrom", how: "whole" },
 ];
 for (const extractor of cases) {
  test(`round-trips ${extractor.name}`, () => {
   const back = draftToExtractor(extractorToDraft(extractor));
   // `from` defaults to "body" on the way out, so an absent-from input comes back explicit — the
   // server treats the two identically (extractFrom), which is the equality that matters.
   expect(back).toEqual({ ...extractor, from: extractor.from ?? "body" });
  });
 }

 test("a regex extraction with no explicit group reads back as group 1 in the draft", () => {
  expect(extractorToDraft({ name: "g", from: "body", how: { regex: { pattern: "x" } } }).group).toBe("1");
 });
});

describe("validateDrafts mirrors the server's 400s", () => {
 const ok = (over: Partial<ExtractorDraft> = {}): ExtractorDraft => ({ ...emptyExtractorDraft(), name: "a", pattern: "x", ...over });

 test("accepts a valid set", () => {
  expect(validateDrafts([ok({ name: "one" }), ok({ name: "two" })])).toBeNull();
  expect(validateDrafts([])).toBeNull();
 });

 test("rejects an empty name", () => {
  expect(validateDrafts([ok({ name: "   " })])).toMatch(/needs a name/);
 });

 test("rejects a duplicate name (after trimming)", () => {
  expect(validateDrafts([ok({ name: "dup" }), ok({ name: " dup " })])).toMatch(/unique/);
 });

 test("rejects more than the server's cap", () => {
  const many = Array.from({ length: MAX_HISTORY_EXTRACTORS + 1 }, (_, i) => ok({ name: `n${i}` }));
  expect(validateDrafts(many)).toMatch(/at most/i);
 });

 test("rejects a header source with no header name", () => {
  expect(validateDrafts([ok({ name: "h", fromKind: "header", header: " " })])).toMatch(/header with no name/);
 });

 test("rejects a regex or json_path method with no pattern", () => {
  expect(validateDrafts([ok({ name: "r", how: "regex", pattern: "" })])).toMatch(/no pattern/);
  expect(validateDrafts([ok({ name: "j", how: "json_path", pattern: "" })])).toMatch(/no path/);
 });

 test("whole-value needs no pattern", () => {
  expect(validateDrafts([ok({ name: "w", how: "whole", pattern: "" })])).toBeNull();
 });
});

describe("column identity", () => {
 test("namespaces the id so a user name cannot shadow a built-in column", () => {
  expect(extractorColumnId("status")).toBe("extractor:status");
  expect(extractorColumnId("status")).not.toBe("status");
 });

 test("the signature changes when the set or its order changes", () => {
  const a: HistoryExtractor = { name: "a", from: "body", how: "whole" };
  const b: HistoryExtractor = { name: "b", from: "body", how: "whole" };
  expect(extractorSignature([a, b])).toBe(extractorSignature([a, b]));
  expect(extractorSignature([a, b])).not.toBe(extractorSignature([b, a]));
  expect(extractorSignature([a])).not.toBe(extractorSignature([a, b]));
 });
});
