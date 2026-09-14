import { describe, expect, test } from "bun:test";
import { describeScopeRule, parseScopePaste } from "./scope-paste";

// Paste URL / Load from file for the scope table (dao). The contract is Burp's
// "Add a new item by pasting a URL": a URL is decomposed into the arms the Add form
// already has. Every refusal below is asserted as carefully as every acceptance,
// because the failure that matters here is silent — a host that never becomes a rule
// leaves the scan either touching something the operator did not authorise or skipping
// something they did, and nothing afterwards says which.

describe("parseScopePaste", () => {
 test("a full URL becomes the arms the form has", () => {
  expect(parseScopePaste("https://api.example.com:8443/v2/orders").rules).toEqual([
   { pattern: "api.example.com", port: 8443, path: "/v2/orders", protocol: "https" },
  ]);
 });

 test("a URL with nothing but a host scopes the whole host", () => {
  // "/" is the whole host, which is what a rule with no path arm already covers; a rule
  // built with path "/" would be right by accident and wrong the moment anything reads
  // the arm — the same reasoning the Add form's "blank means the whole host" follows.
  expect(parseScopePaste("https://example.com").rules).toEqual([{ pattern: "example.com", protocol: "https" }]);
  expect(parseScopePaste("https://example.com/").rules).toEqual([{ pattern: "example.com", protocol: "https" }]);
 });

 test("a default port is dropped rather than written into the rule", () => {
  // A rule with no port arm covers 80 and 443 already. Keeping ":80" would narrow it to
  // that port, which is not what the operator pasted and not what Burp builds.
  expect(parseScopePaste("http://example.com:80/x").rules).toEqual([
   { pattern: "example.com", path: "/x", protocol: "http" },
  ]);
  expect(parseScopePaste("https://example.com:443/x").rules).toEqual([
   { pattern: "example.com", path: "/x", protocol: "https" },
  ]);
 });

 test("a URL's host is lowercased and its path normalised, because that is what is matched", () => {
  expect(parseScopePaste("https://EXAMPLE.com/a/b/../c").rules).toEqual([
   { pattern: "example.com", path: "/a/c", protocol: "https" },
  ]);
 });

 test("a query is not mistaken for a path arm", () => {
  expect(parseScopePaste("https://example.com/search?q=x").rules).toEqual([
   { pattern: "example.com", path: "/search", protocol: "https" },
  ]);
 });

 test("a bare host pattern is accepted, with or without a port and with a wildcard", () => {
  expect(parseScopePaste("api.example.com").rules).toEqual([{ pattern: "api.example.com" }]);
  expect(parseScopePaste("api.example.com:8443").rules).toEqual([{ pattern: "api.example.com", port: 8443 }]);
  expect(parseScopePaste("*.example.com").rules).toEqual([{ pattern: "*.example.com" }]);
  expect(parseScopePaste("10.0.0.1:8080").rules).toEqual([{ pattern: "10.0.0.1", port: 8080 }]);
 });

 test("a bracketed IPv6 literal keeps its own colons and only takes a port after the bracket", () => {
  expect(parseScopePaste("[2001:db8::1]").rules).toEqual([{ pattern: "[2001:db8::1]" }]);
  expect(parseScopePaste("[2001:db8::1]:8443").rules).toEqual([{ pattern: "[2001:db8::1]", port: 8443 }]);
 });

 test("half a bracket is refused rather than becoming a host nothing can match", () => {
  const result = parseScopePaste("[2001:db8::1");
  expect(result.rules).toEqual([]);
  expect(result.refused[0]!.reason).toContain("bracketed address");
 });

 test("blank lines and comments pass through as nothing at all", () => {
  const result = parseScopePaste("# engagement acme, 2026-09\n\nhttps://a.test\n   \n  # the api host\nhttps://b.test\n");
  expect(result.rules).toEqual([
   { pattern: "a.test", protocol: "https" },
   { pattern: "b.test", protocol: "https" },
  ]);
  expect(result.refused).toEqual([]);
  expect(result.duplicates).toEqual([]);
 });

 test("multiple entries become multiple rules, line by line", () => {
  const result = parseScopePaste("https://a.test/x\nb.test:8443\nhttps://c.test:9443/y");
  expect(result.rules).toEqual([
   { pattern: "a.test", path: "/x", protocol: "https" },
   { pattern: "b.test", port: 8443 },
   { pattern: "c.test", port: 9443, path: "/y", protocol: "https" },
  ]);
 });

 test("an empty box is no rules and no refusals, not one empty rule", () => {
  expect(parseScopePaste("")).toEqual({ rules: [], refused: [], duplicates: [] });
  expect(parseScopePaste("  \n\t\n   \n")).toEqual({ rules: [], refused: [], duplicates: [] });
 });

 test("a comma is not a separator here, so a comma-separated list is refused line by line", () => {
  // The crawl box splits on commas; this one does not. Silently splitting would invent a
  // third format for the input where a misread host means a scan that touches something
  // the operator did not authorise, so the entry is reported instead.
  const result = parseScopePaste(",");
  expect(result.rules).toEqual([]);
  expect(result.refused).toHaveLength(1);
  expect(result.refused[0]!.reason).toContain("not a host pattern");
 });
});

describe("parseScopePaste refusals", () => {
 test("a scheme with no authority is refused rather than read as a host named after its path", () => {
  // `new URL("http:///path")` answers hostname "path". A rule built from that covers a
  // host nobody named, so the empty-authority form has to be caught before the parse.
  const result = parseScopePaste("http:///path");
  expect(result.rules).toEqual([]);
  expect(result.refused).toHaveLength(1);
  expect(result.refused[0]!.line).toBe(1);
  expect(result.refused[0]!.reason).toContain("has no host");
 });

 test("a scheme that is not http or https is refused by name", () => {
  // The arm can only be http or https, so a ftp:// entry would build a rule that matches
  // nothing — a restriction the operator believes is in force and is not.
  const result = parseScopePaste("ftp://files.test/pub");
  expect(result.rules).toEqual([]);
  expect(result.refused[0]!.reason).toContain("ftp:");
 });

 test("a path with no scheme is refused with the URL to paste instead", () => {
  const result = parseScopePaste("example.com/api");
  expect(result.rules).toEqual([]);
  // Asserted on the advice rather than on the words "no scheme": the generic not-a-host-pattern
  // refusal also contains those words, so an assertion on them passes whether or not this entry is
  // recognised as a URL that lost its scheme — which is the case worth telling the operator about,
  // because the fix is to paste the rest of the line rather than to rewrite the host.
  expect(result.refused[0]!.reason).toContain("paste the whole URL");
 });

 test("a port that is not a number, and one outside 1..65535, are both refused", () => {
  const result = parseScopePaste("example.com:abc\nexample.com:70000");
  expect(result.rules).toEqual([]);
  expect(result.refused.map((r) => r.line)).toEqual([1, 2]);
  expect(result.refused[0]!.reason).toContain("not a number");
  expect(result.refused[1]!.reason).toContain("1..65535");
 });

 test("a URL with an unreadable port is refused rather than silently dropping the port", () => {
  const result = parseScopePaste("https://example.com:99999/x");
  expect(result.rules).toEqual([]);
  expect(result.refused).toHaveLength(1);
 });

 test("a line with a space is refused as two entries on one line, and quoted back", () => {
  const result = parseScopePaste("https://a.test https://b.test");
  expect(result.rules).toEqual([]);
  expect(result.refused[0]!.text).toBe("https://a.test https://b.test");
  expect(result.refused[0]!.reason).toContain("not a URL this can read");
 });

 test("every refusal carries the line number the operator can count to", () => {
  const result = parseScopePaste("https://good.test\nbad host\nexample.com:abc\nhttps://also-good.test");
  expect(result.rules.map((r) => r.pattern)).toEqual(["good.test", "also-good.test"]);
  expect(result.refused.map((r) => r.line)).toEqual([2, 3]);
 });
});

describe("parseScopePaste duplicates", () => {
 test("an entry already in scope is reported, not added a second time", () => {
  const result = parseScopePaste("https://api.test/v2", [{ pattern: "api.test", path: "/v2", protocol: "https" }]);
  expect(result.rules).toEqual([]);
  expect(result.duplicates).toHaveLength(1);
  expect(result.duplicates[0]!.reason).toContain("already in scope");
 });

 test("the same entry twice in one box becomes one rule, and the second line is the duplicate", () => {
  const result = parseScopePaste("https://a.test\nhttps://a.test");
  expect(result.rules).toEqual([{ pattern: "a.test", protocol: "https" }]);
  expect(result.duplicates.map((r) => r.line)).toEqual([2]);
 });

 test("two rules on one host differing only in an arm are not duplicates of each other", () => {
  // The ordinary case the scope table exists for: a host-wide rule and a path-narrowed
  // one. Collapsing them would forbid an operator from scoping the whole host and then
  // narrowing part of it.
  const result = parseScopePaste("https://api.test\nhttps://api.test/v2");
  expect(result.rules).toEqual([
   { pattern: "api.test", protocol: "https" },
   { pattern: "api.test", path: "/v2", protocol: "https" },
  ]);
  expect(result.duplicates).toEqual([]);
 });

 describe("describeScopeRule reads like the entry the operator pasted", () => {
  test("a URL rule prints as a URL, not as its arms run together", () => {
   // The arms concatenated produce "httpsa.test" — the scheme has to be followed by its
   // separator, which is a defect the duplicate message showed before this was written.
   expect(describeScopeRule({ pattern: "a.test", port: 9443, path: "/x", protocol: "https" })).toBe("https://a.test:9443/x");
  });

  test("a rule with no scheme arm prints as a pattern, because it genuinely has no scheme", () => {
   expect(describeScopeRule({ pattern: "*.example.com" })).toBe("*.example.com");
   expect(describeScopeRule({ pattern: "a.test", port: 8443 })).toBe("a.test:8443");
  });
 });

 test("a bare-pattern duplicate of a URL rule is recognised as the same rule", () => {
  // protocol is normalised into the identity, so `https://a.test` and a bare `a.test`
  // are different rules (one is scheme-restricted) while `https://a.test` pasted twice
  // is one — the point is that identity is compared on the arms, not on the spelling.
  const result = parseScopePaste("a.test", [{ pattern: "a.test" }]);
  expect(result.duplicates).toHaveLength(1);
  const other = parseScopePaste("https://a.test", [{ pattern: "a.test" }]);
  expect(other.rules.map((r) => r.protocol)).toEqual(["https"]);
 });
});
