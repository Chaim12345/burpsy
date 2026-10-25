import { describe, expect, test } from "bun:test";
import golden from "./intruder-extract.golden.json";
import { buildExtractRule, escapeRegexLiteral, previewExtract } from "./intruder-extract";

// "Define extract grep from response" (df8r). The golden cases are shared with
// internal/web/intruder_extract_golden_test.go, which runs every regex below through the real
// /api/intruder/run and asserts the Go engine extracts the same value the browser previews.

describe("building a Grep - Extract rule from a highlighted response", () => {
  for (const c of golden.cases) {
    test(`golden: ${c.name}`, () => {
      expect(c.response.slice(c.start, c.end)).toBe(c.value);
      const built = buildExtractRule(c.response, c.start, c.end);
      if (!built.ok) throw new Error(built.reason);
      expect(built.rule.regex).toBe(c.regex);
      const preview = previewExtract(built.rule.regex, c.response, { start: c.start, end: c.end });
      expect(preview).toEqual({ ok: true, value: c.value, at: c.start, matchesSelection: true, truncated: false });
    });
  }

  test("regex metacharacters and control characters in the anchors are escaped", () => {
    expect(escapeRegexLiteral("a.b*c+d?(e)[f]{g}|h^i$j\\k")).toBe("a\\.b\\*c\\+d\\?\\(e\\)\\[f\\]\\{g\\}\\|h\\^i\\$j\\\\k");
    expect(escapeRegexLiteral("x\r\n\ty\x00\x7f")).toBe("x\\r\\n\\ty\\x00\\x7f");
    // The escaped literal matches exactly itself.
    const text = "q=(a|b)*[c]$";
    expect(new RegExp(escapeRegexLiteral(text)).exec(`xx${text}yy`)?.index).toBe(2);
  });

  test("a short anchor that occurs earlier is grown until its first occurrence is the right one", () => {
    // "value=" occurs twice; the selection is in the second, so the prefix must reach back past it.
    const text = "HTTP/1.1 200 OK\r\n\r\nid=1 value=first; id=2 value=second;";
    const start = text.indexOf("second");
    const built = buildExtractRule(text, start, start + "second".length);
    if (!built.ok) throw new Error(built.reason);
    expect(built.rule.prefix.endsWith("value=")).toBe(true);
    expect(text.indexOf(built.rule.prefix)).toBe(start - built.rule.prefix.length);
    const preview = previewExtract(built.rule.regex, text, { start, end: start + 6 });
    expect(preview.ok && preview.value).toBe("second");
    expect(preview.ok && preview.matchesSelection).toBe(true);
  });

  test("a delimiter inside a token run longer than 200 characters is cut at 200, not abandoned", () => {
    // A value followed by a long padding run (a JWT, a base64 blob): the boundary-extended delimiter
    // would be the whole run. Burp abandons it and extracts to the end; this keeps 200 characters.
    const text = `HTTP/1.1 200 OK\r\n\r\nuser=admin ${"x".repeat(500)}`;
    const start = text.indexOf("admin");
    const built = buildExtractRule(text, start, start + 5);
    if (!built.ok) throw new Error(built.reason);
    expect(built.rule.suffix.length).toBe(200);
    const preview = previewExtract(built.rule.regex, text, { start, end: start + 5 });
    expect(preview.ok && preview.value).toBe("admin");
    expect(preview.ok && preview.matchesSelection).toBe(true);
  });

  test("an empty or out-of-range selection is refused, not turned into a rule", () => {
    expect(buildExtractRule("abc", 1, 1).ok).toBe(false);
    expect(buildExtractRule("abc", 2, 9).ok).toBe(false);
  });

  test("the preview says when a rule extracts something other than the highlighted text", () => {
    const text = "a=1 a=2";
    const preview = previewExtract("a=(\\d)", text, { start: 6, end: 7 });
    expect(preview).toEqual({ ok: true, value: "1", at: 2, matchesSelection: false, truncated: false });
    expect(previewExtract("zzz(\\d)", text)).toEqual({ ok: true, value: null, at: null, matchesSelection: false, truncated: false });
  });

  test("a leading RE2 inline flag group previews with the matching RegExp flag", () => {
    const preview = previewExtract("(?i)TOKEN=(\\w+)", "token=abc");
    expect(preview.ok && preview.value).toBe("abc");
  });

  test("a value the engine would cut at 256 bytes is flagged", () => {
    const text = `x=${"é".repeat(200)};`;
    const preview = previewExtract("x=([^;]*);", text);
    expect(preview.ok && preview.truncated).toBe(true);
  });

  test("a pattern the browser cannot compile is reported, not previewed as no match", () => {
    const preview = previewExtract("a(", "abc");
    expect(preview.ok).toBe(false);
  });
});
