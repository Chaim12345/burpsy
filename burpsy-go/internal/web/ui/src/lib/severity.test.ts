import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { cookieHeaderTokens } from "./message";
import { severityColor, severityKey, severityTone } from "./severity";

// burpsy-react-ui-axm9: one severity scale for every surface, and cookie colouring in the editor.

describe("severity", () => {
 test("folds every spelling a surface receives", () => {
  expect(severityKey("High")).toBe("high");
  expect(severityKey("HIGH")).toBe("high");
  expect(severityKey("high")).toBe("high");
  expect(severityKey("INFO")).toBe("informational");
  expect(severityKey("Informational")).toBe("informational");
  expect(severityKey("bogus")).toBeUndefined();
 });

 test("keeps the mapping the four surfaces used to repeat", () => {
  expect(["Critical", "High", "Medium", "Low", "Informational", "", "x"].map(severityTone)).toEqual([
   "bad",
   "bad",
   "warn",
   "info",
   "neutral",
   "neutral",
   "neutral",
  ]);
  // Advisories spell severities in capitals; they map the same.
  expect(["HIGH", "MEDIUM", "LOW", "INFO"].map(severityTone)).toEqual(["bad", "warn", "info", "neutral"]);
 });

 test("the colour is the themeable token, and every token it names exists", () => {
  expect(severityColor("Medium")).toBe("var(--severity-medium)");
  expect(severityColor("nope")).toBe("var(--severity-informational)");
  const css = readFileSync(join(import.meta.dir, "..", "styles.css"), "utf8");
  for (const key of ["critical", "high", "medium", "low", "informational"]) expect(css).toMatch(new RegExp(`--severity-${key}:`));
 });

 test("no page decides a severity's colour on its own any more", () => {
  // The four local switches this replaced each matched `case "High":` / `case "HIGH":` and returned a
  // tone. A new one is exactly the drift the shared scale exists to prevent.
  const pages = join(import.meta.dir, "..", "pages");
  const offenders = readdirSync(pages)
   .filter((n) => n.endsWith(".tsx"))
   .filter((n) => /case "(High|HIGH)":[\s\S]{0,80}return "bad"/.test(readFileSync(join(pages, n), "utf8")));
  expect(offenders).toEqual([]);
 });
});

describe("cookieHeaderTokens", () => {
 test("a Cookie line yields every pair's name and value", () => {
  const line = "Cookie: session=abc; theme=dark";
  const spans = cookieHeaderTokens(line).map((t) => [t.cls, line.slice(t.start, t.end)]);
  expect(spans).toEqual([
   ["cookie-name", "session"],
   ["cookie-value", "abc"],
   ["cookie-name", "theme"],
   ["cookie-value", "dark"],
  ]);
 });

 test("a Set-Cookie line yields only the cookie, not its attributes", () => {
  const line = "Set-Cookie: id=42; Path=/; HttpOnly";
  expect(cookieHeaderTokens(line).map((t) => line.slice(t.start, t.end))).toEqual(["id", "42"]);
 });

 test("spans are in increasing order (the editor's RangeSetBuilder requires it) and other headers yield none", () => {
  const spans = cookieHeaderTokens("cookie: a=1;b;c=");
  for (let i = 1; i < spans.length; i++) expect(spans[i]!.start).toBeGreaterThanOrEqual(spans[i - 1]!.end);
  expect(cookieHeaderTokens("Host: example.com")).toEqual([]);
  expect(cookieHeaderTokens("no colon here")).toEqual([]);
 });
});
