import { describe, expect, test } from "bun:test";
import { lockedPreview, PREVIEW_CSP } from "./data.crawllive";

describe("the live view's wire-HTML preview", () => {
 test("puts a deny-all CSP before the page, so the preview loads nothing from the target", () => {
  const out = lockedPreview(
   '<html><head><script src="https://target/x.js"></script></head><body><img src="https://target/a.png"></body></html>',
  );
  expect(out.startsWith('<meta http-equiv="Content-Security-Policy"')).toBe(true);
  expect(PREVIEW_CSP).toContain("default-src 'none'");
  expect(PREVIEW_CSP).not.toContain("script-src");
  expect(out.indexOf("Content-Security-Policy")).toBeLessThan(out.indexOf("<script"));
 });
});
