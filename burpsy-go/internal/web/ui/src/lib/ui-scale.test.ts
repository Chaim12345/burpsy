import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { uiScaleFactor } from "./store";

// burpsy-react-ui-9nlz: --ui-scale multiplies px lengths, so it must be unitless.
describe("uiScaleFactor", () => {
 test("maps every stored scale to a unitless factor", () => {
  expect(["100%", "110%", "125%", "150%"].map(uiScaleFactor)).toEqual(["1", "1.1", "1.25", "1.5"]);
 });
 test("a corrupted preference is the default, not an invalid value", () => {
  expect(uiScaleFactor("")).toBe("1");
  expect(uiScaleFactor("big")).toBe("1");
 });
 test("the stylesheet's default is unitless too", () => {
  const css = readFileSync(join(import.meta.dir, "..", "styles.css"), "utf8");
  const declared = /--ui-scale:\s*([^;]+);/.exec(css)?.[1]?.trim();
  expect(declared).toBe("1");
 });
});
