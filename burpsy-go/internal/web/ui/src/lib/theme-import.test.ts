import { describe, expect, test } from "bun:test";
import { isThemeColour, parseThemeFile, themeTokenVars, THEME_SLOTS } from "./theme-import";

// burpsy-react-ui-fpew: a JSON theme import scoped to burpsy's own tokens. The parser is the honest
// part — it fills only named slots, refuses a slot burpsy has no token for (rather than silently
// dropping it), and refuses a value that is not a colour.
describe("parseThemeFile", () => {
 test("accepts an object naming known slots with colours, keeping the name", () => {
  const result = parseThemeFile('{"name":"House","tokens":{"paper":"#0b0b0b","text":"#e6e6e6"}}');
  expect("theme" in result).toBe(true);
  if ("theme" in result) {
   expect(result.theme.name).toBe("House");
   expect(result.theme.tokens).toEqual({ paper: "#0b0b0b", text: "#e6e6e6" });
  }
 });

 test("refuses a slot burpsy has no token for, naming it", () => {
  const result = parseThemeFile('{"tokens":{"status-critical":"#f00"}}');
  expect("error" in result).toBe(true);
  if ("error" in result) {
   // Names the offending slot — the point of a house palette is that what you handed over is applied.
   expect(result.error).toContain("status-critical");
   expect(result.error).toContain("no token");
  }
 });

 test("refuses a value that is not a colour, naming the slot", () => {
  const result = parseThemeFile('{"tokens":{"paper":"not-a-colour"}}');
  expect("error" in result).toBe(true);
  if ("error" in result) expect(result.error).toContain("paper");
 });

 test("refuses non-JSON, an array, a missing tokens map, and an empty tokens map", () => {
  expect("error" in parseThemeFile("{bad")).toBe(true);
  expect("error" in parseThemeFile("[1,2,3]")).toBe(true);
  expect("error" in parseThemeFile('{"name":"x"}')).toBe(true);
  expect("error" in parseThemeFile('{"tokens":{}}')).toBe(true);
 });

 test("every known slot is accepted (the whitelist and the parser agree)", () => {
  const tokens: Record<string, string> = {};
  for (const slot of THEME_SLOTS) tokens[slot] = "#123456";
  const result = parseThemeFile(JSON.stringify({ tokens }));
  expect("theme" in result).toBe(true);
 });
});

describe("isThemeColour", () => {
 test("accepts hex in 3/4/6/8 digits and rgb/rgba/hsl/hsla", () => {
  for (const ok of ["#abc", "#abcd", "#aabbcc", "#aabbccdd", "rgb(1,2,3)", "rgba(1,2,3,0.5)", "hsl(200 50% 50%)", "hsla(200,50%,50%,.5)"]) {
   expect(isThemeColour(ok), `${ok} should be a colour`).toBe(true);
  }
 });
 test("rejects named colours and anything exotic, so the refusal is a real check", () => {
  for (const no of ["rebeccapurple", "url(x)", "#12", "", "12px", "expression(alert(1))"]) {
   expect(isThemeColour(no), `${no} should not be a colour`).toBe(false);
  }
 });
});

describe("themeTokenVars", () => {
 test("maps each slot to its --custom-property, so the override lands on the right token", () => {
  expect(themeTokenVars({ tokens: { paper: "#fff", "editor-bg": "#000" } })).toEqual({
   "--paper": "#fff",
   "--editor-bg": "#000",
  });
 });
});
