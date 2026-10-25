import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { highlightBorderStyle } from "./collaborator";
import { HIGHLIGHTS } from "../lib/types";

/**
 * burpsy-react-ui-5jve: every highlight coloured the same border because the picker referenced
 * `--accent-<name>` tokens that styles.css never defines — only `--highlight-<name>` is (see the
 * row-highlight-* rules History and Organizer already paint rows with). A pure string assertion on
 * the var() name would pass even for a made-up token, so this reads the real stylesheet and checks
 * the token highlightBorderStyle names is one styles.css actually binds a colour to — the same
 * check that would have caught the original bug, since `--accent-red` never appears there.
 */
const stylesheet = readFileSync(join(import.meta.dir, "..", "styles.css"), "utf8");

function definesCustomProperty(token: string): boolean {
 return new RegExp(`--${token}\\s*:`).test(stylesheet);
}

describe("highlightBorderStyle", () => {
 test("no highlight, or the 'none' sentinel, renders no border", () => {
  expect(highlightBorderStyle(undefined)).toBeUndefined();
  expect(highlightBorderStyle("none")).toBeUndefined();
 });

 test("every named highlight resolves to a --highlight-<name> custom property styles.css actually defines", () => {
  for (const name of HIGHLIGHTS.filter((candidate) => candidate !== "none")) {
   const style = highlightBorderStyle(name);
   const match = style?.borderLeft?.toString().match(/var\((--[\w-]+),/);
   expect(match, `${name}: no var() with a fallback in "${style?.borderLeft}"`).toBeTruthy();
   const token = match![1]!.replace(/^--/, "");
   expect(
    definesCustomProperty(token),
    `${name} resolved to --${token}, which styles.css never defines — it would fall back to the same --accent for every colour`,
   ).toBe(true);
  }
 });

 test("two different colours resolve to two different custom properties, so they can render differently", () => {
  expect(highlightBorderStyle("red")).not.toEqual(highlightBorderStyle("green"));
  expect(highlightBorderStyle("red")).toEqual({ borderLeft: "3px solid var(--highlight-red, var(--accent))" });
 });
});
