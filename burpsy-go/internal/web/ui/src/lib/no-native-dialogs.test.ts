/**
 * No native browser dialog anywhere in the console (burpsy-react-ui-bea3).
 *
 * window.confirm / window.prompt / window.alert ignore the theme and the UI scale, freeze the tab's
 * event loop while open, and return focus wherever the browser decides. Twelve calls in four files
 * existed when this test was written, each beside a comment explaining why a modal was too much
 * trouble at that call site; lib/dialogs.ts removed the trouble, and this keeps a thirteenth from
 * appearing.
 *
 * Structural, like keymap-installed.test.ts, because the defect is a call shape rather than a value.
 * Comments are stripped first so a docstring that names the retired API is not itself a failure.
 */
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const SRC = join(import.meta.dir, "..");

function sourceFiles(dir: string): string[] {
 const out: string[] = [];
 for (const entry of readdirSync(dir)) {
  const full = join(dir, entry);
  if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
  else if ((entry.endsWith(".ts") || entry.endsWith(".tsx")) && !entry.endsWith(".test.ts")) out.push(full);
 }
 return out;
}

/** Drop block and line comments. Crude on purpose: a `//` inside a string only loses the rest of
 *  that one line, and a native-dialog call hiding after a URL on the same line is not a real risk. */
export function stripComments(source: string): string {
 return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

/** Every native dialog call in a source text, as `name(` strings. */
export function nativeDialogCalls(source: string): string[] {
 const code = stripComments(source);
 const hits: string[] = [];
 // window.x( / globalThis.x( / self.x(, and the bare global call x( that is not a method on
 // something else (`this.confirm(`, `dialog.prompt(`) and not part of a longer identifier
 // (`confirmDialog(`, `onConfirm(`).
 for (const match of code.matchAll(/(?:\b(?:window|globalThis|self)\s*\.\s*|(?<![\w$.]))(confirm|prompt|alert)\s*\(/g)) {
  hits.push(`${match[1]}(`);
 }
 return hits;
}

const FILES = sourceFiles(SRC);

describe("no native browser dialogs", () => {
 test("positive control: the scanner finds every shape it is meant to", () => {
  const fixture = [
   'if (!window.confirm("Delete?")) return;',
   'const name = window.prompt("Name", "");',
   "alert('x');",
   "const ok = confirm(`sure?`);",
   "globalThis.prompt('y');",
  ].join("\n");
  expect(nativeDialogCalls(fixture)).toEqual(["confirm(", "prompt(", "alert(", "confirm(", "prompt("]);
 });

 test("negative control: lookalikes and comments are not calls", () => {
  const fixture = [
   "void confirmDialog({ title: 'x' });",
   "promptDialog({});",
   "onConfirm();",
   "this.confirm();",
   "dialog.prompt('x');",
   '// window.prompt("retired") is what this used to be',
   "/* window.confirm(...) */",
  ].join("\n");
  expect(nativeDialogCalls(fixture)).toEqual([]);
 });

 test("the corpus was actually read", () => {
  // An empty or mis-rooted walk would pass the real assertion by finding nothing.
  expect(FILES.length).toBeGreaterThan(100);
  expect(FILES.some((file) => file.endsWith("app.tsx"))).toBe(true);
  expect(FILES.some((file) => file.endsWith("lib/actions.ts"))).toBe(true);
 });

 test("no source file calls window.confirm, window.prompt or window.alert", () => {
  const offenders = FILES.flatMap((file) => nativeDialogCalls(readFileSync(file, "utf8")).map((call) => `${relative(SRC, file)}: ${call}`));
  expect(offenders).toEqual([]);
 });
});
