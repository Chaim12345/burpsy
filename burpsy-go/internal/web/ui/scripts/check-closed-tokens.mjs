#!/usr/bin/env node
// Fails the build if a colour, spacing, or font-size value is written as a
// raw literal outside the token files, instead of a var(--...) reference.
//
// Scope is deliberately narrow: this checks the properties the design token
// system actually governs (color/background/border-color/fill/stroke/outline-color,
// font-size, padding/margin/gap/width/height *as spacing*). It does not flag
// border-width, border-radius, box-shadow, or transform values — those are
// shape/elevation/motion, governed by the craft skill's rules, not this
// token contract. Hairlines (1px/0) are exempt everywhere; they're not part
// of the fluid scale by design (see styles.css's header comment).
//
// An inline `/* token-exempt: reason */` comment on the same line silences a
// specific literal that has a documented, deliberate reason not to be a
// token (theme-independent chrome, a third-party widget's own hardcoded
// value, etc.) — grep the codebase for "token-exempt" to see the full list.
import { readFileSync } from "node:fs";
import { globSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.join(here, "..", "src");

// Generated straight from Penpot — the one place raw values are the point.
const EXEMPT_FILES = new Set([
  path.join(srcDir, "tokens", "primitives.css"),
  path.join(srcDir, "tokens", "semantic.css"),
  path.join(srcDir, "tokens", "penpot-export.json"),
]);

const COLOR_PROPS = /^(color|background|background-color|border-color|border(-top|-bottom|-left|-right)?-color|fill|stroke|outline-color)\s*:/;
const SPACING_PROPS = /^(font-size|padding|padding-(top|bottom|left|right)|margin|margin-(top|bottom|left|right)|gap|row-gap|column-gap)\s*:/;

const HEX = /#[0-9a-fA-F]{3,8}\b/;
const RAW_LENGTH = /(?<![\w.-])(-?\d*\.?\d+)(px|rem)\b/;
const HAIRLINE = new Set(["0px", "1px", "-1px"]);

function isCustomPropertyDecl(line) {
  return /^--[\w-]+\s*:/.test(line.trim());
}

function isExempt(line) {
  return line.includes("token-exempt");
}

function checkCssFile(file) {
  const violations = [];
  const text = readFileSync(file, "utf8");
  const lines = text.split("\n");
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("/*") || line.startsWith("*") || isExempt(raw)) return;
    if (isCustomPropertyDecl(line)) return; // defining a token (incl. hand-authored composites) is allowed

    if (COLOR_PROPS.test(line) && HEX.test(line)) {
      violations.push({ file, line: i + 1, text: line, reason: "raw colour literal — use a var(--...) token" });
    }
    if (SPACING_PROPS.test(line)) {
      const m = RAW_LENGTH.exec(line);
      if (m && !HAIRLINE.has(m[0])) {
        violations.push({ file, line: i + 1, text: line, reason: "raw spacing/font-size literal — use a var(--...) token" });
      }
    }
  });
  return violations;
}

function checkTsxFile(file) {
  const violations = [];
  const text = readFileSync(file, "utf8");
  const lines = text.split("\n");
  lines.forEach((raw, i) => {
    if (isExempt(raw)) return;
    if (!/style=\{\{/.test(raw) && !/style=\{/.test(raw)) return;
    if (HEX.test(raw)) {
      violations.push({ file, line: i + 1, text: raw.trim(), reason: "raw colour literal in an inline style — use a CSS custom property" });
    }
  });
  return violations;
}

const cssFiles = globSync(path.join(srcDir, "**", "*.css")).filter((f) => !EXEMPT_FILES.has(f));
const tsxFiles = globSync(path.join(srcDir, "**", "*.tsx"));

const violations = [...cssFiles.flatMap(checkCssFile), ...tsxFiles.flatMap(checkTsxFile)];

if (violations.length) {
  console.error(`Closed token set check failed: ${violations.length} raw literal(s) found outside the token files.\n`);
  for (const v of violations) {
    console.error(`${path.relative(srcDir, v.file)}:${v.line}: ${v.reason}\n    ${v.text}`);
  }
  console.error(`\nFix by referencing a design token, or if the literal is genuinely deliberate, add a trailing`);
  console.error(`"/* token-exempt: <reason> */" comment on that line explaining why it isn't one.`);
  process.exit(1);
}

console.log(`Closed token set check passed (${cssFiles.length} css files, ${tsxFiles.length} tsx files scanned).`);
