#!/usr/bin/env node
// Fails the build if a value the design token system governs is written as a
// raw literal outside the token files, instead of a var(--...) reference.
//
// This used to check only colour, spacing and font-size, and said so — it
// admitted skipping border-width, border-radius, box-shadow, letter-spacing
// and transform on the grounds that those were "shape/elevation/motion,
// governed by the craft skill's rules, not this token contract". That was true
// only because Penpot held no tokens for them. It now does — borderWidth,
// borderRadius and shadow are real Penpot token types — so the exclusion has
// become a hole rather than a boundary, and those categories are checked below.
//
// Each added category has a rule shaped by what Penpot can actually express,
// not by what CSS can say:
//
//   border-width  Non-hairline stroke widths must be a token. Hairlines
//                 (1px/0) stay exempt everywhere: they are not part of the
//                 fluid scale by design, per styles.css's header comment.
//   border-radius Non-zero radii must be a token. A percentage radius cannot
//                 be tokenised at all — a Penpot borderRadius resolves to a
//                 number of pixels — so the one percentage radius in the file
//                 carries a token-exempt with that reason.
//   box-shadow    Only *elevation* shadows are checked. An `inset` box-shadow
//                 in this codebase is structure, not elevation — a row's flag
//                 stripe, a selected row's inner hairline — drawn with a
//                 shadow because CSS has no inner-border property. Penpot's
//                 shadow token does carry an `inset` boolean, so these could
//                 be modelled; they are deliberately not, because calling a
//                 1px inner stripe an elevation recipe would put two unrelated
//                 things in one token type and make the elevation scale
//                 unreadable. The rule follows that decision rather than
//                 fighting it.
//   letter-spacing  Only px/rem tracking is flagged, never em. Penpot's
//                 letterSpacing token is px-only, and fixed px tracking is
//                 wrong under a fluid type scale — it stays put while the
//                 glyphs grow. em tracking is therefore outside the token
//                 contract by construction, not by oversight, which is why it
//                 needs no per-site exemption.
//   transform     Raw px/rem translate distances must be a token; percentages
//                 and angles are geometry, not spacing, and are not flagged.
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
  path.join(srcDir, "tokens", "pending.css"),
  path.join(srcDir, "tokens", "penpot-export.json"),
]);

const COLOR_PROPS = /^(color|background|background-color|border-color|border(-top|-bottom|-left|-right)?-color|fill|stroke|outline-color)\s*:/;
const SPACING_PROPS = /^(font-size|padding|padding-(top|bottom|left|right)|margin|margin-(top|bottom|left|right)|gap|row-gap|column-gap)\s*:/;
// `outline-offset` is not here: it positions a stroke rather than sizing one,
// and every use in the file is a hairline nudge that the token scale has no
// opinion about.
const BORDER_WIDTH_PROPS = /^(border|border-(top|bottom|left|right)|border-width|outline)\s*:/;
const RADIUS_PROPS = /^border(-[a-z-]+)?-radius\s*:/;
const SHADOW_PROPS = /^box-shadow\s*:/;
const TRACKING_PROPS = /^letter-spacing\s*:/;
const TRANSFORM_PROPS = /^transform\s*:/;

const HEX = /#[0-9a-fA-F]{3,8}\b/;
const RAW_LENGTH = /(?<![\w.-])(-?\d*\.?\d+)(px|rem)\b/;
const RAW_LENGTH_ALL = /(?<![\w.-])(-?\d*\.?\d+)(px|rem)\b/g;
const RAW_PERCENT = /(?<![\w.-])(-?\d*\.?\d+)%/;
const HAIRLINE = new Set(["0px", "1px", "-1px"]);

// A raw length after the property name, ignoring anything already inside a
// var()/calc()/color-mix() — those have been through the token layer, and a
// literal percentage inside color-mix() is a blend ratio, not a dimension.
function rawLengths(line) {
  const stripped = line.replace(/\b(var|calc|color-mix|min|max|clamp)\([^)]*\)/g, "");
  return [...stripped.matchAll(RAW_LENGTH_ALL)].map((m) => m[0]);
}

function isCustomPropertyDecl(decl) {
  return /^--[\w-]+\s*:/.test(decl);
}

// Every check below anchors on the property name, so it only ever saw lines
// that *begin* with one. That silently exempted every single-line rule in the
// file — `.sev-critical { background: var(--bad); outline: ... }` and its
// four siblings were never scanned at all, by either the original three
// categories or the new ones. Splitting the line into its declarations first
// closes that hole rather than leaving a check that reports success on code it
// never looked at.
//
// Multi-line values (a declaration whose value wraps onto the next line) are
// still not reassembled; there are none in this codebase, and a checker that
// needs a real CSS parser to say anything is a checker that gets removed.
function declarations(line) {
  const body = line.includes("{") ? line.slice(line.indexOf("{") + 1) : line;
  return body
    .split(";")
    .map((d) => d.replace(/\}.*$/, "").trim())
    .filter(Boolean);
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

    for (const decl of declarations(line)) {
      // defining a token (incl. hand-authored composites) is allowed
      if (isCustomPropertyDecl(decl)) continue;
      const at = (reason) => violations.push({ file, line: i + 1, text: decl, reason });

      if (COLOR_PROPS.test(decl) && HEX.test(decl)) {
        at("raw colour literal — use a var(--...) token");
      }
      if (SPACING_PROPS.test(decl)) {
        const m = RAW_LENGTH.exec(decl);
        if (m && !HAIRLINE.has(m[0])) at("raw spacing/font-size literal — use a var(--...) token");
      }
      if (BORDER_WIDTH_PROPS.test(decl)) {
        const bad = rawLengths(decl).filter((v) => !HAIRLINE.has(v));
        if (bad.length) at(`raw stroke width (${bad.join(", ")}) — use a var(--border-*) token`);
      }
      if (RADIUS_PROPS.test(decl)) {
        const bad = rawLengths(decl).filter((v) => !HAIRLINE.has(v));
        if (bad.length || RAW_PERCENT.test(decl.replace(/\b(var|calc|color-mix)\([^)]*\)/g, ""))) {
          at("raw border-radius — use a var(--radius-*) token");
        }
      }
      // Only elevation shadows; an inset shadow is structure here, see the header.
      if (SHADOW_PROPS.test(decl) && !/\binset\b/.test(decl) && !/\bnone\b/.test(decl)) {
        if (rawLengths(decl).length) at("raw elevation shadow — use a var(--shadow-*) token");
      }
      if (TRACKING_PROPS.test(decl) && rawLengths(decl).length) {
        at("px/rem tracking breaks under the fluid type scale — use a var(--tracking-*) token, or em");
      }
      if (TRANSFORM_PROPS.test(decl)) {
        const bad = rawLengths(decl).filter((v) => !HAIRLINE.has(v));
        if (bad.length) at(`raw translate distance (${bad.join(", ")}) — use a var(--...) token`);
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
