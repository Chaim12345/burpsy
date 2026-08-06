#!/usr/bin/env node
// Reads src/tokens/penpot-export.json (a snapshot of the burpsy Penpot file's
// `primitives`, `semantic/dark` and `semantic/light` token sets) and writes
// src/tokens/primitives.css + src/tokens/semantic.css.
//
// Penpot is canonical for every value here. To pick up a design change:
// re-run the three set dumps documented in the penpot-mcp skill, paste the
// token arrays back into penpot-export.json, then re-run this script.
//
// Penpot cannot store a CSS clamp() — every dimension token it holds is a
// single fixed number, which Penpot's export always treats as the FLOOR of
// the design's fluid scale (the value that was already tuned for AA contrast
// and WCAG 2.5.8 minimum target size). The vw/vh growth term and ceiling are
// not representable in Penpot, so they are not generated: FLUID_WRAP below
// hand-maintains them and is the one place this script is not a pure
// transform of Penpot data. If a primitive's floor changes upstream, this
// script picks up the new floor automatically; the growth term/ceiling only
// change if someone edits FLUID_WRAP.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const tokensDir = path.join(here, "..", "src", "tokens");
const src = JSON.parse(readFileSync(path.join(tokensDir, "penpot-export.json"), "utf8"));

const primitives = new Map(src.primitives.map((t) => [t.name, t]));

function cssName(tokenName) {
  return "--" + tokenName.replace(/\./g, "-");
}

function resolveRef(value) {
  const m = /^\{([^}]+)\}$/.exec(value);
  if (!m) return value;
  const target = primitives.get(m[1]);
  if (!target) throw new Error(`unresolved token reference {${m[1]}}`);
  return target.type === "fontFamilies" ? fontFamilyValue(target.value) : target.value;
}

function fontFamilyValue(list) {
  return list.map((f) => (/[\s-]/.test(f) && f !== "system-ui" && f !== "sans-serif" && f !== "monospace" ? `"${f}"` : f)).join(", ");
}

// primitiveName -> { vw: <mid-viewport-growth term>, ceiling: <max>, unit: "px" }
// vw is a percent-of-viewport-width number for clamp(floor, Xvw, ceiling); vh
// entries use viewport height instead. Every floor still comes from Penpot.
const FLUID_WRAP = {
  "font.size.2xs": { vw: 0.52, ceiling: 12 },
  "font.size.xs": { vw: 0.6, ceiling: 13 },
  "font.size.sm": { vw: 0.68, ceiling: 14 },
  "font.size.md": { vw: 0.76, ceiling: 15 },
  "font.size.lg": { vw: 0.85, ceiling: 16 },
  "font.size.xl": { vw: 0.95, ceiling: 18 },
  "font.size.2xl": { vw: 1.5, ceiling: 26 },
  "font.size.3xl": { vw: 1.7, ceiling: 30 },
  "font.size.4xl": { vw: 3.2, ceiling: 54 },
  "space.1": { vw: 0.3, ceiling: 6 },
  "space.2": { vw: 0.58, ceiling: 11 },
  "space.3": { vw: 0.85, ceiling: 16 },
  "space.4": { vw: 1.1, ceiling: 21 },
  "space.5": { vw: 1.4, ceiling: 26 },
  "space.6": { vw: 1.7, ceiling: 31 },
  "space.8": { vw: 2.2, ceiling: 40 },
  "height.menubar": { vh: 2.6, ceiling: 30 },
  "height.toolbar": { vh: 3.9, ceiling: 44 },
  "height.subtab": { vh: 3.1, ceiling: 34 },
  "height.statusbar": { vh: 2.4, ceiling: 28 },
  "height.control": { vh: 3.1, ceiling: 34 },
  "height.control-sm": { vh: 2.6, ceiling: 30 },
  "height.icon-btn": { vh: 2.9, ceiling: 34 },
  "height.row": { vh: 3, ceiling: 34 },
  "height.row-compact": { vh: 2.5, ceiling: 28 },
  "width.xs": { vw: 9, ceiling: 150 },
  "width.sm": { vw: 11, ceiling: 180 },
  "width.md": { vw: 14, ceiling: 230 },
  "width.lg": { vw: 20, ceiling: 330 },
};

// The rename each primitive gets in CSS. Anything not listed keeps its
// Penpot-derived name (grey/orange/etc. ramps, z-indices).
const PRIMITIVE_ALIAS = {
  "font.size.2xs": "--fs-2xs",
  "font.size.xs": "--fs-xs",
  "font.size.sm": "--fs-sm",
  "font.size.md": "--fs-md",
  "font.size.lg": "--fs-lg",
  "font.size.xl": "--fs-xl",
  "font.size.2xl": "--fs-2xl",
  "font.size.3xl": "--fs-3xl",
  "font.size.4xl": "--fs-4xl",
  "space.1": "--s1",
  "space.2": "--s2",
  "space.3": "--s3",
  "space.4": "--s4",
  "space.5": "--s5",
  "space.6": "--s6",
  "space.8": "--s8",
  "height.menubar": "--menubar-h",
  "height.toolbar": "--toolbar-h",
  "height.subtab": "--subtab-h",
  "height.statusbar": "--statusbar-h",
  "height.control": "--control-h",
  "height.control-sm": "--control-h-sm",
  "height.icon-btn": "--icon-btn",
  "height.row": "--row-h",
  "height.row-compact": "--row-h-compact",
  "width.xs": "--w-xs",
  "width.sm": "--w-sm",
  "width.md": "--w-md",
  "width.lg": "--w-lg",
  "z.sticky": "--z-sticky",
  "z.overlay": "--z-overlay",
  "z.dialog": "--z-dialog",
  "z.menu": "--z-menu",
  "z.tooltip": "--z-tooltip",
  "z.skip": "--z-skip",
  "font.family.sans": "--font-sans",
  "font.family.mono": "--font-mono",
};

function primitiveDecl(token) {
  const name = PRIMITIVE_ALIAS[token.name] ?? cssName(token.name);
  const wrap = FLUID_WRAP[token.name];
  if (wrap) {
    const term = wrap.vw !== undefined ? `${wrap.vw}vw` : `${wrap.vh}vh`;
    return `  ${name}: clamp(${token.value}, ${term}, ${wrap.ceiling}px);`;
  }
  if (token.type === "fontFamilies") {
    return `  ${name}: ${fontFamilyValue(token.value)};`;
  }
  return `  ${name}: ${token.value};`;
}

const primitivesCss = `/* GENERATED FILE — do not hand-edit.
 * Source of truth: Penpot, set "primitives". Regenerate with
 * \`node scripts/gen-tokens.mjs\` after re-exporting src/tokens/penpot-export.json.
 * Fluid clamp() growth terms and ceilings are hand-maintained in gen-tokens.mjs
 * (FLUID_WRAP) because Penpot can only store the floor value; see that file's
 * header comment for why. */
:root {
${src.primitives.map(primitiveDecl).join("\n")}
}
`;
writeFileSync(path.join(tokensDir, "primitives.css"), primitivesCss);

// Semantic tokens are always plain colour references (`{primitive.name}`) in
// this file's model — resolveRef reads the primitive's raw value straight
// through, so a semantic token is always exactly one var() away from a
// primitive with no wrapping needed.
//
// Every semantic token is named "color.<role>" in Penpot, but the app's
// existing components (already written and tested before this generator
// existed) reference the role directly — `--paper`, not `--color-paper`. The
// "color." prefix is dropped here so the generated names match what every
// .tsx file already uses, instead of forcing a mass rename across the app.
function semanticCssName(tokenName) {
  return cssName(tokenName.replace(/^color\./, ""));
}

function semanticDecl(token) {
  const primitiveName = token.value.replace(/[{}]/g, "");
  return `  ${semanticCssName(token.name)}: var(${PRIMITIVE_ALIAS[primitiveName] ?? cssName(primitiveName)});`;
}

const semanticCss = `/* GENERATED FILE — do not hand-edit.
 * Source of truth: Penpot, sets "semantic/dark" and "semantic/light".
 * Regenerate with \`node scripts/gen-tokens.mjs\`.
 *
 * Only the token-modelled color roles live here. A handful of composite or
 * alpha-blended values used by the editor/overlay chrome (--overlay,
 * --editor-line, --editor-active-line, --editor-selection, --editor-start,
 * --editor-header-name, --editor-header-value, --editor-body,
 * --editor-match*, --accent-contrast) are not representable as Penpot color
 * tokens (rgba opacity, or pure aliases of another semantic token) and stay
 * hand-authored in styles.css next to the rest of the theme blocks. */
:root,
[data-theme="light"] {
${src["semantic.light"].map(semanticDecl).join("\n")}
}

[data-theme="dark"] {
${src["semantic.dark"].map(semanticDecl).join("\n")}
}
`;
writeFileSync(path.join(tokensDir, "semantic.css"), semanticCss);

console.log("wrote src/tokens/primitives.css and src/tokens/semantic.css");
