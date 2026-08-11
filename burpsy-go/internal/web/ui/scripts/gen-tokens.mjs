#!/usr/bin/env node
// Reads src/tokens/penpot-export.json (a snapshot of the burpsy Penpot file's
// `primitives`, `semantic/dark` and `semantic/light` token sets) and writes
// src/tokens/primitives.css, src/tokens/semantic.css and src/tokens/pending.css.
//
// Penpot is canonical for every value here. To pick up a design change:
// re-run the three set dumps documented in the penpot-mcp skill, paste the
// token arrays back into penpot-export.json, then re-run this script.
//
// Run with `--check` to verify the checked-in CSS still matches the export
// without writing anything. That closes the drift channel this script used to
// leave open: before, a change to penpot-export.json that nobody regenerated
// would sit in the tree indefinitely, and the CSS the app actually shipped
// would quietly disagree with the design file it claims to be generated from.
// `bun run check` now runs `--check`, so that disagreement fails CI instead.
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
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const tokensDir = path.join(here, "..", "src", "tokens");
const src = JSON.parse(readFileSync(path.join(tokensDir, "penpot-export.json"), "utf8"));

const CHECK = process.argv.includes("--check");
const SET_KEYS = ["primitives", "semantic.dark", "semantic.light"];

// What the Penpot file held the last time a human read it out. A partial
// re-export — a set dump that got truncated, a paste that dropped the tail of
// an array — shrinks one of these arrays silently, and every token that went
// missing simply stops being generated. The app keeps building, because CSS
// treats an undefined var() as "inherit or invalid" rather than an error, and
// the breakage only shows up as something rendering wrong. Asserting the
// counts turns that into a build failure.
//
// These numbers are part of the export contract, not a preference: when the
// design genuinely gains or loses a token, whoever re-exports updates the
// count here in the same commit, and the diff makes the intent explicit.
const EXPECTED_COUNTS = {
  primitives: 75,
  "semantic.dark": 44,
  "semantic.light": 44,
};

for (const key of SET_KEYS) {
  const got = src[key]?.length;
  if (got !== EXPECTED_COUNTS[key]) {
    throw new Error(
      `penpot-export.json set "${key}" holds ${got} tokens, expected ${EXPECTED_COUNTS[key]}.\n` +
        `Either the export is partial (most likely — re-run the set dump and check nothing was truncated),\n` +
        `or the design really did change, in which case update EXPECTED_COUNTS in scripts/gen-tokens.mjs\n` +
        `in the same commit so the new count is a deliberate, reviewable change.`,
    );
  }
}

// A per-set content hash, recorded in penpot-export.json's provenance block.
// IMPORTANT — read the failure message below carefully: this hash proves
// RECENCY, not CORRECTNESS. It can tell you that the token arrays in this
// file have been edited since the recorded hash was taken. It cannot tell you
// whether those arrays match the Penpot file, because nothing in this repo can
// reach Penpot. Only a human re-running the export can establish that.
function setHash(tokens) {
  return createHash("sha256").update(JSON.stringify(tokens)).digest("hex").slice(0, 16);
}

const recordedHashes = src._provenance?.setHashes ?? {};
for (const key of SET_KEYS) {
  const recorded = recordedHashes[key];
  const actual = setHash(src[key]);
  if (recorded === undefined) {
    throw new Error(`penpot-export.json _provenance.setHashes is missing "${key}" — add it (${actual}).`);
  }
  if (recorded !== actual) {
    throw new Error(
      `penpot-export.json set "${key}" no longer matches its recorded hash.\n` +
        `  recorded: ${recorded}\n  actual:   ${actual}\n` +
        `This hash proves RECENCY, NOT CORRECTNESS: it says the array was hand-edited since the last\n` +
        `recorded export, which is exactly what this file forbids. It does NOT and CANNOT prove that\n` +
        `the array matches the Penpot file — nothing in this repo can reach Penpot.\n` +
        `If you edited the value in Penpot and re-exported, update the hash to ${actual} and set\n` +
        `_provenance.exportedAt to today. If you hand-edited the value here, undo it and edit Penpot.`,
    );
  }
}

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

// Two steps of one ordered scale sharing a value is a defect in the design
// file, because Penpot stores only the floor: a designer binding a shape to
// either step sees the same number and has no way to tell them apart. In this
// repo they may still be distinguishable, since FLUID_WRAP can give them
// different ceilings — but FLUID_WRAP is precisely the layer Penpot cannot
// see, so the design file cannot verify a distinction that only exists here.
//
// The check is deliberately scoped to the namespaces below, which are ordered
// scales where a repeated value means a step that was never given one. It is
// NOT applied across namespaces (a 12px font size and a 12px gap are unrelated
// numbers), and not to the role maps — `height.*` and `z.*` map named roles
// rather than steps, and a subtab, a small control and a table row being the
// same height is a design decision, not a missing step.
const SCALE_NAMESPACES = ["font.size", "space", "width"];

// Every collision inside a scale must be listed below with a reason and a
// stated resolution, or the build fails. An entry here is an acknowledged
// debt, not an exemption: it says a human has looked at the pair and decided
// what should happen to it in Penpot.
const ACKNOWLEDGED_DUPLICATE_FLOORS = {
  "font.size.2xs|font.size.xs":
    "Both 11px in Penpot. Neither is dead in the app — --fs-2xs has 16 call sites and " +
    "--fs-xs 18 — and they do differ in the generated CSS, because FLUID_WRAP ceils 2xs " +
    "at 12px and xs at 13px, keeping 2xs the smaller of the two on a wide viewport. So " +
    "this is not a duplicate to delete; it is a floor that was never given a real step. " +
    "Resolution, which is a design decision and belongs in Penpot: set font.size.2xs to " +
    "10px so the scale steps 10/11/12/13/… and the two tokens are distinguishable to a " +
    "designer. That shrinks 16 call sites by 1px at the narrow end, so it needs design " +
    "sign-off rather than a unilateral edit here. Tracked in penpot-export.json's " +
    "_provenance.pendingPenpotEdits.",
};

const seenByValue = new Map();
for (const token of src.primitives) {
  const namespace = SCALE_NAMESPACES.find((ns) => token.name.startsWith(ns + "."));
  if (!namespace) continue;
  const key = `${namespace} ${token.value}`;
  if (!seenByValue.has(key)) seenByValue.set(key, []);
  seenByValue.get(key).push(token.name);
}
for (const names of seenByValue.values()) {
  if (names.length < 2) continue;
  const key = names.join("|");
  if (!(key in ACKNOWLEDGED_DUPLICATE_FLOORS)) {
    throw new Error(
      `Primitives ${names.join(" and ")} are steps of one scale and hold the same value, which makes\n` +
        `them indistinguishable in Penpot. Give one of them a distinct value in Penpot, or — if the\n` +
        `collision is deliberate — add "${key}" to ACKNOWLEDGED_DUPLICATE_FLOORS in\n` +
        `scripts/gen-tokens.mjs with the reason and the resolution you intend, so the debt is recorded\n` +
        `rather than invisible.`,
    );
  }
}

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

function primitiveVar(primitiveName) {
  return PRIMITIVE_ALIAS[primitiveName] ?? cssName(primitiveName);
}

function primitiveDecl(token) {
  const name = primitiveVar(token.name);
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

// ---------------------------------------------------------------------------
// semantic sets
// ---------------------------------------------------------------------------
// Every semantic token in this design is a *pure reference* to a primitive —
// `color.paper` = `{grey.600}`, `text.md` = `{font.size.md}`, `space.gap-lg` =
// `{space.4}` — so a semantic declaration is always exactly one var() away
// from a primitive, with no wrapping needed. A fluid clamp() reaches the alias
// for free through that var(), which is why the alias layer does not need to
// know anything about FLUID_WRAP.
//
// Semantic tokens are named with a category prefix in Penpot ("color.paper",
// "space.gap-lg"), but the app's existing components — written and tested
// before this generator existed — reference the role directly: `--paper`, not
// `--color-paper`. The prefixes are dropped here so the generated names match
// what every .tsx and CSS rule already uses, instead of forcing a mass rename
// across the app.
function semanticCssName(tokenName) {
  return SEMANTIC_ALIAS[tokenName] ?? cssName(tokenName.replace(/^color\./, ""));
}

// The non-colour semantic tokens Penpot holds and the repo had never read out.
// These are the intent-named layer: `--gap-lg` says "the large gap", `--s4`
// says "the fourth step of the spacing scale". Both resolve to 12px, and so
// does `--pad-page`.
//
// That is three names for one value, which is only defensible as intent naming
// if the app consistently reaches for the *most* semantic one available: page
// padding uses `--pad-page`, a gap between related controls uses `--gap-lg`,
// and `--s4` is reserved for the cases where the number genuinely is "the
// fourth step" and no role fits. If call sites drift toward picking whichever
// name is shortest, the layer stops carrying information and becomes three
// synonyms — at which point the honest move is to delete the aliases, not to
// keep pretending. Migration is therefore deliberately incremental: sites move
// when someone can say which role they mean, never in a sweep.
const SEMANTIC_ALIAS = {
  "space.gap-xs": "--gap-xs",
  "space.gap-sm": "--gap-sm",
  "space.gap-md": "--gap-md",
  "space.gap-default": "--gap",
  "space.gap-lg": "--gap-lg",
  "space.gap-xl": "--gap-xl",
  "space.gap-2xl": "--gap-2xl",
  "space.gap-3xl": "--gap-3xl",
  "space.pad-page": "--pad-page",
  "font.family.body": "--font-body",
  "font.family.code": "--font-code",
};

function semanticDecl(token) {
  const m = /^\{([^}]+)\}$/.exec(String(token.value));
  if (!m) {
    throw new Error(
      `semantic token "${token.name}" holds a literal (${token.value}) rather than a reference to a primitive.\n` +
        `This generator models the semantic sets as a pure alias layer over primitives; a literal here\n` +
        `means the design grew a value that has no primitive behind it. Add the primitive in Penpot and\n` +
        `point the semantic token at it.`,
    );
  }
  return `  ${semanticCssName(token.name)}: var(${primitiveVar(m[1])});`;
}

const isColorToken = (t) => t.type === "color";

const darkColors = src["semantic.dark"].filter(isColorToken);
const lightColors = src["semantic.light"].filter(isColorToken);
const darkOther = src["semantic.dark"].filter((t) => !isColorToken(t));
const lightOther = src["semantic.light"].filter((t) => !isColorToken(t));

// Both semantic sets currently carry byte-identical non-colour tokens: the
// type scale, the gap scale and the font stacks do not change between themes,
// only the palette does. Emitting them once in :root rather than twice keeps
// the generated file honest about that — a reader can see at a glance that the
// theme switch is a palette switch and nothing more.
//
// But "currently" is doing real work in that sentence, and a future export
// could diverge (a light theme wanting slightly tighter type, say). So the
// sameness is *detected*, not assumed: if the two sets ever disagree, the
// non-colour tokens theme-split automatically alongside the colours, and the
// generated CSS silently stays correct instead of the light theme quietly
// inheriting dark's numbers.
const sharedNonColor =
  darkOther.length === lightOther.length &&
  darkOther.every((t, i) => t.name === lightOther[i].name && String(t.value) === String(lightOther[i].value));

const lightBlock = sharedNonColor ? lightColors : src["semantic.light"];
const darkBlock = sharedNonColor ? darkColors : src["semantic.dark"];

const sharedBlock = sharedNonColor
  ? `
/* Theme-independent semantic tokens, emitted once because both semantic sets
 * hold them identically. gen-tokens.mjs checks that each time it runs and
 * theme-splits these automatically if a future export makes them diverge. */
:root {
${darkOther.map(semanticDecl).join("\n")}
}
`
  : "";

const semanticCss = `/* GENERATED FILE — do not hand-edit.
 * Source of truth: Penpot, sets "semantic/dark" and "semantic/light".
 * Regenerate with \`node scripts/gen-tokens.mjs\`.
 *
 * Only the token-modelled roles live here. A handful of composite or
 * alpha-blended values used by the editor/overlay chrome (--overlay,
 * --editor-line, --editor-active-line, --editor-selection, --editor-start,
 * --editor-header-name, --editor-header-value, --editor-body,
 * --editor-match*, --accent-contrast) are not representable as Penpot color
 * tokens — rgba opacity, a syntax palette with no semantic role, or a pure
 * alias of another semantic token — and stay hand-authored in styles.css next
 * to the rest of the theme blocks. */
${sharedBlock}
:root,
[data-theme="light"] {
${lightBlock.map(semanticDecl).join("\n")}
}

[data-theme="dark"] {
${darkBlock.map(semanticDecl).join("\n")}
}
`;

// ---------------------------------------------------------------------------
// pending: token types Penpot supports that this design does not yet use
// ---------------------------------------------------------------------------
// This is the one generated file where the REPO, not Penpot, is currently
// canonical, and that inversion is deliberate and temporary. The values below
// were read out of styles.css — they are what the app already does — and they
// are modelled here in the shape Penpot's token types require so that a human
// with the plugin open can create them in one pass and re-export, at which
// point they move into the primitives/semantic arrays and this file empties.
//
// Until that happens the header on the generated file says so, loudly, rather
// than letting these pass for exported design data.
function pendingDecls(tokens) {
  const out = [];
  for (const token of tokens) {
    const name = cssName(token.name);
    switch (token.type) {
      case "borderWidth":
      case "borderRadius":
      case "opacity":
      case "textCase":
      case "fontWeights":
      case "color":
        out.push(`  ${name}: ${token.value};`);
        break;
      // Penpot's letterSpacing token is px-only — its value is documented as
      // "a number or a reference" with a numeric resolvedValue, so there is
      // nowhere to put a unit. Fixed px tracking is wrong under a fluid type
      // scale: it stays put while the glyphs grow, so the same token reads
      // correctly at one viewport and loose at another. The em figure is
      // therefore stored as a plain `number` token, Penpot keeps the number
      // canonical, and this script supplies the `em` the CSS needs.
      case "number":
        out.push(`  ${name}: ${token.value}${token.cssUnit ?? ""};`);
        break;
      // A Penpot shadow token holds exactly six fields — offsetX, offsetY,
      // blur, spread, inset and color — with no alpha of its own, so the
      // transparency has to come from the colour it references. It can:
      // Penpot's colour tokens accept 8-digit #RRGGBBAA, so each shadow
      // references a scrim colour that carries its own alpha, and this case is
      // a straight assembly of the six fields with no blending to do. See the
      // _shadowAlphaNote in penpot-export.json for why that beats splitting
      // the hue from an opacity token.
      case "shadow": {
        const v = token.value;
        const inset = v.inset === "true" || v.inset === true ? "inset " : "";
        const spread = v.spread && Number(v.spread) !== 0 ? " " + px(v.spread) : "";
        out.push(`  ${name}: ${inset}${px(v.offsetX)} ${px(v.offsetY)} ${px(v.blur)}${spread} ${pendingValue(v.color)};`);
        break;
      }
      // CSS has no composite typography type, so a Penpot `typography` token
      // flattens into the `font:` shorthand plus the two properties the
      // shorthand cannot carry. Emitting the shorthand — rather than five
      // separate vars a rule has to reassemble — is what makes the composite
      // worth having at the call site.
      case "typography": {
        const v = token.value;
        out.push(`  ${name}: ${pendingValue(v.fontWeight)} ${pendingValue(v.fontSizes)}/${v.lineHeight} ${pendingValue(v.fontFamilies)};`);
        out.push(`  ${name}-tracking: ${pendingValue(v.letterSpacing)};`);
        out.push(`  ${name}-case: ${pendingValue(v.textCase)};`);
        break;
      }
      default:
        throw new Error(`pending token "${token.name}" has unhandled type "${token.type}"`);
    }
  }
  return out;
}

const pending = src._pendingPenpot?.tokens ?? [];
const pendingByName = new Map(pending.map((t) => [t.name, t]));
const semanticByName = new Map(src["semantic.dark"].map((t) => [t.name, semanticCssName(t.name)]));

// A reference inside a pending token may point at another pending token, a
// semantic token or a primitive; in every case the CSS wants a var(). Bare
// values pass through.
function pendingValue(value) {
  const m = /^\{([^}]+)\}$/.exec(String(value));
  if (!m) return String(value);
  const target = m[1];
  if (pendingByName.has(target)) return `var(${cssName(target)})`;
  if (primitives.has(target)) return `var(${primitiveVar(target)})`;
  if (semanticByName.has(target)) return `var(${semanticByName.get(target)})`;
  throw new Error(`pending token reference {${target}} resolves to nothing`);
}

const px = (n) => (Number(n) === 0 ? "0" : `${n}px`);

const pendingCss = `/* GENERATED FILE — do not hand-edit.
 * NOT EXPORTED FROM PENPOT. This is the one token file where this repo, not
 * Penpot, is currently the source of truth — deliberately and temporarily.
 *
 * These are values the app already uses (read out of styles.css) expressed in
 * the shape Penpot's borderWidth / borderRadius / shadow / fontWeights /
 * letterSpacing / textCase / opacity / typography token types require, so
 * that someone with the Penpot plugin open can create them in one pass. Once
 * they exist in Penpot and have been re-exported they move into the
 * primitives/semantic sets and this file goes away.
 *
 * Until then: do not treat anything here as a design decision Penpot has
 * ratified. Edit the values in src/tokens/penpot-export.json's
 * _pendingPenpot block, not here. */
:root {
${pendingDecls(pending).join("\n")}
}
`;

// ---------------------------------------------------------------------------
// write, or diff
// ---------------------------------------------------------------------------
const outputs = [
  ["primitives.css", primitivesCss],
  ["semantic.css", semanticCss],
  ["pending.css", pendingCss],
];

// Deliberately a plain longest-common-subsequence diff rather than a
// dependency: these files are ~100 lines, and a generator that needs an npm
// package to explain its own failure is a generator that will get skipped.
function diff(expected, actual) {
  const a = expected.split("\n");
  const b = actual.split("\n");
  const lcs = Array.from({ length: a.length + 1 }, () => new Uint32Array(b.length + 1));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const lines = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      lines.push(`  - ${a[i++]}`);
    } else {
      lines.push(`  + ${b[j++]}`);
    }
  }
  while (i < a.length) lines.push(`  - ${a[i++]}`);
  while (j < b.length) lines.push(`  + ${b[j++]}`);
  return lines;
}

if (CHECK) {
  const stale = [];
  for (const [file, content] of outputs) {
    const full = path.join(tokensDir, file);
    let onDisk;
    try {
      onDisk = readFileSync(full, "utf8");
    } catch {
      stale.push({ file, lines: [`  (missing — src/tokens/${file} has never been generated)`] });
      continue;
    }
    if (onDisk !== content) stale.push({ file, lines: diff(content, onDisk) });
  }
  if (stale.length) {
    console.error(`Token drift: ${stale.length} generated file(s) do not match src/tokens/penpot-export.json.\n`);
    console.error(`"-" is what the export says the file should contain; "+" is what is checked in.\n`);
    for (const { file, lines } of stale) {
      console.error(`src/tokens/${file}:`);
      console.error(lines.join("\n"));
      console.error("");
    }
    console.error(`Fix by running \`bun run gen:tokens\` and committing the result. If the checked-in CSS is`);
    console.error(`the version you want, the change belongs in Penpot and then in penpot-export.json — not`);
    console.error(`in the generated file, which the next regeneration will overwrite.`);
    process.exit(1);
  }
  console.log(`Token check passed (${outputs.length} generated files match penpot-export.json).`);
} else {
  for (const [file, content] of outputs) writeFileSync(path.join(tokensDir, file), content);
  console.log(`wrote ${outputs.map(([f]) => "src/tokens/" + f).join(", ")}`);
}
