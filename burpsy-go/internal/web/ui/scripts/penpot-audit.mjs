#!/usr/bin/env node
// Audits a fetched Penpot file against the token catalogue, and derives a
// proposed token change set from what the mockups are actually drawn at.
//
//   node scripts/fetch-penpot-file.mjs --save-raw /tmp/file.json
//   node scripts/penpot-audit.mjs /tmp/file.json
//
// Why this exists rather than a list of numbers in a document: the six token
// values this workstream was about to adopt came from four measurements typed
// into docs/ui-map/07-design-analysis.md by hand. That is a sample of four from
// a 970-shape file, and adopting a design system from it would be the same class
// of mistake as trusting a hand-pasted token export. This reads the file.
//
// The output has two halves and they answer different questions:
//
//   LINT — where the design file fails to use its own token system. Raw hex
//   fills matching no token, font sizes off the type scale, radii that no token
//   describes, and shapes with a tokenisable property and no binding at all.
//   Reported as counts and a breakdown by component path, never as one line per
//   shape: 970 unbound shapes is a fact about the file, and printing 970 lines
//   would bury it.
//
//   PROPOSED TOKEN DIFF — for each role, the value the boards actually use
//   against the value the token holds. The agreement/disagreement columns are
//   the point. A role where all 19 boards say 24px is a decision the mockups
//   have made and can be adopted. A role where 11 say 24 and 8 say 26 is drift
//   *inside* the mockups, and adopting either number would be guessing dressed
//   up as measurement. Those two cases are reported separately and never
//   collapsed, and a split role is marked NEEDS A DECISION rather than given a
//   recommendation this script is not entitled to make.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { collectShapes, shapePath, isReference } from "./lib/penpot-file.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const exportPath = path.join(here, "..", "src", "tokens", "penpot-export.json");

const fileArg = process.argv[2];
if (!fileArg) {
  console.error(`usage: node scripts/penpot-audit.mjs <decoded-file.json>`);
  console.error(`Produce the input with: node scripts/fetch-penpot-file.mjs --save-raw <path>`);
  console.error(`\nSKIPPED — no input file. This is a skip, not a pass: nothing was audited.`);
  process.exit(3);
}

const exported = JSON.parse(readFileSync(exportPath, "utf8"));
const raw = JSON.parse(readFileSync(fileArg, "utf8"));
const data = raw.data ?? raw;
if (!data["pages-index"]) {
  console.error(`penpot-audit: ${fileArg} has no data.pages-index — that is not a decoded Penpot file.`);
  process.exit(1);
}

// --- the token catalogue, flattened for lookup ----------------------------
const primitives = new Map(exported.primitives.map((t) => [t.name, t]));
const allTokens = [...exported.primitives, ...exported["semantic.dark"], ...exported["semantic.light"]];

function resolve(value, depth = 0) {
  if (depth > 8 || !isReference(value)) return value;
  const target = primitives.get(value.trim().slice(1, -1));
  return target ? resolve(target.value, depth + 1) : value;
}

const norm = (hex) => String(hex).trim().toLowerCase();
// Every colour any token can produce, mapped back to the token names that
// produce it. Both themes are included: a fill matching the light theme's paper
// is using the system even though the dark theme disagrees.
const colorToTokens = new Map();
for (const t of allTokens) {
  if (t.type !== "color") continue;
  const hex = norm(resolve(t.value));
  if (!/^#[0-9a-f]{6}([0-9a-f]{2})?$/.test(hex)) continue;
  if (!colorToTokens.has(hex)) colorToTokens.set(hex, []);
  colorToTokens.get(hex).push(t.name);
}

const typeScale = new Map();
for (const t of exported.primitives) {
  if (!t.name.startsWith("font.size.")) continue;
  typeScale.set(parseFloat(t.value), t.name);
}

// --- walk the file --------------------------------------------------------
const objectsByPage = new Map();
for (const [pageId, page] of Object.entries(data["pages-index"])) objectsByPage.set(pageId, page.objects ?? {});

const shapes = collectShapes(data).map((s) => ({ ...s, path: shapePath(s.shape, objectsByPage.get(s.pageId) ?? {}) }));

// A shape has a tokenisable property if the token system has something to say
// about it at all. A group with no fill, no radius and no text is not "unbound",
// it is simply not a thing tokens govern, and counting it as a violation would
// inflate the number that matters.
function tokenisable(shape) {
  const props = [];
  if ((shape.fills ?? []).some((f) => f["fill-color"])) props.push("fill");
  if (["r1", "r2", "r3", "r4", "rx", "ry"].some((k) => Number(shape[k]) > 0)) props.push("radius");
  if (shape.type === "text") props.push("fontSize");
  if ((shape.strokes ?? []).length) props.push("stroke");
  return props;
}

function textAttrs(shape, out = []) {
  const node = shape;
  const walk = (n) => {
    if (!n || typeof n !== "object") return;
    if (n["font-size"] !== undefined) out.push({ "font-size": Number(n["font-size"]), "font-family": n["font-family"], "font-weight": n["font-weight"] });
    for (const child of n.children ?? []) walk(child);
  };
  walk(node.content);
  return out;
}

const lint = { rawFills: [], offScaleType: [], untokenisedRadius: [], unbound: [] };

for (const { shape, path: p } of shapes) {
  const applied = shape["applied-tokens"] ?? {};

  for (const fill of shape.fills ?? []) {
    const hex = norm(fill["fill-color"]);
    if (!hex || hex === "undefined") continue;
    if (applied.fill) continue; // bound to a token; the value is the token's problem
    if (!colorToTokens.has(hex)) lint.rawFills.push({ path: p, hex });
  }

  for (const k of ["r1", "r2", "r3", "r4"]) {
    const r = Number(shape[k]);
    if (r > 0 && !applied[`borderRadius${k}`] && !applied.borderRadius) lint.untokenisedRadius.push({ path: p, radius: r });
  }

  if (shape.type === "text" && !applied.fontSize) {
    for (const a of textAttrs(shape)) {
      if (a["font-size"] && !typeScale.has(a["font-size"])) lint.offScaleType.push({ path: p, size: a["font-size"] });
    }
  }

  const props = tokenisable(shape);
  const boundProps = Object.keys(applied);
  if (props.length && boundProps.length === 0) lint.unbound.push({ path: p, props });
}

// --- proposed token diff --------------------------------------------------
// Each probe says: which token a role should be reading, which shapes embody
// that role, and how to measure it. Matching is on the shape path so that a
// measurement is traceable to the board it came from.
const PROBES = [
  { token: "height.menubar", match: /menu-?bar/i, measure: (s) => round(s.height), unit: "px" },
  { token: "height.toolbar", match: /tool-?bar/i, measure: (s) => round(s.height), unit: "px" },
  { token: "height.subtab", match: /sub-?tabs?\b/i, measure: (s) => round(s.height), unit: "px" },
  { token: "height.statusbar", match: /status-?bar/i, measure: (s) => round(s.height), unit: "px" },
  { token: "height.row", match: /\brow\b/i, measure: (s) => round(s.height), unit: "px" },
  { token: "height.control", match: /\b(input|control|field)\b/i, measure: (s) => round(s.height), unit: "px" },
  { token: "color.chrome", match: /chrome|tool-?bar|menu-?bar/i, measure: (s) => norm(s.fills?.[0]?.["fill-color"]), unit: "" },
  { token: "color.paper", match: /\b(page|canvas|background|paper)\b/i, measure: (s) => norm(s.fills?.[0]?.["fill-color"]), unit: "" },
];

const round = (n) => (Number.isFinite(Number(n)) ? Math.round(Number(n) * 100) / 100 : undefined);

// A semantic token has a different value per theme, so "the token value" is two
// values. Flattening them into one — which a single Map keyed by name does,
// silently keeping whichever set was read last — would compare a dark board fill
// against the light theme's colour and report a difference that is not one.
function tokenValueLabel(name) {
  const primitive = exported.primitives.find((t) => t.name === name);
  if (primitive) return String(resolve(primitive.value));
  const dark = exported["semantic.dark"].find((t) => t.name === name);
  const light = exported["semantic.light"].find((t) => t.name === name);
  if (!dark && !light) return "(no such token)";
  const d = dark ? String(resolve(dark.value)) : "—";
  const l = light ? String(resolve(light.value)) : "—";
  return d === l ? d : `${d} / ${l}`;
}

// A board value matches the token if it matches EITHER theme — the mockups are
// drawn in one theme and that does not make the other theme wrong.
function agreesWithToken(name, boardValue) {
  const candidates = [exported.primitives, exported["semantic.dark"], exported["semantic.light"]]
    .map((set) => set.find((t) => t.name === name))
    .filter(Boolean)
    .map((t) => String(resolve(t.value)));
  return candidates.some((c) => norm(c) === norm(boardValue));
}
const proposals = [];
for (const probe of PROBES) {
  const tally = new Map(); // measured value -> [paths]
  for (const { shape, path: p } of shapes) {
    if (!probe.match.test(p || shape.name || "")) continue;
    const v = probe.measure(shape);
    if (v === undefined || v === null || v === "" || v === "undefined") continue;
    const key = `${v}${probe.unit}`;
    if (!tally.has(key)) tally.set(key, []);
    tally.get(key).push(p);
  }
  if (tally.size === 0) continue;
  const ranked = [...tally.entries()].sort((a, b) => b[1].length - a[1].length);
  const total = ranked.reduce((n, [, paths]) => n + paths.length, 0);
  const current = tokenValueLabel(probe.token);
  proposals.push({
    token: probe.token,
    current,
    boardValue: ranked[0][0],
    agree: ranked[0][1].length,
    disagree: total - ranked[0][1].length,
    spread: ranked,
    examplePaths: ranked[0][1].slice(0, 3),
  });
}

// --- report ---------------------------------------------------------------
const bar = "=".repeat(78);
console.log(`${bar}\nPENPOT AUDIT — ${shapes.length} shapes across ${objectsByPage.size} page(s)\nsource: ${fileArg}\n${bar}`);

// Grouped by the LEAF of the component path ("toolbar"), not the whole path
// ("tool-3 / toolbar"). Whole paths are close to unique in this file, so grouping
// on them produces one line per shape — a list wearing a breakdown's clothes.
// The leaf is the role, and the role is what a reader is deciding about.
function byRole(entries) {
  const groups = new Map();
  for (const e of entries) {
    const leaf = (e.path || "").split(" / ").filter(Boolean).pop() || "(no path)";
    if (!groups.has(leaf)) groups.set(leaf, []);
    groups.get(leaf).push(e);
  }
  return [...groups.entries()].sort((a, b) => b[1].length - a[1].length);
}

console.log(`\nLINT\n----`);
console.log(`raw fills matching no token          ${lint.rawFills.length}`);
console.log(`font sizes off the type scale        ${lint.offScaleType.length}`);
console.log(`non-zero radii with no radius token  ${lint.untokenisedRadius.length}`);
console.log(`shapes with a tokenisable property and NO binding at all   ${lint.unbound.length} of ${shapes.length}`);

if (lint.rawFills.length) {
  console.log(`\n  raw fills, by colour (the colours the design uses that the system does not name):`);
  const byHex = new Map();
  for (const f of lint.rawFills) byHex.set(f.hex, (byHex.get(f.hex) ?? 0) + 1);
  for (const [hex, n] of [...byHex.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20)) console.log(`    ${hex}  ${n} shape(s)`);
}
if (lint.untokenisedRadius.length) {
  console.log(`\n  radii in use (the app is radius-0 everywhere, so every one of these is a real difference):`);
  const byR = new Map();
  for (const r of lint.untokenisedRadius) byR.set(r.radius, (byR.get(r.radius) ?? 0) + 1);
  for (const [r, n] of [...byR.entries()].sort((a, b) => b[1] - a[1])) console.log(`    ${r}px  ${n} corner(s)`);
}
if (lint.offScaleType.length) {
  console.log(`\n  off-scale font sizes:`);
  const bySize = new Map();
  for (const t of lint.offScaleType) bySize.set(t.size, (bySize.get(t.size) ?? 0) + 1);
  for (const [size, n] of [...bySize.entries()].sort((a, b) => b[1] - a[1])) console.log(`    ${size}px  ${n} text node(s)   (scale: ${[...typeScale.keys()].sort((a, b) => a - b).join(", ")})`);
}
if (lint.unbound.length) {
  const roles = byRole(lint.unbound);
  console.log(`\n  unbound shapes by role (top 20 of ${roles.length} roles):`);
  for (const [p, entries] of roles.slice(0, 20)) {
    const props = new Set(entries.flatMap((e) => e.props));
    console.log(`    ${String(entries.length).padStart(4)}  ${p || "(no path)"}   [${[...props].join(", ")}]`);
  }
}

console.log(`\n\nPROPOSED TOKEN DIFF\n-------------------`);
if (proposals.length === 0) {
  console.log(`No probe matched any shape. Either the boards use names this script does not recognise —`);
  console.log(`adjust PROBES — or the file is not the one you think it is. Reporting nothing rather than`);
  console.log(`inventing agreement.`);
} else {
  const vw = Math.max(11, ...proposals.map((p) => p.current.length));
  const bw = Math.max(11, ...proposals.map((p) => String(p.boardValue).length));
  console.log(`${"token".padEnd(20)} ${"token value".padEnd(vw)} ${"board value".padEnd(bw)} ${"agree".padStart(5)} ${"differ".padStart(6)}  verdict`);
  for (const p of proposals) {
    const verdict = agreesWithToken(p.token, p.boardValue)
      ? "already agrees"
      : p.disagree === 0
        ? "ADOPT — boards are unanimous"
        : "NEEDS A DECISION — boards disagree with each other";
    console.log(`${p.token.padEnd(20)} ${p.current.padEnd(vw)} ${String(p.boardValue).padEnd(bw)} ${String(p.agree).padStart(5)} ${String(p.disagree).padStart(6)}  ${verdict}`);
  }
  const split = proposals.filter((p) => p.disagree > 0);
  if (split.length) {
    console.log(`\n  where the boards disagree with each other, the full spread — adopting the most common`);
    console.log(`  value here would be picking a side, which is a design decision and not this script's:`);
    for (const p of split) {
      console.log(`    ${p.token}`);
      for (const [value, paths] of p.spread) console.log(`      ${String(value).padEnd(12)} ${String(paths.length).padStart(4)} shape(s)   e.g. ${paths.slice(0, 2).join(" | ") || "(no path)"}`);
    }
  }
  const unanimous = proposals.filter((p) => p.disagree === 0 && !agreesWithToken(p.token, p.boardValue));
  if (unanimous.length) {
    console.log(`\n  ready to apply IN PENPOT (not here — see PENDING-TOKEN-CHANGES.md for why):`);
    for (const p of unanimous) console.log(`    ${p.token}: ${p.current} -> ${p.boardValue}   (${p.agree} shape(s) agree, e.g. ${p.examplePaths.join(" | ")})`);
  }
}
console.log(`\n${bar}`);
