#!/usr/bin/env bun
/**
 * Bring the design file's text contrast up to WCAG AA, using the colours the
 * shipped app already uses.
 *
 * Why the values are not invented here
 * -----------------------------------
 * The React app passes AA already (its axe suite went 41 violations -> 0). The
 * design file drifted behind it: it still paints accent text as the identity
 * orange #ff6633, which cannot carry small text on any of our dark greys
 * (4.40 / 3.64 / 3.32 against #323232 / #3c3f41 / #414547).
 *
 * The app solved this with a separate role: `--accent-strong`, which in dark
 * theme resolves to --orange-strong-dark = #ff9670. That clears AA on all three
 * (6.01 / 4.98 / 4.54). Adopting it here closes the drift instead of inventing a
 * fourth orange. The same reasoning applies to the muted greys below.
 *
 * Why not `openpencil lint --rule color-contrast`
 * ----------------------------------------------
 * That rule resolves a text node's background by walking ancestors. Nearly
 * everything here is absolutely positioned, so the rectangle a label sits on is
 * usually a sibling. The rule therefore both misses real failures and flags
 * plain rectangles that contain no text. This script resolves the background the
 * way a reader sees it: topmost painted box, drawn before the text, containing
 * its centre.
 *
 * Usage:  bun fix-design-contrast.ts [--dry-run] [--doc tab-4] [--save <path>]
 */

import { readFileSync } from "node:fs";
import { createOpenpencilClient } from "./openpencil-client";

// Read the live token: the app regenerates it on restart and cached copies go
// stale silently.
process.env.OPENPENCIL_MCP_AUTH_TOKEN = JSON.parse(
  readFileSync("/root/.openpencil/mcp.json", "utf8"),
).authToken;

const args = process.argv.slice(2);
const DRY = args.includes("--dry-run");
const DOC = valueOf("--doc") ?? "tab-4";
const SAVE = valueOf("--save");

function valueOf(flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

/**
 * Replacement colours, keyed by the colour being replaced.
 *
 * `#ff6633` is the brand accent and stays exactly that everywhere it is a fill,
 * a border or an icon — it only changes where it is *text*, because that is the
 * only place the contrast rule applies. That distinction is why this is keyed by
 * colour and applied only to TEXT nodes.
 */
const REPLACEMENTS: Record<string, { to: string; why: string }> = {
  "#ff6633": { to: "#ff9670", why: "--accent-strong (dark) — AA on all three greys" },
  "#8a8d8f": { to: "#a4a9ab", why: "muted text, was 3.18-3.84:1" },
  "#6b6e70": { to: "#9aa0a2", why: "disabled/out-of-scope text, was 2.50:1" },
  "#bbbbbb": { to: "#c6c6c6", why: "only where it sits on the lighter #4b5052" },
};

const AUDIT = String.raw`
function hex(c){const h=n=>Math.round(n*255).toString(16).padStart(2,'0');
  return ('#'+h(c.r)+h(c.g)+h(c.b)).toLowerCase();}
function lum(c){const f=v=>v<=0.03928?v/12.92:Math.pow((v+0.055)/1.055,2.4);
  return 0.2126*f(c.r)+0.7152*f(c.g)+0.0722*f(c.b);}
function ratio(a,b){const l1=lum(a),l2=lum(b);
  const hi=Math.max(l1,l2),lo=Math.min(l1,l2);return (hi+0.05)/(lo+0.05);}
const g = figma.graph;

// absolute geometry + paint order (document order: later paints on top)
const abs = new Map(); let order = 0;
function walk(id, ox, oy) {
  const n = g.nodes.get(id); if (!n) return;
  const x = ox + (n.x||0), y = oy + (n.y||0);
  abs.set(id, {x, y, w: n.width||0, h: n.height||0, order: order++, node: n});
  for (const c of (n.childIds||[])) walk(c, x, y);
}
for (const [id, n] of g.nodes) {
  const p = g.nodes.get(n.parentId);
  if (n.type === 'FRAME' && p && p.type === 'CANVAS') walk(id, 0, 0);
}
function fillOf(n) {
  const f = (n.fills||[])[0];
  if (!f || f.type !== 'SOLID' || !f.color) return null;
  if (f.visible === false) return null;
  if (f.color.a === 0) return null;
  return f.color;
}
const rows = [];
for (const [id, a] of abs) {
  const n = a.node;
  if (n.type !== 'TEXT' || n.visible === false) continue;
  const fg = fillOf(n); if (!fg) continue;
  const cx = a.x + a.w/2, cy = a.y + a.h/2;
  let bg = null, bgOrder = -1;
  for (const [oid, o] of abs) {
    if (oid === id || o.order > a.order || o.node.type === 'TEXT') continue;
    const c = fillOf(o.node); if (!c) continue;
    if (cx < o.x || cx > o.x+o.w || cy < o.y || cy > o.y+o.h) continue;
    if (o.order > bgOrder) { bgOrder = o.order; bg = c; }
  }
  if (!bg) continue;
  const size = n.fontSize || 12, bold = (n.fontWeight||400) >= 700;
  const need = (size >= 24 || (size >= 18.66 && bold)) ? 3.0 : 4.5;
  const r = ratio(fg, bg);
  if (r < need) rows.push({id, name: n.name, fg: hex(fg), bg: hex(bg),
                           ratio: +r.toFixed(2), need});
}
return rows;
`;

function applyScript(plan: Record<string, string>) {
  return String.raw`
const PLAN = ${JSON.stringify(plan)};
const g = figma.graph;
function rgb(h){return {r:parseInt(h.slice(1,3),16)/255,
  g:parseInt(h.slice(3,5),16)/255, b:parseInt(h.slice(5,7),16)/255, a:1};}
let fixed = 0;
for (const [id, hexv] of Object.entries(PLAN)) {
  const n = g.nodes.get(id); if (!n) continue;
  n.fills = [{type:'SOLID', color: rgb(hexv), opacity:1, visible:true, blendMode:'NORMAL'}];
  // the old binding pointed at the failing colour; drop it rather than leave it lying
  if (n.boundVariables) delete n.boundVariables['fills/0/color'];
  fixed++;
}
return {fixed};
`;
}

// The generated client wraps tool results as {raw:{raw:{content:[{text}]}}};
// the payload we want is that innermost text, which is JSON.
const unwrap = (r: any) => {
  let cur = r;
  while (cur && typeof cur === "object" && "raw" in cur) cur = (cur as any).raw;
  const text = cur?.content?.[0]?.text;
  if (typeof text === "string") return JSON.parse(text);
  return cur;
};

const client = await createOpenpencilClient();
try {
  const before = unwrap(await client.eval({ document_id: DOC, code: AUDIT })) as any[];
  console.log(`failing text nodes: ${before.length}`);

  const grouped = new Map<string, number>();
  for (const r of before) {
    const k = `${r.fg} on ${r.bg} (${r.ratio}:1)`;
    grouped.set(k, (grouped.get(k) ?? 0) + 1);
  }
  for (const [k, n] of [...grouped].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${k.padEnd(34)} x${n}`);
  }

  const plan: Record<string, string> = {};
  const unhandled: any[] = [];
  for (const r of before) {
    const rule = REPLACEMENTS[r.fg];
    if (rule) plan[r.id] = rule.to;
    else unhandled.push(r);
  }

  console.log("\nplanned changes:");
  for (const [from, rule] of Object.entries(REPLACEMENTS)) {
    const n = before.filter((r) => r.fg === from).length;
    if (n) console.log(`  ${from} -> ${rule.to}  x${n}   ${rule.why}`);
  }
  if (unhandled.length) {
    // Left deliberately: an unexplained colour should be a visible decision,
    // not something this script quietly invents a value for.
    console.log("\nnot handled (needs a human decision):");
    for (const r of unhandled) console.log(`  ${r.name}: ${r.fg} on ${r.bg} @ ${r.ratio}:1`);
  }

  if (DRY) {
    console.log("\ndry run — nothing written");
  } else {
    console.log(`\napplying ${Object.keys(plan).length} changes ...`);
    console.log(JSON.stringify(unwrap(await client.eval({ document_id: DOC, code: applyScript(plan) }))));

    const after = unwrap(await client.eval({ document_id: DOC, code: AUDIT })) as any[];
    console.log(`failing after fix: ${after.length}`);
    for (const r of after) console.log(`  ${r.name}: ${r.fg} on ${r.bg} @ ${r.ratio}:1`);

    if (SAVE) {
      console.log(`saving -> ${SAVE}`);
      await client.save_file({ document_id: DOC, path: SAVE });
    }
  }
} finally {
  await client.close();
}
