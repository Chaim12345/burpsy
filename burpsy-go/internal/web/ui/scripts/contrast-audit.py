#!/usr/bin/env python3
"""
Audit (and optionally fix) WCAG AA text contrast in an OpenPencil document.

Why this is not just `openpencil lint`
--------------------------------------
The built-in `color-contrast` rule resolves a text node's background by walking
its ancestors. In this document almost everything is absolutely positioned, so
the rectangle a label actually sits on (a toolbar, a panel) is usually a
*sibling*, not an ancestor. That makes the built-in rule both miss real failures
and report false ones -- it flags plain rectangles like `tab / active-bg`, which
have no text and cannot fail a text-contrast rule.

This script instead resolves the background the way a reader sees it: the
topmost painted rectangle that is drawn before the text and overlaps its centre.

Contrast maths is WCAG 2.1: relative luminance, (L1+0.05)/(L2+0.05). The
threshold is 4.5:1, or 3.0:1 for large text (>=18pt, or >=14pt bold).

Usage:
    python3 contrast-audit.py --doc tab-4                 # report
    python3 contrast-audit.py --doc tab-4 --fix           # lighten failures
    python3 contrast-audit.py --doc tab-4 --fix --save out.fig
"""

import argparse
import json
import os
import subprocess
import sys

MCP_STATE = "/root/.openpencil/mcp.json"


def token():
    with open(MCP_STATE) as fh:
        return json.load(fh)["authToken"]


def call(tool, **params):
    env = dict(os.environ, OPENPENCIL_MCP_AUTH_TOKEN=token())
    proc = subprocess.run(
        ["mcporter", "call", f"openpencil.{tool}", "--args", json.dumps(params),
         "--output", "json", "--timeout", "180000"],
        capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"{tool}: {(proc.stderr or proc.stdout)[:500]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"raw": proc.stdout.strip()}


# Resolve each text node's true visual background, then report contrast.
# Paint order is document order: a node painted later sits on top.
AUDIT = r"""
function hex(c){const h=n=>Math.round(n*255).toString(16).padStart(2,'0');
  return ('#'+h(c.r)+h(c.g)+h(c.b)).toLowerCase();}
function lum(c){const f=v=>v<=0.03928?v/12.92:Math.pow((v+0.055)/1.055,2.4);
  return 0.2126*f(c.r)+0.7152*f(c.g)+0.0722*f(c.b);}
function ratio(a,b){const l1=lum(a),l2=lum(b);
  const hi=Math.max(l1,l2),lo=Math.min(l1,l2);return (hi+0.05)/(lo+0.05);}

const g = figma.graph;

// Absolute geometry + paint order, per board.
const abs = new Map();     // id -> {x,y,w,h,order,node}
let order = 0;
function walk(id, ox, oy) {
  const n = g.nodes.get(id); if (!n) return;
  const x = ox + (n.x || 0), y = oy + (n.y || 0);
  abs.set(id, {x, y, w: n.width || 0, h: n.height || 0, order: order++, node: n});
  for (const c of (n.childIds || [])) walk(c, x, y);
}
const boards = [];
for (const [id, n] of g.nodes) {
  const p = g.nodes.get(n.parentId);
  if (n.type === 'FRAME' && p && p.type === 'CANVAS') boards.push(id);
}
boards.forEach(b => walk(b, 0, 0));

function paintedFill(n) {
  const f = (n.fills || [])[0];
  if (!f || f.type !== 'SOLID' || !f.color) return null;
  if (f.visible === false) return null;
  if (f.color.a !== undefined && f.color.a === 0) return null;
  return f.color;
}

const rows = [];
for (const [id, a] of abs) {
  const n = a.node;
  if (n.type !== 'TEXT') continue;
  if (n.visible === false) continue;
  const fg = paintedFill(n); if (!fg) continue;
  const cx = a.x + a.w / 2, cy = a.y + a.h / 2;

  // topmost painted box drawn before this text that contains its centre
  let bg = null, bgName = null, bgOrder = -1;
  for (const [oid, o] of abs) {
    if (oid === id) continue;
    if (o.order > a.order) continue;          // painted after -> above, ignore
    if (o.node.type === 'TEXT') continue;
    const c = paintedFill(o.node); if (!c) continue;
    if (cx < o.x || cx > o.x + o.w || cy < o.y || cy > o.y + o.h) continue;
    if (o.order > bgOrder) { bgOrder = o.order; bg = c; bgName = o.node.name; }
  }
  if (!bg) continue;

  const size = n.fontSize || 12;
  const bold = (n.fontWeight || 400) >= 700;
  const large = size >= 24 || (size >= 18.66 && bold);
  const need = large ? 3.0 : 4.5;
  const r = ratio(fg, bg);
  if (r < need) {
    rows.push({id, name: n.name, text: (n.text||'').slice(0,24),
               fg: hex(fg), bg: hex(bg), bgName, size, bold,
               ratio: +r.toFixed(2), need});
  }
}
rows.sort((a,b)=>a.ratio-b.ratio);
const pairs = {};
for (const r of rows) {
  const k = r.fg + ' on ' + r.bg;
  pairs[k] = pairs[k] || {count:0, ratio:r.ratio, need:r.need, examples:[]};
  pairs[k].count++;
  if (pairs[k].examples.length < 3) pairs[k].examples.push(r.name);
}
return {failing: rows.length, pairs, worst: rows.slice(0, 12)};
"""


# Raise the foreground's lightness until it clears the threshold with margin.
# Hue is preserved: we scale toward white rather than replacing the colour, so
# accent and severity colours stay recognisably themselves.
FIX = r"""
const PLAN = __PLAN__;
const g = figma.graph;
function rgb(h){return {r:parseInt(h.slice(1,3),16)/255,
  g:parseInt(h.slice(3,5),16)/255, b:parseInt(h.slice(5,7),16)/255, a:1};}
let fixed = 0;
for (const [id, newHex] of Object.entries(PLAN)) {
  const n = g.nodes.get(id); if (!n) continue;
  const f = (n.fills || [])[0]; if (!f || !f.color) continue;
  const c = rgb(newHex);
  n.fills = [{type:'SOLID', color:c, opacity:1, visible:true, blendMode:'NORMAL'}];
  if (n.boundVariables) delete n.boundVariables['fills/0/color'];
  fixed++;
}
return {fixed};
"""


def luminance(hexs):
    def chan(v):
        v = int(hexs[v:v+2], 16) / 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    return 0.2126 * chan(1) + 0.7152 * chan(3) + 0.0722 * chan(5)


def contrast(a, b):
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def lighten(fg, bg, need, margin=0.15):
    """Blend fg toward white until it clears `need` with a little headroom.

    Aiming exactly at the threshold is fragile -- rounding at the boundary has
    bitten this project before, so overshoot slightly.
    """
    target = need + margin
    r, g_, b = (int(fg[1:3], 16), int(fg[3:5], 16), int(fg[5:7], 16))
    best = fg
    for step in range(0, 101):
        t = step / 100
        nr = round(r + (255 - r) * t)
        ng = round(g_ + (255 - g_) * t)
        nb = round(b + (255 - b) * t)
        cand = f"#{nr:02x}{ng:02x}{nb:02x}"
        if contrast(cand, bg) >= target:
            return cand
        best = cand
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--doc", default="tab-4")
    ap.add_argument("--fix", action="store_true")
    ap.add_argument("--save")
    args = ap.parse_args()

    audit = call("eval", document_id=args.doc, code=AUDIT)
    print(f"failing text nodes: {audit['failing']}")
    if audit["failing"]:
        print("\n%-26s %6s %6s  %s" % ("PAIR", "RATIO", "COUNT", "EXAMPLES"))
        for pair, info in sorted(audit["pairs"].items(), key=lambda kv: -kv[1]["count"]):
            print("%-26s %6.2f %6d  %s" % (pair, info["ratio"], info["count"],
                                           ", ".join(info["examples"])))
    if not args.fix or not audit["failing"]:
        return 0

    # Re-run the audit to get every failing node, then compute a per-node colour.
    rows = call("eval", document_id=args.doc, code=AUDIT.replace(
        "return {failing: rows.length, pairs, worst: rows.slice(0, 12)};",
        "return rows;"))
    plan, changes = {}, {}
    for r in rows:
        new = lighten(r["fg"], r["bg"], r["need"])
        plan[r["id"]] = new
        changes[f'{r["fg"]} -> {new} on {r["bg"]}'] = changes.get(
            f'{r["fg"]} -> {new} on {r["bg"]}', 0) + 1

    print(f"\napplying {len(plan)} colour changes:")
    for k, n in sorted(changes.items(), key=lambda kv: -kv[1]):
        print(f"  {k}  x{n}")
    print(json.dumps(call("eval", document_id=args.doc,
                          code=FIX.replace("__PLAN__", json.dumps(plan)))))

    after = call("eval", document_id=args.doc, code=AUDIT)
    print(f"\nfailing after fix: {after['failing']}")
    if after["failing"]:
        print(json.dumps(after["pairs"], indent=2))

    if args.save:
        print(f"saving -> {args.save}")
        call("save_file", document_id=args.doc, path=args.save)
    return 0 if after["failing"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
