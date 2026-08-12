#!/usr/bin/env python3
"""
Bind burpsy design tokens into the OpenPencil design file.

The design file ships every fill as a raw hex, so editing a token changes
nothing on canvas and the file cannot be the source of truth its provenance
claims. This script creates real variables from src/tokens/penpot-export.json
and binds them to every matching fill and stroke.

Lessons carried over from the app-shell retrofit script
-------------------------------------------------------
1. Read the auth token live from ~/.openpencil/mcp.json. The app regenerates it
   on restart, and the copy in ~/.claude.json goes stale silently.
2. Do the work in ONE `eval` call, not one MCP call per edit. The retrofit ran
   ~30 calls per page and spent almost all its wall time on connection
   handshakes -- it looked stalled for minutes at a time. `figma.graph.nodes`
   is a live Map and `node.boundVariables` is a plain object, so ~1200 bindings
   collapse into a single round trip. (Verified: a binding written through the
   graph is visible to the `node_bindings` tool.)
3. Verify by re-reading state, never by trusting an OK response. The retrofit
   returned success for deletes that had not landed.
4. Be idempotent. The retrofit could not be safely re-run; this one rebuilds the
   collection from scratch and can be run repeatedly.
5. Never bind by hex alone. Four hexes map to more than one semantic token
   (#2b2b2b is paper-sunken / ink / field-bg / editor-bg), so the role is
   decided from node type and name. Binding those blind would silently give
   text the panel-background token.

Usage:
    python3 bind-design-tokens.py --doc tab-4 [--dry-run] [--save PATH]
"""

import argparse
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKENS = os.path.join(REPO, "src", "tokens", "penpot-export.json")
MCP_STATE = "/root/.openpencil/mcp.json"


def auth_token():
    """Lesson 1: always read the live token, never a cached copy."""
    with open(MCP_STATE) as fh:
        return json.load(fh)["authToken"]


def call(tool, doc, **params):
    env = dict(os.environ, OPENPENCIL_MCP_AUTH_TOKEN=auth_token())
    cmd = ["mcporter", "call", f"openpencil.{tool}", f"document_id={doc}"]
    for key, value in params.items():
        cmd.append(f"{key}={value}")
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"{tool} failed: {proc.stderr.strip()[:400]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"raw": proc.stdout.strip()}


def call_eval(code, doc):
    """eval takes a large code blob, so pass it as a JSON payload rather than
    argv key=value -- the code contains quotes, braces and newlines that shell
    word-splitting would mangle."""
    env = dict(os.environ, OPENPENCIL_MCP_AUTH_TOKEN=auth_token())
    payload = json.dumps({"document_id": doc, "code": code})
    proc = subprocess.run(
        ["mcporter", "call", "openpencil.eval", "--args", payload,
         "--output", "json", "--timeout", "180000"],
        capture_output=True, text=True, env=env,
    )
    if proc.returncode != 0 or "error" in proc.stdout[:60].lower():
        raise RuntimeError(f"eval failed: {(proc.stderr or proc.stdout).strip()[:600]}")
    return json.loads(proc.stdout)


def load_tokens():
    """Resolve {alias} references down to concrete hex values per theme."""
    with open(TOKENS) as fh:
        data = json.load(fh)
    primitives = {t["name"]: t for t in data["primitives"]}

    def resolve(value, depth=0):
        while isinstance(value, str) and value.startswith("{") and depth < 10:
            key = value[1:-1]
            if key not in primitives:
                return None
            value = primitives[key]["value"]
            depth += 1
        return value

    themes = {}
    for theme, key in (("dark", "semantic.dark"), ("light", "semantic.light")):
        out = {}
        for token in data[key]:
            if token["type"] != "color":
                continue
            hexval = resolve(token["value"])
            if isinstance(hexval, str) and hexval.startswith("#"):
                out[token["name"]] = hexval.lower()
        themes[theme] = out
    return themes


# Lesson 5: hexes that several tokens share. Order matters -- first match wins,
# so the most specific test is listed first. `kind` is "text" for TEXT nodes.
DISAMBIGUATION = {
    "#2b2b2b": [
        ("editor", "color.editor-bg"),
        ("field|input", "color.field-bg"),
        ("__text__", "color.ink"),
        ("*", "color.paper-sunken"),
    ],
    "#a9b7c6": [
        ("editor", "color.editor-fg"),
        ("*", "color.text-soft"),
    ],
    "#313335": [
        ("gutter", "color.editor-gutter-bg"),
        ("*", "color.chrome"),
    ],
    "#ff6633": [
        ("*", "color.accent"),
    ],
}


def build_eval(themes, dry_run):
    dark = themes["dark"]
    light = themes["light"]
    # hex -> token, for the unambiguous majority
    by_hex = {}
    for name, hexval in dark.items():
        by_hex.setdefault(hexval, []).append(name)
    simple = {h: names[0] for h, names in by_hex.items()
              if len(names) == 1 and h not in DISAMBIGUATION}

    payload = {
        "dark": dark,
        "light": light,
        "simple": simple,
        "rules": DISAMBIGUATION,
        "dryRun": dry_run,
    }

    return """
const P = %s;
const g = figma.graph;
const log = [];

function hex(c){const h=n=>Math.round(n*255).toString(16).padStart(2,'0');
  return ('#'+h(c.r)+h(c.g)+h(c.b)).toLowerCase();}
function rgb(h){return {r:parseInt(h.slice(1,3),16)/255, g:parseInt(h.slice(3,5),16)/255,
  b:parseInt(h.slice(5,7),16)/255, a:1};}

// ---- 1. rebuild the semantic collection (idempotent: drop any previous one)
for (const [id,c] of Array.from(g.variableCollections)) {
  if (c.name === 'semantic') {
    for (const vid of (c.variableIds||[])) g.variables.delete(vid);
    g.variableCollections.delete(id);
  }
}
const colId = 'sem:col';
const darkMode = 'sem:dark', lightMode = 'sem:light';
g.variableCollections.set(colId, {
  id: colId, name: 'semantic',
  modes: [{modeId: darkMode, name: 'dark'}, {modeId: lightMode, name: 'light'}],
  defaultModeId: darkMode, variableIds: []
});
const col = g.variableCollections.get(colId);

// ---- 2. one variable per semantic token, valued in both themes
const varOf = {};
let made = 0;
for (const name of Object.keys(P.dark)) {
  const id = 'sem:' + name;
  const values = {};
  values[darkMode] = rgb(P.dark[name]);
  if (P.light[name]) values[lightMode] = rgb(P.light[name]);
  g.variables.set(id, {
    id, name, type: 'COLOR', collectionId: colId,
    valuesByMode: values, description: '', hiddenFromPublishing: false
  });
  col.variableIds.push(id);
  varOf[name] = id;
  made++;
}

// ---- 3. decide which token a given colour+node means (lesson 5)
function tokenFor(h, node) {
  const rules = P.rules[h];
  if (rules) {
    const nm = (node.name || '').toLowerCase();
    for (const [test, token] of rules) {
      if (test === '*') return token;
      if (test === '__text__') { if (node.type === 'TEXT') return token; continue; }
      if (new RegExp(test).test(nm)) return token;
    }
    return null;
  }
  return P.simple[h] || null;
}

// ---- 4. bind every solid fill and stroke we have a token for
let boundFills = 0, boundStrokes = 0, skipped = 0;
const unmatched = {};
for (const [id, n] of g.nodes) {
  if (Array.isArray(n.fills)) {
    n.fills.forEach((f, i) => {
      if (!f || f.type !== 'SOLID' || !f.color) return;
      const h = hex(f.color);
      const tok = tokenFor(h, n);
      if (!tok || !varOf[tok]) { unmatched[h] = (unmatched[h]||0)+1; skipped++; return; }
      if (!P.dryRun) {
        if (!n.boundVariables) n.boundVariables = {};
        n.boundVariables['fills/'+i+'/color'] = varOf[tok];
      }
      boundFills++;
    });
  }
  if (Array.isArray(n.strokes)) {
    n.strokes.forEach((s, i) => {
      if (!s || !s.color) return;
      const h = hex(s.color);
      const tok = tokenFor(h, n);
      if (!tok || !varOf[tok]) { unmatched[h] = (unmatched[h]||0)+1; skipped++; return; }
      if (!P.dryRun) {
        if (!n.boundVariables) n.boundVariables = {};
        n.boundVariables['strokes/'+i+'/color'] = varOf[tok];
      }
      boundStrokes++;
    });
  }
}

const top = Object.entries(unmatched).sort((a,b)=>b[1]-a[1]).slice(0,15);
return {dryRun: P.dryRun, variablesCreated: made, boundFills, boundStrokes,
        skipped, distinctUnmatched: Object.keys(unmatched).length, topUnmatched: top};
""" % json.dumps(payload)


VERIFY = """
const g = figma.graph;
let nodesWithBindings = 0, totalBindings = 0;
for (const [id,n] of g.nodes) {
  if (n.boundVariables && Object.keys(n.boundVariables).length) {
    nodesWithBindings++;
    totalBindings += Object.keys(n.boundVariables).length;
  }
}
let vars = 0; for (const _ of g.variables) vars++;
const cols = [];
for (const [id,c] of g.variableCollections) cols.push({name:c.name, modes:c.modes.map(m=>m.name), vars:(c.variableIds||[]).length});
return {nodesWithBindings, totalBindings, variables: vars, collections: cols};
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--doc", default="tab-4")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--save", help="save the document to this path when done")
    args = ap.parse_args()

    themes = load_tokens()
    print(f"tokens: {len(themes['dark'])} dark, {len(themes['light'])} light")

    print("binding" + (" (dry run)" if args.dry_run else "") + " ...")
    result = call_eval(build_eval(themes, args.dry_run), args.doc)
    print(json.dumps(result, indent=2))

    # Lesson 3: verify by re-reading, not by trusting the call above.
    print("\nverifying ...")
    check = call_eval(VERIFY, args.doc)
    print(json.dumps(check, indent=2))

    if args.dry_run:
        print("\ndry run -- nothing written")
        return 0
    if check.get("totalBindings", 0) == 0:
        print("\nFAILED: no bindings present after run", file=sys.stderr)
        return 1

    if args.save:
        print(f"\nsaving -> {args.save}")
        print(json.dumps(call("save_file", args.doc, path=args.save), indent=2))
    print("\nOK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
