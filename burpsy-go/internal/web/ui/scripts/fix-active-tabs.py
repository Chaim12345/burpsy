#!/usr/bin/env python3
"""
Give every tool board its own active-tab marker as REAL nodes.

Why this exists
---------------
The app-shell retrofit set each board's active tab by overriding the shell
instance's children. That looked correct in-session, but OpenPencil does not
serialise instance overrides: after save + reopen, all 16 instances come back
with `overrideCount: 0` and every board highlights "Dashboard". The retrofit was
verified live and never re-verified from disk, so the loss went unnoticed.

Fix: the shell component carries NO active state, and each board owns a real
pill + label drawn on top of its shell instance. Real child nodes survive the
round trip; overrides do not.

Lessons carried forward
-----------------------
1. Live auth token from ~/.openpencil/mcp.json (it rotates on app restart).
2. Bulk work in as few calls as possible -- `render` builds a whole overlay from
   one JSX string, so this is ~1 call per board instead of ~6.
3. Verify against the SAVED file by reopening it, not against live memory. That
   is precisely the check that would have caught the override loss.
4. Idempotent: existing overlays are removed before new ones are drawn.

Usage:
    python3 fix-active-tabs.py --doc tab-4 --save /path/out.fig [--verify]
"""

import argparse
import json
import os
import subprocess
import sys

MCP_STATE = "/root/.openpencil/mcp.json"
OVERLAY = "active-tab-marker"

# x/width of the pill and x of the label, measured from the shell component.
TABS = {
    "Dashboard": (6, 75, 12),
    "Target":    (91, 54, 97),
    "Proxy":     (155, 47, 161),
    "Intruder":  (212, 68, 218),
    "Repeater":  (290, 68, 296),
    "Sequencer": (368, 75, 374),
    "Decoder":   (453, 61, 459),
    "Comparer":  (524, 68, 530),
    "Logger":    (602, 54, 608),
    "Organizer": (666, 75, 672),
    "Session":   (751, 61, 757),
    "Settings":  (822, 68, 828),
}

# Board name prefix -> which tool tab is active.
PREFIX = {
    "00 Dashboard": "Dashboard", "01 Target": "Target", "02 Proxy": "Proxy",
    "03 Intruder": "Intruder", "04 Repeater": "Repeater", "05 Sequencer": "Sequencer",
    "06 Decoder": "Decoder", "07 Comparer": "Comparer", "08 Logger": "Logger",
    "09 Organizer": "Organizer", "10 Session": "Session", "11 Settings": "Settings",
}


def token():
    with open(MCP_STATE) as fh:
        return json.load(fh)["authToken"]


def call(tool, **params):
    env = dict(os.environ, OPENPENCIL_MCP_AUTH_TOKEN=token())
    proc = subprocess.run(
        ["mcporter", "call", f"openpencil.{tool}", "--args", json.dumps(params),
         "--output", "json", "--timeout", "120000"],
        capture_output=True, text=True, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"{tool}: {(proc.stderr or proc.stdout)[:400]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"raw": proc.stdout.strip()}


def tool_for(board_name):
    for prefix, tab in PREFIX.items():
        if board_name.startswith(prefix):
            return tab
    return None


# Strip the component's baked-in Dashboard highlight, and drop any overlay from a
# previous run, in one pass.
PREP = """
const g = figma.graph;
let neutralised = 0, removed = 0;
for (const [id, n] of Array.from(g.nodes)) {
  if (n.name === '%s') {
    const p = g.nodes.get(n.parentId);
    if (p && p.childIds) p.childIds = p.childIds.filter(c => c !== id);
    g.nodes.delete(id); removed++;
    continue;
  }
  const parent = g.nodes.get(n.parentId);
  const inShell = parent && /app-shell/.test(parent.name || '');
  if (!inShell) continue;
  if (n.name === 'tab / Dashboard' && n.type === 'TEXT') {
    n.fills = [{type:'SOLID', color:{r:0.733,g:0.733,b:0.733,a:1}, opacity:1, visible:true, blendMode:'NORMAL'}];
    n.fontWeight = 400;
    if (n.boundVariables) delete n.boundVariables['fills/0/color'];
    neutralised++;
  }
  if (n.name === 'tab / active-bg') { n.visible = false; neutralised++; }
}
const boards = [];
for (const [id, n] of g.nodes) {
  if (n.parentId && g.nodes.get(n.parentId) && g.nodes.get(n.parentId).type === 'CANVAS'
      && n.type === 'FRAME' && n.width === 1440 && n.height === 900) {
    boards.push({id, name: n.name});
  }
}
return {neutralised, removed, boards};
""" % OVERLAY


def overlay_jsx(tab):
    x, w, tx = TABS[tab]
    return (
        f'<Frame name="{OVERLAY}" x={{0}} y={{0}} w={{1440}} h={{62}} bg="#00000000">'
        f'<Rectangle name="active-pill" x={{{x}}} y={{28}} w={{{w}}} h={{30}} bg="#3C3F41" rounded={{2}} />'
        f'<Text name="active-label" x={{{tx}}} y={{36}} size={{12}} weight="bold" '
        f'lineHeight={{14.4}} color="#FF6633">{tab}</Text>'
        f'</Frame>'
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--doc", default="tab-4")
    ap.add_argument("--save")
    ap.add_argument("--verify", action="store_true",
                    help="reopen the saved file and re-check from disk")
    args = ap.parse_args()

    print("preparing shell + clearing old overlays ...")
    prep = call("eval", document_id=args.doc, code=PREP)
    print(f"  neutralised {prep['neutralised']}, removed {prep['removed']} old overlays")

    boards = [b for b in prep["boards"] if tool_for(b["name"])]
    print(f"  {len(boards)} tool boards")

    for board in sorted(boards, key=lambda b: b["name"]):
        tab = tool_for(board["name"])
        call("render", document_id=args.doc, parent_id=board["id"],
             jsx=overlay_jsx(tab))
        print(f"  {board['name']:<34} -> {tab}")

    if not args.save:
        print("\nno --save given; nothing written")
        return 0

    print(f"\nsaving -> {args.save}")
    call("save_file", document_id=args.doc, path=args.save)

    if args.verify:
        # Lesson 3: the only check that counts is reading the file back.
        print("verifying from disk ...")
        opened = call("open_file", path=args.save)
        doc = opened["target"]["documentId"]
        check = call("eval", document_id=doc, code="""
        function hex(c){const h=n=>Math.round(n*255).toString(16).padStart(2,'0');
          return ('#'+h(c.r)+h(c.g)+h(c.b)).toLowerCase();}
        const g=figma.graph; const rows=[];
        for (const [id,n] of g.nodes){
          if(n.type!=='FRAME'||n.width!==1440||n.height!==900) continue;
          const p=g.nodes.get(n.parentId); if(!p||p.type!=='CANVAS') continue;
          let label=null;
          const stack=[...(n.childIds||[])];
          while(stack.length){
            const c=g.nodes.get(stack.pop()); if(!c) continue;
            if(c.childIds) stack.push(...c.childIds);
            if(c.name==='active-label'&&c.type==='TEXT') label=c.text;
          }
          rows.push({board:n.name,active:label});
        }
        const missing = rows.filter(r=>!r.active).length;
        return {boards: rows.length, missing, rows};
        """)
        print(json.dumps(check, indent=2))
        if check["missing"]:
            print(f"\nFAILED: {check['missing']} board(s) lost their marker", file=sys.stderr)
            return 1
        print("\nverified from disk: every board kept its active tab")
    print("\nOK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
