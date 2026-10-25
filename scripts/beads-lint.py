#!/usr/bin/env python3
"""beads-lint.py — check .beads/issues.jsonl against the closure rule in docs/DEVELOPMENT-PROCESS.md.

    python3 -I scripts/beads-lint.py --base BASE [--head HEAD] [--jsonl PATH]

The rule exists because "closed" stopped meaning "landed": beads were closed for work that never
reached master (wtm2, qpfy, tni8, lxqq), and only about a quarter of closures named a commit at all.
So a closure must now point at the commit that did the work, and that commit must be in the history
being merged. Existing closures are grandfathered: only what changed between BASE and the file
checked here is judged.

Checks, each reported with the bead id it concerns:
  1. every line is a JSON object with a string "id", no blank lines, the file ends in a newline;
  2. ids are unique;
  3. no bead present at BASE has disappeared (an export that loses issues is how a merge driver once
     wiped the 264-issue tracker — see .gitattributes);
  4. every bead NEWLY closed (open at BASE, or absent there and added closed, or closed at BASE with
     a changed close_reason) has a close_reason that either
       a. cites `PR #N (<sha>)` or `PR #N (merge <sha>)` — the form both the close script and the
          existing closures use — and every cited sha is a commit that is an ancestor of HEAD; or
          starts with `MERGED via integrator` and names the landed commit(s) in its opening clause
          ("(<sha>)", "at <sha>", "fast-track (<sha>+<sha>)"), each an ancestor of HEAD. This is for
          merges the integrator made without a PR; no PR number is invented and a closure with no sha
          is still rejected; or
       b. says it fixed nothing and names why: starts with "Duplicate of <id>" / "Superseded by
          <id>" (an id in this file), or with "WONTFIX", "Won't fix", "INVALID" or "Not a defect".
          Those land no code, so there is no commit to cite; they are not an escape hatch for work
          that was done (a reviewer reads them in the diff); or
       c. the bead is an epic with at least one child (a parent-child dependency on it), and every
          child is closed in this file — the children carry the commits.

BASE: in CI, HEAD^1 — for a pull request the checkout is GitHub's merge commit, whose first parent
is the base branch it merges into; for a push to master it is the previous tip. Needs full history
(actions/checkout fetch-depth: 0). In a shallow clone a commit older than the clone's history cannot be
found and is reported as missing, with a warning that the clone is shallow.

Exit status: 0 clean, 1 rule violations, 2 usage or environment error.
"""

import argparse
import json
import os
import re
import subprocess
import sys

JSONL = ".beads/issues.jsonl"
FIX_RX = re.compile(r"PR #(\d+) \((?:merge )?([0-9a-f]{7,40})\)")
# "MERGED via integrator (<sha>)", "... at <sha>", "... fast-track (<sha>+<sha>)": the form closures use when a
# change lands by the integrator's own merge and no PR number exists (none may be invented). Only the
# opening clause is read for shas, and a sha needs a digit so an English word of hex letters is not one.
MERGED_RX = re.compile(r"^MERGED via integrator\b[^.:;\n]{0,80}")
SHA_RX = re.compile(r"\b(?=[0-9a-f]*\d)[0-9a-f]{7,40}\b")
NOFIX_REF_RX = re.compile(r"^(?:duplicate of|superseded by)\s+([A-Za-z0-9][A-Za-z0-9._-]*)", re.I)
NOFIX_RX = re.compile(r"^(?:wontfix|won't fix|invalid|not a defect)\b", re.I)


def git(*args, check=True):
    p = subprocess.run(["git", *args], capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {p.stderr.decode(errors='replace').strip()}")
    return p


def parse(raw, where, errors):
    """Parse JSONL bytes into {id: record}, appending format errors (prefixed by where)."""
    beads = {}
    if raw and not raw.endswith(b"\n"):
        errors.append(f"{where}: file does not end with a newline")
    lines = raw.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for n, line in enumerate(lines, 1):
        if not line.strip():
            errors.append(f"{where}:{n}: blank line")
            continue
        try:
            rec = json.loads(line)
        except ValueError as e:
            errors.append(f"{where}:{n}: not JSON ({e})")
            continue
        if not isinstance(rec, dict) or not isinstance(rec.get("id"), str):
            errors.append(f"{where}:{n}: not an object with a string id")
            continue
        if rec["id"] in beads:
            errors.append(f"{where}:{n}: duplicate id {rec['id']}")
            continue
        # The fields the rules read must have the types the rules assume. A wrong type is reported
        # against the bead and the field is set aside, so one bad record yields an error line, not a
        # traceback that hides every other result.
        for field, ok in (("status", str), ("close_reason", str), ("issue_type", str), ("dependencies", list)):
            if field in rec and rec[field] is not None and not isinstance(rec[field], ok):
                errors.append(f"{where}:{n}: {rec['id']}: field {field!r} is {type(rec[field]).__name__}, want {ok.__name__}")
                rec[field] = None
        deps = rec.get("dependencies") or []
        if any(not isinstance(d, dict) for d in deps):
            errors.append(f"{where}:{n}: {rec['id']}: a dependency entry is not an object")
            rec["dependencies"] = [d for d in deps if isinstance(d, dict)]
        beads[rec["id"]] = rec
    return beads


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", required=True, help="revision to compare against (CI: HEAD^1)")
    ap.add_argument("--head", default="HEAD", help="history a cited sha must be in (default HEAD)")
    ap.add_argument("--jsonl", default=JSONL, help=f"file to check (default {JSONL} in the work tree)")
    a = ap.parse_args()

    try:
        shallow = git("rev-parse", "--is-shallow-repository").stdout.strip() == b"true"
        if shallow:
            print("warning: shallow clone — a cited commit older than this clone's history will be "
                  "reported as missing (CI uses fetch-depth: 0)", file=sys.stderr)
        base = git("rev-parse", "--verify", a.base + "^{commit}").stdout.decode().strip()
        head = git("rev-parse", "--verify", a.head + "^{commit}").stdout.decode().strip()
    except RuntimeError as e:
        print(f"beads-lint: {e}", file=sys.stderr)
        return 2

    try:
        with open(a.jsonl, "rb") as f:
            raw = f.read()
    except OSError as e:
        print(f"beads-lint: {e}", file=sys.stderr)
        return 2
    base_p = git("show", f"{base}:{JSONL}", check=False)
    base_raw = base_p.stdout if base_p.returncode == 0 else b""

    errors = []
    beads = parse(raw, a.jsonl, errors)
    base_errors = []
    old = parse(base_raw, f"{base[:12]}:{JSONL}", base_errors)  # base format is not this PR's fault

    for bid in sorted(set(old) - set(beads)):
        errors.append(f"{bid}: present at base {base[:12]} but missing here — beads are closed, never deleted")

    sha_ok = {}

    def is_landed(sha):
        if sha not in sha_ok:
            full = git("rev-parse", "--verify", "--quiet", sha + "^{commit}", check=False)
            if full.returncode != 0:
                sha_ok[sha] = "is not a commit in this repository" + (" (shallow clone)" if shallow else "")
            elif git("merge-base", "--is-ancestor", full.stdout.decode().strip(), head, check=False).returncode != 0:
                sha_ok[sha] = f"is not in the history of {head[:12]} (not landed)"
            else:
                sha_ok[sha] = ""
        return sha_ok[sha]

    children = {}
    for rec in beads.values():
        for d in rec.get("dependencies") or []:
            if d.get("type") == "parent-child" and isinstance(d.get("depends_on_id"), str):
                children.setdefault(d["depends_on_id"], []).append(rec)

    newly = fixed = nofix = epics = 0
    for bid, rec in beads.items():
        if rec.get("status") != "closed":
            continue
        prev = old.get(bid)
        if prev is not None and prev.get("status") == "closed" and prev.get("close_reason") == rec.get("close_reason"):
            continue  # grandfathered: closed before, and the closure was not edited
        newly += 1
        reason = rec.get("close_reason") or ""
        cites = FIX_RX.findall(reason)
        if cites:
            bad = [f"{sha} {why}" for _, sha in cites if (why := is_landed(sha))]
            if bad:
                errors.append(f"{bid}: close_reason cites " + "; ".join(bad))
            else:
                fixed += 1
            continue
        mm = MERGED_RX.match(reason)
        if mm:
            shas = SHA_RX.findall(mm.group(0))
            if not shas:
                errors.append(
                    f"{bid}: 'MERGED via integrator' must cite the landed commit, e.g. "
                    f"'MERGED via integrator (<sha>)'; got {reason[:90]!r}"
                )
                continue
            bad = [f"{sha} {why}" for sha in shas if (why := is_landed(sha))]
            if bad:
                errors.append(f"{bid}: close_reason cites " + "; ".join(bad))
            else:
                fixed += 1
            continue
        kids = children.get(bid, [])
        if rec.get("issue_type") == "epic" and kids and all(k.get("status") == "closed" for k in kids):
            epics += 1
            continue
        m = NOFIX_REF_RX.match(reason)
        if m:
            ref = m.group(1).rstrip(".,;:")
            if ref in beads or any(k.endswith("-" + ref) for k in beads):
                nofix += 1
            else:
                errors.append(f"{bid}: close_reason names {ref!r}, which is not a bead in this file")
            continue
        if NOFIX_RX.match(reason):
            nofix += 1
            continue
        shown = (reason[:90] + "…") if len(reason) > 90 else reason
        errors.append(
            f"{bid}: newly closed without a landed commit — close_reason must cite 'PR #N (<sha>)' "
            f"(or start with Duplicate of/Superseded by <id>, WONTFIX, INVALID, Not a defect; or be an epic "
            f"whose children are all closed); got {shown!r}"
        )

    prefix = "::error::" if os.environ.get("GITHUB_ACTIONS") == "true" else "error: "
    for e in errors:
        print(prefix + e)
    print(
        f"beads-lint: {len(beads)} beads at {a.jsonl}, base {base[:12]} ({len(old)} beads); "
        f"{newly} newly closed: {fixed} cite a landed commit, {epics} epics with every child closed, "
        f"{nofix} closed as not-fixed, {newly - fixed - epics - nofix} rejected; {len(errors)} error(s)"
    )
    if base_errors:
        print(f"note: the base file itself has {len(base_errors)} format problem(s); not counted against this change")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
