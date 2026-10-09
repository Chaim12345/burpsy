#!/usr/bin/env python3
"""beads-close-merged.py — close the beads a round's merges carry, straight in .beads/issues.jsonl.

    python3 -I scripts/beads-close-merged.py [RANGE] [--apply] [--pr SHA=N ...] [--now TIMESTAMP]

RANGE is a git range (`origin/master..round/2026-10-10-1`) or a single revision R, read as
`origin/master..R` (`--base` changes that default). Default: `origin/master..HEAD`, i.e. run on the
round branch's tip. Dry run by default: it prints what it would close and changes nothing; `--apply`
writes the file.

What it reads. Every merge on the FIRST-PARENT line of RANGE is one item landing on the round branch.
For each merge M, the commits it brought in (M^1..M, M included) are searched for `Bead: <id>`
trailers — one id or a comma/space-separated list per trailer; a full id or its unique short suffix
(`ar8v` for burpsy-react-ui-ar8v). Each named bead is closed with

    Fixed by PR #N (<M, 12 hex>): <PR title>

which is the form scripts/beads-lint.py (the CI `beads` job) accepts, and M is in the round's history,
so the closure survives the lint once the round PR merges with a merge commit. A bead trailed by
several merges cites each of them; the title is the latest one's.

PR number and title, in this order: a GitHub merge ("Merge pull request #N from …", title on the
first body line); a local merge whose subject is "Merge PR #N: <title>" (the form the process doc
tells the lead to use with `git merge --no-ff`); `--pr <M>=<N>` on the command line. A merge with no
PR number is reported and its beads are NOT closed.

The "(id)" subject suffix older commits use is deliberately NOT a closure signal. It names the bead a
commit is about, and an epic or a partly-done bead is named that way too; closing on it would
manufacture exactly the "closed but never landed" records this process exists to stop. Such mentions
are listed so the lead can add a trailer or close by hand — never applied.

How it writes. No Dolt, no `bd`: the local Dolt DB is a scratch copy and refs/dolt/data is dead
(see docs/DEVELOPMENT-PROCESS.md). Only the lines of the beads being closed change; each is
re-encoded the way bd's Go exporter writes (compact, keys in bd's field order, <, > and & escaped as
\\u003c/\\u003e/\\u0026, other non-ASCII kept as UTF-8). Before touching a line the script checks
that re-encoding it unchanged reproduces it byte for byte, and refuses that bead otherwise, so a
format it does not understand can never be rewritten "close enough". The fields set are exactly
those bd sets on close: status, updated_at, closed_at, close_reason.

Exit status: 0 nothing wrong; 1 something was unresolved (and, with --apply, NOTHING is written
unless --allow-partial); 2 usage or environment error.
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile

JSONL = ".beads/issues.jsonl"
# The key order bd's exporter uses, derived from every record in the file (no record disagrees).
KEY_ORDER = [
    "_type", "id", "title", "description", "design", "acceptance_criteria", "notes", "status",
    "priority", "issue_type", "assignee", "owner", "created_at", "created_by", "updated_at",
    "started_at", "closed_at", "close_reason", "labels", "dependencies", "comments",
    "dependency_count", "dependent_count", "comment_count",
]
GH_MERGE_RX = re.compile(r"^Merge pull request #(\d+)\b")
LOCAL_MERGE_RX = re.compile(r"^Merge PR #(\d+)\b:?\s*(.*)$")
TRAILER_RX = re.compile(r"^(?:Bead|PR|Co-Authored-By|Claude-Session|Signed-off-by):\s", re.I)
SUBJECT_ID_RX = re.compile(r"\(([a-z0-9]{3,4}(?:\.\d+)?(?:,\s*[a-z0-9]{3,4}(?:\.\d+)?)*)\)\s*$")


def git(*args):
    p = subprocess.run(["git", *args], capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {p.stderr.decode(errors='replace').strip()}")
    return p.stdout.decode()


def encode(rec):
    """Serialise one record exactly as bd's Go exporter does (encoding/json defaults, compact)."""
    s = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
    for a, b in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                 ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        s = s.replace(a, b)
    return s.encode()


def merges_in(rng):
    out = git("log", "--first-parent", "--merges", "--reverse", "--format=%H", rng)
    return [h for h in out.split() if h]


def describe(m, pr_overrides):
    """Return (pr_number or None, title) for merge commit m."""
    subject = git("log", "-1", "--format=%s", m).strip()
    body = [ln.strip() for ln in git("log", "-1", "--format=%b", m).splitlines()]
    first_body = next((ln for ln in body if ln and not TRAILER_RX.match(ln)), "")
    g = GH_MERGE_RX.match(subject)
    if g:
        return int(g.group(1)), first_body or subject
    lm = LOCAL_MERGE_RX.match(subject)
    if lm:
        return int(lm.group(1)), lm.group(2).strip() or first_body or subject
    for key, n in pr_overrides.items():
        if m.startswith(key):
            return n, first_body or git("log", "-1", "--format=%s", m + "^2").strip()
    return None, subject


def trailers_and_mentions(m):
    """Bead trailer values, and "(id)" subject mentions, over the commits merge m brought in."""
    fmt = "%H%x1f%s%x1f%(trailers:key=Bead,valueonly,unfold,separator=%x1e)%x1d"
    out = git("log", "--format=" + fmt, f"{m}^1..{m}")
    trailed, mentioned = [], []
    for rec in out.split("\x1d"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, subject, tr = (rec.split("\x1f") + ["", ""])[:3]
        for v in tr.split("\x1e"):
            trailed += [t for t in re.split(r"[,\s]+", v.strip()) if t]
        sm = SUBJECT_ID_RX.search(subject)
        if sm:
            mentioned += [(t.strip(), sha[:12], subject) for t in sm.group(1).split(",")]
    return trailed, mentioned


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("range", nargs="?", default="HEAD", help="A..B, or a revision R meaning BASE..R (default HEAD)")
    ap.add_argument("--base", default="origin/master", help="base for a single-revision RANGE (default origin/master)")
    ap.add_argument("--jsonl", default=JSONL, help=f"file to update (default {JSONL})")
    ap.add_argument("--apply", action="store_true", help="write the file (default: dry run)")
    ap.add_argument("--allow-partial", action="store_true", help="with --apply, write even if something was unresolved")
    ap.add_argument("--pr", action="append", default=[], metavar="SHA=N", help="PR number for a merge whose message has none")
    ap.add_argument("--now", help="timestamp for updated_at/closed_at (default: now, UTC, e.g. 2026-10-09T15:37:15Z)")
    a = ap.parse_args()

    rng = a.range if ".." in a.range else f"{a.base}..{a.range}"
    now = a.now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", now):
        print(f"--now must look like 2026-10-09T15:37:15Z, got {now!r}", file=sys.stderr)
        return 2
    overrides = {}
    for p in a.pr:
        k, _, v = p.partition("=")
        if not re.fullmatch(r"[0-9a-f]{7,40}", k) or not v.isdigit():
            print(f"--pr wants <merge sha>=<number>, got {p!r}", file=sys.stderr)
            return 2
        overrides[k] = int(v)

    try:
        merges = merges_in(rng)
    except RuntimeError as e:
        print(e, file=sys.stderr)
        return 2
    try:
        with open(a.jsonl, "rb") as f:
            raw = f.read()
    except OSError as e:
        print(e, file=sys.stderr)
        return 2
    if not raw.endswith(b"\n"):
        print(f"{a.jsonl} does not end in a newline; refusing to edit it", file=sys.stderr)
        return 2
    lines = raw.split(b"\n")[:-1]
    index = {}
    for n, line in enumerate(lines):
        try:
            rec = json.loads(line)
            bid = rec["id"] if isinstance(rec, dict) else None
        except ValueError as e:
            print(f"{a.jsonl}:{n + 1}: not JSON ({e}); refusing to edit the file (run scripts/beads-lint.py)", file=sys.stderr)
            return 2
        if not isinstance(bid, str) or bid in index:
            print(f"{a.jsonl}:{n + 1}: missing or duplicate id; refusing to edit the file (run scripts/beads-lint.py)", file=sys.stderr)
            return 2
        index[bid] = n

    def resolve(token):
        if token in index:
            return token
        hits = [i for i in index if i.endswith("-" + token)]
        return hits[0] if len(hits) == 1 else None

    problems, notes = [], []
    plan = {}  # bead id -> list of (pr, merge sha, title)
    untrailed = {}  # "(id)" mention -> commits naming it
    print(f"range {rng}: {len(merges)} first-parent merge(s)")
    for m in merges:
        pr, title = describe(m, overrides)
        trailed, mentioned = trailers_and_mentions(m)
        print(f"  {m[:12]} PR #{pr if pr else '?'} {title[:80]!r}: Bead trailers {trailed or 'none'}")
        tm = SUBJECT_ID_RX.search(title)
        if tm:
            mentioned += [(t.strip(), m[:12], title) for t in tm.group(1).split(",")]
        trailed_ids = {resolve(x) for x in trailed}
        for t, sha, subj in mentioned:
            if t not in trailed and resolve(t) not in trailed_ids:
                untrailed.setdefault(t, []).append(sha)
        if not trailed:
            continue
        if pr is None:
            problems.append(f"merge {m[:12]} has no PR number (use 'Merge PR #N: <title>' or --pr {m[:12]}=N); "
                            f"its beads {trailed} were NOT closed")
            continue
        for t in trailed:
            bid = resolve(t)
            if bid is None:
                problems.append(f"Bead: {t} (merge {m[:12]}, PR #{pr}) matches no bead, or more than one")
                continue
            plan.setdefault(bid, []).append((pr, m, title))

    changed = {}
    for bid, cites in plan.items():
        n = index[bid]
        rec = json.loads(lines[n])
        if encode(rec) != lines[n]:
            problems.append(f"{bid}: its line does not re-encode byte for byte; refusing to rewrite it")
            continue
        if any(k not in KEY_ORDER for k in rec) or list(rec) != sorted(rec, key=KEY_ORDER.index):
            problems.append(f"{bid}: unexpected fields or field order {list(rec)}; refusing to rewrite it")
            continue
        if rec.get("status") == "closed":
            notes.append(f"{bid}: already closed ({(rec.get('close_reason') or '')[:60]!r}) — left untouched")
            continue
        seen, uniq = set(), []
        for c in cites:
            if (c[0], c[1]) not in seen:
                seen.add((c[0], c[1]))
                uniq.append(c)
        reason = "Fixed by " + ", ".join(f"PR #{pr} ({m[:12]})" for pr, m, _ in uniq) + ": " + uniq[-1][2]
        rec.update(status="closed", updated_at=now, closed_at=now, close_reason=reason)
        rec = {k: rec[k] for k in sorted(rec, key=KEY_ORDER.index)}
        changed[n] = encode(rec)
        print(f"  close {bid} [{json.loads(lines[n]).get('status')} -> closed]: {reason[:110]}")

    for t, shas in untrailed.items():
        notes.append(f"{t}: named as '({t})' in {len(shas)} subject(s)/title(s) ({', '.join(shas[:3])}"
                     f"{', …' if len(shas) > 3 else ''}) but no Bead: trailer — NOT closed")
    for note in notes:
        print("note: " + note)
    for p in problems:
        print("PROBLEM: " + p)
    print(f"{len(changed)} bead(s) to close, {len(problems)} problem(s), {len(notes)} note(s)")

    if not a.apply:
        print("dry run: nothing written (pass --apply to write)")
        return 1 if problems else 0
    if problems and not a.allow_partial:
        print("not written: resolve the problems above, or pass --allow-partial", file=sys.stderr)
        return 1
    out = [changed.get(n, line) for n, line in enumerate(lines)]
    # Write a sibling temp file and rename it over the original: an interrupted write leaves the old
    # file intact, never a truncated tracker (a zero-length export once wiped it — see .gitattributes).
    d = os.path.dirname(os.path.abspath(a.jsonl))
    fd, tmp = tempfile.mkstemp(prefix=".issues.", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(b"\n".join(out) + b"\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, os.stat(a.jsonl).st_mode & 0o777)
        os.replace(tmp, a.jsonl)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    print(f"wrote {a.jsonl}: {len(changed)} line(s) rewritten in place, {len(lines) - len(changed)} untouched")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
