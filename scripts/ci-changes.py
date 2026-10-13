#!/usr/bin/env python3
"""ci-changes.py — decide what go.yml runs for a diff. Used by go.yml's `changes` job.

    python3 -I scripts/ci-changes.py --event pull_request --base HEAD^1
    python3 -I scripts/ci-changes.py --event push --base <before-sha>

Prints the decision and its reasons, and writes to $GITHUB_OUTPUT when that is set:

    code=true|false     run the Go jobs (lint, test) and ui. false only when EVERY changed file is
                        one no Go test and no UI check reads (docs, .beads data, benchmark scripts).
    mode=full|affected  full: every shard runs everything (scripts/ci-shard.sh without
                        CI_AFFECTED_BASE). affected: shards run only what
                        scripts/affected-go-tests.sh selects for BASE...HEAD.
    base=<sha>          the resolved BASE, for affected mode.

Rules, and why each one exists:

  * Only pull requests run in affected mode. A push to master, a manual dispatch and anything this
    script cannot classify run the full suite: master is the tree that landed, and its full run is
    the evidence that it passes. The affected set cannot see merge skew or a test that reads a file
    without importing it (scripts/affected-go-tests.sh lists both); the round workflow already ran
    the affected set locally (T1/T2), so on a PR CI repeats it on GitHub's merge commit, and the
    push to master closes the gap.
  * A PR that touches what decides or provisions the run itself runs everything: any go.mod,
    go.sum, go.work or go.work.sum (at any depth — a workspace file at the repository root changes
    burpsy-go's build) and any vendor/ directory, .github/** and scripts/ci-* and scripts/affected-go-tests.sh (the selection
    logic and the test environment), and any testdata/ directory (testdata is the one kind of input
    another package's tests read without importing — internal/web reads internal/scanner/testdata —
    so a narrower rule would depend on knowing every such reader).
  * Skippable paths: docs/**, burpsy-go/docs/**, Markdown outside burpsy-go's packages, .beads/**
    except .beads/hooks/** (cmd/burpsy's hooks_parse_test.go parses those), and the benchmark
    scripts (scripts/bench/**, burpsy-go/bench/** — a separate Go module `go list ./...` never
    includes — and burpsy-go/scripts/crawl-benchmark/**). Nothing under them is compiled,
    go:embed-ed, or read by a Go test or by the ui job's checks; affected-go-tests.sh selects
    internal/web for them only through the byte rule below.
  * The control-byte rule runs here on EVERY event, over every tracked file, because it is the one
    Go test a skipped docs-only change could still break: internal/web's
    TestNoTrackedTextFileIsInvisibleToGrep fails when any tracked text file holds a raw control
    byte (grep then reports zero matches in it while exiting 0). The check below is a copy of that
    test's rule — same extensions, same dist/ exclusion, same allowed bytes. The Go test stays the
    authority and still runs whenever internal/web does.
"""

import argparse
import os
import re
import subprocess
import sys

# Kept identical to internal/web/ui_source_bytes_test.go (textExt, controlBytesAllowed, "/dist/").
TEXT_EXT = {".go", ".ts", ".tsx", ".js", ".jsx", ".css", ".md", ".json", ".yml", ".yaml", ".sh",
            ".html", ".toml", ".txt", ".sql"}
# Every byte below 0x20 except tab, newline and carriage return, plus DEL.
CONTROL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

ZERO_SHA = "0" * 40


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def runs_everything(path):
    """A path whose change makes a PR run the full suite, with the reason."""
    # Any go.mod/go.sum/go.work/go.work.sum, at any depth: burpsy-go's own, a nested module's, or a
    # workspace file — the go command finds go.work by walking UP from burpsy-go, so one at the
    # repository root changes the build as much as one beside go.mod. A vendor/ directory replaces
    # module sources. None of these is a package file, so affected-go-tests.sh would attribute them
    # to no package and select nothing.
    if os.path.basename(path) in ("go.mod", "go.sum", "go.work", "go.work.sum"):
        return "a module, workspace or dependency file changed"
    if "/vendor/" in "/" + path:
        return "vendored module sources changed"
    if path.startswith(".github/"):
        return "the CI definition changed"
    if path.startswith("scripts/ci-") or path == "scripts/affected-go-tests.sh":
        return "the CI test selection or environment changed"
    if "/testdata/" in "/" + path:
        return "testdata changed (another package's tests may read it without importing it)"
    return None


def skippable(path):
    """True when no Go test, Go build or ui check reads PATH."""
    if path.startswith(("docs/", "burpsy-go/docs/", "scripts/bench/", "burpsy-go/bench/",
                        "burpsy-go/scripts/crawl-benchmark/")):
        return True
    if path.startswith(".beads/"):
        return not path.startswith(".beads/hooks/")
    if path.lower().endswith(".md"):
        # Markdown inside a package directory could be go:embed-ed (internal/bcheck/bundled embeds a
        # whole directory); everywhere else it is prose.
        return not path.startswith(("burpsy-go/internal/", "burpsy-go/cmd/", "burpsy-go/pkg/"))
    return False


def control_byte_offenders(root):
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"], check=True, capture_output=True).stdout
    offenders, scanned = [], 0
    for raw_name in out.split(b"\0"):
        if not raw_name:
            continue
        name = raw_name.decode("utf-8", "surrogateescape")
        if os.path.splitext(name)[1].lower() not in TEXT_EXT or "/dist/" in name:
            continue
        try:
            with open(os.path.join(root, name), "rb") as f:
                data = f.read()
        except OSError:
            continue  # tracked but not on disk: not this check's problem, as in the Go test
        scanned += 1
        m = CONTROL.search(data)
        if m:
            line = data.count(b"\n", 0, m.start()) + 1
            offenders.append(f"{name}:{line} holds a raw control byte 0x{data[m.start()]:02x}")
    return scanned, offenders


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--event", required=True)
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="HEAD")
    args = ap.parse_args()

    root = git("rev-parse", "--show-toplevel").strip()
    decision = {"code": "true", "mode": "full", "base": ""}
    reasons = []

    scanned, offenders = control_byte_offenders(root)
    print(f"control-byte check: scanned {scanned} tracked text files")
    if scanned < 100:
        print("::error::the control-byte check scanned fewer than 100 files; its file listing is broken")
        return 1
    if offenders:
        for o in offenders:
            print(f"::error::{o} — grep reports zero matches in this whole file while exiting 0; write it as an escape")
        return 1

    base = ""
    if args.base and args.base != ZERO_SHA:
        try:
            base = git("rev-parse", "--verify", "--quiet", args.base + "^{commit}").strip()
        except subprocess.CalledProcessError:
            base = ""

    if not base:
        reasons.append(f"no usable base ({args.base or 'none given'}): everything runs")
    else:
        # Two dots for a push (before..after are both on master); three for a PR, so a branch behind
        # master is not blamed for master's changes. On GitHub's PR merge commit HEAD^1 is the base
        # tip, so the two agree there.
        spec = f"{base}...{args.head}" if args.event == "pull_request" else f"{base}..{args.head}"
        files = [f for f in git("diff", "--name-only", "--no-renames", spec).splitlines() if f]
        print(f"{len(files)} file(s) changed in {spec}")
        if not files:
            # Nothing to select from (an empty merge, a revert of a revert): run everything rather
            # than an affected set that is empty by construction.
            reasons.append("the diff is empty: nothing to select from, so the full suite runs")
        elif all(skippable(f) for f in files):
            decision["code"] = "false"
            reasons.append("every changed file is documentation, .beads data or a benchmark script: "
                           "the Go and ui jobs are skipped (gate still reports)")
        elif args.event == "pull_request":
            full = sorted({r for r in (runs_everything(f) for f in files) if r})
            if full:
                reasons += [f"full suite: {r}" for r in full]
            else:
                decision["mode"] = "affected"
                decision["base"] = base
                reasons.append("pull request: the test shards run only the packages "
                               "scripts/affected-go-tests.sh selects (the push to master runs them all); "
                               "a shard with nothing selected says NOT RUN in its summary")
        else:
            reasons.append(f"{args.event}: the full suite runs")

    for k, v in decision.items():
        print(f"{k}={v}")
    for r in reasons:
        print(f"  - {r}")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            for k, v in decision.items():
                f.write(f"{k}={v}\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(f"### What this run tests\n\ncode={decision['code']}, mode={decision['mode']}\n\n")
            f.write("".join(f"- {r}\n" for r in reasons))
    return 0


if __name__ == "__main__":
    sys.exit(main())
