#!/usr/bin/env python3
"""ci-vulncheck-gate.py — fail only on vulnerabilities that are NOT in the baseline.

Reads `govulncheck -format json` on stdin and the baseline file (one OSV id per line, `#` comments)
as argv[1]. A vulnerability counts when govulncheck found it reachable (a finding whose trace has a
function frame); the findings that only say "a module you require has one" do not gate. Exit 0 when
every counted id is in the baseline, 1 when one is not, 2 on bad input. Baseline ids that no longer
fire are listed so the baseline can shrink (bead burpsy-react-ui-ctdl).
"""
import json
import sys


def decode_stream(text):
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        obj, i = dec.raw_decode(text, i)
        yield obj


def baseline_ids(path):
    ids = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                ids.add(line)
    return ids


def main(argv):
    if len(argv) != 2:
        print("usage: ci-vulncheck-gate.py BASELINE < govulncheck.json", file=sys.stderr)
        return 2
    text = sys.stdin.read()
    if not text.strip():
        print("ci-vulncheck-gate: govulncheck produced no output; refusing to pass", file=sys.stderr)
        return 2
    summaries, reached = {}, set()
    try:
        for obj in decode_stream(text):
            if "osv" in obj:
                summaries[obj["osv"]["id"]] = obj["osv"].get("summary", "")
            f = obj.get("finding")
            if f and any("function" in fr for fr in f.get("trace", [])):
                reached.add(f["osv"])
    except (ValueError, KeyError) as e:
        print(f"ci-vulncheck-gate: cannot read govulncheck output: {e}", file=sys.stderr)
        return 2
    known = baseline_ids(argv[1])
    new = sorted(reached - known)
    gone = sorted(known - reached)
    if gone:
        print("baseline entries that no longer fire (remove them): " + ", ".join(gone))
    if new:
        print("NEW reachable vulnerabilities, not in the baseline:")
        for i in new:
            print(f"  {i}  {summaries.get(i, '')}  https://pkg.go.dev/vuln/{i}")
        return 1
    print(f"govulncheck: {len(reached)} reachable, all in the baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
