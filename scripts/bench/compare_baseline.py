#!/usr/bin/env python3
"""Compare a run_vulnapp.py result with the tracked baseline and fail on regressions (bead j1mk.38).

    compare_baseline.py RESULT.json BASELINE.json [--margin PCT]

A regression is any of: the strict score falling by more than --margin points (default 1.0);
a vulnerability type whose strict true positives dropped; one whose false positives rose. An
improvement never fails; the run prints it so the baseline can be moved up on purpose (copy the
result over BASELINE.json in a reviewed commit). Exit 0 clean, 1 regression, 2 bad input,
3 no baseline yet (the caller decides whether that is a failure).
"""
import argparse
import json
import sys


def load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("result")
    ap.add_argument("baseline")
    ap.add_argument("--margin", type=float, default=1.0)
    a = ap.parse_args(argv)
    try:
        res = load(a.result)
    except (OSError, ValueError) as e:
        print(f"compare_baseline: cannot read result {a.result}: {e}", file=sys.stderr)
        return 2
    try:
        base = load(a.baseline)
    except FileNotFoundError:
        print(f"compare_baseline: no baseline at {a.baseline}; commit this run's result there to start tracking", file=sys.stderr)
        return 3
    except ValueError as e:
        print(f"compare_baseline: baseline {a.baseline} is not JSON: {e}", file=sys.stderr)
        return 2
    try:
        rs, bs = res["strict"]["score_pct"], base["strict"]["score_pct"]
        rt, bt = res["by_type"], base["by_type"]
    except KeyError as e:
        print(f"compare_baseline: missing field {e} in result or baseline", file=sys.stderr)
        return 2
    bad, good = [], []
    if rs < bs - a.margin:
        bad.append(f"strict score {bs:.1f}% -> {rs:.1f}% (more than {a.margin} points down)")
    elif rs > bs:
        good.append(f"strict score {bs:.1f}% -> {rs:.1f}%")
    for t in sorted(set(rt) | set(bt)):
        r, b = rt.get(t, {}), bt.get(t, {})
        if r.get("tp", 0) < b.get("tp", 0):
            bad.append(f"{t}: true positives {b.get('tp', 0)} -> {r.get('tp', 0)}")
        elif r.get("tp", 0) > b.get("tp", 0):
            good.append(f"{t}: true positives {b.get('tp', 0)} -> {r.get('tp', 0)}")
        if r.get("fp", 0) > b.get("fp", 0):
            bad.append(f"{t}: false positives {b.get('fp', 0)} -> {r.get('fp', 0)}")
    for g in good:
        print("improved:", g)
    if bad:
        print("REGRESSIONS against the baseline:")
        for b in bad:
            print("  " + b)
        return 1
    print("no regression against the baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
