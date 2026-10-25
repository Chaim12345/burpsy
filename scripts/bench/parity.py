#!/usr/bin/env python3
"""Parity harness core (bead burpsy-react-ui-j1mk.1): diff burpsy's findings with a reference tool's
on the same target, per vulnerability class, and score both against ground truth when it is given.

This is the comparison step. It takes findings already collected as JSON lists (one object per
finding with `url`, `parameter`, `class` and optional `technique`), so it holds for any target and any
reference tool: an adapter turns a tool's own output into this shape (the format is below), the
target's labels become the truth list, and nothing here touches the scanner.

    parity.py --burpsy B.json --reference R.json [--truth T.json] --out DIR [--ref-name sqlmap]

Findings are normalised to (endpoint, parameter, class, technique): the endpoint is the URL path
(scheme, host, port, query and fragment dropped, trailing slash dropped), the parameter and class are
lower-cased and stripped, and a missing technique is "". Two findings are the same finding when
endpoint, parameter and class match; technique is kept for the report but does not split a match.
Per class the report lists: both found, reference-only (a burpsy miss, to file as a bead),
burpsy-only (to verify: true positive or false positive), and, given a truth list, precision and
recall for each tool. Output: DIR/parity.json and DIR/parity.md. Exit 0 always: a report, not a gate.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit


def norm_endpoint(url):
    path = urlsplit(url).path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def norm(f):
    return (
        norm_endpoint(f["url"]),
        str(f.get("parameter") or "").strip().lower(),
        str(f["class"]).strip().lower(),
        str(f.get("technique") or "").strip().lower(),
    )


def keyset(findings):
    """{(endpoint, parameter, class): technique} — duplicates collapse to one finding."""
    out = {}
    for f in findings:
        e, p, c, t = norm(f)
        out.setdefault((e, p, c), t)
    return out


def prf(found, truth):
    tp = len(found & truth)
    fp = len(found - truth)
    fn = len(truth - found)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "recall": round(tp / (tp + fn), 3) if tp + fn else None,
    }


def compare(burpsy, reference, truth=None):
    b, r = keyset(burpsy), keyset(reference)
    t = set(keyset(truth)) if truth is not None else None
    classes = defaultdict(lambda: {"both": [], "reference_only": [], "burpsy_only": []})
    for k in sorted(set(b) | set(r)):
        bucket = "both" if k in b and k in r else ("burpsy_only" if k in b else "reference_only")
        classes[k[2]][bucket].append({"endpoint": k[0], "parameter": k[1], "technique": (b.get(k) if k in b else r.get(k))})
    report = {"classes": {c: classes[c] for c in sorted(classes)}}
    if t is not None:
        by_class = defaultdict(lambda: {"burpsy": set(), "reference": set(), "truth": set()})
        for k in b:
            by_class[k[2]]["burpsy"].add(k)
        for k in r:
            by_class[k[2]]["reference"].add(k)
        for k in t:
            by_class[k[2]]["truth"].add(k)
        report["truth"] = {
            c: {"burpsy": prf(v["burpsy"], v["truth"]), "reference": prf(v["reference"], v["truth"]),
                "truth_cases": len(v["truth"])}
            for c, v in sorted(by_class.items())
        }
        report["truth_total"] = {"burpsy": prf(set(b), t), "reference": prf(set(r), t)}
    return report


def markdown(report, ref_name):
    lines = [f"# Parity: burpsy vs {ref_name}", "",
             f"| class | both | {ref_name}-only (burpsy miss) | burpsy-only (verify) |", "|---|---|---|---|"]
    for c, v in report["classes"].items():
        lines.append(f"| {c} | {len(v['both'])} | {len(v['reference_only'])} | {len(v['burpsy_only'])} |")
    if "truth" in report:
        lines += ["", "## Against ground truth", "",
                  f"| class | cases | burpsy P / R | {ref_name} P / R |", "|---|---|---|---|"]
        fmt = lambda s: f"{s['precision'] if s['precision'] is not None else '-'} / {s['recall'] if s['recall'] is not None else '-'}"
        for c, v in report["truth"].items():
            lines.append(f"| {c} | {v['truth_cases']} | {fmt(v['burpsy'])} | {fmt(v['reference'])} |")
        tt = report["truth_total"]
        lines.append(f"| **all** | | {fmt(tt['burpsy'])} | {fmt(tt['reference'])} |")
    return "\n".join(lines) + "\n"


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--burpsy", required=True)
    ap.add_argument("--reference", required=True)
    ap.add_argument("--truth")
    ap.add_argument("--out", required=True)
    ap.add_argument("--ref-name", default="reference")
    a = ap.parse_args(argv)
    try:
        load = lambda p: json.loads(Path(p).read_text())
        report = compare(load(a.burpsy), load(a.reference), load(a.truth) if a.truth else None)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"parity: bad input: {e!r}", file=sys.stderr)
        return 2
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "parity.json").write_text(json.dumps(report, indent=1))
    (out / "parity.md").write_text(markdown(report, a.ref_name))
    print((out / "parity.md").read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
