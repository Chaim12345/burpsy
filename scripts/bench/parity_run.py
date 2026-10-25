#!/usr/bin/env python3
"""The parity harness runner (j1mk.1): one harness every reference-parity class bead uses.

Per class it: collects burpsy's findings on the class's seeded targets (through burpsy's proxy,
audited, filtered to the rows the spec names), runs the pinned reference tool against the same
targets, adapts both to the shared finding shape (parity_adapters), diffs them (parity.compare)
and writes <out>/<class>/{burpsy,reference,truth,parity}.json + parity.md, plus one line per run
in <out>/history.jsonl so the trend over nights is readable without digging artifacts.

Like parity.py this is a report, not a gate: exit 0 when every requested class RAN, whatever it
found; exit 1 when a class could not run at all (infrastructure), with the failure named. A class
whose reference-only list is long is the harness working, not failing.

A class spec is a dict (parity_specs.CLASSES):
  name        the parity class, e.g. "crlf-injection"
  bead        the bead that owns the spec
  ref_tool    key into parity_tools.TOOLS
  ref_name    display name for the report
  adapter     parity_adapters "from_<adapter>_*" selector: arjun | corsy | crlfuzz
  burpsy_rows {scanner check_name: class} the comparison counts
  targets     [{url, method, parameter, headers?}] seeded through burpsy AND handed to the tool
  truth       optional ground-truth findings for precision/recall
  tool_args   callable(target_url, tool_desc, out_dir) -> argv list for the reference tool

The network is behind two seams so the orchestration is testable without a target:
ctx.collect_burpsy(spec, out_dir) -> burpsy findings; ctx.run_reference(spec, out_dir) -> the
tool's raw output text. LiveCtx implements them against real processes; tests inject fakes.
"""
import argparse
import datetime
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import parity  # noqa: E402
import parity_adapters  # noqa: E402
import parity_tools  # noqa: E402
from run_vulnapp import CONFIRM_HEADER, confirm, http_json, proxied_through  # noqa: E402


def load_spec(name):
    from parity_specs import CLASSES
    return CLASSES[name]  # KeyError is the loud failure the caller reports


def append_history(out_dir, entry):
    with open(Path(out_dir) / "history.jsonl", "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def adapt(spec, raw):
    kind = spec["adapter"]
    if kind == "arjun":
        return parity_adapters.from_arjun_json(raw, spec["name"])
    if kind == "corsy":
        return parity_adapters.from_corsy_json(raw, spec["name"])
    if kind == "crlfuzz":
        return parity_adapters.from_crlfuzz_text(
            raw, spec["name"], [t["url"] for t in spec["targets"]])
    raise ValueError(f"unknown adapter {kind!r}")


def run_class(spec, out_dir, ctx):
    """Run one class end to end. Returns the class's report dict."""
    cdir = Path(out_dir) / spec["name"]
    cdir.mkdir(parents=True, exist_ok=True)
    burpsy = ctx.collect_burpsy(spec, cdir)
    raw = ctx.run_reference(spec, cdir)
    reference = adapt(spec, raw)
    (cdir / "burpsy.json").write_text(json.dumps(burpsy, indent=1))
    (cdir / "reference.json").write_text(json.dumps(reference, indent=1))
    (cdir / "reference.raw.txt").write_text(raw or "")
    truth = spec.get("truth")
    if truth is not None:
        (cdir / "truth.json").write_text(json.dumps(truth, indent=1))
    report = parity.compare(burpsy, reference, truth)
    (cdir / "parity.json").write_text(json.dumps(report, indent=1))
    (cdir / "parity.md").write_text(parity.markdown(report, spec["ref_name"]))
    totals = {"both": 0, "reference_only": 0, "burpsy_only": 0}
    for c in report["classes"].values():
        for k in totals:
            totals[k] += len(c[k])
    append_history(out_dir, {
        "date": datetime.date.today().isoformat(),
        "class": spec["name"], "bead": spec.get("bead", ""), "reference": spec["ref_name"],
        "reference_version": parity_tools.TOOLS.get(spec["ref_tool"], {}).get("version", ""),
        **totals})
    return report


def run_classes(specs_or_names, out_dir, ctx):
    """Run every requested class; 0 when all ran, 1 when any could not (failure named)."""
    rc = 0
    for item in specs_or_names:
        spec = load_spec(item) if isinstance(item, str) else item
        try:
            run_class(spec, out_dir, ctx)
            print(f"[{spec['name']}] report written under {Path(out_dir) / spec['name']}")
        except Exception as e:  # infrastructure failure: named, counted, never silently skipped
            rc = 1
            print(f"[{spec.get('name', item)}] FAILED TO RUN: {type(e).__name__}: {e}",
                  file=sys.stderr)
    return rc


class LiveCtx:
    """The real seams: burpsy over its HTTP API, the reference tool as a subprocess."""

    def __init__(self, proxy, web, tools_dir, audit_timeout=180):
        self.proxy = proxy
        self.web = web
        self.tools_dir = tools_dir
        self.audit_timeout = audit_timeout

    def collect_burpsy(self, spec, out_dir):
        row_to_class = spec.get("burpsy_rows", {})
        findings = []
        for t in spec["targets"]:
            proxied_through(self.proxy, t["url"], t.get("method", "GET"))
            time.sleep(0.05)
            ex = _latest_exchange(self.web)
            if ex is None:
                raise RuntimeError(f"the proxy did not capture {t['url']} (out of scope?)")
            body = {"async": True}
            token = confirm(self.web, "POST", f"/api/audit/{ex}", body)
            started = http_json("POST", f"{self.web}/api/audit/{ex}", body,
                                {CONFIRM_HEADER: token}, timeout=30)
            _wait_task(self.web, started.get("task_id"), self.audit_timeout)
            issues = http_json("GET", f"{self.web}/api/issues")
            for f in issues["findings"]:
                if any(o["exchange_id"] == ex for o in f.get("occurrences", [])):
                    findings.extend(parity_adapters.from_burpsy_findings([f], t["url"], row_to_class))
        return findings

    def run_reference(self, spec, out_dir):
        desc = parity_tools.ensure_tool(parity_tools.TOOLS[spec["ref_tool"]], self.tools_dir)
        chunks = []
        for t in spec["targets"]:
            argv = spec["tool_args"](t["url"], desc, out_dir)
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=900)
            chunks.append(proc.stdout)
            stderr_note = cdir_note = Path(out_dir) / f"reference.{len(chunks)}.stderr.txt"
            stderr_note.write_text(proc.stderr)
        return "\n".join(chunks)


def _latest_exchange(web):
    rows = http_json("GET", f"{web}/api/history")
    return rows[-1]["id"] if rows else None


def _wait_task(web, task, timeout):
    deadline = time.time() + timeout
    while True:
        poll = http_json("GET", f"{web}/api/tasks/{task}", timeout=15)
        if poll.get("done"):
            return
        if time.time() > deadline:
            try:
                http_json("POST", f"{web}/api/tasks/{task}/cancel", timeout=10)
            except Exception:
                pass
            raise TimeoutError(f"audit did not finish within {timeout}s")
        time.sleep(1.0)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--class", dest="classes", action="append", default=[],
                    help="parity class to run (repeatable)")
    ap.add_argument("--all", action="store_true", help="every registered class")
    ap.add_argument("--list", action="store_true", help="list registered classes and exit")
    ap.add_argument("--out", required=True)
    ap.add_argument("--burpsy-web", help="burpsy web API base, e.g. http://127.0.0.1:18081")
    ap.add_argument("--burpsy-proxy", help="burpsy proxy, e.g. http://127.0.0.1:18080")
    ap.add_argument("--tools-dir", default="/tmp/burpsy-parity-tools")
    a = ap.parse_args(argv)

    from parity_specs import CLASSES
    if a.list:
        for name, spec in sorted(CLASSES.items()):
            print(f"{name}\t{spec['ref_name']}\t{spec.get('bead', '')}")
        if not CLASSES:
            print("no class specs registered yet; the class beads (j1mk.13, .14, .15, ...) add theirs")
        return 0
    names = sorted(CLASSES) if a.all else a.classes
    if not names:
        if a.all:
            print("parity: no class specs registered; nothing to run")
            return 0
        ap.error("give --class NAME or --all")
    if not a.burpsy_web or not a.burpsy_proxy:
        ap.error("live runs need --burpsy-web and --burpsy-proxy")
    Path(a.out).mkdir(parents=True, exist_ok=True)
    ctx = LiveCtx(a.burpsy_proxy, a.burpsy_web, a.tools_dir)
    return run_classes(names, a.out, ctx)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
