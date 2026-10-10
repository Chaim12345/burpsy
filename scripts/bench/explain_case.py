#!/usr/bin/env python3
"""Explain why one VulnerableApp case is a miss: seed it, audit it, print every finding.

The scoring harness (run_vulnapp.py) answers "which categories do we miss". This answers "why" for
one case, which is what turning a miss into a fix needs: the exchange id, the audit's own outcome
counters (so a probe that failed is distinguishable from a probe that ran clean), and every finding
raised on that exchange with its CWE set beside the case's, so an off-target hit is visible rather
than hidden by the CWE filter.

    python3 scripts/bench/explain_case.py --url http://127.0.0.1:9090/VulnerableApp/PathTraversal/LEVEL_3
    python3 scripts/bench/explain_case.py PathTraversal/LEVEL_3          # shorthand

Stdlib only, like the rest of scripts/bench.
"""

import argparse
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vulnapp_cases import FAMILY_PARAMS, TYPE_CWES  # noqa: E402
from run_vulnapp import FULL_PROFILE, configure_scanner  # noqa: E402

CONFIRM = "X-Burpsy-Confirm"


def http(method, url, body=None, headers=None, timeout=120):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    return json.loads(raw) if raw else None


def mint(web, method, path, body):
    return http("POST", f"{web}/api/audit/confirm",
                {"method": method, "url": path, "body": json.dumps(body, separators=(",", ":"))})["token"]


def family_of(url):
    return [p for p in url.split("/") if p][-2]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="a full URL or a Family/LEVEL path")
    ap.add_argument("--app", default="http://127.0.0.1:9090")
    ap.add_argument("--proxy", default="http://127.0.0.1:18080")
    ap.add_argument("--web", default="http://127.0.0.1:18081")
    ap.add_argument("--example", default="1")
    ap.add_argument("--probe-timeout-ms", type=int, default=8000)
    ap.add_argument("--full-profile", action="store_true",
                    help="turn on every check family, matching run_vulnapp.py --full-profile")
    args = ap.parse_args()

    url = args.target if args.target.startswith("http") else f"{args.app}/VulnerableApp/{args.target}"
    family = family_of(url)
    param = FAMILY_PARAMS.get(family)
    target = f"{url}{'&' if '?' in url else '?'}{param}={args.example}" if param else url
    print(f"case     : {url}\nfamily   : {family}\nparam    : {param}\nseed     : {target}\n")

    # Set the per-probe clock and (optionally) the full check profile. Reuses the harness's own
    # configure_scanner so the two tools cannot disagree about which route the token is minted at.
    configure_scanner(args.web, args.probe_timeout_ms, FULL_PROFILE if args.full_profile else {})

    before = {r["id"] for r in http("GET", f"{args.web}/api/history")}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy}))
    try:
        opener.open(target, timeout=60).read()
    except Exception as e:
        print(f"seed fetch: {type(e).__name__}: {e}")
    rows = http("GET", f"{args.web}/api/history")
    new = [r for r in rows if r["id"] not in before]
    if not new:
        print("the proxy captured nothing — the request never reached it (scope?)")
        return 1
    ex = new[-1]
    print(f"exchange : id={ex['id']} status={ex['status']} len={ex['response_len']} mime={ex['mime']}")

    abody = {"async": True}
    started = http("POST", f"{args.web}/api/audit/{ex['id']}", abody, {CONFIRM: mint(args.web, "POST", f"/api/audit/{ex['id']}", abody)})
    import time
    deadline = time.time() + 90
    while True:
        poll = http("GET", f"{args.web}/api/tasks/{started['task_id']}")
        if poll.get("done"):
            break
        if time.time() > deadline:
            print("audit did not finish within 90s")
            return 1
        time.sleep(1)
    result = poll.get("result") or {}
    outcome = result.get("outcome") or {}
    print(f"audit    : state={outcome.get('state')} ran={outcome.get('ran')} findings={outcome.get('findings')} "
          f"send_failures={outcome.get('send_failures')} skipped={outcome.get('skipped')} "
          f"refused={outcome.get('refused')} budget_spent={outcome.get('request_budget_spent')}")
    for d in result.get("dispositions") or []:
        if d.get("count"):
            print(f"  disposition: {d['disposition']} x{d['count']} — {d.get('reason')}")

    issues = http("GET", f"{args.web}/api/issues")
    on_ex = [f for f in issues["findings"] if any(o["exchange_id"] == ex["id"] for o in f.get("occurrences", []))]
    print(f"\nfindings on this exchange: {len(on_ex)}")
    for f in on_ex:
        cwes = set()
        for c in (f.get("advisory") or {}).get("classifications") or []:
            t = c.get("title", "")
            if t.startswith("CWE-"):
                try:
                    cwes.add(int(t.split("-")[1].split(":")[0]))
                except (ValueError, IndexError):
                    pass
        print(f"  [{f['severity']}/{f['confidence']}] {f['check_name']!r} cwes={sorted(cwes)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
