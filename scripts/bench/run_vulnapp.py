#!/usr/bin/env python3
"""Score burpsy's active scanner against OWASP VulnerableApp.

This is the burpsy side of reference-parity bead j1mk.1 for one target, and the harness j1mk.38
asks to live in the repo. It is a behavioural benchmark, not a parity count: a case is a
(URL, method, parameter, CWE) fact the application itself declares through its own /scanner
endpoint, and the score is how many of the cases burpsy's audit finds.

Flow, per case:
  1. the app's /scanner gives URL, method, variant and VulnerabilityType;
  2. append the family's parameter with an example value (FAMILY_PARAMS, from the template JS);
  3. send it THROUGH burpsy's proxy, so it becomes a captured exchange (scope-authorised and
     recorded the same way browser traffic is);
  4. POST /api/audit/{exchange_id} runs the active scan over that exchange;
  5. a finding counts when one of the CWE numbers in its advisory matches one of the case's.

TP/FN on UNSECURE cases, FP/TN on SECURE ones. "Strict" drops the blanket posture checks that
fire on every response (BLANKET_CHECK_NAMES), which is what the earlier hand-run baseline
reported; the lenient number is kept beside it. Exit code 0 always — this is a report, and the
caller (CI or a person) decides what a score means. `--fail-under N` turns it into a gate.

The result is JSON (machine) plus a markdown table (human), both written under --out.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vulnapp_cases import BLANKET_CHECK_NAMES, FAMILY_PARAMS, TYPE_CWES  # noqa: E402

CONFIRM_HEADER = "X-Burpsy-Confirm"


def http(method, url, body=None, headers=None, timeout=60):
    # A str body is already-serialised JSON and is sent byte-for-byte; a dict is serialised here.
    # Both cases matter to the confirm gate, which hashes the exact body bytes it was shown: a
    # str that got re-serialised into a JSON string literal would be a different request than the
    # one the token was minted for, and the PUT would be refused (428).
    if body is None:
        data = None
    elif isinstance(body, bytes):
        data = body
    elif isinstance(body, str):
        data = body.encode()
    else:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return raw


def http_json(method, url, body=None, headers=None, timeout=60):
    raw = http(method, url, body, headers, timeout)
    return json.loads(raw) if raw else None


# FULL_PROFILE turns on every check family the scanner offers. The default server config leaves
# several off (check_active_injection, check_reflection_probes, check_extended_active,
# check_extended_coverage, check_xxe, check_stored, check_corpus), which is j1mk.37: a default scan
# scores far below the full profile on VulnerableApp. A benchmark of what the scanner CAN detect
# must run the full profile, so a miss is a detection gap and not a configuration choice.
FULL_PROFILE = {
    "check_sqli": True, "check_xss": True, "check_path_traversal": True, "check_ssrf": True,
    "check_xxe": True, "check_jwt_weak": True, "check_js_vulns": True, "check_headers": True,
    "check_cache_poisoning": True, "check_extended_coverage": True, "check_reflection_probes": True,
    "check_host_discovery": True, "check_response_dependence": True, "check_passive_posture": True,
    "check_passive_analysis": True, "check_active_injection": True, "check_extended_active": True,
    "check_out_of_band": True, "check_stored": True,
    # DOM stays off: it needs Chrome and its own budget, and the DOM family is scored separately.
    "check_dom": False, "check_corpus": False,
}


def configure_scanner(web, ms, profile):
    """Set the per-probe clock and (by default) the full check profile through one PUT.

    A target that accepts a request and never answers — the app's command-injection endpoints leave
    a shell waiting on a stdout that never closes — is then bounded by the per-probe clock rather
    than a case's whole audit budget. PUT /api/scanner/config is gated, so the token is minted at
    its own /confirm route. Best-effort: if the process refuses, the run still works, just slower.

    The body is serialised ONCE, to the exact bytes both the mint and the PUT send: the confirm
    gate hashes the body it was shown, so a mint made from one spelling and a PUT that sends
    another are two different requests and the PUT is refused (428)."""
    body = json.dumps({**profile, "probe_timeout_ms": ms}, separators=(",", ":"))
    try:
        tok = json.loads(http("POST", f"{web}/api/scanner/config/confirm",
                              {"method": "PUT", "url": "/api/scanner/config", "body": body}))["token"]
        confirmed = http_json("PUT", f"{web}/api/scanner/config", body, {CONFIRM_HEADER: tok})
        on = [k for k, v in confirmed.items() if k.startswith("check_") and v]
        sys.stderr.write(f"scanner profile: {len(on)} families on\n")
    except Exception as e:
        sys.stderr.write(f"warning: could not set the scanner profile: {e}\n")


def confirm(web, method, path, body):
    """POST the call description to /api/audit/confirm and return the token.

    The audit route is gated (route-risk: attack), so an unconfirmed POST is a 428. The token is
    bound to the exact (method, path, body) triple, which is why it is fetched per call rather
    than once."""
    payload = {"method": method, "url": path, "body": json.dumps(body, separators=(",", ":"))}
    ans = http_json("POST", f"{web}/api/audit/confirm", payload)
    return ans["token"]


# FAMILY_BODIES seeds a request BODY for families whose vulnerability is carried in one rather than
# in a query parameter. The app's UI builds these bodies in JavaScript; a benchmark that sent an
# empty body left the scanner nothing to inject into (the insertion-point enumerator needs a body
# point to exist before it can rewrite one), so those families scored as misses for a reason that was
# the harness's, not the scanner's. Each value is the smallest body the app's own handler accepts,
# verified live against the target; the scanner replaces the leaf values with its payloads.
FAMILY_BODIES = {
    # An XML book document: XXE splices a whole DOCTYPE-carrying document into the body.
    "XXEVulnerability": (
        "application/xml",
        '<?xml version="1.0" encoding="UTF-8"?><book><name>burpsy</name><author>burpsy</author>'
        '<isbn>1</isbn><publisher>burpsy</publisher><others>burpsy</others></book>',
    ),
}


def proxied_through(proxy, url, method="GET", body=None, content_type=None):
    """Send url through burpsy's own proxy so the exchange is captured.

    urllib with an http proxy set sends the absolute-form request the proxy expects; an https
    target would need CONNECT, which is why this benchmark uses http only (VulnerableApp serves
    http). The proxy decides scope, so an out-of-scope host is not captured and the case becomes a
    missing exchange rather than a silent pass. A POST carries an empty body unless the family's
    vulnerability is IN the body (FAMILY_BODIES), in which case the scanner needs a body point to
    rewrite and an empty one leaves it nothing to test."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    if method == "POST":
        data = body.encode() if body else b""
    else:
        data = None
    req = urllib.request.Request(url, data=data, method=method)
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with opener.open(req, timeout=60) as resp:
            resp.read()
    except urllib.error.HTTPError:
        # A 4xx/5xx is the target's ANSWER to a missing or refused parameter, not a transport
        # failure: the proxy recorded the exchange on the way through, and the audit is about what
        # the target said. Raising here skipped every case the app answers with an error page —
        # the whole file-upload and JWT families — and scored them untestable when they were
        # perfectly auditable. Only a genuine transport failure (no response at all) propagates.
        pass


def fetch_cases(app):
    return http_json("GET", f"{app}/VulnerableApp/scanner")


def case_param(url):
    parts = [p for p in url.split("/") if p]
    # .../VulnerableApp/<Family>/<LEVEL>
    family = parts[-2]
    return family, FAMILY_PARAMS.get(family)


# The app labels a case with ONE coarse CWE per VulnerabilityType; burpsy's catalogue rows carry the
# precise CWEs Burp assigns to the specific defect. Where the app's label is a parent of the row's
# CWE, matching on the app's number alone scores a real detection as a miss — the scanner found the
# defect and the report counts it absent.
#
# This maps an app CWE to the FINDING NAMES that answer it, and it is deliberately by NAME rather
# than by CWE number. CWE-16 ("Configuration") is shared by "Missing X-Content-Type-Options Header"
# and "Cookie without HttpOnly flag set", so crediting CWE-16 would let a generic header-posture row
# answer every client-side-JWT case — which is the dishonest counting this project forbids. Naming
# the rows keeps the credit to the ones that genuinely report the case's defect.
#
# Every entry is a defect the app names and burpsy has a row for, confirmed live, not a guess:
#
#   CWE-522 (Insufficiently Protected Credentials) is the app's label for its client-side JWT levels.
#   Those levels hand a JWT to the browser in a Set-Cookie missing HttpOnly, Secure or SameSite,
#   which burpsy reports as the cookie-flag rows named below. Verified live on LEVEL_2 with
#   ?fetch=true: the app sets `Set-Cookie: JWT=…; httponly` (no Secure, no SameSite).
#
#   CWE-1188 (Insecure Default Initialization) is the app's label for its weak-key and algorithm-
#   confusion JWT levels, answered by the weak-secret row.
CWE_PARENT_OF = {
    522: {"Cookie without HttpOnly flag set", "Cookie Missing HttpOnly Flag",
          "TLS cookie without secure flag set", "Cookie Missing SameSite Flag",
          "Cookie Missing Secure Flag"},
    1188: {"JWT weak HMAC secret"},
}


def family_cwes(types):
    out = set()
    for t in types:
        out.update(TYPE_CWES.get(t, ()))
    return out


def credit_names(types):
    """Finding NAMES that legitimately answer any of these VulnerabilityTypes, via CWE_PARENT_OF."""
    names = set()
    for t in types:
        for cwe in TYPE_CWES.get(t, ()):
            names |= CWE_PARENT_OF.get(cwe, set())
    return names


def finding_cwes(finding):
    out = set()
    for c in (finding.get("advisory") or {}).get("classifications") or []:
        title = c.get("title", "")
        if title.startswith("CWE-"):
            try:
                out.add(int(title.split("-")[1].split(":")[0]))
            except (ValueError, IndexError):
                pass
    return out


def seed_value(app, family, param, example):
    """The example value for a case's parameter.

    Most parameters take the harness's inert default. A few families cannot be exercised with one:

    - The JWT endpoints issue themselves a signed token only when the parameter is ABSENT, and every
      JWT check forges from a token it can FIND in the request — so `JWT=1` hands the scanner nothing
      to forge and the checks return "nothing to do". Fetch the app's own token instead.
    - The JWT cookie levels (2, 3, 5, 7, 8, 9, 10) only reach their Set-Cookie path when `fetch` is
      present; without it the handler throws and answers 500. `fetch=true` is the value the app's own
      JS sends, so it is the request the case is actually about.
    """
    if family == "JWTVulnerability":
        for _ in range(3):
            try:
                got = http_json("GET", f"{app}/VulnerableApp/JWTVulnerability/LEVEL_1")
                tok = (got or {}).get("content")
                if param == "JWT" and tok and tok.count(".") == 2:
                    # Both: a token to forge from, and `fetch` so the cookie levels answer instead
                    # of throwing.
                    return f"{tok}&fetch=true"
                if param == "fetch":
                    return "true"
            except Exception:
                pass
            time.sleep(0.2)
        return example  # no token available; reported untestable rather than faked
    return example


def extra_seed_params(family, param):
    """Additional inert parameters some endpoints require before they reach their injection point.

    A login-shaped handler short-circuits with "provide username and password" unless BOTH are
    present, so seeding only the injected parameter leaves the endpoint answering a validation error
    and the scanner with nothing to inject into — OWASP VulnerableApp's LDAP LEVEL_3/5 and
    Authentication LEVEL_8/9/10 are all shaped this way. Each value here is inert; the scanner
    replaces the injected parameter's value with its own payloads.
    """
    if family == "LDAPInjectionVulnerability":
        return {"password": "x"}
    return {}


def run_case(app, proxy, web, case, example, audit_timeout):
    """Send one case through the proxy, audit it, return the findings tied to its exchange.

    Returns (findings, exchange_id or None, note). A case with no known parameter, or a URL the
    proxy did not capture, is reported by name — never scored as a pass."""
    url = case["url"]
    family, param = case_param(url)
    if param is None:
        # A family whose vulnerability is not carried by a parameter (clickjacking is the response
        # itself; the page is the subject). Audit the endpoint as it stands rather than skip it —
        # and inject nothing, so no injection check can fire on a parameter that does not exist.
        target = url
    else:
        joiner = "&" if "?" in url else "?"
        target = f"{url}{joiner}{param}={seed_value(app, family, param, example)}"
        for extra, value in extra_seed_params(family, param).items():
            if extra != param:
                target += f"&{extra}={value}"

    try:
        before = {row["id"] for row in http_json("GET", f"{web}/api/history")}
    except Exception as e:
        return None, None, f"history read failed: {e}"
    ctype, cbody = FAMILY_BODIES.get(family, (None, None))
    try:
        proxied_through(proxy, target, case["method"], cbody, ctype)
    except Exception as e:
        # Any transport failure is this case's, not the run's: an open-redirect case legitimately
        # sends the client somewhere that closes the connection, and one broken case must not end
        # the benchmark. Reported untestable, never scored as a pass.
        return None, None, f"proxy fetch failed: {type(e).__name__}: {e}"
    time.sleep(0.05)
    try:
        rows = http_json("GET", f"{web}/api/history")
    except Exception as e:
        return None, None, f"history re-read failed: {e}"
    new = [r for r in rows if r["id"] not in before]
    if not new:
        return None, None, "the proxy did not capture the request (out of scope?)"
    ex = new[-1]["id"]

    # Async, then poll. A synchronous POST /api/audit/{id} holds the connection open for the
    # whole audit and gives up only at the client timeout, so a target wedged by an earlier
    # probe blocks the run for the full budget with no way to observe progress. The async form
    # answers 202 at once and the poll deadline is ours: a case that overruns is reported
    # untestable and the run moves on. See the harness note in README.md.
    body = {"async": True}
    try:
        token = confirm(web, "POST", f"/api/audit/{ex}", body)
        started = http_json("POST", f"{web}/api/audit/{ex}", body, {CONFIRM_HEADER: token}, timeout=30)
    except urllib.error.HTTPError as e:
        return None, ex, f"audit HTTP {e.code}: {e.read()[:200]!r}"
    except (TimeoutError, urllib.error.URLError) as e:
        return None, ex, f"could not start the audit: {e}"
    task = started.get("task_id")
    deadline = time.time() + audit_timeout
    while True:
        try:
            poll = http_json("GET", f"{web}/api/tasks/{task}", timeout=15)
        except Exception as e:
            return None, ex, f"polling the audit failed: {type(e).__name__}: {e}"
        if poll.get("done"):
            break
        if time.time() > deadline:
            # Abandon it, so the task does not keep hammering a wedged target while later cases
            # run; the cancel endpoint is the server's own stop primitive.
            try:
                http("POST", f"{web}/api/tasks/{task}/cancel")
            except Exception:
                pass
            return None, ex, f"audit did not finish within {audit_timeout}s"
        time.sleep(1.0)

    issues = http_json("GET", f"{web}/api/issues")
    found = [
        f for f in issues["findings"]
        if any(o["exchange_id"] == ex for o in f.get("occurrences", []))
    ]
    return found, ex, None


def app_alive(app):
    try:
        with urllib.request.urlopen(f"{app}/VulnerableApp/scanner", timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


def score(cases, results, blanket_credits=False):
    """Turn per-case results into TP/FN/TN/FP and a per-type table.

    A finding counts when its CWE set intersects the case's — the same test for every row, blanket
    posture rows included. That is the strict number, and it is the honest one: "Frameable response
    (potential Clickjacking)" legitimately answers a clickjacking case (CWE-1021) and is noise on a
    path-traversal one, and the CWE intersection is exactly what tells those apart. An earlier version
    dropped the whole BLANKET_CHECK_NAMES list and so scored a real clickjacking detection as a miss.

    lenient adds blanket posture rows as evidence for ANY case (blanket_credits=True). It is kept
    because it is the number that flatters a scanner reporting only header posture, and showing both
    makes the gap visible rather than argued about.
    """
    by_type = defaultdict(lambda: Counter())
    tp = fn = tn = fp = 0
    for case, res in zip(cases, results):
        if res is None:  # untestable case, already reported
            continue
        types = case["vulnerabilityTypes"]
        case_cwes = family_cwes(types)
        unsecure = case["variant"] != "SECURE"

        rel = [f for f in res if finding_cwes(f) & case_cwes or f["check_name"] in credit_names(types)]
        if blanket_credits:
            rel = rel or [f for f in res if f["check_name"] in BLANKET_CHECK_NAMES]
        hit = bool(rel)
        for t in types:
            if unsecure:
                by_type[t][("tp" if hit else "fn")] += 1
            else:
                by_type[t][("fp" if hit else "tn")] += 1
        if unsecure:
            tp += hit
            fn += not hit
        else:
            fp += hit
            tn += not hit
    return tp, fn, tn, fp, by_type


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--app", default="http://127.0.0.1:9090", help="VulnerableApp base URL")
    ap.add_argument("--proxy", default="http://127.0.0.1:18080", help="burpsy proxy")
    ap.add_argument("--web", default="http://127.0.0.1:18081", help="burpsy web API")
    ap.add_argument("--example", default="1", help="example value for the case parameter")
    ap.add_argument("--limit", type=int, default=0, help="scan at most N cases (0 = all)")
    ap.add_argument("--family", default="", help="only cases in this family (e.g. PathTraversal) or "
                                                 "carrying this VulnerabilityType (e.g. PATH_TRAVERSAL)")
    ap.add_argument("--full-profile", action="store_true",
                    help="turn on every check family (the default server config leaves several off)")
    ap.add_argument("--probe-timeout-ms", type=int, default=8000,
                    help="per-probe cap set via /api/scanner/config, so one wedged probe cannot "
                         "consume the whole audit budget")
    ap.add_argument("--audit-timeout", type=int, default=120,
                    help="seconds to wait for one case's audit before reporting it untestable")
    ap.add_argument("--out", default=".", help="directory for the JSON and markdown reports")
    ap.add_argument("--fail-under", type=float, default=None,
                    help="exit non-zero when the strict score percent is under this")
    args = ap.parse_args()

    configure_scanner(args.web, args.probe_timeout_ms, FULL_PROFILE if args.full_profile else {})
    cases = fetch_cases(args.app)
    # Hazardous families run LAST: the command-injection and RCE endpoints execute what they are
    # sent, and a probe loop can wedge the target's request thread (seen live: CommandInjection
    # LEVEL_1 left the app unresponsive for minutes). Ordered last, such a case costs the run the
    # cases after it and nothing else, and the health check below reports it rather than hiding it.
    HAZARD = {"COMMAND_INJECTION", "REMOTE_CODE_EXECUTION", "INSECURE_DESERIALIZATION",
              "DENIAL_OF_SERVICE", "UNCONTROLLED_RESOURCE_CONSUMPTION"}
    cases.sort(key=lambda c: any(t in HAZARD for t in c["vulnerabilityTypes"]))
    if args.family:
        want = args.family
        cases = [c for c in cases
                 if want in [p for p in c["url"].split("/") if p]
                 or want in c["vulnerabilityTypes"]]
        sys.stderr.write(f"family filter {want!r}: {len(cases)} case(s)\n")
    if args.limit:
        cases = cases[: args.limit]

    results, notes = [], []
    for i, case in enumerate(cases, 1):
        if i > 1 and i % 10 == 0 and not app_alive(args.app):
            notes.append({"url": case["url"], "variant": case["variant"],
                          "note": "the target stopped answering; remaining cases not attempted"})
            for rest in cases[i:]:
                notes.append({"url": rest["url"], "variant": rest["variant"],
                              "note": "not attempted: target wedged by an earlier hazardous probe"})
                results.append(None)
            break
        try:
            res, ex, note = run_case(args.app, args.proxy, args.web, case, args.example, args.audit_timeout)
        except Exception as e:
            # A benchmark's job is to score 168 cases; one case that trips an unhandled client-side
            # error must be a reported untestable row, not the end of the run.
            res, ex, note = None, None, f"harness error: {type(e).__name__}: {e}"
        if note:
            notes.append({"url": case["url"], "variant": case["variant"], "note": note})
        results.append(res)
        mark = "?" if note else ("+" if res else "-")
        sys.stderr.write(f"[{i}/{len(cases)}] {mark} {case['variant']:8} {case['url']}\n")
        sys.stderr.flush()

    strict = score(cases, results, blanket_credits=False)
    lenient = score(cases, results, blanket_credits=True)

    def pct(t):
        tp, fn, tn, fp, _ = t
        denom = tp + fn + fp + tn
        return 100.0 * (tp - fp) / denom if denom else 0.0

    # Per-case detail: a table of categories answers "which class do we miss"; this answers "which
    # case", which is what a fix needs. A miss names every finding raised on the exchange, so an
    # off-target hit is visible rather than hidden by the CWE filter.
    per_case = []
    for case, res in zip(cases, results):
        if res is None:
            continue
        types = case["vulnerabilityTypes"]
        rel = [f for f in res if finding_cwes(f) & family_cwes(types) or f["check_name"] in credit_names(types)]
        per_case.append({
            "url": case["url"],
            "variant": case["variant"],
            "types": types,
            "hit": bool(rel),
            "findings": sorted({f["check_name"] for f in res}),
        })

    report = {
        "app": args.app,
        "cases": len(cases),
        "untestable": notes,
        "strict": {"tp": strict[0], "fn": strict[1], "tn": strict[2], "fp": strict[3], "score_pct": round(pct(strict), 1)},
        "lenient": {"tp": lenient[0], "fn": lenient[1], "tn": lenient[2], "fp": lenient[3], "score_pct": round(pct(lenient), 1)},
        "by_type": {
            t: dict(c) for t, c in sorted(strict[4].items())
        },
        "per_case": per_case,
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d")
    (out / f"vulnapp-{stamp}.json").write_text(json.dumps(report, indent=1))

    lines = [
        f"# VulnerableApp score — {stamp}",
        "",
        f"- app: {args.app}, cases: {len(cases)} (untestable: {len(notes)})",
        f"- strict: TP {strict[0]} / FN {strict[1]} / TN {strict[2]} / FP {strict[3]} = **{pct(strict):.1f}%**",
        f"- lenient: TP {lenient[0]} / FN {lenient[1]} / TN {lenient[2]} / FP {lenient[3]} = {pct(lenient):.1f}%",
        "",
        "| Vulnerability type | TP | FN | TN | FP |",
        "|---|---|---|---|---|",
    ]
    for t, c in sorted(strict[4].items()):
        lines.append(f"| {t} | {c['tp']} | {c['fn']} | {c['tn']} | {c['fp']} |")
    if notes:
        lines += ["", "## Untestable", ""] + [f"- {n['url']} ({n['variant']}): {n['note']}" for n in notes]
    table = "\n".join(lines) + "\n"
    (out / f"vulnapp-{stamp}.md").write_text(table)
    print(table)

    if args.fail_under is not None and pct(strict) < args.fail_under:
        print(f"FAIL: strict score {pct(strict):.1f}% is under --fail-under {args.fail_under}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
