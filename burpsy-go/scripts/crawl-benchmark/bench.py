#!/usr/bin/env python3
"""Crawler coverage benchmark: burpsy's crawl vs Katana on the same target (burpsy-react-ui-dvi7).

usage: bench.py <target-url> <name> [--depth N] [--duration SECS] [--burpsy BIN] [--out DIR]

Runs both crawlers with the same seed, depth and wall-clock budget, normalises every URL each one
reached to (path, sorted query-parameter NAMES) on the target's own origin, and writes:
  <out>/<name>/katana.jsonl, burpsy-report.json   raw outputs
  <out>/<name>/results.md                         found-by-both / Katana-only / burpsy-only, by class

Each crawler gets its strongest settings, because the question is coverage, not defaults:
  katana: -jc -jsl -kf all -aff -hl -nos -xhr  (headless hybrid, JS + jsluice, known files, forms)
  burpsy: -dom chrome (its rendered pass, the counterpart of -hl), submit_forms + request_speculative,
          through its own API exactly as the console drives it (scope include, then a confirmed crawl).
"""
import argparse, json, os, re, shutil, socket, subprocess, sys, tempfile, time, urllib.request
from urllib.parse import urlsplit, parse_qsl

STATIC = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|map|mp4|webm)$", re.I)

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def api(base, method, path, body=None, confirm=False):
    headers = {"Content-Type": "application/json", "Origin": base}
    if confirm:
        req = urllib.request.Request(base + path + "/confirm", method="POST", headers=headers, data=b"")
        headers["X-Burpsy-Confirm"] = json.load(urllib.request.urlopen(req))["token"]
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, method=method, headers=headers, data=data)
    with urllib.request.urlopen(req) as r:
        raw = r.read()
        return json.loads(raw) if raw else None

def key(url, origin):
    """(path, query-param names) on the target origin, or None for another origin."""
    u = urlsplit(url)
    if f"{u.scheme}://{u.netloc}".lower() != origin.lower():
        return None
    path = re.sub(r"/+$", "", u.path) or "/"
    names = ",".join(sorted({k for k, _ in parse_qsl(u.query, keep_blank_values=True)}))
    return (path, names)

def klass(path):
    if STATIC.search(path): return "static"
    if path.endswith((".js", ".mjs")): return "script"
    if re.search(r"^/(api|rest|graphql|v[0-9]+)(/|$)", path): return "api"
    return "page/other"

def run_katana(target, depth, duration, outdir):
    out = os.path.join(outdir, "katana.jsonl")
    cmd = ["katana", "-u", target, "-d", str(depth), "-ct", f"{duration}s", "-jc", "-jsl", "-kf", "all",
           "-aff", "-hl", "-nos", "-xhr", "-fs", "fqdn", "-j", "-or", "-ob", "-silent", "-o", out]
    overran = False
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=duration + 120)
    except subprocess.TimeoutExpired:
        # Katana can overrun its own -ct budget (observed: >2 min past it with -hl). subprocess.run has
        # already killed it; what it wrote so far is the result, and the overrun is reported.
        overran = True
    urls = set()
    if not os.path.exists(out):
        return urls, overran
    for line in open(out, encoding="utf-8", errors="replace"):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        req = rec.get("request") or {}
        if req.get("endpoint"): urls.add(req["endpoint"])
        for x in (rec.get("response") or {}).get("xhr_requests") or []:
            if x.get("endpoint"): urls.add(x["endpoint"])
    return urls, overran

def run_burpsy(target, depth, duration, outdir, binary):
    web, proxy = free_port(), free_port()
    work = tempfile.mkdtemp(prefix="bench-burpsy-")
    # -dom chrome: burpsy's rendered-DOM pass, the counterpart of Katana's headless hybrid mode — run
    # both crawlers with a browser or neither, or the comparison measures the flag, not the crawler.
    proc = subprocess.Popen([binary, "-db", os.path.join(work, "p.db"), "-web", f"127.0.0.1:{web}",
                             "-proxy", f"127.0.0.1:{proxy}", "-dom", "chrome"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{web}"
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(base + "/api/stats", timeout=1); break
            except Exception:
                time.sleep(0.2)
        host = urlsplit(target).hostname
        api(base, "POST", "/api/scope", {"action": "include", "pattern": host}, confirm=True)
        start = api(base, "POST", "/api/crawl", {"seeds": [target], "max_depth": depth,
                    "max_duration_secs": duration, "max_requests": 5000, "submit_forms": True,
                    "request_speculative": True}, confirm=True)
        tid = start["task_id"]
        deadline = time.time() + duration + 180
        run = None
        while time.time() < deadline:
            run = api(base, "GET", f"/api/crawl?task={tid}")
            if run.get("state") != "running": break
            time.sleep(1)
        json.dump(run, open(os.path.join(outdir, "burpsy-report.json"), "w"), indent=1)
        report = (run or {}).get("report") or {}
        return {f["url"] for f in report.get("fetches") or [] if f.get("url")}
    finally:
        proc.terminate(); proc.wait(timeout=10); shutil.rmtree(work, ignore_errors=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target"); ap.add_argument("name")
    ap.add_argument("--depth", type=int, default=3); ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--burpsy", default="burpsy"); ap.add_argument("--out", default="bench-out")
    a = ap.parse_args()
    outdir = os.path.join(a.out, a.name); os.makedirs(outdir, exist_ok=True)
    u = urlsplit(a.target); origin = f"{u.scheme}://{u.netloc}"

    k_urls, k_overran = run_katana(a.target, a.depth, a.duration, outdir)
    b_urls = run_burpsy(a.target, a.depth, a.duration, outdir, a.burpsy)
    K = {k for k in (key(x, origin) for x in k_urls) if k}
    B = {k for k in (key(x, origin) for x in b_urls) if k}

    lines = [f"# Crawl coverage: {a.name}", "", f"Target `{a.target}`, depth {a.depth}, budget {a.duration}s." + (" Katana overran its budget and was stopped; its partial output is used." if k_overran else ""), "",
             "| class | both | Katana only | burpsy only |", "|---|---:|---:|---:|"]
    classes = sorted({klass(p) for p, _ in K | B})
    for c in classes + ["**total**"]:
        sel = (lambda s: s) if c == "**total**" else (lambda s, c=c: {x for x in s if klass(x[0]) == c})
        lines.append(f"| {c} | {len(sel(K & B))} | {len(sel(K - B))} | {len(sel(B - K))} |")
    for title, s in (("Katana only", K - B), ("burpsy only", B - K)):
        lines += ["", f"## {title} ({len(s)})", ""]
        for p, q in sorted(s, key=lambda x: (klass(x[0]), x)):
            lines.append(f"- `{klass(p)}` {p}" + (f" ?{q}" if q else ""))
    open(os.path.join(outdir, "results.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines[:6 + len(classes) + 1]))

if __name__ == "__main__":
    main()
