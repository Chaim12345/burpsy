#!/usr/bin/env python3
"""Adapters: turn a reference tool's own output into the parity harness's finding shape.

One finding is {"url", "parameter", "class", "technique"} — the input parity.py normalises and
diffs. An adapter's only job is faithful extraction: it never decides whether a tool was RIGHT,
only what the tool SAID. The formats below were verified against the pinned versions in
parity_tools.py, not remembered:

- arjun 2.2.7 `-oJ`: one JSON object, {url: {"method", "headers", "params": {name: value}}}.
  Written only when parameters were discovered; a missing/empty file means "nothing found".
- corsy 1.0-rc `-o`: one JSON object, {url: {"class", "description", "severity", "acao header",
  "acac header"}}. Written only when a misconfiguration was found.
- crlfuzz v1.4.1: stdout lines, `[VLN] <url>` for a hit (ANSI-coloured in a terminal), the bare
  URL per line in `-s` silent mode. crlfuzz reports a vulnerable URL, not a parameter: it injects
  into the path and into a `crlfuzz` query parameter it adds itself. The adapter maps each hit
  back to the seeded target URL it extends (the harness knows the seeds; the tool does not report
  them), and recovers the injected parameter when the hit is a query-string hit.
- OpenRedireX 383aea0: stdout lines, `[FOUND] <url> redirects to <chain>` (multi-hop) or
  `[INFO] <url> redirects to <chain>` (single hop). Both count: the tool prints whenever its
  HEAD request was redirected at all; a refused payload prints nothing.
- Oralyzer 2.0.0 `-o`: one JSON array, [{"type", "request_url", "payload", "status_code",
  "destination"}]. A missing file means "nothing found".
"""
import json
import re
from urllib.parse import parse_qsl, urlsplit


def from_katana_jsonl(text, class_name):
    """katana v1.8.0 `-jsonl`: one JSON object per line, {"request": {"method", "endpoint",
    "tag", "attribute", "source"}, "response": {...}} — verified against the pinned release
    (2026-10-25). Each line is one fetched URL; the tag/attribute pair is the discovery
    mechanism ("a.href", "form.action"), kept as the technique. The seed line carries no tag.
    Duplicate endpoints collapse (a page linked from two pages is one discovery)."""
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue  # katana prints no non-JSON lines in -jsonl mode; tolerate, never invent
        req = row.get("request") or {}
        url = req.get("endpoint")
        if not url:
            continue
        tag, attr = req.get("tag") or "", req.get("attribute") or ""
        technique = f"{tag}.{attr}" if tag or attr else ""
        out.setdefault(url, _finding(url, "", class_name, technique))
    return list(out.values())


def from_burpsy_crawl_history(rows, class_name):
    """burpsy's side of a crawl-coverage run: the /api/history rows the crawl's capture path
    added (CRAWL-02: crawled traffic travels the same store). Each row is one fetched URL,
    rebuilt as scheme://host:port+path; the comparison normalises default ports away."""
    out = {}
    for r in rows:
        path = r["path"]
        # burpsy-nf-<12 hex>[.ext] as the LAST path segment is the crawler's own soft-404
        # calibration probe (internal/crawler/notfound.go: rand.Read 6 bytes, hex-encoded,
        # joined under the probed item's directory): a request burpsy generated to baseline the
        # target's missing-page response, never a URL the target offered. The match is the
        # exact probe shape, never a substring - a real page whose name merely carries the
        # marker (crawlfix's /guide/burpsy-nf-notes) is coverage and MUST stay counted.
        if _NF_PROBE.match(path.rsplit("/", 1)[-1]):
            continue
        scheme = "https" if r.get("tls") else "http"
        url = f"{scheme}://{r['host']}:{r['port']}{path}"
        out.setdefault(url, _finding(url, "", class_name))
    return list(out.values())

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# The soft-404 calibration probe's exact name shape (see from_burpsy_crawl_history).
_NF_PROBE = re.compile(r"^burpsy-nf-[0-9a-f]{12}(\.[^/]*)?$")


def _finding(url, parameter, class_name, technique=""):
    return {"url": url, "parameter": parameter, "class": class_name, "technique": technique}


def from_arjun_json(text, class_name):
    """Arjun -oJ output. text=None or "" is a file that was never written: no findings."""
    if not text:
        return []
    data = json.loads(text)
    out = []
    for url, data_for_url in sorted(data.items()):
        for param in sorted((data_for_url or {}).get("params") or {}):
            out.append(_finding(url, param, class_name))
    return out


def from_corsy_json(text, class_name):
    """Corsy -o output. The per-URL 'class' (e.g. 'Subdomains allowed') is kept as the technique."""
    if not text:
        return []
    data = json.loads(text)
    out = []
    for url, detail in sorted(data.items()):
        technique = str((detail or {}).get("class") or "")
        out.append(_finding(url, "", class_name, technique))
    return out


def from_crlfuzz_text(text, class_name, base_urls):
    """crlfuzz stdout. Every VLN line (or bare-URL line) is a hit on the seed it extends.

    base_urls are the harness's seeds; a hit that extends no seed is kept against its own path so
    the report still shows it, with the parameter recovered from its query string when there is
    one. The injected value is kept as the technique."""
    out = []
    for line in (text or "").splitlines():
        line = _ANSI.sub("", line).strip()
        if not line or line.startswith("[ERR]"):
            continue
        m = re.match(r"^\[VLN\]\s*(\S+)$", line)
        url = m.group(1) if m else (line if line.startswith(("http://", "https://")) else None)
        if not url:
            continue
        base = _longest_base(url, base_urls)
        target, parameter = _split_hit(url, base)
        out.append(_finding(target, parameter, class_name, technique=url))
    return out


def _longest_base(url, base_urls):
    """The seed whose scheme://netloc/path the hit extends (payloads change the query, so the
    match is on the path, not a string prefix of the whole seed)."""
    u = urlsplit(url)
    upath = u.path or "/"
    best = None
    for b in base_urls or []:
        bu = urlsplit(b)
        if bu.scheme == u.scheme and bu.netloc == u.netloc:
            bpath = bu.path or "/"
            if upath == bpath or upath.startswith(bpath.rstrip("/") + "/"):
                if best is None or len(bpath) > len(urlsplit(best).path):
                    best = b
    return best


def _split_hit(url, base):
    """Map a crlfuzz hit to (seed endpoint, injected parameter).

    A hit on a seed with a query (?msg=seed) that kept the seed's parameters is a query-parameter
    hit on the injected name; a hit that is the seed path with a payload suffix is a path hit on
    the seed itself (parameter "")."""
    if base is None:
        u = urlsplit(url)
        target = f"{u.scheme}://{u.netloc}{u.path}"
        qs = dict(parse_qsl(u.query))
        injected = next((k for k in qs if "crlfuzz" in k.lower()), "")
        return target, injected
    base_q = dict(parse_qsl(urlsplit(base).query))
    u = urlsplit(url)
    hit_q = dict(parse_qsl(u.query))
    if base_q and u.path == urlsplit(base).path:
        base_noquery = base.split("?", 1)[0]
        # crlfuzz either replaces a seed parameter's value with its payload or adds one of its
        # own. The parameter it rode is the one whose value carries its marker, else a new name,
        # else the one whose value changed.
        for k, v in hit_q.items():
            if "crlfuzz" in str(v).lower():
                return base_noquery, k
        for k in hit_q:
            if k not in base_q:
                return base_noquery, k
        for k, v in hit_q.items():
            if base_q.get(k) != v:
                return base_noquery, k
        return base_noquery, next(iter(base_q), "")
    return base.split("?", 1)[0], ""


def _seed_and_param(hit_url, base):
    """Map a redirect-tool hit URL back to (seed endpoint, injected parameter).

    Both open-redirect tools fuzz one query parameter of the seed at a time, so the injected
    parameter is the one whose value changed; when nothing differs (the tool rewrote the whole
    query), fall back to the seed's first parameter. Without a seed match, keep the hit's own
    endpoint so the report still shows it."""
    if base is None:
        u = urlsplit(hit_url)
        return f"{u.scheme}://{u.netloc}{u.path}", ""
    base_q = dict(parse_qsl(urlsplit(base).query))
    hit_q = dict(parse_qsl(urlsplit(hit_url).query))
    target = base.split("?", 1)[0]
    for k, v in hit_q.items():
        if base_q.get(k) != v:
            return target, k
    return target, next(iter(base_q), "")


def from_openredirex_text(text, class_name, base_urls):
    """OpenRedireX stdout. A printed line means "sending this payload produced a redirect":
    [FOUND] is its multi-hop highlight, [INFO] a single hop - the tool HEAD-follows every
    redirect and prints whenever response.history is non-empty, so BOTH are its idea of a hit,
    and an endpoint that refuses the payload (no redirect at all) prints nothing. The followed
    chain is kept as the technique. ANSI-coloured in a terminal."""
    out = []
    for line in (text or "").splitlines():
        line = _ANSI.sub("", line).strip()
        m = re.match(r"^\[(?:FOUND|INFO)\]\s+(\S+)\s+redirects to\s+(.+)$", line)
        if not m:
            continue
        url, chain = m.group(1), m.group(2)
        base = _longest_base(url, base_urls)
        target, parameter = _seed_and_param(url, base)
        out.append(_finding(target, parameter, class_name, technique=chain))
    return out


def from_oralyzer_json(text, class_name, base_urls):
    """Oralyzer -o output: a JSON array of {"type", "request_url", "payload", "status_code",
    "destination"}. A header finding means the 3xx Location CONTAINED the payload string -
    substring semantics, not "the browser would leave the origin", which is exactly the
    difference this class measures. The type+destination is kept as the technique."""
    if not text:
        return []
    out = []
    for item in json.loads(text):
        url = item.get("request_url", "")
        base = _longest_base(url, base_urls)
        target, parameter = _seed_and_param(url, base)
        technique = f"{item.get('type', '')}: {item.get('destination', '')}"
        out.append(_finding(target, parameter, class_name, technique))
    return out


def from_burpsy_findings(findings, url, row_to_class):
    """burpsy /api/issues findings for one seeded exchange.

    row_to_class maps the scanner's check_name to the parity class; a finding whose row the spec
    does not name is not part of this class's comparison. The parameter comes from the finding's
    own params/param (empty for a resource-level row)."""
    out = []
    for f in findings or []:
        class_name = row_to_class.get(f.get("check_name"))
        if class_name is None:
            continue
        params = f.get("params") or ([f["param"]] if f.get("param") else [""])
        for p in params:
            out.append(_finding(url, p, class_name))
    return out


def from_x8_json(text, class_name):
    """x8 -O json: progress/log lines, then one JSON array of
    {"method","url","status","size","found_params":[...],"injection_place"}. found_params entries
    are objects carrying a "name" (a bare string is tolerated). When x8 echoes the array more than
    once (progress redraw), the LAST parseable array is the final result."""
    if not text:
        return []
    best = None
    for line in text.splitlines():
        line = _ANSI.sub("", line).strip()
        if not line.startswith("["):
            continue
        try:
            arr = json.loads(line)
        except ValueError:
            continue
        if isinstance(arr, list):
            best = arr
    out = []
    for entry in best or []:
        url = entry.get("url", "")
        for p in entry.get("found_params") or []:
            name = p.get("name") if isinstance(p, dict) else str(p)
            if name:
                out.append(_finding(url, name, class_name))
    return out
