#!/usr/bin/env python3
"""The parity class registry (j1mk.1): one entry per reference-parity class bead.

The harness (parity_run.py) owns the mechanism; each class bead (j1mk.13 hidden parameters,
j1mk.14 CORS, j1mk.15 CRLF, ...) owns ONE entry here — the seed targets both sides see, the
scanner rows the comparison counts, the reference tool's argv, and the ground truth when the
target declares it. Keeping the specs in one reviewed file is what makes "same targets, same
endpoints, compare what each finds" auditable across classes.

The spec shape is documented in parity_run.py's module docstring.
"""

TARGET_BASE = "http://127.0.0.1:19090"


def _crlfuzz_args(url, desc, out_dir):
    # -s: one vulnerable URL per line. Concurrency capped so a nightly run stays polite to the
    # loopback target it shares with burpsy's audit.
    return [desc["binary"], "-u", url, "-s", "-c", "10"]


CLASSES = {
    # j1mk.15: CRLF / response header injection vs crlfuzz. Targets are the vulnapp host/CRLF
    # family's rows (internal/vulnapp/vulnapp_hostcrlf.go): path reflection into Location, a
    # URL-decoded Referer written raw into a response header, and Unicode narrowing (U+560D/U+560A
    # -> CR LF), each with its safe twin. crlfuzz fuzzes path and query only, so the Referer row
    # is an EXPECTED reference miss — its truth row keeps the difference a measured capability
    # gap rather than a silent omission.
    "crlf-injection": {
        "name": "crlf-injection",
        "bead": "burpsy-react-ui-j1mk.15",
        "ref_tool": "crlfuzz",
        "ref_name": "crlfuzz",
        "adapter": "crlfuzz",
        "burpsy_rows": {"HTTP response header injection": "crlf-injection"},
        "targets": [
            {"url": TARGET_BASE + "/crlf/r/home", "method": "GET", "parameter": ""},
            {"url": TARGET_BASE + "/crlf/ref", "method": "GET", "parameter": "Referer",
             "headers": {"Referer": "http://127.0.0.1/start"}},
            {"url": TARGET_BASE + "/crlf/unicode?msg=seed", "method": "GET", "parameter": "msg"},
            {"url": TARGET_BASE + "/crlf/safe/r/home", "method": "GET", "parameter": ""},
            {"url": TARGET_BASE + "/crlf/safe/ref", "method": "GET", "parameter": "Referer",
             "headers": {"Referer": "http://127.0.0.1/start"}},
            {"url": TARGET_BASE + "/crlf/safe/unicode?msg=seed", "method": "GET", "parameter": "msg"},
        ],
        "truth": [
            {"url": TARGET_BASE + "/crlf/r/home", "parameter": "", "class": "crlf-injection"},
            # burpsy's row is resource-level (no parameter attribution, measured 2026-10-25), so
            # the truth keys at endpoint granularity; per-parameter/encoding detail lives in the
            # reference technique column.
            {"url": TARGET_BASE + "/crlf/ref", "parameter": "", "class": "crlf-injection"},
            {"url": TARGET_BASE + "/crlf/unicode", "parameter": "", "class": "crlf-injection"},
        ],
        "tool_args": _crlfuzz_args,
    },
}

def _corsy_args(url, desc, out_dir):
    # corsy.py is a script in the unpacked source tree, run with its venv's python (deps: requests).
    return [desc["venv_bin"] + "/python", desc["script"], "-u", url, "-q", "-t", "8",
            "-o", str(out_dir) + "/corsy.json"]


# j1mk.14: CORS misconfiguration vs Corsy. Targets: the header family's two CORS rows plus the
# permissive-by-default catalog that triggers the base informational row, each with its safe
# twin (internal/vulnapp/vulnapp_headers.go, vulnapp_remaining.go). Corsy's classes (origin
# reflection, null origin, prefix/suffix/regex bypasses, third-party allowed) map to the
# finding's technique; burpsy's rows are its catalogue names. Truth is the manifest's vulnerable
# set. Corsy's "class" per URL is one verdict, so an endpoint with two defects (reflection AND
# cleartext) is one technique on the reference side - noted in the report, not smoothed over.
#
# Corsy reads its -o JSON only when it finds something; the adapter treats a missing file as
# empty. The runner passes each target URL on its own; the harness collects Corsy's JSON after
# each run and concatenates (Corsy overwrites the file per invocation, so tool_output joins them).
CLASSES["cors-misconfiguration"] = {
    "name": "cors-misconfiguration",
    "bead": "burpsy-react-ui-j1mk.14",
    "ref_tool": "corsy",
    "ref_name": "Corsy",
    "adapter": "corsy",
    "burpsy_rows": {
        "Cross-origin resource sharing": "cors-misconfiguration",
        "Cross-origin resource sharing: arbitrary origin trusted": "cors-misconfiguration",
        "Cross-origin resource sharing: unencrypted origin trusted": "cors-misconfiguration",
        "Cross-origin resource sharing: all subdomains trusted": "cors-misconfiguration",
    },
    # Every seed carries an Origin: burpsy's CORS rows evaluate the exchange's Origin against the
    # response's ACAO (it probes actively too, but the captured Origin is what the per-request
    # dispatch reads), and a seed without one measures the harness, not the scanner. Measured
    # 2026-10-25: with no Origin seeded, zero rows fired even with check_headers on; with it,
    # both rows fired on /hd/cors-unenc.
    "targets": [
        {"url": TARGET_BASE + "/hd/cors-unenc", "method": "GET", "parameter": "",
         "headers": {"Origin": "https://evil.example.com"}},
        {"url": TARGET_BASE + "/hd/cors-subs", "method": "GET", "parameter": "",
         "headers": {"Origin": "https://app.evil.example"}},
        {"url": TARGET_BASE + "/rm/catalog", "method": "GET", "parameter": "",
         "headers": {"Origin": "https://evil.example.com"}},
        {"url": TARGET_BASE + "/hd/safe/cors-unenc", "method": "GET", "parameter": "",
         "headers": {"Origin": "http://evil.example.com"}},
        {"url": TARGET_BASE + "/hd/safe/cors-subs", "method": "GET", "parameter": "",
         "headers": {"Origin": "https://app.evil.example"}},
        {"url": TARGET_BASE + "/rm/safe/catalog", "method": "GET", "parameter": "",
         "headers": {"Origin": "https://evil.example.com"}},
    ],
    "truth": [
        {"url": TARGET_BASE + "/hd/cors-unenc", "parameter": "", "class": "cors-misconfiguration"},
        {"url": TARGET_BASE + "/hd/cors-subs", "parameter": "", "class": "cors-misconfiguration"},
        {"url": TARGET_BASE + "/rm/catalog", "parameter": "", "class": "cors-misconfiguration"},
    ],
    "burpsy_config": {"check_headers": True},
    "tool_args": _corsy_args,
    "tool_output": "merged-json-file",
}

def _arjun_args(url, desc, out_dir):
    import os
    wordlist = os.path.join(os.path.dirname(desc["venv_bin"].rstrip("/")), "lib",
                            "python3.10", "site-packages", "arjun", "db", "small.txt")
    # small.txt is the pinned version's 835-name list; both fixture names sit on it (checked
    # 2026-10-25), so a miss is detection, not coverage. --stable: arjun's own consistency pass.
    return [desc["venv_bin"] + "/arjun", "-u", url, "-oJ", out_dir + "/arjun.json",
            "--stable", "-t", "15", "-T", "8", "-w", wordlist, "-q"]


def _x8_args(url, desc, out_dir):
    return [desc["binary"], "-u", url, "-O", "json", "--disable-progress-bar",
            "--disable-colors", "-c", "5"]


# j1mk.13: hidden parameter discovery vs Arjun (and x8 as the second reference). Targets are the
# vulnapp hidden-input fixtures (internal/vulnapp/vulnapp_hidden_inputs.go): /hidden/account reads
# a hidden query param (preview), a hidden header (X-Api-Version), a hidden cookie (premium) and a
# reflected query param (ref); /hidden/random answers noise (a finding there is a false positive);
# /hidden/echo reflects everything (the other false-positive shape). burpsy's side is its
# Param-Miner action (POST /api/hidden-inputs), not an audit - per the engine's own design note.
# Arjun/x8 discover query parameters only; the header/cookie truth rows are theirs to miss and the
# report says so, which is the comparison the bead asks for (Param Miner behaviour vs a
# query-only guesser).
_HIDDEN_TARGETS = [
    {"url": TARGET_BASE + "/hidden/account", "method": "GET", "parameter": ""},
    {"url": TARGET_BASE + "/hidden/random", "method": "GET", "parameter": ""},
    {"url": TARGET_BASE + "/hidden/echo", "method": "GET", "parameter": ""},
]
_HIDDEN_TRUTH = [
    {"url": TARGET_BASE + "/hidden/account", "parameter": "preview",
     "class": "hidden-parameter-discovery"},
    {"url": TARGET_BASE + "/hidden/account", "parameter": "ref",
     "class": "hidden-parameter-discovery"},
    {"url": TARGET_BASE + "/hidden/account", "parameter": "x-api-version",
     "class": "hidden-parameter-discovery"},
    {"url": TARGET_BASE + "/hidden/account", "parameter": "premium",
     "class": "hidden-parameter-discovery"},
]

CLASSES["hidden-parameter-discovery"] = {
    "name": "hidden-parameter-discovery",
    "bead": "burpsy-react-ui-j1mk.13",
    "ref_tool": "arjun",
    "ref_name": "Arjun",
    "adapter": "arjun",
    "burpsy_collect": "hidden-inputs",
    "targets": [dict(t) for t in _HIDDEN_TARGETS],
    "truth": [dict(t) for t in _HIDDEN_TRUTH],
    "tool_args": _arjun_args,
    "tool_output": "merged-json-file",
}

CLASSES["hidden-parameter-discovery-x8"] = {
    "name": "hidden-parameter-discovery",
    "bead": "burpsy-react-ui-j1mk.13",
    "ref_tool": "x8",
    "ref_name": "x8",
    "adapter": "x8",
    "burpsy_collect": "hidden-inputs",
    "targets": [dict(t) for t in _HIDDEN_TARGETS],
    "truth": [dict(t) for t in _HIDDEN_TRUTH],
    "tool_args": _x8_args,
}


# ---- j1mk.27: crawler coverage -----------------------------------------------------------------
#
# Reference: ProjectDiscovery katana (the modern baseline; ZAP's spiders need a Java stack the
# nightly runner does not carry — assessed 2026-10-25, filed as a follow-up). The comparison unit
# is the fetched URL: burpsy's side is the crawl's captured traffic (burpsy_collect "crawl"),
# katana's is its -jsonl request stream, both from one seed root. Truth comes from the fixture's
# own declaration (crawlfix.py TRUTH; crawlfix_test.py pins the two copies together), with the
# exposing mechanism riding in `technique` so it never splits a match key.
#
# Both sides run an EXPLICIT, matched discovery posture — the ruling's symmetry call is "both
# explicit": every switch that steers discovery is named, per side, and the request/argv are the
# artifacts that prove it.
#   burpsy (crawl_request): submit_forms/interact off (the house rule: a no-config crawl never
#     writes), request_speculative off (the engine's shipped default, named so the report shows
#     the choice), robots/sitemap discovery and JavaScript-file mining are engine defaults that
#     stay on; rendering is a SERVER capability (-dom), recorded per run below.
#   katana (tool_args): -jc (JavaScript endpoint parsing, katana's default is off) and -kf all
#     (robots.txt+sitemap.xml as known files, default off) are switched ON to match burpsy's
#     shipped defaults; -aff stays off to match submit_forms off; -fs rdn is katana's default
#     scope. Form actions are therefore measured as DISCOVERED-or-not, never as submitted —
#     /submit in the truth set is exactly the case that separates "found the form's action"
#     from "sent the form".

CRAWLFIX_BASE = "http://127.0.0.1:19091"


def _katana_args(url, desc, out_dir):
    # -d 5: the fixture's graph is two deep; 5 covers it without inviting katana to wander. -c 5
    # keeps the loopback target polite. -nc: no ANSI in the jsonl stream.
    return [desc["binary"], "-u", url, "-jsonl", "-silent", "-nc",
            "-d", "5", "-kf", "all", "-jc", "-c", "5"]


def _katana_headless_args(url, desc, out_dir):
    # The AJAX half: katana's headless mode renders pages in the system Chrome (rod would
    # otherwise download its own browser), which is what the js-dom-append mechanism needs.
    return _katana_args(url, desc, out_dir) + ["-headless", "-system-chrome"]


def _crawlfix_truth():
    rows = [("/", "seed"), ("/a", "href"), ("/b", "href-relative"), ("/abs", "href-absolute"),
            ("/a/child", "href-depth-2"), ("/search", "form-action-get"),
            ("/submit", "form-action-post"), ("/b/next", "form-action-depth-2"),
            ("/meta-start", "href"), ("/meta", "meta-refresh"),
            ("/guide/burpsy-nf-notes", "href-negative-control"), ("/comment-link", "html-comment"),
            ("/js-inline", "js-inline-string"), ("/js-rendered", "js-dom-append"),
            ("/robots.txt", "known-file"), ("/robots-only", "robots-disallow"),
            ("/sitemap.xml", "robots-sitemap-directive"), ("/sitemap-only", "sitemap")]
    return [{"url": CRAWLFIX_BASE + path, "parameter": "",
             "class": "crawl-coverage", "technique": mechanism} for path, mechanism in rows]


CLASSES["crawl-coverage"] = {
    "name": "crawl-coverage",
    "bead": "burpsy-react-ui-j1mk.27",
    "ref_tool": "katana",
    "ref_name": "katana",
    "adapter": "katana",
    "burpsy_collect": "crawl",
    "targets": [{"url": CRAWLFIX_BASE + "/", "method": "GET", "parameter": ""}],
    "crawl_request": {"submit_forms": False, "interact": False, "request_speculative": False},
    "truth": _crawlfix_truth(),
    "tool_args": _katana_args,
}

# The headless spec shares the class label and truth; its slug-named dir keeps its report.
CLASSES["crawl-coverage-headless"] = {
    "name": "crawl-coverage",
    "bead": "burpsy-react-ui-j1mk.27",
    "ref_tool": "katana",
    "ref_name": "katana (headless)",
    "adapter": "katana",
    "burpsy_collect": "crawl",
    "targets": [{"url": CRAWLFIX_BASE + "/", "method": "GET", "parameter": ""}],
    "crawl_request": {"submit_forms": False, "interact": False, "request_speculative": False},
    "truth": _crawlfix_truth(),
    "tool_args": _katana_headless_args,
}

# vulnapp as-is: no declared link-graph truth (its manifest is scanner rows, not crawl coverage),
# so this spec diffs the two tools without precision/recall.
CLASSES["crawl-coverage-vulnapp"] = {
    "name": "crawl-coverage",
    "bead": "burpsy-react-ui-j1mk.27",
    "ref_tool": "katana",
    "ref_name": "katana",
    "adapter": "katana",
    "burpsy_collect": "crawl",
    "targets": [{"url": TARGET_BASE + "/", "method": "GET", "parameter": ""}],
    "crawl_request": {"submit_forms": False, "interact": False, "request_speculative": False},
    "tool_args": _katana_args,
}
