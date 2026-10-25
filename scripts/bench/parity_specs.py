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
            {"url": TARGET_BASE + "/crlf/ref", "parameter": "referer", "class": "crlf-injection"},
            {"url": TARGET_BASE + "/crlf/unicode", "parameter": "msg", "class": "crlf-injection"},
        ],
        "tool_args": _crlfuzz_args,
    },
}
