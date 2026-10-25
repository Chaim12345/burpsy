#!/usr/bin/env python3
"""Tests for parity.py. Run: python3 scripts/bench/parity_test.py"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import parity  # noqa: E402


def f(url, param, cls, tech=""):
    return {"url": url, "parameter": param, "class": cls, "technique": tech}


class Parity(unittest.TestCase):
    def test_endpoint_drops_host_query_and_trailing_slash(self):
        self.assertEqual(parity.norm_endpoint("http://a.test:8080/x/y/?q=1#z"), "/x/y")
        self.assertEqual(parity.norm_endpoint("https://a.test"), "/")

    def test_same_finding_across_hosts_case_and_technique(self):
        b = [f("http://127.0.0.1:1/search?q=1", "Q", "XSS", "reflected")]
        r = [f("http://localhost:9/search", "q", "xss")]
        rep = parity.compare(b, r)
        self.assertEqual(len(rep["classes"]["xss"]["both"]), 1)
        self.assertEqual(rep["classes"]["xss"]["reference_only"], [])

    def test_buckets(self):
        b = [f("/a", "p", "sqli"), f("/only-b", "p", "xss")]
        r = [f("/a", "p", "sqli"), f("/only-r", "p", "sqli")]
        rep = parity.compare(b, r)
        self.assertEqual(len(rep["classes"]["sqli"]["both"]), 1)
        self.assertEqual(rep["classes"]["sqli"]["reference_only"][0]["endpoint"], "/only-r")
        self.assertEqual(rep["classes"]["xss"]["burpsy_only"][0]["endpoint"], "/only-b")

    def test_duplicates_collapse(self):
        rep = parity.compare([f("/a", "p", "xss"), f("/a?x=1", "p", "xss")], [f("/a", "p", "xss")])
        self.assertEqual(len(rep["classes"]["xss"]["both"]), 1)

    def test_precision_recall_against_truth(self):
        truth = [f("/a", "p", "xss"), f("/b", "p", "xss")]
        b = [f("/a", "p", "xss"), f("/zz", "p", "xss")]   # 1 tp, 1 fp, 1 fn
        r = [f("/a", "p", "xss"), f("/b", "p", "xss")]    # 2 tp
        rep = parity.compare(b, r, truth)
        bs, rs = rep["truth"]["xss"]["burpsy"], rep["truth"]["xss"]["reference"]
        self.assertEqual((bs["tp"], bs["fp"], bs["fn"], bs["precision"], bs["recall"]), (1, 1, 1, 0.5, 0.5))
        self.assertEqual((rs["precision"], rs["recall"]), (1.0, 1.0))

    def test_cli_writes_json_and_markdown_and_rejects_bad_input(self):
        tool = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parity.py")
        with tempfile.TemporaryDirectory() as d:
            p = lambda n, v: (open(os.path.join(d, n), "w").write(json.dumps(v)), os.path.join(d, n))[1]
            b, r = p("b.json", [f("/a", "p", "xss")]), p("r.json", [f("/a", "p", "xss")])
            rc = subprocess.run([sys.executable, tool, "--burpsy", b, "--reference", r, "--out", d + "/o"],
                                capture_output=True, text=True).returncode
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(d + "/o/parity.json") and os.path.exists(d + "/o/parity.md"))
            bad = p("bad.json", [{"nourl": 1}])
            rc = subprocess.run([sys.executable, tool, "--burpsy", bad, "--reference", r, "--out", d + "/o2"],
                                capture_output=True, text=True).returncode
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
