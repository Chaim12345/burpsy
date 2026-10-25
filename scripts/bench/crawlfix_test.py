#!/usr/bin/env python3
"""Tests for the crawl-coverage fixture server and its contract with the parity spec (j1mk.27).

Run: python3 scripts/bench/crawlfix_test.py
"""
import json
import sys
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import crawlfix  # noqa: E402


class FixtureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = crawlfix.serve("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as r:
            return r.status, r.read().decode()

    def test_every_truth_path_is_served(self):
        for row in crawlfix.TRUTH:
            status, _ = self.get(row["path"])
            self.assertEqual(200, status, row["path"])

    def test_truth_declares_a_mechanism_per_row(self):
        for row in crawlfix.TRUTH:
            self.assertTrue(row["mechanism"], row)
            self.assertTrue(row["path"].startswith("/"), row)

    def test_index_carries_the_traps(self):
        _, body = self.get("/")
        # The scope trap must be fetchable-if-tried (the fixture serves it on 127.0.0.2), so a
        # crawler honouring scope REFUSES it rather than fails it.
        self.assertIn(f"http://127.0.0.2:{self.port}/outside", body)
        self.assertIn("mailto:", body)          # non-http scheme trap
        self.assertIn('href="#section"', body)  # fragment trap: no new location
        self.assertNotIn('http-equiv="refresh"', body)  # the refresh is isolated on /meta-start
        _, meta_start = self.get("/meta-start")
        self.assertIn('content="0; url=/meta"', meta_start)

    def test_outside_is_actually_served_on_the_other_loopback(self):
        with urllib.request.urlopen(f"http://127.0.0.2:{self.port}/outside", timeout=5) as r:
            self.assertEqual(200, r.status)

    def test_truth_endpoint_renders_the_table(self):
        status, body = self.get("/truth.json")
        self.assertEqual(200, status)
        rows = json.loads(body)
        self.assertEqual(len(crawlfix.TRUTH), len(rows))
        self.assertEqual({r["path"] for r in crawlfix.TRUTH}, {r["path"] for r in rows})

    def test_every_declared_mechanism_is_present_and_resolvable(self):
        # Truth-pin: a mechanism that is table-present but broken in the bytes would
        # masquerade as a crawler miss. Each row's exposing mechanism is checked in what the
        # fixture actually serves.
        _, index = self.get("/")
        for href in ("/a", "b", f"{self.base}/abs", "/meta-start", "/guide/burpsy-nf-notes"):
            self.assertIn(f'href="{href}"', index)
        self.assertIn('action="/search"', index)
        self.assertIn('action="/submit"', index)
        self.assertIn('name="q"', index)
        _, b = self.get("/b")
        self.assertIn('action="/b/next"', b)
        _, meta_start = self.get("/meta-start")
        self.assertIn('content="0; url=/meta"', meta_start)
        self.assertIn("<!-- the archived export moved to /comment-link -->", index)
        self.assertIn('var nextPage = "/js-inline";', index)
        self.assertIn('a.href = "/js-rendered";', index)
        _, robots = self.get("/robots.txt")
        self.assertIn("Disallow: /robots-only", robots)
        self.assertIn(f"Sitemap: {self.base}/sitemap.xml", robots)
        import xml.etree.ElementTree as ET
        _, sitemap = self.get("/sitemap.xml")
        locs = [e.text for e in ET.fromstring(sitemap).iter()
                if e.tag.endswith("loc")]
        self.assertEqual([f"{self.base}/sitemap-only"], locs)

    def test_js_dom_append_is_real_in_a_browser(self):
        # The js-dom-append mechanism is only discoverable if a browser's DOM actually gains the
        # link. Pinned with the same browser family the crawl renders with; skips cleanly where
        # no chrome exists (the CI runner carries one).
        import shutil
        import subprocess
        chrome = shutil.which("google-chrome") or shutil.which("chromium")
        if not chrome:
            self.skipTest("no chrome on PATH")
        dom = subprocess.run(
            [chrome, "--headless", "--disable-gpu", "--no-sandbox", "--dump-dom",
             "--virtual-time-budget=3000", self.base + "/"],
            capture_output=True, text=True, timeout=60).stdout
        self.assertIn('href="/js-rendered"', dom)

    def test_spec_truth_matches_the_fixture_declaration(self):
        # The parity spec's ground truth and the fixture's own table are two copies of one fact;
        # this test is what keeps them the same fact.
        import parity_specs
        spec = parity_specs.CLASSES["crawl-coverage"]
        truth = json.loads(self.get("/truth.json")[1])
        # The mechanism rides in technique (a report field, not a match key) so the truth rows
        # key like any finding: (endpoint, "", class).
        from urllib.parse import urlsplit
        want = {(r["path"], r["mechanism"]) for r in truth}
        got = {(urlsplit(t["url"]).path or "/", t.get("technique", "")) for t in spec["truth"]}
        self.assertEqual(want, got)


if __name__ == "__main__":
    unittest.main(verbosity=2)
