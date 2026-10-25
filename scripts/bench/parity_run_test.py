#!/usr/bin/env python3
"""Tests for the parity harness runner, tool pins and adapters (j1mk.1 part 2).

Run: python3 scripts/bench/parity_run_test.py
"""
import hashlib
import io
import json
import tarfile
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import parity_adapters  # noqa: E402
import parity_run  # noqa: E402
import parity_tools  # noqa: E402


class TestToolPins(unittest.TestCase):
    def test_every_pin_is_complete(self):
        for name, pin in parity_tools.TOOLS.items():
            self.assertEqual(name, pin["name"])
            self.assertTrue(pin["version"], name)
            self.assertTrue(pin["url"].startswith("https://"), name)
            self.assertEqual(64, len(pin["sha256"]), name)
            int(pin["sha256"], 16)  # hex
            self.assertIn(pin["kind"], ("pip-tarball", "script-tarball", "tarball-binary", "gzip-binary", "zip-binary"), name)
            self.assertTrue(pin["note"], name)  # maintenance status, checked when pinned

    def test_ensure_downloads_verifies_and_stamps(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo("f.bin")
            data = b"binary"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        payload = buf.getvalue()
        digest = hashlib.sha256(payload).hexdigest()
        fetched = []

        def fetcher(url, dest):
            fetched.append(url)
            Path(dest).write_bytes(payload)

        pin = {"name": "faketool", "version": "1.0", "kind": "tarball-binary",
               "url": "https://example.test/f.tgz", "sha256": digest,
               "path_in_archive": "f.bin", "note": "test"}
        with tempfile.TemporaryDirectory() as d:
            got = parity_tools.ensure_tool(pin, d, fetcher=fetcher)
            self.assertEqual(["https://example.test/f.tgz"], fetched)
            self.assertTrue(Path(got["stamp"]).exists())
            # Second call: stamp matches, nothing fetched again.
            got2 = parity_tools.ensure_tool(pin, d, fetcher=fetcher)
            self.assertEqual(1, len(fetched))
            self.assertEqual(got, got2)

    def test_ensure_refuses_a_hash_mismatch(self):
        def fetcher(url, dest):
            Path(dest).write_bytes(b"tampered")

        pin = {"name": "faketool", "version": "1.0", "kind": "tarball-binary",
               "url": "https://example.test/f.tgz",
               "sha256": hashlib.sha256(b"expected").hexdigest(),
               "path_in_archive": "f.bin", "note": "test"}
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(parity_tools.HashMismatch):
                parity_tools.ensure_tool(pin, d, fetcher=fetcher)


class TestAdapters(unittest.TestCase):
    def test_arjun_json(self):
        text = json.dumps({
            "http://127.0.0.1:19090/hidden/account": {
                "method": "GET", "headers": {},
                "params": {"preview": "", "ref": ""}}})
        got = parity_adapters.from_arjun_json(text, "hidden-parameter")
        self.assertEqual(
            {("http://127.0.0.1:19090/hidden/account", "preview"),
             ("http://127.0.0.1:19090/hidden/account", "ref")},
            {(f["url"], f["parameter"]) for f in got})
        for f in got:
            self.assertEqual("hidden-parameter", f["class"])

    def test_arjun_missing_file_is_empty(self):
        self.assertEqual([], parity_adapters.from_arjun_json(None, "hidden-parameter"))
        self.assertEqual([], parity_adapters.from_arjun_json("", "hidden-parameter"))

    def test_corsy_json(self):
        text = json.dumps({
            "http://127.0.0.1:19090/hd/cors-subs": {
                "class": "Subdomains allowed", "description": "d", "severity": "medium",
                "acao header": "http://sub.127.0.0.1", "acac header": "True"}})
        got = parity_adapters.from_corsy_json(text, "cors-misconfiguration")
        self.assertEqual(1, len(got))
        f = got[0]
        self.assertEqual("http://127.0.0.1:19090/hd/cors-subs", f["url"])
        self.assertEqual("cors-misconfiguration", f["class"])
        self.assertEqual("Subdomains allowed", f["technique"])

    def test_crlfuzz_lines(self):
        text = ("\x1b[32m[VLN]\x1b[0m \x1b[32mhttp://127.0.0.1:19090/crlf/r/home/%0aSet-Cookie:x=y;\x1b[0m\n"
                "[ERR] http://127.0.0.1:19090/crlf/r/home/%00Set-Cookie:x=y;\n"
                "http://127.0.0.1:19090/crlf/unicode?msg=%0d%0aX-Injected:%20crlfuzz\n")
        got = parity_adapters.from_crlfuzz_text(
            text, "crlf-injection", base_urls=["http://127.0.0.1:19090/crlf/r/home",
                                              "http://127.0.0.1:19090/crlf/unicode?msg=seed"])
        urls = {f["url"] for f in got}
        self.assertIn("http://127.0.0.1:19090/crlf/r/home", urls)
        self.assertIn("http://127.0.0.1:19090/crlf/unicode", urls)
        for f in got:
            self.assertEqual("crlf-injection", f["class"])
        uni = [f for f in got if f["url"].endswith("unicode")][0]
        self.assertEqual("msg", uni["parameter"])

    def test_burpsy_findings(self):
        findings = [
            {"check_name": "CRLF injection", "param": "msg", "params": ["msg"],
             "occurrences": [{"exchange_id": 7}]},
            {"check_name": "Some other row", "param": "q", "occurrences": [{"exchange_id": 7}]},
        ]
        got = parity_adapters.from_burpsy_findings(
            findings, "http://127.0.0.1:19090/crlf/unicode", {"CRLF injection": "crlf-injection"})
        self.assertEqual(1, len(got))
        self.assertEqual({"url": "http://127.0.0.1:19090/crlf/unicode",
                          "parameter": "msg", "class": "crlf-injection", "technique": ""},
                         got[0])


class FakeCtx:
    """A run context with the network replaced: burpsy collection and the reference tool's
    command are fakes, so the whole orchestration is exercised without a target."""

    def __init__(self, burpsy, reference_raw):
        self._burpsy = burpsy
        self._reference_raw = reference_raw
        self.tool_runs = []

    def collect_burpsy(self, spec, out_dir):
        return self._burpsy

    def run_reference(self, spec, out_dir):
        self.tool_runs.append(spec["name"])
        return self._reference_raw


CRLF_SPEC = {
    "name": "crlf-injection",
    "bead": "burpsy-react-ui-j1mk.15",
    "ref_tool": "crlfuzz",
    "ref_name": "crlfuzz",
    "adapter": "crlfuzz",
    "targets": [{"url": "http://127.0.0.1:19090/crlf/r/home", "method": "GET", "parameter": ""}],
    "truth": [{"url": "http://127.0.0.1:19090/crlf/r/home", "parameter": "",
               "class": "crlf-injection"}],
}


class TestReferenceFailureIsLoud(unittest.TestCase):
    def test_reference_tool_dying_silently_fails_the_class(self):
        # A reference tool that exits non-zero with no output must fail the run, not report
        # "found nothing" (pre-review on j1mk.14).
        class DeadToolCtx(FakeCtx):
            def run_reference(self, spec, out_dir):
                raise RuntimeError("crlfuzz exited 1 with no output on http://x")
        with tempfile.TemporaryDirectory() as d:
            rc = parity_run.run_classes([dict(CRLF_SPEC)], d, DeadToolCtx([], ""))
            self.assertEqual(1, rc)
            self.assertFalse((Path(d) / "crlf-injection" / "parity.json").exists())


class TestSlugDirs(unittest.TestCase):
    def test_two_specs_sharing_a_class_label_do_not_overwrite(self):
        a = dict(CRLF_SPEC, slug="crlf-vs-a")
        b = dict(CRLF_SPEC, slug="crlf-vs-b")
        with tempfile.TemporaryDirectory() as d:
            rc = parity_run.run_classes([a, b], d, FakeCtx([], ""))
            self.assertEqual(0, rc)
            self.assertTrue((Path(d) / "crlf-vs-a" / "parity.json").exists())
            self.assertTrue((Path(d) / "crlf-vs-b" / "parity.json").exists())
            hist = (Path(d) / "history.jsonl").read_text()
            self.assertIn('"spec": "crlf-vs-a"', hist)
            self.assertIn('"spec": "crlf-vs-b"', hist)


class TestRunner(unittest.TestCase):
    def test_run_class_writes_report_and_history(self):
        burpsy = [{"url": "http://127.0.0.1:19090/crlf/r/home", "parameter": "",
                   "class": "crlf-injection", "technique": ""}]
        ref_raw = "[VLN] http://127.0.0.1:19090/crlf/r/home/%0aSet-Cookie:x=y;\n"
        with tempfile.TemporaryDirectory() as d:
            ctx = FakeCtx(burpsy, ref_raw)
            rc = parity_run.run_classes([dict(CRLF_SPEC)], d, ctx)
            self.assertEqual(0, rc)
            cdir = Path(d) / "crlf-injection"
            report = json.loads((cdir / "parity.json").read_text())
            self.assertTrue((cdir / "parity.md").exists())
            self.assertTrue((cdir / "burpsy.json").exists())
            self.assertTrue((cdir / "reference.json").exists())
            cls = report["classes"]["crlf-injection"]
            self.assertEqual(1, len(cls["both"]))
            self.assertEqual([], cls["reference_only"])
            self.assertEqual([], cls["burpsy_only"])
            history = [json.loads(l) for l in (Path(d) / "history.jsonl").read_text().splitlines()]
            self.assertEqual(1, len(history))
            self.assertEqual("crlf-injection", history[0]["class"])
            self.assertEqual(1, history[0]["both"])
            self.assertIn("date", history[0])

    def test_reference_only_is_a_reported_miss_not_an_error(self):
        ref_raw = "[VLN] http://127.0.0.1:19090/crlf/r/home/%0aSet-Cookie:x=y;\n"
        with tempfile.TemporaryDirectory() as d:
            rc = parity_run.run_classes([dict(CRLF_SPEC)], d, FakeCtx([], ref_raw))
            self.assertEqual(0, rc)  # a report, not a gate
            report = json.loads((Path(d) / "crlf-injection" / "parity.json").read_text())
            self.assertEqual(1, len(report["classes"]["crlf-injection"]["reference_only"]))

    def test_unknown_class_fails_loudly(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(KeyError):
                parity_run.run_classes(["no-such-class"], d, FakeCtx([], ""))


class TestSpecs(unittest.TestCase):
    def test_registered_specs_are_complete_and_consistent(self):
        from parity_specs import CLASSES
        import parity_tools as pt
        for name, spec in CLASSES.items():
            # spec["name"] is the parity class label (two tools can share it); the registry key
            # is what --class selects.
            self.assertTrue(spec["name"], name)
            self.assertIn(spec["ref_tool"], pt.TOOLS)
            self.assertTrue(spec["bead"].startswith("burpsy-react-ui-j1mk."))
            # audit-collected specs name their rows; the hidden-inputs collector names its mode.
            self.assertTrue(spec.get("burpsy_rows") or spec.get("burpsy_collect"), name)
            self.assertTrue(spec["targets"], name)
            self.assertTrue(callable(spec["tool_args"]), name)
            argv = spec["tool_args"](spec["targets"][0]["url"], {"binary": "/b/tool", "venv_bin": "/b", "script": "/b/tool.py"}, "/tmp")
            # The argv names the pinned tool's executable (binary, or the venv python for scripts).
            self.assertTrue(argv[0].startswith("/b/"), (name, argv))
            for t in spec.get("truth", []):
                self.assertEqual(spec["name"], t["class"])

    def test_crlf_truth_endpoints_are_seeded_targets(self):
        from parity_specs import CLASSES
        spec = CLASSES["crlf-injection"]
        seeded = {t["url"].split("?")[0] for t in spec["targets"]}
        for t in spec["truth"]:
            self.assertIn(t["url"].split("?")[0], seeded)




class TestZipBinaryTool(unittest.TestCase):
    """katana ships as a zip (j1mk.27): a kind the installer did not have."""

    def test_ensure_installs_a_zip_binary(self):
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("katana", b"#!/bin/sh\n")
            zf.writestr("README.md", b"x")
        payload = buf.getvalue()
        pin = {"name": "katana", "version": "v1.8.0", "kind": "zip-binary",
               "url": "https://example.test/k.zip", "sha256": hashlib.sha256(payload).hexdigest(),
               "path_in_archive": "katana", "note": "test"}
        fetched = []

        def fetcher(url, dest):
            fetched.append(url)
            Path(dest).write_bytes(payload)

        with tempfile.TemporaryDirectory() as d:
            got = parity_tools.ensure_tool(pin, d, fetcher=fetcher)
            self.assertTrue(Path(got["binary"]).exists())
            self.assertTrue(os.access(got["binary"], os.X_OK))
            got2 = parity_tools.ensure_tool(pin, d, fetcher=fetcher)
            self.assertEqual(1, len(fetched))  # stamped: no second fetch
            self.assertEqual(got, got2)


# Real katana v1.8.0 -jsonl output lines (bodies trimmed), captured 2026-10-25 against the
# demo target - the format the adapter is written to, per the harness's "verified against the
# pinned version" rule.
KATANA_SAMPLE = (
    '{"timestamp":"2026-10-25T18:56:02+02:00","request":{"method":"GET",'
    '"endpoint":"http://127.0.0.1:19091/"},'
    '"response":{"status_code":200,"headers":{},"content_length":10}}\n'
    '{"timestamp":"2026-10-25T18:56:03+02:00","request":{"method":"GET",'
    '"endpoint":"http://127.0.0.1:19091/a","tag":"a","attribute":"href",'
    '"source":"http://127.0.0.1:19091/"},'
    '"response":{"status_code":200,"headers":{},"content_length":10}}\n'
    '{"timestamp":"2026-10-25T18:56:04+02:00","request":{"method":"POST",'
    '"endpoint":"http://127.0.0.1:19091/submit","tag":"form","attribute":"action",'
    '"source":"http://127.0.0.1:19091/"},'
    '"response":{"status_code":200,"headers":{},"content_length":10}}\n'
    '{"timestamp":"2026-10-25T18:56:05+02:00","request":{"method":"GET",'
    '"endpoint":"http://127.0.0.1:19091/a","tag":"a","attribute":"href",'
    '"source":"http://127.0.0.1:19091/b"},'
    '"response":{"status_code":200,"headers":{},"content_length":10}}\n'
    'not json at all\n'
)


class TestKatanaAdapter(unittest.TestCase):
    def test_jsonl_endpoints_deduped_with_mechanism(self):
        got = parity_adapters.from_katana_jsonl(KATANA_SAMPLE, "crawl-coverage")
        by_url = {f["url"]: f for f in got}
        self.assertEqual({"http://127.0.0.1:19091/", "http://127.0.0.1:19091/a",
                          "http://127.0.0.1:19091/submit"}, set(by_url))
        for f in got:
            self.assertEqual("crawl-coverage", f["class"])
            self.assertEqual("", f["parameter"])
        self.assertEqual("a.href", by_url["http://127.0.0.1:19091/a"]["technique"])
        self.assertEqual("form.action", by_url["http://127.0.0.1:19091/submit"]["technique"])
        # The seed line has no tag/attribute; its technique is empty, not a crash.
        self.assertEqual("", by_url["http://127.0.0.1:19091/"]["technique"])

    def test_empty_output_is_empty(self):
        self.assertEqual([], parity_adapters.from_katana_jsonl("", "crawl-coverage"))
        self.assertEqual([], parity_adapters.from_katana_jsonl(None, "crawl-coverage"))


class TestCrawlHistoryAdapter(unittest.TestCase):
    def test_rows_become_urls(self):
        rows = [
            {"id": 9, "host": "127.0.0.1", "port": 19091, "tls": False,
             "method": "GET", "path": "/a"},
            {"id": 10, "host": "127.0.0.1", "port": 19091, "tls": False,
             "method": "GET", "path": "/"},
            {"id": 11, "host": "127.0.0.1", "port": 19091, "tls": True,
             "method": "GET", "path": "/tls-page"},
            {"id": 12, "host": "127.0.0.1", "port": 19091, "tls": False,
             "method": "GET", "path": "/a/burpsy-nf-03ed818a94a8"},
            {"id": 13, "host": "127.0.0.1", "port": 19091, "tls": False,
             "method": "GET", "path": "/guide/burpsy-nf-notes"},
            {"id": 14, "host": "127.0.0.1", "port": 19091, "tls": False,
             "method": "GET", "path": "/search?q=burpsy-nf-03ed818a94a8"},
        ]
        got = parity_adapters.from_burpsy_crawl_history(rows, "crawl-coverage")
        # The probe row is filtered by its exact shape; the two negative controls — a real page
        # whose name carries the marker, and the marker in a QUERY — must stay counted.
        self.assertEqual(
            {"http://127.0.0.1:19091/a", "http://127.0.0.1:19091/",
             "https://127.0.0.1:19091/tls-page",
             "http://127.0.0.1:19091/guide/burpsy-nf-notes",
             "http://127.0.0.1:19091/search?q=burpsy-nf-03ed818a94a8"},
            {f["url"] for f in got})
        for f in got:
            self.assertEqual("crawl-coverage", f["class"])
            self.assertEqual("", f["parameter"])

    def test_duplicates_collapse(self):
        rows = [{"id": i, "host": "h", "port": 80, "tls": False, "method": "GET", "path": "/x"}
                for i in (1, 2, 3)]
        got = parity_adapters.from_burpsy_crawl_history(rows, "crawl-coverage")
        self.assertEqual(1, len(got))


CRAWL_SPEC = {
    "name": "crawl-coverage",
    "bead": "burpsy-react-ui-j1mk.27",
    "ref_tool": "katana",
    "ref_name": "katana",
    "adapter": "katana",
    "burpsy_collect": "crawl",
    "targets": [{"url": "http://127.0.0.1:19091/", "method": "GET", "parameter": ""}],
    "truth": [{"url": "http://127.0.0.1:19091/a", "parameter": "",
               "class": "crawl-coverage"}],
}


class _FakeHTTP:
    """The _collect_crawl seams scripted: a history that gains rows, a crawl that walks the
    given states, and a confirm that hands back a token."""

    def __init__(self, states, rows_before, rows_after):
        self.states = list(states)
        self.rows_before = rows_before
        self.rows_after = rows_after
        self.cancelled = False
        self.confirmed_body = None

    def http_json(self, method, url, body=None, headers=None, timeout=60):
        if url.endswith("/api/history?limit=1000000"):
            # While crawl states remain the crawl is still running: the "before" snapshot.
            return self.rows_before if self.states else self.rows_after
        if url.endswith("/api/crawl") and method == "POST":
            self.confirmed_body = body
            self.headers = headers
            return {"task_id": 42, "state": "running"}
        if "/api/crawl?task=42" in url:
            st = self.states.pop(0) if self.states else "done"
            return {"state": st, "report": {"fetched": 1}, "error": ""}
        if "/api/tasks/42/cancel" in url:
            self.cancelled = True
            return {}
        raise AssertionError(url)

    def confirm(self, web, method, path, body, confirm_route=""):
        self.confirm_route = confirm_route
        return "tok"


def _crawl_row(i, path, host="127.0.0.1", port=19091, source="crawl"):
    return {"id": i, "host": host, "port": port, "tls": False, "method": "GET",
            "path": path, "source": source}


class TestCollectCrawlLoop(unittest.TestCase):
    SPEC = {"name": "crawl-coverage", "targets": [{"url": "http://127.0.0.1:19091/"}]}

    def test_running_then_done_collects_only_the_crawls_own_rows(self):
        after = [_crawl_row(2, "/a"),
                 _crawl_row(3, "/x", source="proxy"),       # someone else's traffic in the window
                 _crawl_row(4, "/y", host="10.9.9.9"),      # another host entirely
                 _crawl_row(5, "/z", port=19090)]           # the vulnapp class's own crawl
        fx = _FakeHTTP(["running", "done"], [_crawl_row(1, "/seeded-earlier")], after)
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            got = parity_run._collect_crawl(dict(self.SPEC), d, "http://web", 30,
                                            fx.http_json, fx.confirm, lambda s: None)
            self.assertEqual(["http://127.0.0.1:19091/a"], [f["url"] for f in got])
            self.assertTrue((Path(d) / "burpsy_crawl_report.json").exists())
            self.assertEqual("tok", fx.headers.get("X-Burpsy-Confirm"))
            self.assertEqual("/api/crawl/confirm", fx.confirm_route)

    def test_timeout_cancels_the_crawl(self):
        fx = _FakeHTTP(["running", "running", "running"], [], [])
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(TimeoutError) as cm:
                parity_run._collect_crawl(dict(self.SPEC), d, "http://web", 0,
                                          fx.http_json, fx.confirm, lambda s: None)
            self.assertTrue(fx.cancelled)
            self.assertIn("cancelled", str(cm.exception))

    def test_failed_state_is_loud(self):
        fx = _FakeHTTP(["failed"], [], [])
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):
                parity_run._collect_crawl(dict(self.SPEC), d, "http://web", 30,
                                            fx.http_json, fx.confirm, lambda s: None)


class TestCrawlSpecOrchestration(unittest.TestCase):
    def test_run_class_writes_the_report(self):
        burpsy = [{"url": "http://127.0.0.1:19091/a", "parameter": "",
                   "class": "crawl-coverage", "technique": ""}]
        with tempfile.TemporaryDirectory() as d:
            rc = parity_run.run_classes([dict(CRAWL_SPEC)], d,
                                        FakeCtx(burpsy, KATANA_SAMPLE))
            self.assertEqual(0, rc)
            report = json.loads((Path(d) / "crawl-coverage" / "parity.json").read_text())
            cls = report["classes"]["crawl-coverage"]
            self.assertEqual(1, len(cls["both"]))           # /a found by both
            self.assertEqual(2, len(cls["reference_only"]))  # / and /submit katana-only
            self.assertEqual(0, len(cls["burpsy_only"]))
            self.assertIn("truth", report)

    def test_specs_register_the_class(self):
        from parity_specs import CLASSES
        for key in ("crawl-coverage", "crawl-coverage-headless", "crawl-coverage-vulnapp"):
            self.assertIn(key, CLASSES)
            self.assertEqual("crawl", CLASSES[key]["burpsy_collect"])
            self.assertEqual("katana", CLASSES[key]["ref_tool"])


import os  # noqa: E402


if __name__ == "__main__":
    unittest.main(verbosity=2)
