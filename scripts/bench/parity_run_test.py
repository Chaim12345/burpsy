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
            self.assertIn(pin["kind"], ("pip-tarball", "script-tarball", "tarball-binary"), name)
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
            self.assertEqual(name, spec["name"])
            self.assertIn(spec["ref_tool"], pt.TOOLS)
            self.assertTrue(spec["bead"].startswith("burpsy-react-ui-j1mk."))
            self.assertTrue(spec["burpsy_rows"], name)
            self.assertTrue(spec["targets"], name)
            self.assertTrue(callable(spec["tool_args"]), name)
            argv = spec["tool_args"](spec["targets"][0]["url"], {"binary": "/b/tool", "venv_bin": "/b", "script": "/b/tool.py"}, "/tmp")
            # The argv names the pinned tool's executable (binary, or the venv python for scripts).
            self.assertTrue(argv[0].startswith("/b/"), (name, argv))
            for t in spec.get("truth", []):
                self.assertEqual(name, t["class"])

    def test_crlf_truth_endpoints_are_seeded_targets(self):
        from parity_specs import CLASSES
        spec = CLASSES["crlf-injection"]
        seeded = {t["url"].split("?")[0] for t in spec["targets"]}
        for t in spec["truth"]:
            self.assertIn(t["url"].split("?")[0], seeded)


if __name__ == "__main__":
    unittest.main(verbosity=2)
