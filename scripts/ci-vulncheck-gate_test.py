#!/usr/bin/env python3
"""Tests for ci-vulncheck-gate.py. Run: python3 scripts/ci-vulncheck-gate_test.py"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

GATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ci-vulncheck-gate.py")


def run(stream, baseline_lines):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as b:
        b.write("\n".join(baseline_lines) + "\n")
    try:
        p = subprocess.run([sys.executable, GATE, b.name], input=stream, capture_output=True, text=True)
    finally:
        os.unlink(b.name)
    return p.returncode, p.stdout + p.stderr


def osv(i):
    return json.dumps({"osv": {"id": i, "summary": "s " + i}})


def finding(i, called):
    frame = {"module": "m", "function": "F"} if called else {"module": "m"}
    return json.dumps({"finding": {"osv": i, "trace": [frame]}})


class Gate(unittest.TestCase):
    def test_baselined_reachable_passes(self):
        rc, out = run("\n".join([osv("GO-1"), finding("GO-1", True)]), ["GO-1  # why"])
        self.assertEqual(rc, 0, out)

    def test_new_reachable_fails_and_is_named(self):
        rc, out = run("\n".join([osv("GO-2"), finding("GO-2", True)]), ["GO-1"])
        self.assertEqual(rc, 1, out)
        self.assertIn("GO-2", out)

    def test_required_but_not_called_does_not_gate(self):
        rc, out = run("\n".join([osv("GO-3"), finding("GO-3", False)]), [])
        self.assertEqual(rc, 0, out)

    def test_empty_output_never_passes(self):
        rc, _ = run("", [])
        self.assertEqual(rc, 2)

    def test_garbage_never_passes(self):
        rc, _ = run("not json", [])
        self.assertEqual(rc, 2)

    def test_stale_baseline_entries_are_listed(self):
        rc, out = run(osv("GO-4"), ["GO-9"])
        self.assertEqual(rc, 0, out)
        self.assertIn("GO-9", out)


if __name__ == "__main__":
    unittest.main()
