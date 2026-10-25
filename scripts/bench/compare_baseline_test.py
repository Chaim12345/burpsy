#!/usr/bin/env python3
"""Tests for compare_baseline.py. Run: python3 scripts/bench/compare_baseline_test.py"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "compare_baseline.py")


def rep(score, **types):
    return {"strict": {"score_pct": score}, "by_type": {t: dict(v) for t, v in types.items()}}


def run(result, baseline, *extra):
    with tempfile.TemporaryDirectory() as d:
        r = os.path.join(d, "r.json")
        b = os.path.join(d, "b.json")
        json.dump(result, open(r, "w"))
        if baseline is not None:
            json.dump(baseline, open(b, "w"))
        p = subprocess.run([sys.executable, TOOL, r, b, *extra], capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr


class Compare(unittest.TestCase):
    def test_same_is_clean(self):
        rc, _ = run(rep(50, XSS={"tp": 3, "fp": 0}), rep(50, XSS={"tp": 3, "fp": 0}))
        self.assertEqual(rc, 0)

    def test_score_drop_beyond_margin_fails(self):
        rc, out = run(rep(47), rep(50))
        self.assertEqual(rc, 1, out)

    def test_score_drop_within_margin_passes(self):
        rc, _ = run(rep(49.5), rep(50))
        self.assertEqual(rc, 0)

    def test_type_tp_drop_fails_even_when_score_holds(self):
        rc, out = run(rep(50, SQLI={"tp": 2, "fp": 0}), rep(50, SQLI={"tp": 3, "fp": 0}))
        self.assertEqual(rc, 1, out)
        self.assertIn("SQLI", out)

    def test_type_fp_rise_fails(self):
        rc, _ = run(rep(50, XSS={"tp": 3, "fp": 1}), rep(50, XSS={"tp": 3, "fp": 0}))
        self.assertEqual(rc, 1)

    def test_improvement_passes_and_is_reported(self):
        rc, out = run(rep(60, XSS={"tp": 5, "fp": 0}), rep(50, XSS={"tp": 3, "fp": 0}))
        self.assertEqual(rc, 0)
        self.assertIn("improved", out)

    def test_missing_baseline_is_3(self):
        rc, _ = run(rep(50), None)
        self.assertEqual(rc, 3)

    def test_bad_result_is_2(self):
        rc, _ = run({"nope": 1}, rep(50))
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
