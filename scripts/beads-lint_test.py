#!/usr/bin/env python3
"""beads-lint_test.py — drives scripts/beads-lint.py against throwaway git repos.

    python3 -I scripts/beads-lint_test.py
"""
import json
import os
import subprocess
import tempfile
import unittest

LINT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "beads-lint.py")


def sh(cwd, *a):
    return subprocess.run(a, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def jl(*recs):
    return "".join(json.dumps(r) + "\n" for r in recs)


class Lint(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        sh(self.d, "git", "init", "-q")
        sh(self.d, "git", "config", "user.email", "t@t")
        sh(self.d, "git", "config", "user.name", "t")
        os.makedirs(os.path.join(self.d, ".beads"))
        self.write(jl({"id": "x-a", "status": "open"}, {"id": "x-b", "status": "open"}))
        self.landed = self.commit("work")
        self.base = self.landed

    def write(self, text):
        with open(os.path.join(self.d, ".beads/issues.jsonl"), "w") as f:
            f.write(text)

    def commit(self, msg):
        sh(self.d, "git", "add", "-A")
        sh(self.d, "git", "commit", "-q", "--allow-empty", "-m", msg)
        return sh(self.d, "git", "rev-parse", "HEAD")

    def lint(self, reason, bid="x-a"):
        self.write(jl({"id": "x-a", "status": "closed", "close_reason": reason}, {"id": "x-b", "status": "open"}))
        self.commit("close")
        # The lint prints "::error::" under GitHub Actions and "error: " elsewhere; pin the second so the
        # tests read the same everywhere.
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_ACTIONS"}
        p = subprocess.run(["python3", "-I", LINT, "--base", self.base], cwd=self.d, capture_output=True, text=True, env=env)
        return p.returncode, p.stdout

    def test_pr_form_still_accepted(self):
        self.assertEqual(self.lint(f"Fixed by PR #7 ({self.landed[:12]}): t")[0], 0)

    def test_merged_via_integrator_paren_sha(self):
        self.assertEqual(self.lint(f"MERGED via integrator ({self.landed[:8]}). done")[0], 0)

    def test_merged_via_integrator_at_sha(self):
        self.assertEqual(self.lint(f"MERGED via integrator at {self.landed[:8]}. done")[0], 0)

    def test_fast_track_two_shas(self):
        self.assertEqual(self.lint(f"MERGED via integrator fast-track ({self.landed[:8]}+{self.landed[:10]}): x")[0], 0)

    def test_after_round_form(self):
        self.assertEqual(self.lint(f"MERGED via integrator after round-2 fixes ({self.landed[:8]}). done")[0], 0)

    def test_no_sha_is_rejected(self):
        rc, out = self.lint("MERGED via integrator. everything fine")
        self.assertEqual(rc, 1)
        self.assertIn("must cite the landed commit", out)

    def test_unlanded_sha_is_rejected(self):
        rc, out = self.lint("MERGED via integrator (deadbee1)")
        self.assertEqual(rc, 1)
        self.assertIn("not a commit", out)

    def test_sha_only_in_the_body_does_not_count(self):
        rc, _ = self.lint(f"MERGED via integrator. see also {self.landed[:8]} in the notes")
        self.assertEqual(rc, 1)

    def test_one_unlanded_sha_among_valid_ones_rejects_the_closure(self):
        rc, out = self.lint(f"MERGED via integrator fast-track ({self.landed[:8]}+deadbee1)")
        self.assertEqual(rc, 1)
        self.assertIn("deadbee1", out)
        err = [l for l in out.splitlines() if l.startswith("error:")]
        self.assertEqual(len(err), 1)
        self.assertNotIn(self.landed[:8], err[0])

    def test_a_number_or_hex_word_outside_a_citation_position_is_not_a_sha(self):
        for reason in ("MERGED via integrator, patch 1234567 reviewed", f"MERGED via integrator, {self.landed[:8]} reviewed"):
            rc, out = self.lint(reason)
            self.assertEqual(rc, 1, reason)
            self.assertIn("must cite", out)

    def test_spaced_or_junk_multi_citation_is_rejected_not_half_checked(self):
        g = self.landed[:8]
        for reason in (f"MERGED via integrator ({g} + deadbee1)", f"MERGED via integrator ({g}+zzz)",
                       f"MERGED via integrator ({g}+)", f"MERGED via integrator ({g}+DEADBEE1)"):
            rc, out = self.lint(reason)
            self.assertEqual(rc, 1, reason)
            self.assertIn("malformed", out, reason)

    def test_uppercase_sha_is_not_a_citation(self):
        rc, out = self.lint(f"MERGED via integrator ({self.landed[:8].upper()})")
        self.assertEqual(rc, 1)
        self.assertIn("must cite", out)

    def test_sha_grammar_directly(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("bl", LINT)
        bl = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bl)
        grab = lambda r: bl.merged_citations(bl.MERGED_RX.match(r).group(0))[0]
        self.assertEqual(bl.merged_citations("MERGED via integrator (abcdefa + 1234567)")[0], [])
        self.assertNotEqual(bl.merged_citations("MERGED via integrator (abcdefa + 1234567)")[1], "")
        self.assertEqual(grab("MERGED via integrator (abcdefa)"), ["abcdefa"])  # an all-letter sha is a sha
        self.assertEqual(grab("MERGED via integrator at 593179a3."), ["593179a3"])
        self.assertEqual(grab("MERGED via integrator fast-track (244d0b75+3f10641d): x"), ["244d0b75", "3f10641d"])
        self.assertEqual(grab("MERGED via integrator after round-2 fixes (ab8501e4). d"), ["ab8501e4"])
        self.assertEqual(grab("MERGED via integrator (abc123)"), [])  # 6 hex: too short
        self.assertEqual(grab("MERGED via integrator, patch 1234567"), [])

    def test_a_hex_word_is_not_a_sha(self):
        rc, out = self.lint("MERGED via integrator after defaced")
        self.assertEqual(rc, 1)
        self.assertIn("must cite", out)

    def test_prefix_must_be_exact(self):
        rc, _ = self.lint(f"Merged by someone ({self.landed[:8]})")
        self.assertEqual(rc, 1)

    def test_a_sha_not_in_head_history_is_rejected(self):
        sh(self.d, "git", "checkout", "-q", "-b", "side")
        side = self.commit("side")
        sh(self.d, "git", "checkout", "-q", "-")
        rc, out = self.lint(f"MERGED via integrator ({side[:8]})")
        self.assertEqual(rc, 1)
        self.assertIn("not landed", out)


if __name__ == "__main__":
    unittest.main()
