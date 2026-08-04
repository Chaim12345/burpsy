// HARD-02's tests. Each asserts on the exit contract — the code a wrapper actually reads — and only
// then on the text, because a run that prints the word "SKIPPED" and exits 0 is still a run every CI
// harness records as a pass.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oneValidCheck is the canonical minimal passive check, the same source internal/bcheck's own tests
// use as their known-good input.
const oneValidCheck = `
metadata:
  language: v1-beta
  name: "NuGet API Key"
  description: "Looks for NuGet API keys in page source."
  author: "@puzzlepeaches"
  tags: "nuget", "token", "exposure"

given response then
  if {latest.response} matches "oy2[a-z0-9]{43}" then
      report issue:
          severity: info
          confidence: tentative
          detail: "NuGet API key found in page."
  end if
`

// writeCheck drops src into dir under name and returns the path.
func writeCheck(t *testing.T, dir, name, src string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// reportOf renders an outcome the way main does, for the assertions about what a reader sees.
func reportOf(t *testing.T, o outcome) string {
	t.Helper()
	var sb strings.Builder
	o.report(&sb)
	return sb.String()
}

// The bug HARD-02 names, exactly as it was reproduced: `conform /nonexistent/corpus` printed
// `parsed OK: 0 / failed: 0` and exited 0.
func Test_a_nonexistent_corpus_root_is_reported_as_skipped_and_never_as_a_pass(t *testing.T) {
	o := inspect(filepath.Join(t.TempDir(), "definitely-not-here"))

	if got := o.verdict(); got != verdictSkipped {
		t.Fatalf("verdict = %s, want SKIPPED", got)
	}
	// The exit contract is the assertion that matters: this is what a wrapper reads.
	if got := o.verdict().exitCode(); got != exitSkipped {
		t.Fatalf("exit code = %d, want %d (skipped)", got, exitSkipped)
	}
	if o.verdict().exitCode() == exitPass {
		t.Fatal("a skipped check must not exit with the pass code")
	}
	if o.SkipReason == "" {
		t.Fatal("a skip must name its reason")
	}

	out := reportOf(t, o)
	if !strings.Contains(out, "SKIPPED") {
		t.Errorf("report does not say SKIPPED:\n%s", out)
	}
	// No count lines at all. A wrapper that greps for these would otherwise lift "0 failed" out of a
	// skipped run and present it as conformance.
	for _, forbidden := range []string{"parsed OK", "failed         :", "accept rate"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("a skipped run must print no conformance counts, but the report has %q:\n%s", forbidden, out)
		}
	}
}

// An existing-but-empty directory is a different situation from an absent one — the operator has a
// path problem, not a missing fixture — so it gets its own reason while sharing the exit contract.
func Test_a_present_but_empty_corpus_directory_is_skipped_with_its_own_reason(t *testing.T) {
	empty := inspect(t.TempDir())
	absent := inspect(filepath.Join(t.TempDir(), "definitely-not-here"))

	if got := empty.verdict(); got != verdictSkipped {
		t.Fatalf("verdict = %s, want SKIPPED", got)
	}
	if got := empty.verdict().exitCode(); got != exitSkipped {
		t.Fatalf("exit code = %d, want %d (skipped)", got, exitSkipped)
	}
	if empty.Files != 0 || empty.Parsed != 0 {
		t.Fatalf("files/parsed = %d/%d, want 0/0", empty.Files, empty.Parsed)
	}
	if empty.SkipReason == absent.SkipReason {
		t.Errorf("an empty directory and a missing one must not share a reason; both said %q", empty.SkipReason)
	}
	if !strings.Contains(empty.SkipReason, "no .bcheck files") {
		t.Errorf("reason = %q, want it to say the directory holds no .bcheck files", empty.SkipReason)
	}
}

// A directory holding files that are not checks is the same "wrong path" situation, and must not be
// mistaken for a corpus that happens to contain zero checks passing.
func Test_a_directory_with_no_bcheck_files_in_it_is_skipped_not_passed(t *testing.T) {
	dir := t.TempDir()
	writeCheck(t, dir, "README.md", "not a check")
	writeCheck(t, dir, "check.bcheck.txt", oneValidCheck)

	o := inspect(dir)
	if got := o.verdict().exitCode(); got != exitSkipped {
		t.Fatalf("exit code = %d, want %d (skipped)", got, exitSkipped)
	}
}

// A path that names something other than a directory or a check is a third wrong-input case, and is
// still a skip: nothing was walked, so nothing was established.
func Test_a_root_that_is_not_a_directory_or_a_check_is_skipped(t *testing.T) {
	dir := t.TempDir()
	o := inspect(writeCheck(t, dir, "notes.txt", "hello"))
	if got := o.verdict().exitCode(); got != exitSkipped {
		t.Fatalf("exit code = %d, want %d (skipped)", got, exitSkipped)
	}
	if !strings.Contains(o.SkipReason, "neither a directory nor a .bcheck file") {
		t.Errorf("reason = %q, want it to name the wrong kind of path", o.SkipReason)
	}
}

// The pass case, so the three skips above are not vacuously satisfied by a program that can only skip.
func Test_a_corpus_that_parses_reports_pass_with_a_holding_partition(t *testing.T) {
	dir := t.TempDir()
	writeCheck(t, dir, "one.bcheck", oneValidCheck)
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCheck(t, filepath.Join(dir, "nested"), "two.bcheck", oneValidCheck)

	o := inspect(dir)
	if got := o.verdict(); got != verdictPass {
		t.Fatalf("verdict = %s, want PASS (reason: %s)", got, o.failReason())
	}
	if got := o.verdict().exitCode(); got != exitPass {
		t.Fatalf("exit code = %d, want %d", got, exitPass)
	}
	if o.Files != 2 || o.Parsed != 2 {
		t.Fatalf("files/parsed = %d/%d, want 2/2 (the walk must reach nested directories)", o.Files, o.Parsed)
	}
	if !o.partitionHolds() {
		t.Error("the partition must hold on a clean run")
	}
	if !strings.Contains(reportOf(t, o), "result         : PASS") {
		t.Errorf("report does not say PASS:\n%s", reportOf(t, o))
	}
}

// A single .bcheck file is a legitimate one-file corpus, matching the Rust runner.
func Test_a_single_check_file_is_a_one_file_corpus(t *testing.T) {
	o := inspect(writeCheck(t, t.TempDir(), "one.bcheck", oneValidCheck))
	if got := o.verdict(); got != verdictPass {
		t.Fatalf("verdict = %s, want PASS (reason: %s)", got, o.failReason())
	}
	if o.Files != 1 {
		t.Fatalf("files = %d, want 1", o.Files)
	}
}

func Test_a_corpus_with_an_unparsable_check_fails_and_names_it(t *testing.T) {
	dir := t.TempDir()
	writeCheck(t, dir, "good.bcheck", oneValidCheck)
	writeCheck(t, dir, "bad.bcheck", "this is not a bcheck at all")

	o := inspect(dir)
	if got := o.verdict(); got != verdictFail {
		t.Fatalf("verdict = %s, want FAIL", got)
	}
	if got := o.verdict().exitCode(); got != exitFail {
		t.Fatalf("exit code = %d, want %d", got, exitFail)
	}
	if o.Files != 2 || o.Parsed != 1 || o.Failed != 1 {
		t.Fatalf("files/parsed/failed = %d/%d/%d, want 2/1/1", o.Files, o.Parsed, o.Failed)
	}
	if !o.partitionHolds() {
		t.Error("a failure must still partition")
	}
	out := reportOf(t, o)
	if !strings.Contains(out, "bad.bcheck") {
		t.Errorf("report does not name the failing file:\n%s", out)
	}
}

// The `continue` this loop used to do on a read error meant an unreadable file was counted in `files`
// and in nothing else, so `files: N, parsed: 0, failed: 0` was a reachable — and clean-looking —
// output. A dangling symlink is the read failure that works for any uid, including root.
func Test_an_unreadable_check_is_its_own_bucket_and_not_silently_dropped(t *testing.T) {
	dir := t.TempDir()
	writeCheck(t, dir, "good.bcheck", oneValidCheck)
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling.bcheck")); err != nil {
		t.Skipf("this platform cannot create the dangling symlink this case needs: %v", err)
	}

	o := inspect(dir)
	if o.Files != 2 {
		t.Fatalf("files = %d, want 2: an unreadable file is still a discovered file", o.Files)
	}
	if o.Unreadable != 1 || o.Parsed != 1 || o.Failed != 0 {
		t.Fatalf("parsed/failed/unreadable = %d/%d/%d, want 1/0/1", o.Parsed, o.Failed, o.Unreadable)
	}
	if !o.partitionHolds() {
		t.Errorf("the partition must account for the unreadable file: %d != %d+%d+%d",
			o.Files, o.Parsed, o.Failed, o.Unreadable)
	}
	if got := o.verdict(); got != verdictFail {
		t.Fatalf("verdict = %s, want FAIL: a file that was never read is not a file that conformed", got)
	}
	if !strings.Contains(reportOf(t, o), "dangling.bcheck") {
		t.Error("the report must name the file it could not read")
	}
}

// The exit codes are the contract, so they are pinned: three distinct values, none of them shared.
func Test_the_three_verdicts_have_three_distinct_exit_codes(t *testing.T) {
	seen := map[int]verdict{}
	for _, v := range []verdict{verdictPass, verdictFail, verdictSkipped} {
		code := v.exitCode()
		if prev, dup := seen[code]; dup {
			t.Fatalf("%s and %s share exit code %d, so a wrapper cannot tell them apart", prev, v, code)
		}
		seen[code] = v
	}
	if verdictPass.exitCode() != 0 {
		t.Errorf("pass exit code = %d, want 0", verdictPass.exitCode())
	}
	if verdictSkipped.exitCode() == 0 {
		t.Error("a skip must not exit 0")
	}
}

// The zero value must not read as a pass. This is the fail-safe direction CheckCoverage takes with
// never-dispatched: an outcome nobody filled in has established nothing.
func Test_an_empty_outcome_is_not_a_pass(t *testing.T) {
	if got := (outcome{}).verdict(); got == verdictPass {
		t.Fatal("the zero outcome must not be a pass")
	}
	if (outcome{}).failReason() == "" {
		t.Error("a failure must name its reason")
	}
}
