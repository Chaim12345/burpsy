// Conformance runner for the Go bcheck parser, mirroring crates/bcheck/src/bin/conform.rs
// so both parsers are measured over the identical corpus.
//
// # Why the verdict is three-valued
//
// HARD-02: "The corpus partition invariant is verified on machines without the corpus fixture, and a
// skipped check reports as skipped rather than as a pass."
//
// The corpus is a PortSwigger fixture that is not in this repository and is absent from most
// machines. This program used to answer an absent corpus with `files: 0 / parsed OK: 0 / failed: 0`
// and exit 0 — byte for byte the shape of a clean run, and the exit code every CI wrapper reads as
// success. Nothing said the check had not run. That is exactly the collapse
// internal/scanner/coverage.go exists to prevent, one layer up: "ran and found nothing wrong" and
// "never ran" produced the same signal.
//
// So there are three verdicts, and the exit code carries them as well as the text:
//
//	PASS    (0) every discovered file was read, and every one of them parsed
//	FAIL    (1) the corpus was walked and something did not check out
//	SKIPPED (2) the check never ran, because there was no corpus to walk
//
// Two is deliberate rather than folding a skip into 1. A wrapper whose rule is "non-zero means the
// parser is broken" would report a missing fixture as a parser defect, which is the mirror-image lie;
// a wrapper whose rule is "zero means it conformed" still refuses to call a skip a pass. Both
// readings stay honest without the wrapper having to parse text, and a wrapper that wants the
// distinction has it.
//
// # Why absent and empty are different messages
//
// They call for different actions. An absent root means the operator has no corpus and needs to fetch
// one; a present root with no `.bcheck` files in it means they have pointed this at the wrong
// directory, or at a corpus whose layout changed. Collapsing the two into "no corpus" would leave the
// second reader hunting for a fixture they already have.
//
// # Why the partition is printed
//
// Every file discovered by the walk lands in exactly one of parsed / failed / unreadable, and the sum
// is checked against the discovered count rather than assumed. The old loop skipped an unreadable
// file with a bare `continue`, so a corpus whose files could be listed but not read reported
// `files: 264, parsed OK: 0, failed: 0` — 264 files silently accounted for by nothing. An
// arithmetic identity that is printed is one a reader can check; one that is only implied is one that
// can quietly stop holding.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// defaultCorpusRoot is where verify.sh and the Rust runner both expect the PortSwigger corpus.
const defaultCorpusRoot = "/tmp/BChecks"

// maxReportedFailures bounds the failure list so a corpus that fails wholesale does not bury the
// verdict line under thousands of messages. The count above it is never truncated — only the detail
// is, and the report says so.
const maxReportedFailures = 25

// Exit codes. See the package docs for why a skip gets its own code instead of being folded into
// either of the other two.
const (
	exitPass    = 0
	exitFail    = 1
	exitSkipped = 2
)

// verdict is the answer this program exists to give. Named states rather than a bool, because the
// third one is the whole point: "the corpus conforms", "it does not", and "nobody looked".
type verdict int

const (
	verdictPass verdict = iota
	verdictFail
	verdictSkipped
)

func (v verdict) String() string {
	switch v {
	case verdictPass:
		return "PASS"
	case verdictFail:
		return "FAIL"
	case verdictSkipped:
		return "SKIPPED"
	}
	return "UNKNOWN"
}

func (v verdict) exitCode() int {
	switch v {
	case verdictPass:
		return exitPass
	case verdictFail:
		return exitFail
	case verdictSkipped:
		return exitSkipped
	}
	// An unnamed verdict is not a pass. Reaching here means a state was added above without being
	// mapped, and the safe direction is the one that fails loudly.
	return exitFail
}

// outcome is one run's evidence. The zero value is not a pass: verdict() reads a zero Files with no
// SkipReason as a failure, because a run that discovered nothing and did not say why has not
// established anything.
type outcome struct {
	// Root is the path that was asked about, echoed so a reader of a skip knows which path was wrong.
	Root string
	// SkipReason is non-empty exactly when the check never ran. It is the one field that turns the
	// verdict into SKIPPED.
	SkipReason string

	// Files is how many .bcheck files the walk discovered — the total the partition must account for.
	Files int
	// Parsed, Failed and Unreadable partition Files. Unreadable is its own bucket rather than being
	// skipped silently: a file that could not be read was not checked, and that is not a pass for it.
	Parsed     int
	Failed     int
	Unreadable int

	// Failures and Unreadables carry the per-file detail behind those two counts.
	Failures    []string
	Unreadables []string
	// WalkErrors names every path the walk could not traverse. A subtree that could not be listed
	// holds an unknown number of unchecked files, so this forces a FAIL rather than being absorbed
	// into a smaller Files count that still looks complete.
	WalkErrors []string
}

// partitionHolds reports whether every discovered file is accounted for exactly once.
func (o outcome) partitionHolds() bool {
	return o.Files == o.Parsed+o.Failed+o.Unreadable
}

// verdict collapses the evidence. Anything short of "every discovered file was read and parsed, and
// the arithmetic proves it" is a failure — never a pass with a footnote.
func (o outcome) verdict() verdict {
	if o.SkipReason != "" {
		return verdictSkipped
	}
	if o.Files == 0 || o.Failed > 0 || o.Unreadable > 0 || len(o.WalkErrors) > 0 || !o.partitionHolds() {
		return verdictFail
	}
	return verdictPass
}

// failReason names, in one line, what stopped this from being a pass. Empty for a pass or a skip.
func (o outcome) failReason() string {
	switch {
	case o.verdict() != verdictFail:
		return ""
	case !o.partitionHolds():
		return fmt.Sprintf("the partition does not hold: %d file(s) discovered but %d accounted for",
			o.Files, o.Parsed+o.Failed+o.Unreadable)
	case o.Files == 0:
		return "no file was discovered and no skip reason was recorded, so nothing was established"
	case len(o.WalkErrors) > 0 && o.Failed == 0 && o.Unreadable == 0:
		return fmt.Sprintf("%d path(s) could not be traversed, so the corpus was not seen in full", len(o.WalkErrors))
	default:
		return fmt.Sprintf("%d file(s) failed to parse, %d could not be read", o.Failed, o.Unreadable)
	}
}

// inspect walks root and parses everything it finds, returning what happened rather than printing it,
// so the exit contract can be asserted directly in a test instead of by scraping stdout.
func inspect(root string) outcome {
	o := outcome{Root: root}

	// Stat before walking. filepath.Walk reports a missing root through its callback like any other
	// error, which is how the absent corpus used to become an empty file list and a clean exit; asking
	// first is what lets absent, unreadable and wrong-kind become three different messages.
	info, err := os.Stat(root)
	switch {
	case err != nil && os.IsNotExist(err):
		o.SkipReason = fmt.Sprintf("the corpus root %s does not exist, so the partition invariant is unverified on this machine", root)
		return o
	case err != nil:
		o.SkipReason = fmt.Sprintf("the corpus root %s could not be read (%v), so the partition invariant is unverified on this machine", root, err)
		return o
	}

	var files []string
	switch {
	case info.IsDir():
		// Walk errors are collected, not returned: one unreadable subtree must not abandon the rest of
		// the corpus, the same way one bad check must not silence the other 104. What changed is that
		// they are now counted and reported instead of discarded.
		_ = filepath.Walk(root, func(p string, fi os.FileInfo, werr error) error {
			if werr != nil {
				o.WalkErrors = append(o.WalkErrors, fmt.Sprintf("%s: %v", p, werr))
				return nil
			}
			if !fi.IsDir() && filepath.Ext(p) == ".bcheck" {
				files = append(files, p)
			}
			return nil
		})
		if len(files) == 0 {
			if len(o.WalkErrors) > 0 {
				o.SkipReason = fmt.Sprintf("the corpus root %s could not be traversed, so no .bcheck file was reached and the partition invariant is unverified on this machine", root)
			} else {
				o.SkipReason = fmt.Sprintf("the corpus root %s exists but holds no .bcheck files, so there was no corpus to check — this is a wrong path, not a missing fixture", root)
			}
			return o
		}
	case filepath.Ext(root) == ".bcheck":
		// A single file is a legitimate one-file corpus; the Rust runner accepts one too.
		files = []string{root}
	default:
		o.SkipReason = fmt.Sprintf("%s is neither a directory nor a .bcheck file, so there was no corpus to walk", root)
		return o
	}
	sort.Strings(files)
	o.Files = len(files)

	for _, f := range files {
		src, rerr := os.ReadFile(f)
		if rerr != nil {
			o.Unreadable++
			o.Unreadables = append(o.Unreadables, fmt.Sprintf("%s: %v", f, rerr))
			continue
		}
		if _, perr := bcheck.Parse(string(src)); perr != nil {
			o.Failed++
			o.Failures = append(o.Failures, fmt.Sprintf("%s: %v", f, perr))
			continue
		}
		o.Parsed++
	}
	return o
}

// report writes the human-readable form. A skip prints its reason and no counts at all: a
// `parsed OK      : 0` line sitting under a SKIPPED verdict is precisely what HARD-02 forbids,
// because a grep in a wrapper script can lift that line out of its context and present it as a
// conformance result.
func (o outcome) report(w io.Writer) {
	v := o.verdict()
	fmt.Fprintf(w, "corpus root    : %s\n", o.Root)
	if v == verdictSkipped {
		fmt.Fprintf(w, "result         : %s\n", v)
		fmt.Fprintf(w, "reason         : %s\n", o.SkipReason)
		o.reportList(w, "paths that could not be traversed", o.WalkErrors)
		return
	}

	fmt.Fprintf(w, "files          : %d\n", o.Files)
	fmt.Fprintf(w, "parsed OK      : %d\n", o.Parsed)
	fmt.Fprintf(w, "failed         : %d\n", o.Failed)
	fmt.Fprintf(w, "unreadable     : %d\n", o.Unreadable)
	holds := "holds"
	if !o.partitionHolds() {
		holds = "DOES NOT HOLD"
	}
	fmt.Fprintf(w, "partition      : %d discovered = %d parsed + %d failed + %d unreadable (%s)\n",
		o.Files, o.Parsed, o.Failed, o.Unreadable, holds)
	if o.Files > 0 {
		fmt.Fprintf(w, "accept rate    : %.1f%%\n", float64(o.Parsed)*100.0/float64(o.Files))
	}
	fmt.Fprintf(w, "result         : %s\n", v)
	if reason := o.failReason(); reason != "" {
		fmt.Fprintf(w, "reason         : %s\n", reason)
	}
	o.reportList(w, fmt.Sprintf("failures (%d)", o.Failed), o.Failures)
	o.reportList(w, fmt.Sprintf("unreadable files (%d)", o.Unreadable), o.Unreadables)
	o.reportList(w, fmt.Sprintf("paths that could not be traversed (%d)", len(o.WalkErrors)), o.WalkErrors)
}

// reportList prints at most maxReportedFailures entries, saying how many it withheld rather than
// trailing off.
func (o outcome) reportList(w io.Writer, title string, entries []string) {
	if len(entries) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s:\n", title)
	for i, e := range entries {
		if i >= maxReportedFailures {
			fmt.Fprintf(w, "  … and %d more\n", len(entries)-maxReportedFailures)
			break
		}
		fmt.Fprintf(w, "  %s\n", e)
	}
}

func main() {
	root := defaultCorpusRoot
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	o := inspect(root)
	o.report(os.Stdout)
	os.Exit(o.verdict().exitCode())
}
