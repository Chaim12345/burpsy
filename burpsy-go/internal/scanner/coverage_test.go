package scanner

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

func bcheckNamed(name string) *bcheck.Check {
	return &bcheck.Check{Name: name}
}

func Test_a_new_tracker_marks_every_check_never_dispatched(t *testing.T) {
	checks := []*bcheck.Check{bcheckNamed("first"), bcheckNamed("second"), bcheckNamed("third")}
	tr := newCoverageTracker(checks)

	rep := tr.Snapshot()
	if len(rep.Checks) != 3 {
		t.Fatalf("snapshot has %d checks, want 3", len(rep.Checks))
	}
	for _, c := range rep.Checks {
		if c.State() != CoverageStateNeverDispatched {
			t.Errorf("check %q state = %s, want never dispatched (default must be not-run)", c.Name, c.State())
		}
	}
	if got := rep.Count(CoverageStateNeverDispatched); got != 3 {
		t.Errorf("Count(never dispatched) = %d, want 3", got)
	}
	if sum := partitionSum(rep.Partition()); sum != 3 {
		t.Errorf("partition sums to %d, want 3 (the tested invariant: every check in exactly one bucket)", sum)
	}
}

func Test_a_clean_run_and_a_finding_run_are_distinguishable_in_the_coverage_snapshot(t *testing.T) {
	checks := []*bcheck.Check{bcheckNamed("clean"), bcheckNamed("leaky")}
	tr := newCoverageTracker(checks)

	// One scan: "clean" ran and found nothing; "leaky" ran and produced two findings.
	tr.RecordScan([]ScanDelta{{Findings: 0}, {Findings: 2}})

	rep := tr.Snapshot()
	clean := rep.Checks[0]
	leaky := rep.Checks[1]
	if clean.State() != CoverageStateRanClean {
		t.Errorf("clean check state = %s, want ran clean", clean.State())
	}
	if leaky.State() != CoverageStateRanAndFound {
		t.Errorf("leaky check state = %s, want ran and found", leaky.State())
	}
	if leaky.Ran != 1 || leaky.Findings != 2 {
		t.Errorf("leaky counters = ran:%d findings:%d, want ran:1 findings:2", leaky.Ran, leaky.Findings)
	}
	if got := rep.Count(CoverageStateRanClean); got != 1 {
		t.Errorf("Count(ran clean) = %d, want 1", got)
	}
	if got := rep.Count(CoverageStateRanAndFound); got != 1 {
		t.Errorf("Count(ran and found) = %d, want 1", got)
	}
}

func Test_a_clean_run_and_an_erroring_run_are_distinguishable_in_the_coverage_snapshot(t *testing.T) {
	checks := []*bcheck.Check{bcheckNamed("clean"), bcheckNamed("bad")}
	tr := newCoverageTracker(checks)

	tr.RecordScan([]ScanDelta{{Findings: 0}, {Err: "regex construction failed"}})

	rep := tr.Snapshot()
	clean := rep.Checks[0]
	bad := rep.Checks[1]
	if clean.State() != CoverageStateRanClean {
		t.Errorf("clean check state = %s, want ran clean", clean.State())
	}
	if bad.State() != CoverageStateErrored {
		t.Errorf("bad check state = %s, want errored", bad.State())
	}
	if bad.LastError != "regex construction failed" {
		t.Errorf("bad check last_error = %q, want the runtime error message", bad.LastError)
	}
	// The erroring run must not have been counted as having run cleanly.
	if bad.Ran != 0 || bad.Errored != 1 {
		t.Errorf("bad check counters = ran:%d errored:%d, want ran:0 errored:1", bad.Ran, bad.Errored)
	}
}

func Test_erroring_beats_a_clean_run_in_state_classification(t *testing.T) {
	checks := []*bcheck.Check{bcheckNamed("mostly-broken")}
	tr := newCoverageTracker(checks)

	// Ninety-nine clean responses must not paper over one error: the check reads as errored.
	for i := 0; i < 99; i++ {
		tr.RecordScan([]ScanDelta{{Findings: 0}})
	}
	tr.RecordScan([]ScanDelta{{Err: "boom"}})

	rep := tr.Snapshot()
	if got := rep.Checks[0]; got.State() != CoverageStateErrored || got.Ran != 99 || got.Errored != 1 {
		t.Errorf("state = %s ran:%d errored:%d, want errored ran:99 errored:1", got.State(), got.Ran, got.Errored)
	}
}

func Test_findings_can_exceed_ran_because_one_response_carries_many_matches(t *testing.T) {
	checks := []*bcheck.Check{bcheckNamed("multi")}
	tr := newCoverageTracker(checks)

	tr.RecordScan([]ScanDelta{{Findings: 4}})

	rep := tr.Snapshot()
	c := rep.Checks[0]
	if c.Ran != 1 || c.Findings != 4 {
		t.Errorf("counters = ran:%d findings:%d, want ran:1 findings:4", c.Ran, c.Findings)
	}
	if c.State() != CoverageStateRanAndFound {
		t.Errorf("state = %s, want ran and found", c.State())
	}
}

func Test_an_errored_check_keeps_its_last_error_not_the_first(t *testing.T) {
	checks := []*bcheck.Check{bcheckNamed("bad")}
	tr := newCoverageTracker(checks)

	tr.RecordScan([]ScanDelta{{Err: "first error"}})
	tr.RecordScan([]ScanDelta{{Err: "latest error"}})

	rep := tr.Snapshot()
	if got := rep.Checks[0].LastError; got != "latest error" {
		t.Errorf("last_error = %q, want the most recent error", got)
	}
}

func Test_record_scan_keeps_identity_with_the_passive_check_set_by_position(t *testing.T) {
	// The contract of RecordScan is index-alignment with the check set: a delta at index i is the
	// outcome for the check at index i. A shorter buffer folds fewer records and shifts nothing.
	checks := []*bcheck.Check{bcheckNamed("a"), bcheckNamed("b"), bcheckNamed("c")}
	tr := newCoverageTracker(checks)

	tr.RecordScan([]ScanDelta{{Findings: 0}, {Findings: 0}})

	rep := tr.Snapshot()
	if rep.Checks[0].Ran != 1 || rep.Checks[1].Ran != 1 {
		t.Errorf("first two checks did not fold their deltas: %+v", rep.Checks[:2])
	}
	if rep.Checks[2].State() != CoverageStateNeverDispatched {
		t.Errorf("third check state = %s, want never dispatched (no delta arrived for it)", rep.Checks[2].State())
	}
}

func Test_skips_are_counted_per_reason_and_named(t *testing.T) {
	tr := newCoverageTracker(nil)
	tr.RecordSkip(ScanSkipOutOfScope)
	tr.RecordSkip(ScanSkipOutOfScope)
	tr.RecordSkip(ScanSkipResponseNotFound)

	rep := tr.Snapshot()
	if len(rep.Skips) != len(ScanSkipAll) {
		t.Fatalf("snapshot has %d skip reasons, want %d", len(rep.Skips), len(ScanSkipAll))
	}
	byReason := map[string]uint64{}
	for _, s := range rep.Skips {
		if s.Reason == "" {
			t.Errorf("a skip count with an empty reason is not acceptable output")
		}
		byReason[s.Reason] = s.Count
	}
	if byReason["the host is outside the engagement scope"] != 2 {
		t.Errorf("out-of-scope count = %d, want 2", byReason["the host is outside the engagement scope"])
	}
	if byReason["the response id is not in the store"] != 1 {
		t.Errorf("response-not-found count = %d, want 1", byReason["the response id is not in the store"])
	}
}

func Test_snapshot_is_owned_and_later_writes_do_not_retroactively_edit_it(t *testing.T) {
	checks := []*bcheck.Check{bcheckNamed("a")}
	tr := newCoverageTracker(checks)

	first := tr.Snapshot()
	tr.RecordScan([]ScanDelta{{Findings: 1}})

	if first.Checks[0].Ran != 0 {
		t.Errorf("snapshot taken before the scan changed under us: %+v", first.Checks[0])
	}
	second := tr.Snapshot()
	if second.Checks[0].Ran != 1 {
		t.Errorf("snapshot taken after the scan did not observe it: %+v", second.Checks[0])
	}
}

func Test_scan_skip_slots_cover_every_variant_exactly_once(t *testing.T) {
	seen := make(map[int]bool)
	for _, s := range ScanSkipAll {
		sl := s.slot()
		if seen[sl] {
			t.Fatalf("slot %d assigned to more than one ScanSkip", sl)
		}
		seen[sl] = true
	}
	if len(seen) != len(ScanSkipAll) {
		t.Fatalf("slots cover %d variants, want %d (the mapping must be total)", len(seen), len(ScanSkipAll))
	}
}

func Test_the_four_partition_states_always_sum_to_the_number_of_loaded_checks(t *testing.T) {
	checks := []*bcheck.Check{bcheckNamed("a"), bcheckNamed("b"), bcheckNamed("c"), bcheckNamed("d")}
	tr := newCoverageTracker(checks)

	tr.RecordScan([]ScanDelta{{Findings: 0}, {Err: "boom"}, {Findings: 3}})

	sum := partitionSum(tr.Snapshot().Partition())
	if sum != 4 {
		t.Errorf("partition sums to %d, want 4", sum)
	}
}

func partitionSum(p [4]CoverageCount) int {
	sum := 0
	for _, c := range p {
		sum += c.Count
	}
	return sum
}
