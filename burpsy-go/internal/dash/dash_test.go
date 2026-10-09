package dash

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ---- DASH-03: a count cannot be read without its breakdown --------------------------------------

// The zero value must still emit all four buckets. This is the easiest thing in the whole feature to
// get wrong — an omitempty on each field is the obvious way to write the struct, and it would make
// every caveat disappear from the wire exactly when it is zero, which is precisely when a UI would
// stop rendering it and start showing bare numbers again.
func TestBreakdownZeroValueStillEmitsEveryBucket(t *testing.T) {
	raw, err := json.Marshal(Breakdown{})
	if err != nil {
		t.Fatalf("marshal zero breakdown: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	for _, key := range []string{"found", "skipped", "errored", "gated", "unaccounted", "complete", "summary"} {
		if _, ok := got[key]; !ok {
			t.Errorf("zero breakdown is missing %q; wire was %s", key, raw)
		}
	}
}

// The derived fields are derived, never taken from the caller: a hand-written total that disagreed
// with its parts would be worse than no total at all.
func TestBreakdownDerivedFieldsFollowTheBuckets(t *testing.T) {
	b := Breakdown{Found: 12, Skipped: 3, Errored: 1, Gated: 2}
	if b.Unaccounted() != 6 {
		t.Errorf("unaccounted = %d, want 6", b.Unaccounted())
	}
	if b.Complete() {
		t.Error("complete with 6 unaccounted units of work")
	}
	if !(Breakdown{Found: 12}).Complete() {
		t.Error("a count with no caveats reports incomplete")
	}
	// Zero found and zero caveats is "looked everywhere, found nothing" — a complete answer, and the
	// one place where a zero must not read as a gap.
	if !(Breakdown{}).Complete() {
		t.Error("the zero breakdown reports incomplete; found nothing having looked everywhere is a complete answer")
	}
}

// The summary line names every non-zero caveat. The whole breakdown is lost if its human-readable
// form collapses back to the found count.
func TestBreakdownSummaryNamesEveryNonZeroCaveat(t *testing.T) {
	line := Breakdown{Found: 12, Skipped: 3, Errored: 1, Gated: 2}.Summary()
	for _, want := range []string{"12", "3 skipped", "1 errored", "2 gated", "floor"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary %q does not mention %q", line, want)
		}
	}
	clean := Breakdown{Found: 4}.Summary()
	if strings.Contains(clean, "floor") {
		t.Errorf("a complete count reads as a floor: %q", clean)
	}
}

// The custom marshaller needs its unmarshaller, or anything that round-trips a summary decodes to a
// zero value — which would silently claim every caveat was clear.
func TestBreakdownRoundTripsThroughJSON(t *testing.T) {
	want := Breakdown{Found: 7, Skipped: 2, Errored: 5, Gated: 1}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Breakdown
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	if got != want {
		t.Errorf("round trip gave %+v, want %+v", got, want)
	}
}

// Get must distinguish an unknown bucket from a zero one, so a renamed bucket surfaces as unknown
// rather than as empty.
func TestBreakdownGetSeparatesUnknownFromZero(t *testing.T) {
	b := Breakdown{Skipped: 4}
	if n, ok := b.Get(BucketFound); !ok || n != 0 {
		t.Errorf("Get(found) = %d, %v; want 0, true", n, ok)
	}
	if n, ok := b.Get(BucketSkipped); !ok || n != 4 {
		t.Errorf("Get(skipped) = %d, %v; want 4, true", n, ok)
	}
	if _, ok := b.Get(Bucket("invented")); ok {
		t.Error("Get reported an unknown bucket as known")
	}
}

// A caveat must never travel nameless. A projection that forgot its reasons produces a visibly
// unattributed one, so the missing projection is a bug report rather than a silent gap.
func TestSummaryNeverCarriesANamelessCaveat(t *testing.T) {
	s := NewSummary("Issues", "issues", "checks", Breakdown{Found: 12, Gated: 3})
	if len(s.Reasons) != 1 {
		t.Fatalf("reasons = %+v, want one synthesised reason", s.Reasons)
	}
	if s.Reasons[0].Count != 3 {
		t.Errorf("synthesised reason count = %d, want the whole 3-unit shortfall", s.Reasons[0].Count)
	}
	if !strings.Contains(s.Reasons[0].Detail, "unattributed") {
		t.Errorf("synthesised reason %q does not name itself unattributed", s.Reasons[0].Detail)
	}
}

// Zero-count reasons are dropped: a reason that explains nothing is noise next to the ones that do.
func TestSummaryDropsReasonsThatExplainNothing(t *testing.T) {
	s := NewSummary("Issues", "issues", "checks", Breakdown{Found: 1, Skipped: 2},
		Reason{Bucket: BucketSkipped, Detail: "real", Count: 2},
		Reason{Bucket: BucketErrored, Detail: "never happened", Count: 0},
	)
	if len(s.Reasons) != 1 || s.Reasons[0].Detail != "real" {
		t.Errorf("reasons = %+v, want only the one with a non-zero count", s.Reasons)
	}
}

// A complete count with no reasons stays reasonless — nothing is synthesised where there is nothing
// to explain.
func TestSummaryOnACompleteCountHasNoReasons(t *testing.T) {
	if s := NewSummary("Issues", "issues", "checks", Breakdown{Found: 12}); len(s.Reasons) != 0 {
		t.Errorf("reasons = %+v, want none for a complete count", s.Reasons)
	}
}

// ---- DASH-01: the task registry -----------------------------------------------------------------

func TestRegistryReportsRunningWorkWithItsProgress(t *testing.T) {
	r := NewRegistry()
	h := r.Start(KindCrawl, "https://shop.test/", 10)
	h.Advance(3)
	h.Advance(1)
	h.SetNote("frontier still growing")

	tasks := r.Snapshot()
	if len(tasks) != 1 {
		t.Fatalf("tasks = %d, want 1", len(tasks))
	}
	got := tasks[0]
	if got.Kind != KindCrawl || got.Target != "https://shop.test/" {
		t.Errorf("task = %+v, want the crawl as registered", got)
	}
	if !got.Running() || got.EndedMs != 0 {
		t.Errorf("state = %v, ended_ms = %d; want running and unended", got.State, got.EndedMs)
	}
	if got.Done != 4 {
		t.Errorf("done = %d, want 4 after advancing 3 then 1", got.Done)
	}
	if f, known := got.Fraction(); !known || f < 0.39 || f > 0.41 {
		t.Errorf("fraction = %v (known %v), want ~0.4", f, known)
	}
	if got.Note != "frontier still growing" {
		t.Errorf("note = %q", got.Note)
	}
	if r.Running() != 1 {
		t.Errorf("running = %d, want 1", r.Running())
	}
}

// An unknown total is unknown, not zero. A crawl whose frontier grows as it is walked would otherwise
// render as a progress bar pinned at 0% — indistinguishable from a stalled one.
func TestTaskWithNoTotalReportsAnUnknownFraction(t *testing.T) {
	r := NewRegistry()
	h := r.Start(KindCrawl, "https://shop.test/", 0)
	h.Advance(9)

	got := r.Snapshot()[0]
	if _, known := got.Fraction(); known {
		t.Error("fraction reported as known with no total")
	}
	if !strings.Contains(got.ProgressLabel(), "not yet known") {
		t.Errorf("progress label %q does not say the total is unknown", got.ProgressLabel())
	}
	h.SetTotal(20)
	if f, known := r.Snapshot()[0].Fraction(); !known || f < 0.44 || f > 0.46 {
		t.Errorf("after SetTotal(20): fraction = %v (known %v), want ~0.45", f, known)
	}
}

// A task can be done without being complete. This is the whole distinction the dashboard exists to
// make, at the level of one task.
func TestTaskFinishedWithABoundedResultIsDoneButNotComplete(t *testing.T) {
	r := NewRegistry()

	clean := r.Start(KindAudit, "a", 2)
	clean.Advance(2)
	clean.Finish(Breakdown{Found: 1})

	bounded := r.Start(KindAudit, "b", 2)
	bounded.Advance(2)
	bounded.Finish(Breakdown{Found: 1, Gated: 40})

	shortOfTotal := r.Start(KindAudit, "c", 10)
	shortOfTotal.Advance(2)
	shortOfTotal.Finish(Breakdown{Found: 1})

	byTarget := map[string]Task{}
	for _, task := range r.Snapshot() {
		byTarget[task.Target] = task
	}
	if !byTarget["a"].Complete() {
		t.Error("a task that ran everything it was given and found something reports incomplete")
	}
	if byTarget["b"].Complete() {
		t.Error("a task with 40 gated units reports complete; a bound is not a clean result")
	}
	if byTarget["c"].Complete() {
		t.Error("a task that finished 2 of 10 reports complete")
	}
	for target, task := range byTarget {
		if task.State != TaskDone {
			t.Errorf("task %q state = %v, want done", target, task.State)
		}
	}
}

// The first terminal answer wins. A late Finish overwriting an earlier Fail would erase the failure,
// which is the one direction this must never round in.
func TestFirstTerminalStateWins(t *testing.T) {
	r := NewRegistry()
	h := r.Start(KindIntruder, "shop.test", 5)
	h.Fail(errors.New("connection refused"))
	h.Finish(Breakdown{Found: 99})

	got := r.Snapshot()[0]
	if got.State != TaskFailed {
		t.Errorf("state = %v, want failed: the first terminal answer is the true one", got.State)
	}
	if got.Result.Found != 0 {
		t.Errorf("result found = %d, want 0; the late Finish must not have applied", got.Result.Found)
	}
	if !strings.Contains(got.Note, "connection refused") {
		t.Errorf("note = %q, want the failure reason", got.Note)
	}
}

// Eviction never takes a running task, however full the table. A registry that dropped live work to
// make room for finished work would answer "what is running?" with silence.
func TestRegistryNeverEvictsARunningTask(t *testing.T) {
	r := NewRegistry().WithCapacity(3)

	live := r.Start(KindCrawl, "live", 0)
	for i := 0; i < 10; i++ {
		h := r.Start(KindAudit, "finished", 1)
		h.Advance(1)
		h.Finish(Breakdown{})
	}
	_ = live

	tasks := r.Snapshot()
	if len(tasks) > 3 {
		t.Errorf("tasks = %d, want no more than the capacity of 3", len(tasks))
	}
	foundLive := false
	for _, task := range tasks {
		if task.Target == "live" {
			foundLive = true
		}
	}
	if !foundLive {
		t.Error("the running task was evicted to make room for finished ones")
	}
	if r.Dropped() == 0 {
		t.Error("dropped = 0 after evicting; a bounded window must say what it dropped")
	}
}

// A table entirely full of running work overshoots capacity rather than trimming. An honest overshoot
// beats a dishonest trim, and dropped stays at zero because nothing was dropped.
func TestRegistryOvershootsCapacityRatherThanDropLiveWork(t *testing.T) {
	r := NewRegistry().WithCapacity(2)
	for i := 0; i < 5; i++ {
		r.Start(KindCrawl, "live", 0)
	}
	if n := len(r.Snapshot()); n != 5 {
		t.Errorf("tasks = %d, want all 5 running tasks kept", n)
	}
	if r.Dropped() != 0 {
		t.Errorf("dropped = %d, want 0: nothing was dropped", r.Dropped())
	}
}

// The registry's own count follows the same rules it enforces on everything else: running work is not
// a result, and a bounded finish is not a clean one.
func TestRegistryBreakdownCountsRunningWorkAsUnaccounted(t *testing.T) {
	r := NewRegistry()
	r.Start(KindCrawl, "running", 0)

	done := r.Start(KindAudit, "done", 1)
	done.Advance(1)
	done.Finish(Breakdown{Found: 1})

	bounded := r.Start(KindAudit, "bounded", 1)
	bounded.Advance(1)
	bounded.Finish(Breakdown{Gated: 3})

	failed := r.Start(KindAudit, "failed", 1)
	failed.Fail(errors.New("nope"))

	b := r.Breakdown()
	if b.Found != 1 || b.Skipped != 1 || b.Errored != 1 || b.Gated != 1 {
		t.Errorf("breakdown = %+v, want found 1 skipped 1 errored 1 gated 1", b)
	}
	if b.Complete() {
		t.Error("a registry with a running, a bounded and a failed task reports a complete count")
	}
	if len(r.Reasons()) != 3 {
		t.Errorf("reasons = %+v, want one per non-zero caveat bucket", r.Reasons())
	}
}

// A nil registry hands out a nil handle, and every method on it is a working no-op. Callers register
// work unconditionally; a nil check someone forgets is a panic in the middle of an audit.
func TestNilRegistryAndHandleAreWorkingNoOps(t *testing.T) {
	var r *Registry
	h := r.Start(KindAudit, "nowhere", 3)
	if h != nil {
		t.Fatalf("nil registry returned %+v, want a nil handle", h)
	}
	// None of these may panic.
	h.Advance(1)
	h.SetTotal(9)
	h.SetNote("still fine")
	h.Finish(Breakdown{Found: 1})
	h.Stop(Breakdown{}, "stopped")
	h.Fail(errors.New("failed"))
	if h.ID() != 0 {
		t.Errorf("nil handle ID = %d, want 0", h.ID())
	}
	if r.Snapshot() != nil || r.Running() != 0 || r.Dropped() != 0 {
		t.Error("a nil registry reported state")
	}
	if !r.Breakdown().Complete() {
		t.Error("a nil registry's breakdown is not the empty one")
	}
}

// The wire shape carries the derived progress, so the UI never recomputes completeness and never has
// the chance to compute it differently from Go.
func TestTaskJSONCarriesItsDerivedProgress(t *testing.T) {
	r := NewRegistry()
	h := r.Start(KindLiveAudit, "shop.test (200 exchange(s))", 200)
	h.Advance(50)

	raw, err := json.Marshal(r.Snapshot()[0])
	if err != nil {
		t.Fatalf("marshal task: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	for _, key := range []string{"id", "kind", "target", "state", "done", "total", "started_ms",
		"result", "elapsed_ms", "fraction", "fraction_known", "progress", "complete"} {
		if _, ok := got[key]; !ok {
			t.Errorf("task JSON missing %q; wire was %s", key, raw)
		}
	}
	// The state marshals as its name, not its ordinal — an integer state would be unreadable in the
	// UI and would silently shift if the constants were reordered.
	if string(got["state"]) != `"running"` {
		t.Errorf("state marshalled as %s, want \"running\"", got["state"])
	}
}

// FailWith keeps the counts a run produced before it broke (burpsy-react-ui-wlz8): a failed run that
// had found things must not read as found 0, and a result that would claim completeness is marked
// as not the whole answer.
func TestFailWithKeepsTheBreakdownAndNeverReadsComplete(t *testing.T) {
	r := NewRegistry()
	h := r.Start(KindHiddenInputs, "shop.test", 500)
	h.FailWith(Breakdown{Found: 2, Gated: 40}, errors.New("refused by scope"))
	got := r.Snapshot()[0]
	if got.State != TaskFailed || got.Result.Found != 2 || got.Result.Gated != 40 || got.Result.Errored != 0 {
		t.Errorf("task = %+v; want failed with found 2 and gated 40 kept", got)
	}
	h2 := r.Start(KindHiddenInputs, "shop.test", 500)
	h2.FailWith(Breakdown{Found: 1}, errors.New("boom"))
	if res := r.Snapshot()[0].Result; res.Complete() || res.Errored != 1 {
		t.Errorf("result %+v reads complete; a failed run is never the whole answer", res)
	}
}
