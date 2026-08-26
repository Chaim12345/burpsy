package schedule

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Every test here drives Tick at an instant it chose. There is no time.Sleep and no fake-clock
// plumbing, because Tick takes the time as a parameter and Run is a thin loop over it — see the
// package docs on why. A test that slept would be asserting on the scheduler's timing *and* on the
// machine's, and the machine would eventually lose.

// at is a fixed wall-clock instant to build schedules around. A real date rather than the epoch: a
// bug that used a zero time would still look plausible against epoch-relative numbers.
var at = time.Date(2026, 8, 25, 2, 0, 0, 0, time.UTC)

// startedRunner returns a runner with one kind registered, and a pointer to the number of times that
// kind was started.
func startedRunner(t *testing.T, note string, err error) (*Runner, *[]Schedule) {
	t.Helper()
	var started []Schedule
	r := NewRunner()
	r.Register("crawl", func(ctx context.Context, s Schedule) (string, error) {
		started = append(started, s)
		return note, err
	})
	return r, &started
}

// A schedule fires when its time arrives, and not before.
func Test_a_schedule_fires_at_its_first_occurrence_and_not_before(t *testing.T) {
	r, started := startedRunner(t, "crawl task 1", nil)
	if err := r.Add(Schedule{
		Name: "nightly", Kind: "crawl", Enabled: true, FirstMs: at.UnixMilli(),
	}); err != nil {
		t.Fatalf("arming: %v", err)
	}

	if fired := r.Tick(at.Add(-time.Second)); len(fired) != 0 {
		t.Fatalf("a tick one second early acted on %d schedules: %+v", len(fired), fired)
	}
	if len(*started) != 0 {
		t.Fatal("the starter ran before the schedule's first occurrence")
	}

	fired := r.Tick(at)
	if len(fired) != 1 || !fired[0].Started {
		t.Fatalf("the tick at the first occurrence produced %+v, want one started entry", fired)
	}
	if len(*started) != 1 {
		t.Fatalf("the starter ran %d times, want 1", len(*started))
	}
	got, err := r.Get("nightly")
	if err != nil {
		t.Fatalf("reading the schedule back: %v", err)
	}
	if got.Runs != 1 || got.Failures != 0 || got.Missed != 0 {
		t.Errorf("after one clean firing the counters are runs=%d failures=%d missed=%d, want 1/0/0",
			got.Runs, got.Failures, got.Missed)
	}
	if got.NextMs != 0 {
		t.Errorf("a one-shot that has fired still has a next occurrence at %d", got.NextMs)
	}
}

// A one-shot fires once. A second tick past its time must not fire it again — the difference between
// "no next occurrence" and "due every time we look".
func Test_a_one_shot_fires_exactly_once(t *testing.T) {
	r, started := startedRunner(t, "", nil)
	if err := r.Add(Schedule{Name: "once", Kind: "crawl", Enabled: true, FirstMs: at.UnixMilli()}); err != nil {
		t.Fatalf("arming: %v", err)
	}
	r.Tick(at)
	r.Tick(at.Add(time.Hour))
	if len(*started) != 1 {
		t.Errorf("a one-shot started %d runs, want exactly 1", len(*started))
	}
}

// An interval schedule fires on each occurrence and re-arms for the next.
func Test_an_interval_schedule_re_arms(t *testing.T) {
	r, started := startedRunner(t, "", nil)
	if err := r.Add(Schedule{
		Name: "hourly", Kind: "crawl", Enabled: true,
		FirstMs: at.UnixMilli(), IntervalSecs: 3600,
	}); err != nil {
		t.Fatalf("arming: %v", err)
	}
	r.Tick(at)
	r.Tick(at.Add(time.Hour))
	r.Tick(at.Add(2 * time.Hour))
	if len(*started) != 3 {
		t.Fatalf("three occurrences started %d runs", len(*started))
	}
	got, _ := r.Get("hourly")
	if got.Runs != 3 {
		t.Errorf("runs is %d, want 3", got.Runs)
	}
	if got.NextMs != at.Add(3*time.Hour).UnixMilli() {
		t.Errorf("the next occurrence is %d, want %d", got.NextMs, at.Add(3*time.Hour).UnixMilli())
	}
}

// The missed-window decision, which is the whole reason this package documents a choice.
//
// A schedule armed for 02:00 that is first consulted at 09:30 — a process that was down all night —
// must not run: not once, and certainly not seven times. It counts what was missed and arms the next
// occurrence. Firing "now" would start an out-of-hours crawl in the middle of the working day it was
// scheduled to avoid, which is not a partial version of honouring the schedule.
func Test_an_occurrence_missed_while_nothing_was_running_does_not_fire_late(t *testing.T) {
	r, started := startedRunner(t, "", nil)
	if err := r.Add(Schedule{
		Name: "out of hours", Kind: "crawl", Enabled: true,
		FirstMs: at.UnixMilli(), IntervalSecs: 24 * 3600,
	}); err != nil {
		t.Fatalf("arming: %v", err)
	}

	// Seven nights and seven and a half hours later: the process has been down the whole time.
	fired := r.Tick(at.Add(7*24*time.Hour + 7*time.Hour + 30*time.Minute))
	if len(*started) != 0 {
		t.Fatalf("%d runs were started to catch up; a week of nightly crawls at once is a denial of "+
			"service dressed as catching up", len(*started))
	}
	if len(fired) != 1 {
		t.Fatalf("the tick reported %d decisions, want 1 — a missed window must be reported, never "+
			"silently dropped", len(fired))
	}
	if fired[0].Started {
		t.Error("the entry claims it started something")
	}
	if fired[0].Missed != 8 {
		t.Errorf("%d occurrences were counted as missed, want 8 (the first plus seven nights)", fired[0].Missed)
	}
	if fired[0].Note == "" {
		t.Error("a missed window produced no note, so an operator has no account of what happened")
	}

	got, _ := r.Get("out of hours")
	if got.Missed != 8 || got.Runs != 0 {
		t.Errorf("the schedule reads runs=%d missed=%d, want 0 and 8", got.Runs, got.Missed)
	}
	// Armed for the *next* real occurrence, not for a time in the past — otherwise the next tick
	// would write off another window immediately.
	if got.NextMs <= at.Add(7*24*time.Hour+7*time.Hour+30*time.Minute).UnixMilli() {
		t.Errorf("the next occurrence is %d, which is not in the future of the tick that re-armed it",
			got.NextMs)
	}
	_, _, missed, _ := r.Totals()
	if missed != 8 {
		t.Errorf("the runner's own missed total is %d, want 8", missed)
	}
}

// Within the grace window a late occurrence does fire, because a busy tick or a slow start must not
// turn a scheduled run into a missed one.
func Test_an_occurrence_within_the_grace_window_still_fires(t *testing.T) {
	r, started := startedRunner(t, "", nil)
	r.WithGrace(time.Minute)
	if err := r.Add(Schedule{Name: "n", Kind: "crawl", Enabled: true, FirstMs: at.UnixMilli()}); err != nil {
		t.Fatalf("arming: %v", err)
	}
	fired := r.Tick(at.Add(30 * time.Second))
	if len(*started) != 1 {
		t.Fatalf("a run 30s inside a 60s grace window did not fire: %+v", fired)
	}
	if fired[0].Missed != 0 {
		t.Errorf("a firing inside the grace window counted %d missed occurrences", fired[0].Missed)
	}
}

// A restart is not a special case: a schedule restored with a NextMs in the past goes through exactly
// the same rule as any other late occurrence. One rule, one implementation.
func Test_a_restored_schedule_meets_the_same_missed_window_rule(t *testing.T) {
	r, started := startedRunner(t, "", nil)
	// Persisted mid-life: it has run four times, missed one, and is armed for a time now well past.
	refused := r.Restore([]Schedule{{
		Name: "nightly", Kind: "crawl", Enabled: true,
		FirstMs: at.UnixMilli(), IntervalSecs: 24 * 3600,
		NextMs: at.Add(24 * time.Hour).UnixMilli(),
		Runs:   4, Failures: 1, Missed: 1, LastRunMs: at.UnixMilli(),
	}})
	if len(refused) != 0 {
		t.Fatalf("a valid persisted schedule was refused on load: %v", refused)
	}
	got, err := r.Get("nightly")
	if err != nil {
		t.Fatalf("the restored schedule is not there: %v", err)
	}
	// The counters are the record of what this schedule has done. A restart that reset them would
	// erase the evidence that it has been failing.
	if got.Runs != 4 || got.Failures != 1 || got.Missed != 1 {
		t.Errorf("restored counters are runs=%d failures=%d missed=%d, want 4/1/1",
			got.Runs, got.Failures, got.Missed)
	}

	// 79.5 hours on: the occurrence at +72h is the most recent due one and is 7.5 hours late, well
	// past the grace window. Deliberately not a whole multiple of the interval — a tick landing exactly
	// on an occurrence is on time, not late, and asserting "did not fire" at such an instant would be
	// asserting the opposite of the rule.
	r.Tick(at.Add(79*time.Hour + 30*time.Minute))
	if len(*started) != 0 {
		t.Error("a restored schedule whose window had passed fired late, which the startup path must " +
			"not do any more than the steady-state path does")
	}
	got, _ = r.Get("nightly")
	if got.Missed <= 1 {
		t.Errorf("missed is %d; the windows passed while the process was down were not counted onto "+
			"the restored total", got.Missed)
	}
}

// A starter that fails still counts as a run, and also counts as a failure. Both numbers, because
// "it fired" and "it worked" are different facts — this is what the fifth argument to record is for.
func Test_a_failed_start_counts_as_both_a_run_and_a_failure(t *testing.T) {
	r, _ := startedRunner(t, "", errors.New("the target refused the connection"))
	if err := r.Add(Schedule{
		Name: "nightly", Kind: "crawl", Enabled: true, FirstMs: at.UnixMilli(), IntervalSecs: 3600,
	}); err != nil {
		t.Fatalf("arming: %v", err)
	}
	r.Tick(at)
	r.Tick(at.Add(time.Hour))

	got, _ := r.Get("nightly")
	if got.Runs != 2 {
		t.Errorf("runs is %d, want 2: a start that returned an error still happened, and calling it "+
			"zero runs would make a schedule failing every night look like one that never fired", got.Runs)
	}
	if got.Failures != 2 {
		t.Errorf("failures is %d, want 2", got.Failures)
	}
	if got.LastNote == "" {
		t.Error("the failure left no note, so an operator cannot see why it failed")
	}
	fired, failed, _, unstarted := r.Totals()
	if fired != 2 || failed != 2 {
		t.Errorf("the runner's totals are fired=%d failed=%d, want 2 and 2", fired, failed)
	}
	if unstarted != 0 {
		t.Errorf("unstarted is %d; a kind that ran and failed is not a kind nothing could start", unstarted)
	}
}

// An occurrence due for a kind nothing in this build can start is a third outcome, counted apart
// from both a run and a failure: a different fault with a different fix.
func Test_an_unstartable_kind_is_counted_apart_from_a_failure(t *testing.T) {
	r, _ := startedRunner(t, "", nil)
	// Restore rather than Add, because Add refuses an unregistered kind outright — which is the point:
	// this state is only reachable from a database written by a build that had the capability.
	r.Restore([]Schedule{{
		Name: "audit nightly", Kind: "audit", Enabled: true,
		FirstMs: at.UnixMilli(), NextMs: at.UnixMilli(),
	}})
	fired := r.Tick(at)
	if len(fired) != 1 {
		t.Fatalf("the tick reported %d decisions, want 1", len(fired))
	}
	if fired[0].Started {
		t.Error("an occurrence with no registered starter claims to have started")
	}
	if fired[0].Err == "" {
		t.Error("an occurrence nothing could start reported no error")
	}
	f, failed, _, unstarted := r.Totals()
	if unstarted != 1 {
		t.Errorf("unstarted is %d, want 1", unstarted)
	}
	if f != 0 || failed != 0 {
		t.Errorf("fired=%d failed=%d; an occurrence that never ran is neither", f, failed)
	}
	got, _ := r.Get("audit nightly")
	if got.Runs != 0 {
		t.Errorf("runs is %d; nothing ran", got.Runs)
	}
}

// A disabled schedule is kept and does not fire. Distinct from deleting it, and distinct from one
// whose occurrence has passed.
func Test_a_disabled_schedule_does_not_fire(t *testing.T) {
	r, started := startedRunner(t, "", nil)
	if err := r.Add(Schedule{Name: "n", Kind: "crawl", FirstMs: at.UnixMilli()}); err != nil {
		t.Fatalf("arming: %v", err)
	}
	r.Tick(at.Add(time.Hour))
	if len(*started) != 0 {
		t.Error("a disabled schedule fired")
	}
	if r.Len() != 1 {
		t.Error("a disabled schedule was not kept")
	}
}

// A kind this build cannot start is refused at save time, so an operator cannot arm something that
// would fail at 02:00.
func Test_an_unregistered_kind_is_refused_at_save_time(t *testing.T) {
	r, _ := startedRunner(t, "", nil)
	err := r.Add(Schedule{Name: "n", Kind: "teleport", Enabled: true, FirstMs: at.UnixMilli()})
	if err == nil {
		t.Fatal("a schedule naming a kind nothing can start was accepted")
	}
	// The message must say what this build *can* start, or the operator is left guessing.
	if !strings.Contains(err.Error(), "crawl") {
		t.Errorf("the refusal (%q) does not name the kinds that are available", err)
	}
}

// An edit re-arms the timing and keeps the counters. Both halves matter: an un-re-armed schedule
// fires at the old time, and a reset counter erases the record of a schedule that has been failing.
func Test_an_edit_re_arms_the_timing_and_keeps_the_counters(t *testing.T) {
	r, _ := startedRunner(t, "", nil)
	if err := r.Add(Schedule{
		Name: "n", Kind: "crawl", Enabled: true, FirstMs: at.UnixMilli(), IntervalSecs: 3600,
	}); err != nil {
		t.Fatalf("arming: %v", err)
	}
	r.Tick(at)

	moved := at.Add(48 * time.Hour)
	if err := r.Update("n", Schedule{
		Name: "n", Kind: "crawl", Enabled: true, FirstMs: moved.UnixMilli(), IntervalSecs: 3600,
	}); err != nil {
		t.Fatalf("editing: %v", err)
	}
	got, _ := r.Get("n")
	if got.NextMs != moved.UnixMilli() {
		t.Errorf("after an edit that moved the first occurrence, the next occurrence is %d, want %d — "+
			"an un-re-armed schedule fires at the old time", got.NextMs, moved.UnixMilli())
	}
	if got.Runs != 1 {
		t.Errorf("runs is %d after an edit, want the 1 it had: an edit is not a reset", got.Runs)
	}
}

// An interval too short to be a schedule is refused: at that rate it is a loop, and a run that
// outlasts its own interval would overlap itself.
func Test_an_interval_shorter_than_the_minimum_is_refused(t *testing.T) {
	if err := (Schedule{
		Name: "n", Kind: "crawl", FirstMs: at.UnixMilli(), IntervalSecs: 1,
	}).Validate(); err == nil {
		t.Fatal("a one-second interval was accepted")
	}
}

// A schedule with no first occurrence is refused rather than defaulted to now, which would fire the
// moment it was saved.
func Test_a_schedule_needs_a_first_occurrence(t *testing.T) {
	if err := (Schedule{Name: "n", Kind: "crawl"}).Validate(); err == nil {
		t.Fatal("a schedule with no first occurrence was accepted")
	}
}

// Params are opaque here and must survive untouched, because this package cannot know what a crawl's
// or an audit's configuration looks like.
func Test_params_are_carried_to_the_starter_unchanged(t *testing.T) {
	var seen json.RawMessage
	r := NewRunner()
	r.Register("crawl", func(ctx context.Context, s Schedule) (string, error) {
		seen = s.Params
		return "", nil
	})
	params := json.RawMessage(`{"seeds":["https://example.test/"],"max_depth":3}`)
	if err := r.Add(Schedule{
		Name: "n", Kind: "crawl", Enabled: true, FirstMs: at.UnixMilli(), Params: params,
	}); err != nil {
		t.Fatalf("arming: %v", err)
	}
	r.Tick(at)
	if string(seen) != string(params) {
		t.Errorf("the starter saw params %s, want %s", seen, params)
	}
}

// A pool a schedule references is reported, which is what lets a delete be refused rather than
// leaving a scheduled run to fall back to bounds nobody chose.
func Test_schedules_report_the_pool_they_reference(t *testing.T) {
	r, _ := startedRunner(t, "", nil)
	for _, name := range []string{"a", "b"} {
		if err := r.Add(Schedule{
			Name: name, Kind: "crawl", Enabled: true, FirstMs: at.UnixMilli(), Pool: "Out Of Hours",
		}); err != nil {
			t.Fatalf("arming %s: %v", name, err)
		}
	}
	if err := r.Add(Schedule{
		Name: "c", Kind: "crawl", Enabled: true, FirstMs: at.UnixMilli(),
	}); err != nil {
		t.Fatalf("arming c: %v", err)
	}
	// Case-insensitively, matching how the pool registry keys names: an operator who typed one casing
	// meaning the other must not be able to delete the pool out from under these.
	used := r.UsingPool("out of hours")
	if len(used) != 2 {
		t.Errorf("%d schedules reference the pool, want 2: %v", len(used), used)
	}
	if len(r.UsingPool("never used")) != 0 {
		t.Error("a pool nothing references reported users")
	}
}

// Run is a thin loop over Tick and must stop when its context does. Asserted by cancelling first, so
// no sleep decides the verdict.
func Test_run_returns_when_its_context_ends(t *testing.T) {
	r, _ := startedRunner(t, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		r.Run(ctx, time.Hour)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}
