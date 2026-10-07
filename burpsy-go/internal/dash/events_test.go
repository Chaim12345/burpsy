package dash

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---- DASH-02: the event log ---------------------------------------------------------------------

// Newest first, because that is the order the dashboard reads them, and bounded by the requested n.
func TestEventLogRecentReturnsNewestFirst(t *testing.T) {
	l := NewEventLog()
	l.Record(EventScopeChanged, SeverityInfo, "first")
	l.Record(EventLiveAuditEnabled, SeverityInfo, "second")
	l.Record(EventCrawlBounded, SeverityWarn, "third")

	got := l.Recent(2)
	if len(got) != 2 {
		t.Fatalf("Recent(2) returned %d events, want 2", len(got))
	}
	if got[0].Detail != "third" || got[1].Detail != "second" {
		t.Errorf("Recent(2) = %q, %q; want third, second", got[0].Detail, got[1].Detail)
	}
	if all := l.Recent(0); len(all) != 3 {
		t.Errorf("Recent(0) returned %d, want all 3", len(all))
	}
	// Ids are unique and ascending, so a caller can dedupe across polls.
	if got[0].ID <= got[1].ID {
		t.Errorf("ids %d, %d are not descending in a newest-first list", got[0].ID, got[1].ID)
	}
}

// The bound is real and what it drops is counted. A window presented as the whole history is the
// failure this counter exists to prevent.
func TestEventLogBoundIsReportedNotSilent(t *testing.T) {
	l := NewEventLog().WithCapacity(3)
	for i := 0; i < 10; i++ {
		l.Record(EventCrawlRefused, SeverityWarn, "refused")
	}
	if l.Count() != 3 {
		t.Errorf("count = %d, want the capacity of 3", l.Count())
	}
	if l.Dropped() != 7 {
		t.Errorf("dropped = %d, want 7", l.Dropped())
	}
}

// A task id travels with the event when there is one, and is absent — not a made-up zero task — when
// there is not.
func TestEventLogCarriesATaskIDOnlyWhenItHasOne(t *testing.T) {
	l := NewEventLog()
	l.RecordFor(42, EventTaskFinished, SeverityInfo, "done")
	l.Record(EventScopeChanged, SeverityInfo, "edited")

	got := l.Recent(0)
	if got[0].TaskID != 0 {
		t.Errorf("a scope edit carries task id %d, want none", got[0].TaskID)
	}
	if got[1].TaskID != 42 {
		t.Errorf("task event carries task id %d, want 42", got[1].TaskID)
	}
}

// Severity marshals as its name and reads back as the same severity. Without the unmarshaller a
// persisted or replayed warning would decode to info — a downgrade nobody would notice.
func TestSeverityRoundTripsAndUnknownIsNotInfo(t *testing.T) {
	for _, want := range SeverityAll {
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal %v: %v", want, err)
		}
		if string(raw) != `"`+want.String()+`"` {
			t.Errorf("severity %v marshalled as %s, want its name", want, raw)
		}
		var got Severity
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", raw, err)
		}
		if got != want {
			t.Errorf("round trip of %v gave %v", want, got)
		}
	}
	var unknown Severity
	if err := json.Unmarshal([]byte(`"catastrophe"`), &unknown); err != nil {
		t.Fatalf("unmarshal unknown severity: %v", err)
	}
	if unknown == SeverityInfo {
		t.Error("an unrecognised severity decoded to info; an unknown level must not be quietly downgraded to the least interesting one")
	}
}

// Restore replaces the log and keeps ids unique above whatever was restored.
func TestEventLogRestoreResumesIDsAboveTheSnapshot(t *testing.T) {
	l := NewEventLog()
	l.Restore([]Event{
		{ID: 7, Kind: EventScopeChanged, Severity: SeverityInfo, Detail: "old"},
		{ID: 9, Kind: EventCrawlBounded, Severity: SeverityWarn, Detail: "older bound"},
	})
	if l.Count() != 2 {
		t.Fatalf("count after restore = %d, want 2", l.Count())
	}
	id := l.Record(EventLiveAuditEnabled, SeverityInfo, "new")
	if id <= 9 {
		t.Errorf("post-restore id = %d, want it above the highest restored id (9)", id)
	}
}

// A nil log is a working no-op, so callers record events unconditionally.
func TestNilEventLogIsAWorkingNoOp(t *testing.T) {
	var l *EventLog
	if id := l.Record(EventScopeChanged, SeverityInfo, "nowhere"); id != 0 {
		t.Errorf("nil log returned id %d, want 0", id)
	}
	l.RecordFor(1, EventTaskStarted, SeverityInfo, "nowhere")
	l.Restore([]Event{{ID: 1}})
	if l.Recent(5) != nil || l.Count() != 0 || l.Dropped() != 0 || l.WithCapacity(3) != nil {
		t.Error("a nil log reported state")
	}
}

// Clearing the log empties the window an operator reads and resets the bound counter with it: after
// a deliberate discard there is no window for "N dropped" to qualify. The signal fires so a clear in
// one browser reaches the others through the live stream.
func TestClearEmptiesTheLogResetsDroppedAndSignalsOnce(t *testing.T) {
	l := NewEventLog().WithCapacity(3)
	for i := 0; i < 10; i++ {
		l.Record(EventCrawlRefused, SeverityWarn, "refused")
	}
	if l.Count() != 3 || l.Dropped() != 7 {
		t.Fatalf("before clear: count/dropped = %d/%d, want 3/7", l.Count(), l.Dropped())
	}

	var signals int
	l.OnChange(func() { signals++ })
	l.Clear()

	if l.Count() != 0 {
		t.Errorf("count after clear = %d, want 0", l.Count())
	}
	if l.Dropped() != 0 {
		t.Errorf("dropped after clear = %d, want 0 — a discarded window has no bound to report", l.Dropped())
	}
	if signals != 1 {
		t.Errorf("onChange fired %d times, want exactly 1 so the live stream refetches once", signals)
	}

	// The cleared window marshals as an empty array, never JSON null: the TS Dashboard.events type is
	// a non-nullable array, and a nil slice would cross the wire as null and break it. Recent uses
	// make([]Event, 0, n), so this asserts the marshalled bytes rather than trusting the slice.
	raw, err := json.Marshal(l.Recent(0))
	if err != nil {
		t.Fatalf("marshal Recent(0) after clear: %v", err)
	}
	if string(raw) != "[]" {
		t.Errorf("Recent(0) after clear marshals to %s, want []", raw)
	}

	// Ids stay unique across the clear: the next event is not id 1 again.
	if id := l.Record(EventScopeChanged, SeverityInfo, "after clear"); id != 11 {
		t.Errorf("first id after clearing 10 events = %d, want 11 (ids do not reset)", id)
	}
}

// A nil log clears without panicking, so a caller wired to the "Clear event log" action never has to
// guard the receiver — the same contract every other method keeps.
func TestClearOnNilLogIsANoOp(t *testing.T) {
	var l *EventLog
	l.Clear()
}

// ---- the registry's lifecycle events ------------------------------------------------------------

// One wiring call must give every task start and finish events, so a crawl registered from a package
// that knows nothing about the event log still appears in it.
func TestRegistryEmitsTaskLifecycleEvents(t *testing.T) {
	log := NewEventLog()
	r := NewRegistry().WithEvents(log)

	h := r.Start(KindCrawl, "https://shop.test/", 3)
	h.Advance(3)
	h.Finish(Breakdown{Found: 2})

	events := log.Recent(0)
	if len(events) != 2 {
		t.Fatalf("events = %+v, want a started and a finished", events)
	}
	if events[1].Kind != EventTaskStarted || events[0].Kind != EventTaskFinished {
		t.Errorf("kinds = %q then %q, want started then finished", events[1].Kind, events[0].Kind)
	}
	for _, e := range events {
		if e.TaskID != h.ID() {
			t.Errorf("event %q carries task id %d, want %d", e.Kind, e.TaskID, h.ID())
		}
		if !strings.Contains(e.Detail, "crawl") {
			t.Errorf("event detail %q does not name the kind", e.Detail)
		}
	}
	if events[0].Severity != SeverityInfo {
		t.Errorf("a complete run finished at severity %v, want info", events[0].Severity)
	}
}

// A run that did not cover what it was given finishes as a warning, so a bound does not scroll past at
// the same weight as a clean result.
func TestRegistryGradesAnIncompleteFinishAsAWarning(t *testing.T) {
	log := NewEventLog()
	r := NewRegistry().WithEvents(log)

	bounded := r.Start(KindCrawl, "bounded", 10)
	bounded.Advance(4)
	bounded.FinishWithNote(Breakdown{Found: 1, Gated: 600}, "the frontier bound stopped it")

	failed := r.Start(KindIntruder, "failed", 1)
	failed.Fail(errUnreachable{})

	bySeverity := map[Severity]int{}
	for _, e := range log.Recent(0) {
		if e.Kind == EventTaskFinished {
			bySeverity[e.Severity]++
		}
	}
	if bySeverity[SeverityWarn] != 1 {
		t.Errorf("warn-level finishes = %d, want 1 for the bounded run", bySeverity[SeverityWarn])
	}
	if bySeverity[SeverityError] != 1 {
		t.Errorf("error-level finishes = %d, want 1 for the failed run", bySeverity[SeverityError])
	}
	// The note must reach the event: a bounded run whose reason stayed on the task and never on the
	// log would be a warning with nothing actionable in it.
	found := false
	for _, e := range log.Recent(0) {
		if strings.Contains(e.Detail, "frontier bound") {
			found = true
		}
	}
	if !found {
		t.Error("the bounded run's note did not reach its finished event")
	}
}

type errUnreachable struct{}

func (errUnreachable) Error() string { return "host unreachable" }

// A late Finish over an earlier Fail changes neither the task nor the log — the two cannot disagree
// about how a run ended.
func TestNoSecondFinishedEventForAnAlreadyTerminalTask(t *testing.T) {
	log := NewEventLog()
	r := NewRegistry().WithEvents(log)

	h := r.Start(KindAudit, "a", 1)
	h.Fail(errUnreachable{})
	h.Finish(Breakdown{Found: 99})

	finished := 0
	for _, e := range log.Recent(0) {
		if e.Kind == EventTaskFinished {
			finished++
		}
	}
	if finished != 1 {
		t.Errorf("finished events = %d, want exactly 1", finished)
	}
}

// ---- DASH-01: restore (#5) ----------------------------------------------------------------------

// A task that was running when the snapshot was taken comes back stopped, with a note. Never absent —
// the dashboard would show nothing where a crawl was — and never done, which would report a run that
// covered an unknown fraction of its target as having finished it.
func TestRestoreBringsBackARunningTaskAsStoppedNotDoneAndNotAbsent(t *testing.T) {
	r := NewRegistry()
	r.Restore([]Task{
		{ID: 4, Kind: KindCrawl, Target: "https://shop.test/", State: TaskRunning, Done: 120, Total: 0,
			StartedMs: 1000, Result: Breakdown{Found: 3}},
		{ID: 5, Kind: KindAudit, Target: "GET shop.test/cart", State: TaskDone, Done: 2, Total: 2,
			StartedMs: 1000, EndedMs: 2000, Result: Breakdown{Found: 1}},
	})

	tasks := r.Snapshot()
	if len(tasks) != 2 {
		t.Fatalf("tasks = %d, want both restored", len(tasks))
	}
	byID := map[uint64]Task{}
	for _, task := range tasks {
		byID[task.ID] = task
	}
	crawl := byID[4]
	if crawl.State != TaskStopped {
		t.Errorf("restored running task state = %v, want stopped", crawl.State)
	}
	if crawl.Complete() {
		t.Error("a task interrupted by a restart reports complete")
	}
	if !strings.Contains(crawl.Note, "restarted") {
		t.Errorf("note = %q, want it to say the process restarted", crawl.Note)
	}
	if crawl.EndedMs == 0 {
		t.Error("restored stopped task has no end time, so its elapsed time would keep growing forever")
	}
	// The partial count is kept: a run that really covered 120 URLs and found 3 things did that.
	if crawl.Done != 120 || crawl.Result.Found != 3 {
		t.Errorf("restored progress = %d done / %+v, want the partial count preserved", crawl.Done, crawl.Result)
	}
	// An already-terminal task is restored untouched.
	if done := byID[5]; done.State != TaskDone || done.Note != "" || done.EndedMs != 2000 {
		t.Errorf("a finished task was altered by restore: %+v", done)
	}
	// Ids resume above the snapshot, so a new task cannot collide with a restored one.
	if h := r.Start(KindAudit, "new", 1); h.ID() <= 5 {
		t.Errorf("post-restore task id = %d, want it above the highest restored id (5)", h.ID())
	}
}

// Restore on a nil registry is a no-op rather than a panic, matching every other method.
func TestRestoreOnNilRegistryIsANoOp(t *testing.T) {
	var r *Registry
	r.Restore([]Task{{ID: 1, State: TaskRunning}})
	if r.Snapshot() != nil {
		t.Error("a nil registry restored something")
	}
}
