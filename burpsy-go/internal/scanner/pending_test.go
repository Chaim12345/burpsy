package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func pendingItem(row string) PendingItem {
	return PendingItem{Row: row, What: "canary planted in query parameter q", Deadline: nowUTC().Add(time.Minute)}
}

// The defect this whole file exists to fix: evidence that arrives after the check returned.
func TestAClaimThatResolvesOnALaterPollIsStillReported(t *testing.T) {
	r := NewPendingRegistry()
	calls := 0
	if err := r.Register(pendingItem("Out-of-band resource load (HTTP)"),
		func(context.Context) (*Finding, bool, error) {
			calls++
			if calls < 3 {
				return nil, false, nil
			}
			return &Finding{Name: "Out-of-band resource load (HTTP)"}, true, nil
		}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// The first two polls are the interesting ones: the old code closed the channel after one.
	for range 2 {
		if got, outstanding := r.Poll(context.Background()); len(got) != 0 || outstanding != 1 {
			t.Fatalf("poll returned %d findings and %d outstanding, want 0 and 1: an unanswered "+
				"claim must stay outstanding rather than settle either way", len(got), outstanding)
		}
	}
	got, outstanding := r.Poll(context.Background())
	if len(got) != 1 {
		t.Fatalf("got %d findings on the third poll, want 1: evidence arriving after the check "+
			"returned is exactly what this registry is for", len(got))
	}
	if outstanding != 0 {
		t.Errorf("outstanding = %d, want 0 once the claim settled", outstanding)
	}
}

// An item whose deadline passes unanswered is outstanding. It must never be counted as clean,
// because nobody ever learned the answer.
func TestAnUnansweredClaimIsReportedOutstandingRatherThanClean(t *testing.T) {
	r := NewPendingRegistry()
	item := pendingItem("External service interaction (DNS)")
	item.Deadline = nowUTC().Add(-time.Second) // already past
	if err := r.Register(item, func(context.Context) (*Finding, bool, error) {
		return nil, false, nil
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	found := r.Await(context.Background())
	if len(found) != 0 {
		t.Fatalf("got %d findings, want 0: nothing was confirmed", len(found))
	}
	out := r.Outstanding()
	if len(out) != 1 {
		t.Fatalf("Outstanding() = %d items, want 1: a claim nobody answered has to survive into "+
			"the report, or the scan silently claims it looked", len(out))
	}
	if out[0].What == "" {
		t.Error("an outstanding item must say what it planted; a bare row name is not actionable")
	}
	if s := r.Summarise(); !strings.Contains(s, "outstanding") || !strings.Contains(s, "not clean") {
		t.Errorf("Summarise() = %q, want it to name the outstanding claims and refuse the word "+
			"clean; this string is what a reader sees instead of the answer", s)
	}
}

// A negative answer is a real answer and must be distinguishable from silence.
func TestAClaimAnsweredNegativelyIsNotCountedOutstanding(t *testing.T) {
	r := NewPendingRegistry()
	if err := r.Register(pendingItem("External service interaction (HTTP)"),
		func(context.Context) (*Finding, bool, error) { return nil, true, nil }); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if found := r.Await(context.Background()); len(found) != 0 {
		t.Fatalf("got %d findings, want 0", len(found))
	}
	if out := r.Outstanding(); len(out) != 0 {
		t.Fatalf("Outstanding() = %d, want 0: the target was asked and demonstrably did not call "+
			"back, which is a verdict rather than a gap", len(out))
	}
	if s := r.Summarise(); !strings.Contains(s, "1 answered negatively") {
		t.Errorf("Summarise() = %q, want it to separate a negative answer from an absent one", s)
	}
}

// A resolver that errors must be retried, not discarded. Dropping the claim would convert
// "could not ask" into "asked and got nothing".

func TestAResolverErrorRetriesTheClaim(t *testing.T) {
	r := NewPendingRegistry()
	calls := 0
	if err := r.Register(pendingItem("Out-of-band resource load (HTTP)"),
		func(context.Context) (*Finding, bool, error) {
			calls++
			if calls == 1 {
				return nil, false, errors.New("collaborator unreachable")
			}
			return &Finding{Name: "Out-of-band resource load (HTTP)"}, true, nil
		}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, outstanding := r.Poll(context.Background()); outstanding != 1 {
		t.Fatalf("outstanding = %d after a transport error, want 1: a channel that failed this "+
			"second may answer the next", outstanding)
	}
	if got, _ := r.Poll(context.Background()); len(got) != 1 {
		t.Fatalf("got %d findings after the retry, want 1", len(got))
	}
}

// Registering without a resolver or a description is a programming error, and a silent one: the
// claim would sit in the registry forever and be reported as outstanding for no reason.
func TestRegisterRefusesAClaimItCouldNotReportOn(t *testing.T) {
	r := NewPendingRegistry()
	if err := r.Register(pendingItem("row"), nil); err == nil {
		t.Error("Register accepted a claim with no resolver, which can never settle")
	}
	if err := r.Register(PendingItem{Row: "row"}, func(context.Context) (*Finding, bool, error) {
		return nil, true, nil
	}); err == nil {
		t.Error("Register accepted a claim that does not say what it planted")
	}
}

// Await must not spin forever when the caller's context ends.
func TestAwaitStopsWhenTheContextEnds(t *testing.T) {
	r := NewPendingRegistry()
	if err := r.Register(pendingItem("Out-of-band resource load (HTTP)"),
		func(context.Context) (*Finding, bool, error) { return nil, false, nil }); err != nil {
		t.Fatalf("Register: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = r.Await(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Await ignored its context and would hang a scan")
	}
}
