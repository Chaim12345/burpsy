package intruder

// PaceN: the atomic group reservation behind the scanner's synchronized race groups
// (burpsy-react-ui-0vzb.8). A group either holds its N slots and N tokens together or holds
// nothing; a pool that can never admit the group says so up front instead of queueing the
// impossible.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func groupLimiter(slots int) *RateLimiter {
	per := 1000.0 // fast enough that no test waits on the bucket
	limit := &RateLimit{MaxInFlight: slots, PerSecond: &per, Burst: 8}
	return NewRateLimiter(limit)
}

func TestPaceNRefusesAGroupThePoolCanNeverAdmit(t *testing.T) {
	l := groupLimiter(2)
	if _, err := l.PaceN(context.Background(), 3); err == nil ||
		!strings.Contains(err.Error(), "cannot admit") {
		t.Fatalf("a group of 3 under 2 slots: want an up-front decline, got %v", err)
	}
}

func TestPaceNRefusesAnAbsurdGroupUpFront(t *testing.T) {
	l := groupLimiter(128)
	if _, err := l.PaceN(context.Background(), MaxGroupPace+1); err == nil {
		t.Fatal("a group past the documented cap was not refused")
	}
	if _, err := l.PaceN(context.Background(), 0); err == nil {
		t.Fatal("a group of zero was not refused")
	}
}

func TestPaceNIsAllOrNothingUnderContention(t *testing.T) {
	l := groupLimiter(2)
	held := l.Acquire() // one of two slots already in flight

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := l.PaceN(ctx, 2); err == nil {
		t.Fatal("a group of 2 slipped past a pool with only 1 slot free")
	}

	// The failed group must have given its partial hold back: with the first permit still
	// held, exactly one slot is free, so one more Pace succeeds and a second must wait.
	held2 := l.Acquire()
	queued := make(chan func(), 1)
	go func() {
		release, _ := l.Pace(context.Background())
		queued <- release
	}()
	select {
	case <-queued:
		t.Fatal("a third send found a slot the failed group should never have kept")
	case <-time.After(150 * time.Millisecond):
	}
	held.Release()
	held2.Release()
	// The queued Pace now takes a slot; give it back before asserting the group fits.
	(<-queued)()

	// And once the pool drains, the same group is admitted whole.
	release, err := l.PaceN(context.Background(), 2)
	if err != nil {
		t.Fatalf("a drained pool declined the group: %v", err)
	}
	release()

	// The release returned both slots: a second group is admitted without waiting on leaks.
	release2, err := l.PaceN(context.Background(), 2)
	if err != nil {
		t.Fatalf("the release did not return every slot: %v", err)
	}
	release2()
}

func TestPaceNChargesTheWholeGroupOnce(t *testing.T) {
	per := 20.0 // 50ms per token
	limit := &RateLimit{MaxInFlight: 8, PerSecond: &per, Burst: 1}
	l := NewRateLimiter(limit)

	// The first group spends the burst token and then some; the wait it observes must be one
	// reservation for N tokens, not N sequential reservations.
	start := time.Now()
	release, err := l.PaceN(context.Background(), 4)
	if err != nil {
		t.Fatal(err)
	}
	waited := time.Since(start)
	release()
	if waited > 500*time.Millisecond {
		t.Fatalf("a 4-token reservation waited %v: the tokens were staggered, not charged at once", waited)
	}
}

// Two concurrent groups whose sizes each exceed half the pool can deadlock it when
// acquisition is one slot at a time: each holds a partial share and waits on the other
// forever, and every plain Pace hangs behind them (PR #363 review: cap 4, two PaceN(3)
// each take 2). With acquisition serialized, one group is admitted whole while the other
// holds NOTHING, and the admitted group's release then admits the waiter.
//
// The interleave that splits the pool is a race, so the round count does the work: 200
// rounds make a non-splitting run on the old loop implausible (observed splitting within
// the first few rounds on an 8-core machine).
func TestPaceNGroupsDoNotDeadlockAPoolTheyShare(t *testing.T) {
	for round := 0; round < 200; round++ {
		l := groupLimiter(4)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		type outcome struct {
			release func()
			err     error
		}
		results := make(chan outcome, 2)
		start := make(chan struct{})
		go func() { <-start; r, err := l.PaceN(ctx, 3); results <- outcome{r, err} }()
		go func() { <-start; r, err := l.PaceN(ctx, 3); results <- outcome{r, err} }()
		close(start)
		// One group must be admitted whole while the other still waits; the old loop let
		// both hold a 2-slot split and neither ever returned.
		first := <-results
		if first.err != nil {
			cancel()
			t.Fatalf("round %d: no group was admitted: %v", round, first.err)
		}
		// The admitted group's release frees the waiter's slots; the waiter then completes.
		first.release()
		second := <-results
		cancel()
		if second.err != nil {
			t.Fatalf("round %d: the waiting group was not admitted after the first released: %v", round, second.err)
		}
		second.release()
		// The pool drains fully: a third group is admitted without waiting on a leak.
		release, err := l.PaceN(context.Background(), 3)
		if err != nil {
			t.Fatalf("round %d: the pool did not drain after both groups released: %v", round, err)
		}
		release()
	}
}

// A group queued BEHIND another group's acquisition turn must still honor its own context:
// a plain mutex wait cannot be cancelled, so with a slot-blocked leader (a full pool and a
// long-lived ctx) a queued group would outlive its own deadline by the leader's whole wait.
func TestPaceNWaitingForAnotherGroupStillHonorsContext(t *testing.T) {
	l := groupLimiter(2)
	a, b := l.Acquire(), l.Acquire() // the pool is full; no group can take a slot
	defer a.Release()
	defer b.Release()
	// The leader blocks on slots for far longer than the queued group's deadline.
	slow, stopSlow := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopSlow()
	leader := make(chan error, 1)
	go func() { _, err := l.PaceN(slow, 2); leader <- err }()
	time.Sleep(100 * time.Millisecond) // the leader is inside its acquisition turn

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := l.PaceN(ctx, 2)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the queued group ended with %v, want its own deadline", err)
	}
	// The leader waits 30s; the queued group's own 100ms deadline must end it far sooner. 5s of
	// slack keeps a loaded runner from reading a correct run as a failure (burpsy-react-ui-timing-bounds).
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the queued group outlived its context by %v waiting on the leader's turn", elapsed)
	}
}
