package intruder

// PaceN: the atomic group reservation behind the scanner's synchronized race groups
// (burpsy-react-ui-0vzb.8). A group either holds its N slots and N tokens together or holds
// nothing; a pool that can never admit the group says so up front instead of queueing the
// impossible.

import (
	"context"
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
