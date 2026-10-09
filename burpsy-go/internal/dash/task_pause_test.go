package dash

// Per-task Pause/Resume (burpsy-react-ui-g0ba): one task's pause holds only that task's gate, a
// derived context (a crawl's audit feed) is held by either row, and a finished task drops its pause.

import (
	"context"
	"errors"
	"testing"
	"time"
)

func blocks(r *Registry, ctx context.Context) bool {
	done := make(chan struct{})
	gctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	go func() { r.GateCheck(gctx); close(done) }()
	select {
	case <-done:
		return gctx.Err() != nil // returned only because the timeout fired
	case <-time.After(time.Second):
		return true
	}
}

func TestOneTasksPauseHoldsOnlyThatTasksGate(t *testing.T) {
	r := NewRegistry()
	a, b := r.Start(KindCrawl, "a", 0), r.Start(KindCrawl, "b", 0)
	actx, bctx := a.Pausable(context.Background()), b.Pausable(context.Background())
	if err := r.SetTaskPaused(a.ID(), true); err != nil {
		t.Fatal(err)
	}
	if !blocks(r, actx) {
		t.Error("the paused task's gate did not hold")
	}
	if blocks(r, bctx) {
		t.Error("pausing one task held another")
	}
	// A feed whose context derives from a's, and carries its own task too.
	feed := r.Start(KindAuditSession, "feed", 0)
	fctx := feed.Pausable(actx)
	if !blocks(r, fctx) {
		t.Error("a derived context must be held by its parent task's pause")
	}
	r.SetTaskPaused(a.ID(), false)
	if blocks(r, actx) || blocks(r, fctx) {
		t.Error("resume did not release the gate")
	}
	r.SetTaskPaused(feed.ID(), true)
	if !blocks(r, fctx) || blocks(r, actx) {
		t.Error("the feed's own pause must hold the feed and not its parent")
	}
	feed.Finish(Breakdown{})
	for _, task := range r.Snapshot() {
		if task.ID == feed.ID() && (task.Paused || task.Running()) {
			t.Errorf("a finished task still reports paused: %+v", task)
		}
	}
}

func TestPauseRefusesUnknownFinishedAndNonPausableTasks(t *testing.T) {
	r := NewRegistry()
	plain := r.Start(KindDiscovery, "x", 0)
	if err := r.SetTaskPaused(plain.ID(), true); !errors.Is(err, ErrNotPausable) {
		t.Errorf("non-pausable: %v", err)
	}
	if err := r.SetTaskPaused(999, true); !errors.Is(err, ErrNoSuchTask) {
		t.Errorf("unknown: %v", err)
	}
	done := r.Start(KindCrawl, "y", 0)
	done.Pausable(context.Background())
	done.Finish(Breakdown{})
	if err := r.SetTaskPaused(done.ID(), true); !errors.Is(err, ErrTaskNotRunning) {
		t.Errorf("finished: %v", err)
	}
}
