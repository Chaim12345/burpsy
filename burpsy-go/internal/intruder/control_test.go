package intruder

// Pause, resume and stop, at the engine.
//
// A launched attack ran to completion: no pause, no resume, no stop, and the dashboard task it
// registered was not cancellable. These tests pin the engine half — that the driver loop actually
// stops enumerating, and that the report says the attack was stopped rather than presenting a prefix
// of the payload set as a complete answer.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// controlledAttack builds a one-position sniper over `n` payloads, with a send function the test
// controls. `sent` counts sends that actually happened.
func controlledAttack(t *testing.T, n int, onSend func(ordinal int)) (*Attack, SendFn, *atomic.Int64) {
	t.Helper()
	items := make([]string, n)
	for i := range items {
		items[i] = "p" + string(rune('a'+i%26))
	}
	points := []InsertionPoint{{Kind: PointURLParamValue, Span: core.Span{Offset: 8, Len: 5}, Label: "q"}}
	sets := []PayloadSet{{Items: items}}
	plan := NewAttackPlan(AttackKindSniper, 1, []int{n}, n)
	// One in flight, so the sequence of sends is deterministic and a pause takes effect at a known
	// position instead of racing ten concurrent sends.
	rps := 1000.0
	a := NewAttack([]byte("GET /?q=AAAAA HTTP/1.1\r\nHost: h\r\n\r\n"), points, sets, plan).
		WithLimits(NewRateLimit(&rps, 1, 1))

	var count atomic.Int64
	send := func(raw []byte) (Sent, error) {
		i := int(count.Add(1)) - 1
		if onSend != nil {
			onSend(i)
		}
		status := 200
		return Sent{Raw: []byte("HTTP/1.1 200 OK\r\n\r\nok"), Status: &status, Duration: time.Millisecond}, nil
	}
	return a, send, &count
}

func TestStopHaltsTheDriverLoopRatherThanFailingEveryRemainingOrdinal(t *testing.T) {
	ctrl := NewControl()
	// Stop after the third send. Without a gate in the driver loop the remaining 997 ordinals are
	// still enumerated and every one becomes a send error, so the report claims the target refused
	// 997 requests it never received.
	a, send, count := controlledAttack(t, 1000, func(ordinal int) {
		if ordinal == 2 {
			ctrl.Stop("test")
		}
	})
	report := Run(a.WithControl(ctrl), send, nil)

	if report.Status != StatusStopped {
		t.Fatalf("status = %q, want %q", report.Status, StatusStopped)
	}
	if report.StopReason != "test" {
		t.Errorf("stop_reason = %q, want the reason the caller gave", report.StopReason)
	}
	if got := count.Load(); got > 20 {
		t.Errorf("%d requests were sent after a stop at the third; the loop kept enumerating", got)
	}
	if report.Enumerated >= report.Planned {
		t.Errorf("enumerated = %d of planned %d: a stopped attack must not report the whole plan as "+
			"its denominator", report.Enumerated, report.Planned)
	}
	if report.Failed > 20 {
		t.Errorf("failed = %d: a stopped attack must not report requests it never sent as failures",
			report.Failed)
	}
}

func TestACompletedAttackSaysCompletedAndEnumeratedEverything(t *testing.T) {
	ctrl := NewControl()
	a, send, _ := controlledAttack(t, 5, nil)
	report := Run(a.WithControl(ctrl), send, nil)

	if report.Status != StatusCompleted {
		t.Fatalf("status = %q, want %q", report.Status, StatusCompleted)
	}
	if report.StopReason != "" {
		t.Errorf("stop_reason = %q on a completed attack", report.StopReason)
	}
	if report.Enumerated != report.Planned || report.Sent != 5 {
		t.Errorf("enumerated/planned/sent = %d/%d/%d, want 5/5/5",
			report.Enumerated, report.Planned, report.Sent)
	}
	if ctrl.Status() != StatusCompleted {
		t.Errorf("control status = %q after the run", ctrl.Status())
	}
}

// An attack with no control runs exactly as it did before Control existed, and its report still says
// completed rather than leaving the field empty — an absent status would read as "we did not look".
func TestAnUncontrolledAttackStillReportsCompleted(t *testing.T) {
	a, send, count := controlledAttack(t, 4, nil)
	report := Run(a, send, nil)
	if report.Status != StatusCompleted {
		t.Errorf("status = %q on a nil-control attack, want completed", report.Status)
	}
	if count.Load() != 4 {
		t.Errorf("sent %d, want 4", count.Load())
	}
}

func TestPauseHoldsTheAttackAndResumeReleasesIt(t *testing.T) {
	ctrl := NewControl()
	// Pause on the first send. The driver blocks before enumerating position 1, so no further send
	// happens until Resume.
	paused := make(chan struct{})
	var once sync.Once
	a, send, count := controlledAttack(t, 50, func(ordinal int) {
		if ordinal == 0 {
			ctrl.Pause()
			once.Do(func() { close(paused) })
		}
	})

	done := make(chan *AttackReport, 1)
	go func() { done <- Run(a.WithControl(ctrl), send, nil) }()

	<-paused
	// The first send is what triggered the pause, so at most a small number can be in flight. Give
	// the driver time to reach the gate and prove it is not still working.
	time.Sleep(150 * time.Millisecond)
	if ctrl.Status() != StatusPaused {
		t.Fatalf("status = %q while paused", ctrl.Status())
	}
	stalled := count.Load()
	time.Sleep(150 * time.Millisecond)
	if after := count.Load(); after != stalled {
		t.Fatalf("a paused attack sent %d more requests (%d → %d)", after-stalled, stalled, after)
	}

	if !ctrl.Resume() {
		t.Fatal("Resume reported nothing to resume")
	}
	select {
	case report := <-done:
		if report.Status != StatusCompleted {
			t.Errorf("status = %q after resume, want completed", report.Status)
		}
		if report.Sent != 50 {
			t.Errorf("sent = %d after resume, want the whole plan (50)", report.Sent)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the attack did not finish after Resume")
	}
}

// A paused attack must be stoppable. Without the broadcast in Stop the driver sits in the pause wait
// forever, the run never returns, and the attack is stopped in name only.
func TestStopReleasesAPausedAttack(t *testing.T) {
	ctrl := NewControl()
	paused := make(chan struct{})
	var once sync.Once
	a, send, _ := controlledAttack(t, 500, func(ordinal int) {
		if ordinal == 0 {
			ctrl.Pause()
			once.Do(func() { close(paused) })
		}
	})

	done := make(chan *AttackReport, 1)
	go func() { done <- Run(a.WithControl(ctrl), send, nil) }()
	<-paused
	time.Sleep(100 * time.Millisecond)
	if !ctrl.Stop("stopped while paused") {
		t.Fatal("Stop reported nothing to stop")
	}
	select {
	case report := <-done:
		if report.Status != StatusStopped {
			t.Errorf("status = %q, want stopped", report.Status)
		}
		if report.StopReason != "stopped while paused" {
			t.Errorf("stop_reason = %q", report.StopReason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stopping a paused attack did not release the driver loop")
	}
}

func TestStopOnContextReachesTheDriver(t *testing.T) {
	ctrl := NewControl()
	ctx, cancel := context.WithCancel(context.Background())
	attackDone := make(chan struct{})
	defer close(attackDone)
	// This is the dashboard's stop button: dash.Handle.WithCancel hands the caller a context, and
	// cancelling it must reach the loop.
	ctrl.StopOnContext(ctx, attackDone, "stopped from the dashboard")

	a, send, count := controlledAttack(t, 2000, func(ordinal int) {
		if ordinal == 2 {
			cancel()
		}
	})
	report := Run(a.WithControl(ctrl), send, nil)
	if report.Status != StatusStopped {
		t.Fatalf("status = %q, want stopped: a cancelled dashboard task did not reach the loop",
			report.Status)
	}
	if report.StopReason != "stopped from the dashboard" {
		t.Errorf("stop_reason = %q", report.StopReason)
	}
	if got := count.Load(); got > 200 {
		t.Errorf("%d of 2000 requests were sent after the cancel", got)
	}
}

func TestControlRefusesActionsOnAFinishedAttack(t *testing.T) {
	ctrl := NewControl()
	a, send, _ := controlledAttack(t, 2, nil)
	Run(a.WithControl(ctrl), send, nil)

	if ctrl.Pause() {
		t.Error("Pause reported success on a completed attack")
	}
	if ctrl.Resume() {
		t.Error("Resume reported success on a completed attack")
	}
	if ctrl.Stop("late") {
		t.Error("Stop reported success on a completed attack")
	}
	if ctrl.Status() != StatusCompleted {
		t.Errorf("status = %q, want completed", ctrl.Status())
	}
	if ctrl.StopReason() != "" {
		t.Errorf("stop_reason = %q on a completed attack", ctrl.StopReason())
	}
}

// A second Stop must not overwrite the first reason: the first answer about why a run ended is the
// true one, the same rule dash.Handle.finish applies to task states.
func TestTheFirstStopReasonWins(t *testing.T) {
	ctrl := NewControl()
	if !ctrl.Stop("first") {
		t.Fatal("first Stop refused")
	}
	if ctrl.Stop("second") {
		t.Error("second Stop reported success")
	}
	if ctrl.StopReason() != "first" {
		t.Errorf("stop_reason = %q, want first", ctrl.StopReason())
	}
}

func TestNilControlIsAWorkingNoOp(t *testing.T) {
	var c *Control
	if c.Pause() || c.Resume() || c.Stop("x") {
		t.Error("a nil control reported that it did something")
	}
	if c.Status() != StatusRunning {
		t.Errorf("nil control status = %q, want running", c.Status())
	}
	if c.StopReason() != "" {
		t.Errorf("nil control stop_reason = %q", c.StopReason())
	}
	if !c.gate() {
		t.Error("a nil control stopped the driver loop")
	}
	c.complete()
	c.StopOnContext(context.Background(), nil, "x")
}

func TestProgressCountsWhatTheCollectorSettles(t *testing.T) {
	a, send, _ := controlledAttack(t, 50, nil)
	ctrl := NewControl()
	// One in five sends fails, so both counters move and their sum still reaches the plan.
	flaky := 0
	flakySend := func(raw []byte) (Sent, error) {
		flaky++
		if flaky%5 == 0 {
			return Sent{}, context.DeadlineExceeded
		}
		return send(raw)
	}
	report := Run(a.WithControl(ctrl), flakySend, nil)

	sent, failed := ctrl.Progress()
	if sent != report.Sent || failed != report.Failed {
		t.Errorf("progress = (%d sent, %d failed), report = (%d sent, %d failed): the live view disagrees with the report",
			sent, failed, report.Sent, report.Failed)
	}
	if sent+failed != 50 {
		t.Errorf("sent+failed = %d, want one settled outcome per planned request", sent+failed)
	}
}

func TestNilControlProgressCountsNothing(t *testing.T) {
	var c *Control
	c.note(true)
	c.note(false)
	if sent, failed := c.Progress(); sent != 0 || failed != 0 {
		t.Errorf("nil control progress = (%d, %d), want (0, 0)", sent, failed)
	}
}
