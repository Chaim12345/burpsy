package intruder

import (
	"context"
	"sync"
	"sync/atomic"
)

// Pausing, resuming and stopping a running attack.
//
// # The gap this closes
//
// A launched attack ran to completion. Burp's attack results window has a manual pause/resume control
// and a stop; this engine had none, and the dashboard task an attack registered never called
// Handle.WithCancel, so the dashboard rendered no stop button for it either. A cluster bomb bounded at
// the 200,000-request ceiling and aimed at the wrong host could not be halted from anywhere except by
// killing the process.
//
// A pause/stop engine did exist in this package — Intruder.Stop, AttackProgress.Status — but it
// belongs to the older Intruder type whose only caller is the CLI. Nothing on the web path could
// reach it. This is the same capability for the engine that actually runs an attack.
//
// # Why cancelling the context was not enough
//
// Every send in an attack goes through a caller-supplied SendFn closed over a context. Cancelling
// that context does stop the sends — but the driver loop keeps enumerating the plan, and every
// remaining ordinal becomes an error outcome. A 200,000-request attack stopped at request 12 would
// report 12 sent and 199,988 failed, with 2,000 error buckets, which is not a stopped attack: it is a
// report claiming the target refused 199,988 requests it never received. So the loop itself has to
// stop, and the report has to say it stopped.
//
// # Why pause blocks rather than polls
//
// The driver goroutine waits on a condition variable while paused. The alternative — a sleep-and-recheck
// loop — is a paused attack that still burns a scheduler slot and still has to decide on a polling
// interval, which becomes the resume latency. Neither is a property worth inventing. In-flight sends
// at the moment of a pause are allowed to finish and are collected: they are requests the target has
// already received, and discarding their responses would lose real observations to make a progress
// number tidier.

// AttackStatus is where a controlled attack is, as an operator sees it.
type AttackStatus string

const (
	// StatusRunning is enumerating the plan and sending.
	StatusRunning AttackStatus = "running"
	// StatusPaused is holding at a plan position, sending nothing, with the ordinals already sent
	// collected. Resumable.
	StatusPaused AttackStatus = "paused"
	// StatusStopped is ended before the plan was exhausted. Terminal: an attack cannot be un-stopped,
	// because the collector's report has already been closed out and a second pass would double-count
	// every bucket.
	StatusStopped AttackStatus = "stopped"
	// StatusCompleted is the plan exhausted.
	StatusCompleted AttackStatus = "completed"
)

// Control is the pause/resume/stop handle for one running attack.
//
// Every method tolerates a nil receiver, matching dash.Handle: an attack with no control is the
// uncontrolled attack this package ran before, and a caller that has no control to pass must not have
// to nil-check at every site. A nil Control never pauses and never stops.
type Control struct {
	mu   sync.Mutex
	cond *sync.Cond

	paused  bool
	stopped bool
	// completed is set by Run when the plan is exhausted, so Status distinguishes an attack that
	// finished from one that was stopped — the difference between "the target behaved this way over
	// the whole payload set" and "over an unknown prefix of it".
	completed bool
	// stopReason is what the report and the dashboard note say about why the attack ended early.
	stopReason string

	// settledSends and settledFails count outcomes as the engine's collector absorbs them, so the
	// control routes can answer "is it doing anything" while the attack runs. They are the same
	// totals the eventual report carries, so a live view cannot disagree with it.
	settledSends atomic.Int64
	settledFails atomic.Int64
}

// NewControl returns a control for an attack that has not started.
func NewControl() *Control {
	c := &Control{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// Pause holds the attack at its next plan position. Returns false when there was nothing to pause: an
// attack already stopped or completed. Pausing an already-paused attack is a no-op that returns true —
// the caller asked for a state and got it.
func (c *Control) Pause() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped || c.completed {
		return false
	}
	c.paused = true
	return true
}

// Resume releases a paused attack. Returns false when the attack is stopped or completed, for the
// same reason Pause does: a resume that reported success on a finished attack would put a running
// state on screen for work that is over.
func (c *Control) Resume() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped || c.completed {
		return false
	}
	c.paused = false
	c.cond.Broadcast()
	return true
}

// Stop ends the attack before the plan is exhausted, recording why. Returns false when the attack was
// already over. `why` reaches AttackReport.StopReason, so it is operator-facing text.
//
// Broadcast as well as flagged, because a paused attack must be stoppable: without the broadcast the
// driver would sit in the pause wait forever and the attack would be stopped in name only.
func (c *Control) Stop(why string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped || c.completed {
		return false
	}
	c.stopped = true
	c.paused = false
	if why == "" {
		why = "stopped by the operator"
	}
	c.stopReason = why
	c.cond.Broadcast()
	return true
}

// StopOnContext stops the attack when ctx is cancelled, so a dashboard cancel (which is a
// context.CancelFunc registered through dash.Handle.WithCancel) reaches the driver loop.
//
// The watcher goroutine exits when ctx is done or when `done` is closed, so it does not outlive the
// attack. `done` is the caller's: closing it on the way out of the attack is what makes this safe to
// call per attack rather than once per process.
func (c *Control) StopOnContext(ctx context.Context, done <-chan struct{}, why string) {
	if c == nil || ctx == nil {
		return
	}
	go func() {
		select {
		case <-ctx.Done():
			c.Stop(why)
		case <-done:
		}
	}()
}

// note records one settled send for the live progress view. Run's collector loop calls it as each
// outcome lands, so the counts move with real results rather than with enumerated ordinals.
func (c *Control) note(ok bool) {
	if c == nil {
		return
	}
	if ok {
		c.settledSends.Add(1)
	} else {
		c.settledFails.Add(1)
	}
}

// Progress is how much of the attack has settled so far: sent and failed, the same totals the
// eventual report carries. A paused attack holds its counts; a stopped attack's last in-flight
// sends still land and are counted, as they are in the report.
func (c *Control) Progress() (sent, failed int) {
	if c == nil {
		return 0, 0
	}
	return int(c.settledSends.Load()), int(c.settledFails.Load())
}

// Status is where the attack is now.
func (c *Control) Status() AttackStatus {
	if c == nil {
		return StatusRunning
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.stopped:
		return StatusStopped
	case c.completed:
		return StatusCompleted
	case c.paused:
		return StatusPaused
	}
	return StatusRunning
}

// StopReason is why the attack ended early, or "" when it did not.
func (c *Control) StopReason() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopReason
}

// gate is what the driver loop calls before each plan position: it blocks while paused and reports
// whether the attack may continue. False means stop enumerating.
func (c *Control) gate() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.paused && !c.stopped {
		c.cond.Wait()
	}
	return !c.stopped
}

// holding reports whether the attack is paused or stopped RIGHT NOW, without blocking. gate() is
// the blocking form and is what the driver waits on; this is the question the driver has to ask a
// second time, after it has waited for something else.
//
// It exists because waiting is not free of state changes. The driver gates, then queues for an
// in-flight permit, and a pause raised while it was queueing — by the operator, or by the
// auto-pause predicate reading the very response that freed the permit — was invisible to the gate
// it had already passed. Asking again with the permit in hand costs one mutex and closes that
// window; see gateForSend.
func (c *Control) holding() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.paused || c.stopped
}

// gateForSend takes the in-flight permit this ordinal will be sent under, and re-checks the hold
// with it in hand. It returns the permit to send under, or nil when the attack was stopped and the
// driver should stop enumerating.
//
// # Why the first gate is not enough
//
// Auto-pause (and any operator pause) is raised from inside a send that is already in flight. The
// driver's next iteration gates BEFORE it queues for a permit, so at concurrency 1 the sequence was:
// ordinal n+1 passes the gate while ordinal n is still on the wire, ordinal n's response trips the
// lockout predicate, Pause() is set, ordinal n releases its permit, and ordinal n+1 — already past
// the gate — takes that permit and sends. Exactly one request escaped every halt in the engine:
// every auto-pause, every dashboard stop, every operator pause. For the predicate this feature
// exists to serve ("ACCOUNT LOCKED"), that escapee is one more login attempt against an account the
// operator has already been told is locked. burpsy-react-ui-xqwe filed the test that saw it as
// flaky; the test was right and only intermittently lucky enough to look.
//
// The permit is released before waiting and re-taken after, so the invariant the plan loop states —
// a paused attack holds no in-flight permit, because a held permit throttles nothing and would
// block the first send of a resume — still holds. The loop, rather than a single re-check, covers a
// pause raised while this ordinal was re-queueing.
//
// A nil Control never holds, so an uncontrolled attack pays one non-blocking mutex per request and
// behaves exactly as before.
func gateForSend(c *Control, limiter *RateLimiter) *Permit {
	permit := limiter.Acquire()
	for c.holding() {
		permit.Release()
		if !c.gate() {
			return nil
		}
		permit = limiter.Acquire()
	}
	return permit
}

// reportStatus is the status to put on a finished report.
//
// Run calls complete() before building the report, so a real control is stopped or completed by the
// time this is read and only a nil control can still say "running". A nil control is the attack that
// ran with no handle at all, and it finished — reporting "running" on a report that exists because the
// run is over would be a state no reader can act on, and the honest answer is the same one the
// controlled path gives.
func reportStatus(c *Control) AttackStatus {
	if s := c.Status(); s != StatusRunning {
		return s
	}
	return StatusCompleted
}

// complete marks the plan exhausted. Called by Run, not by an operator: it is what makes "completed"
// a fact the engine observed rather than an absence of a stop.
func (c *Control) complete() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.completed = true
	}
	c.cond.Broadcast()
}
