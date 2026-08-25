package dash

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ---- the task registry (DASH-01) ---------------------------------------------------------------
//
// # The gap this closes
//
// Every long-running thing in this process reported itself only at the end. An audit session
// returned a SessionOutcome once it was finished; the live sweep incremented two counters; an
// intruder attack streamed rows into a response body. From the operator's side, a run in progress
// and a run that never started looked identical: nothing on screen either way.
//
// Registry is the one place work announces itself while it is still running. It is deliberately not
// a scheduler and does not own goroutines — it observes. A caller starts a task, advances it, and
// finishes it; if the caller dies without finishing, the task stays visible as running, which is the
// honest answer rather than a silent disappearance.
//
// # Why Kind is a string
//
// The registry must not import the packages whose work it tracks, or it becomes a hub every one of
// them depends on and none of them can be built without. Kind is a plain string with the known
// values named as constants here, so a package registers work by naming its kind — the crawler in
// particular can register itself while this package knows nothing about crawling.
//
// # Why the Handle is nil-safe
//
// Every method on *Handle tolerates a nil receiver. A caller that has no registry wired (a test, the
// CLI, an unwired server) gets a nil handle from a nil registry and calls Advance/Finish on it
// unconditionally. The alternative is a nil check at every call site, and a nil check that someone
// forgets is a panic in the middle of an audit.

// Kind names what sort of work a task is. Long-running work in this process registers under one of
// these; the set is open, and a kind the dashboard has never seen renders under its own name rather
// than being dropped.
type Kind string

const (
	// KindAudit is one active audit of one captured exchange.
	KindAudit Kind = "audit"
	// KindAuditSession is an audit sweep over many exchanges under one shared budget.
	KindAuditSession Kind = "audit-session"
	// KindLiveAudit is one tick of the live sweep over newly-completed proxied traffic.
	KindLiveAudit Kind = "live-audit"
	// KindIntruder is one intruder attack.
	KindIntruder Kind = "intruder"
	// KindCrawl is one crawl from a seed URL. Named here rather than in the crawler so the crawler
	// depends on this package and not the other way round.
	KindCrawl Kind = "crawl"
	// KindDiscovery is one content-discovery sweep delegated to an external tool (ffuf). Named here
	// for the same reason KindCrawl is: internal/extscan is a leaf that knows nothing about this
	// registry, and the web handler that drives it should not have to invent a kind string.
	KindDiscovery Kind = "discovery"
	// KindSequencerCapture is one sequencer capture: N requests sent to accumulate N session tokens.
	// The first consumer of Handle.WithCancel, because "stop the capture" is a button an operator
	// reaches for and the route behind it used to answer `{"stopped": true}` without a loop to stop.
	KindSequencerCapture Kind = "sequencer-capture"
)

// TaskState is where a task ended up, or that it has not ended.
type TaskState int

const (
	// TaskRunning means started and not yet finished. The zero value: a task exists because
	// something started it, so "running" is the only sound default.
	TaskRunning TaskState = iota
	// TaskDone means the work finished of its own accord. It does not mean the work was complete —
	// Task.Result carries that, and a done task with a non-complete Result is a run that stopped
	// looking.
	TaskDone
	// TaskStopped means the operator or a cancelled context ended it early.
	TaskStopped
	// TaskFailed means it ended on an error.
	TaskFailed
)

// TaskStateAll is all four, so a caller can build a histogram without hard-coding the set.
var TaskStateAll = [4]TaskState{TaskRunning, TaskDone, TaskStopped, TaskFailed}

func (s TaskState) String() string {
	switch s {
	case TaskRunning:
		return "running"
	case TaskDone:
		return "done"
	case TaskStopped:
		return "stopped"
	case TaskFailed:
		return "failed"
	}
	return "unknown state"
}

// MarshalJSON writes the name rather than the ordinal, matching Disposition and ItemState.
func (s TaskState) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Task is one unit of long-running work, as an operator sees it.
type Task struct {
	ID     uint64    `json:"id"`
	Kind   Kind      `json:"kind"`
	Target string    `json:"target"`
	State  TaskState `json:"state"`
	// Done and Total are progress. Total is 0 when the size of the work is not known in advance —
	// a crawl frontier grows as it is walked — and Fraction reports that rather than dividing by
	// zero or pretending the task is complete.
	Done  uint64 `json:"done"`
	Total uint64 `json:"total"`
	// StartedMs and EndedMs are Unix milliseconds. EndedMs is 0 exactly while State is TaskRunning.
	StartedMs uint64 `json:"started_ms"`
	EndedMs   uint64 `json:"ended_ms"`
	// Note is the latest one-line status, e.g. what stopped a bounded run.
	Note string `json:"note,omitempty"`
	// Result is what the work found, with its caveats. A finished task always carries one, so a
	// task cannot report a count on the dashboard without reporting what it did not look at.
	Result Breakdown `json:"result"`

	// cancel stops the work, when its author asked for that by calling Handle.WithCancel. Unexported,
	// so it never reaches the wire; Cancellable is what the dashboard reads.
	//
	// The registry deliberately still does not own goroutines. It holds a function the caller handed
	// it and calls that function when asked — the caller's own select on ctx.Done() is what actually
	// stops the work, and a caller that ignores its context is a task that reports cancellable and
	// keeps running. That is why Registry.Cancel reports what it found rather than what it achieved.
	cancel func()
}

// Cancellable reports whether this task registered a cancel function. Read by the dashboard so a
// stop button appears only where it can do something: a button that silently does nothing is worse
// than no button, and this package's whole purpose is not showing an operator a state that is not
// real.
func (t Task) Cancellable() bool { return t.cancel != nil }

// Fraction is progress in [0,1], and whether it is known at all. Two return values rather than a
// sentinel: a task whose total is not yet known is at an unknown fraction, not at zero, and a
// progress bar that renders those the same way tells the operator a growing crawl is stalled.
func (t Task) Fraction() (float64, bool) {
	if t.Total == 0 {
		return 0, false
	}
	if t.Done >= t.Total {
		return 1, true
	}
	return float64(t.Done) / float64(t.Total), true
}

// Running reports whether this task is still outstanding.
func (t Task) Running() bool { return t.State == TaskRunning }

// Complete reports whether this task both finished and finished the work it was given.
//
// All three conditions matter and none implies another: a task can be TaskDone with items it never
// admitted (Result not complete), or TaskDone having advanced past only half a known total (a
// caller that returned early). Reporting any of those as complete is how a bound turns into a clean
// bill of health.
func (t Task) Complete() bool {
	return t.State == TaskDone && t.Result.Complete() && (t.Total == 0 || t.Done >= t.Total)
}

// ProgressLabel is progress as one operator-facing string, naming an unknown total rather than
// hiding it behind a percentage it cannot compute.
func (t Task) ProgressLabel() string {
	if f, known := t.Fraction(); known {
		return fmt.Sprintf("%d/%d (%.0f%%)", t.Done, t.Total, f*100)
	}
	return fmt.Sprintf("%d done, total not yet known", t.Done)
}

// MarshalJSON emits the task with its progress derived, so the UI never computes completeness itself
// and never has the chance to compute it differently from Go.
//
// ElapsedMs is measured to EndedMs once the task is finished, so a finished task's duration stops
// growing while the dashboard polls it.
func (t Task) MarshalJSON() ([]byte, error) {
	end := t.EndedMs
	if end == 0 {
		end = uint64(time.Now().UnixMilli())
	}
	var elapsed uint64
	if end > t.StartedMs {
		elapsed = end - t.StartedMs
	}
	f, known := t.Fraction()
	// plain drops Task's method set, so the embedded value marshals as a struct instead of calling
	// this method again. Without the alias this recurses until the stack runs out.
	type plain Task
	return json.Marshal(struct {
		plain
		ElapsedMs     uint64  `json:"elapsed_ms"`
		Fraction      float64 `json:"fraction"`
		FractionKnown bool    `json:"fraction_known"`
		Progress      string  `json:"progress"`
		Complete      bool    `json:"complete"`
		Cancellable   bool    `json:"cancellable"`
	}{
		plain:         plain(t),
		ElapsedMs:     elapsed,
		Fraction:      f,
		FractionKnown: known,
		Progress:      t.ProgressLabel(),
		Complete:      t.Complete(),
		Cancellable:   t.Cancellable(),
	})
}

// DefaultTaskCapacity bounds how many finished tasks the registry remembers.
//
// Sized for a session's worth of history rather than a run's: an audit sweep every three seconds for
// an hour is 1200 ticks, so 500 keeps the recent past without letting a long engagement grow the
// registry without bound. Running tasks are never counted against it — see Registry.evictLocked.
const DefaultTaskCapacity = 500

// Registry is the live table of long-running work.
type Registry struct {
	mu       sync.RWMutex
	tasks    []*Task
	capacity int
	dropped  uint64
	nextID   uint64
	// events is an optional lifecycle sink (see WithEvents). Never called while mu is held: the log
	// takes its own lock and must never be able to order against this one. It never calls back here.
	events *EventLog
}

// NewRegistry creates an empty registry at the default capacity.
func NewRegistry() *Registry { return &Registry{capacity: DefaultTaskCapacity} }

// WithEvents attaches an event log, so every task in the process emits a started and a finished event
// without its own author writing either.
//
// One wiring call rather than per-caller discipline. A crawl registered through Start gets lifecycle
// events even though this package knows nothing about crawling and the crawler knows nothing about the
// event log — which is the only version of this that stays true as callers are added.
func (r *Registry) WithEvents(log *EventLog) *Registry {
	if r == nil {
		return r
	}
	r.mu.Lock()
	r.events = log
	r.mu.Unlock()
	return r
}

// restartedNote is what a task interrupted by a restart says about itself. Deliberately not "failed":
// nothing failed, the process went away, and the two are different facts about a run.
const restartedNote = "process restarted while this was running; how much it had covered is not known"

// Restore replaces the registry's contents with a previously persisted snapshot, resuming ids above
// the highest restored one so they stay unique. Mirrors toollog.Restore, including resetting dropped —
// what a previous process dropped is not something this one can report on.
//
// A task that was running when the snapshot was taken comes back **stopped**, with restartedNote. It
// is the only transformation Restore performs, and it is the point of the method: the alternatives are
// both lies. Left running, the dashboard shows a live crawl that no longer exists and whose progress
// will never move again. Marked done, a run that covered an unknown fraction of its target is reported
// as having finished it. Stopped with a note is the honest third answer — the run existed, it ended,
// and nobody knows how far it got, which is exactly what Task.Complete() reports for it.
func (r *Registry) Restore(tasks []Task) {
	if r == nil {
		return
	}
	now := uint64(time.Now().UnixMilli())
	r.mu.Lock()
	r.tasks = make([]*Task, 0, len(tasks))
	for i := range tasks {
		t := tasks[i]
		if t.Running() {
			t.State = TaskStopped
			t.Note = restartedNote
			if t.EndedMs == 0 {
				t.EndedMs = now
			}
			// The result is left exactly as it was — a partial count from a run that really happened
			// is real. What makes it not a complete answer is the state, not a zeroed breakdown.
		}
		r.tasks = append(r.tasks, &t)
		if t.ID >= r.nextID {
			r.nextID = t.ID
		}
	}
	r.dropped = 0
	r.evictLocked()
	r.mu.Unlock()
}

// WithCapacity overrides how many finished tasks are remembered.
func (r *Registry) WithCapacity(c int) *Registry {
	if c < 1 {
		c = 1
	}
	r.mu.Lock()
	r.capacity = c
	r.evictLocked()
	r.mu.Unlock()
	return r
}

// Start registers work that is beginning and returns the handle used to advance and finish it.
//
// total is 0 when the size of the work is not yet known; call Handle.SetTotal once it is. A nil
// registry returns a nil handle, which is a working no-op handle — see the package docs.
func (r *Registry) Start(kind Kind, target string, total uint64) *Handle {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	r.nextID++
	t := &Task{
		ID:        r.nextID,
		Kind:      kind,
		Target:    target,
		State:     TaskRunning,
		Total:     total,
		StartedMs: uint64(time.Now().UnixMilli()),
	}
	r.tasks = append(r.tasks, t)
	r.evictLocked()
	events, id := r.events, t.ID
	r.mu.Unlock()

	// Emitted after the lock is released. The log takes its own mutex, and calling into it while
	// holding this one would make the two orderable — a lock order this package would then have to
	// keep correct forever for no gain.
	events.RecordFor(id, EventTaskStarted, SeverityInfo, string(kind)+": "+target)
	return &Handle{reg: r, id: id}
}

// evictLocked trims the table to capacity by dropping the oldest *finished* tasks.
//
// A running task is never evicted, however old, and however full the table is. The registry exists
// to show what is happening now; dropping a live run to make room for a finished one would answer
// "what is running?" with silence, which is the one answer it must never give. A table entirely full
// of running work therefore grows past capacity, and dropped stays at zero because nothing was
// dropped — an honest overshoot beats a dishonest trim.
func (r *Registry) evictLocked() {
	over := len(r.tasks) - r.capacity
	if over <= 0 {
		return
	}
	kept := make([]*Task, 0, len(r.tasks))
	for _, t := range r.tasks {
		if over > 0 && !t.Running() {
			over--
			r.dropped++
			continue
		}
		kept = append(kept, t)
	}
	r.tasks = kept
}

// findLocked returns the task with this id, or nil. Linear over a table bounded by capacity: an
// index would have to be kept correct through eviction for no measurable gain at 500 entries.
func (r *Registry) findLocked(id uint64) *Task {
	for _, t := range r.tasks {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// Snapshot returns an owned copy of every remembered task, newest first.
//
// Owned rather than a lock guard, and newest first because that is the order the dashboard reads
// them: the run an operator wants to see is the one that just started. Matches
// CoverageTracker.Snapshot in returning values a caller can hold after the lock is released.
func (r *Registry) Snapshot() []Task {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Task, 0, len(r.tasks))
	for i := len(r.tasks) - 1; i >= 0; i-- {
		out = append(out, *r.tasks[i])
	}
	return out
}

// Running counts outstanding tasks.
func (r *Registry) Running() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, t := range r.tasks {
		if t.Running() {
			n++
		}
	}
	return n
}

// Dropped counts finished tasks evicted at the capacity bound. Reported so a dashboard showing "the
// last 500 tasks" can say so rather than presenting a window as the whole history.
func (r *Registry) Dropped() uint64 {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.dropped
}

// Breakdown folds every remembered task into one count, in tasks.
//
// Found is tasks that completed the work they were given; Errored is failures; Gated is runs stopped
// early, either by the operator or by their own budget — a task that finished with an incomplete
// Result stopped looking, and counting it as found is the exact collapse this package exists to
// prevent. Running tasks are Skipped: their answer is not in yet, and folding them into found would
// make a dashboard mid-sweep claim results it does not have.
func (r *Registry) Breakdown() Breakdown {
	var b Breakdown
	for _, t := range r.Snapshot() {
		switch {
		case t.Running():
			b.Skipped++
		case t.State == TaskFailed:
			b.Errored++
		case t.Complete():
			b.Found++
		default:
			b.Gated++
		}
	}
	return b
}

// Reasons explains the registry's own breakdown, one line per non-zero caveat bucket.
func (r *Registry) Reasons() []Reason {
	b := r.Breakdown()
	out := make([]Reason, 0, 3)
	if b.Skipped > 0 {
		out = append(out, Reason{Bucket: BucketSkipped, Detail: "still running; no result yet", Count: b.Skipped})
	}
	if b.Errored > 0 {
		out = append(out, Reason{Bucket: BucketErrored, Detail: "ended on an error", Count: b.Errored})
	}
	if b.Gated > 0 {
		out = append(out, Reason{Bucket: BucketGated, Detail: "stopped early, by the operator or by its own budget", Count: b.Gated})
	}
	return out
}

// Handle is the writer's side of one task. Every method tolerates a nil receiver — see the package
// docs on why.
type Handle struct {
	reg *Registry
	id  uint64
}

// ID is the task's id, for a caller that wants to name it in a log line. Zero for a nil handle.
func (h *Handle) ID() uint64 {
	if h == nil {
		return 0
	}
	return h.id
}

// update applies fn to the task under the registry's lock, if the handle and the task are both live.
func (h *Handle) update(fn func(*Task)) {
	if h == nil || h.reg == nil {
		return
	}
	h.reg.mu.Lock()
	defer h.reg.mu.Unlock()
	if t := h.reg.findLocked(h.id); t != nil {
		fn(t)
	}
}

// WithCancel derives a cancellable context from parent and registers its cancel function against
// this task, returning the derived context and its cancel.
//
// This is the one cancellation primitive in the process, and it has three consumers — sequencer
// capture, audit-task cancel, and intruder attack stop. Each of those had to answer "stop" somehow,
// and without a primitive each answered it separately and wrongly: the sequencer's /stop returned
// `{"stopped": true}` for a loop that did not exist.
//
// The caller must still `defer cancel()`, exactly as with context.WithCancel: the returned function
// is the real one, not a wrapper, and the registry holding a copy of it is not a substitute for
// releasing the context when the work ends. Finish/Stop/Fail also call it, so a task that ends
// normally does not leave a derived context attached to its parent — but that is belt-and-braces, not
// a licence to drop the defer.
//
// A nil handle returns a cancellable context anyway rather than the parent unchanged: the caller's
// select on ctx.Done() must compile and behave the same whether or not a registry is wired, which is
// the same reason every other method here is nil-safe.
func (h *Handle) WithCancel(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	h.update(func(t *Task) { t.cancel = cancel })
	return ctx, cancel
}

// Cancel asks the task with this id to stop, and reports whether there was a running cancellable
// task to ask.
//
// The three return-ish states are deliberately distinguishable by the caller through this bool plus
// its own lookup, because they are three different answers to "did my stop button work": no such
// task, a task that already finished, and a task that never registered a cancel function. A route
// that collapsed them into `{"stopped": true}` is precisely the defect this primitive exists to
// remove.
//
// Cancelling does not itself move the task to TaskStopped. The work does that, by noticing its
// context and calling Handle.Stop with what it had found — a partial result from a cancelled run is
// real, and the registry marking it stopped from out here would have to invent the breakdown.
func (r *Registry) Cancel(id uint64) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	var cancel func()
	if t := r.findLocked(id); t != nil && t.Running() {
		cancel = t.cancel
	}
	r.mu.Unlock()
	// Called with no lock held. context's cancel closes a channel and returns without blocking, so
	// holding mu would be safe today — but the goroutine it wakes will call Handle.Stop, which takes
	// mu, and keeping the two unorderable is worth more than one saved unlock.
	if cancel == nil {
		return false
	}
	cancel()
	return true
}

// CancelKind asks every running cancellable task of this kind to stop, and returns how many it
// asked. Zero means there was nothing running to stop — which is the honest answer a "stop the
// capture" route needs in order to say so.
func (r *Registry) CancelKind(kind Kind) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	var cancels []func()
	for _, t := range r.tasks {
		if t.Kind == kind && t.Running() && t.cancel != nil {
			cancels = append(cancels, t.cancel)
		}
	}
	r.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return len(cancels)
}

// RunningOfKind returns the ids of running tasks of this kind, newest last. Lets a route report which
// run it is talking about instead of asserting that one exists.
func (r *Registry) RunningOfKind(kind Kind) []uint64 {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []uint64
	for _, t := range r.tasks {
		if t.Kind == kind && t.Running() {
			out = append(out, t.ID)
		}
	}
	return out
}

// Advance adds n to the task's completed count.
func (h *Handle) Advance(n uint64) { h.update(func(t *Task) { t.Done += n }) }

// SetTotal records the size of the work once it is known, for a task started before it was.
func (h *Handle) SetTotal(total uint64) { h.update(func(t *Task) { t.Total = total }) }

// SetNote replaces the task's one-line status.
func (h *Handle) SetNote(note string) { h.update(func(t *Task) { t.Note = note }) }

// finish moves the task to a terminal state. Already-terminal tasks are left alone: the first
// terminal answer is the true one, and letting a late Finish overwrite an earlier Fail would hide
// the failure.
//
// The finished event is emitted only for the transition that actually happened, so a late Finish over
// an earlier Fail produces no second event either — the event log and the task table cannot disagree
// about how a run ended.
func (h *Handle) finish(state TaskState, result Breakdown, note string) {
	var finished *Task
	var release func()
	h.update(func(t *Task) {
		if !t.Running() {
			return
		}
		t.State = state
		t.Result = result
		if note != "" {
			t.Note = note
		}
		t.EndedMs = uint64(time.Now().UnixMilli())
		snapshot := *t
		finished = &snapshot
		// A derived context stays attached to its parent until cancelled, so a finished task holding
		// an uncalled cancel is a leak for as long as the parent lives — and for an audit that is the
		// whole process. Cleared as well as called, so Cancellable() stops claiming a finished task
		// can be stopped.
		release, t.cancel = t.cancel, nil
	})
	if release != nil {
		release()
	}
	if finished == nil {
		return
	}
	// Warn rather than info when the run did not cover what it was given: a bounded or stopped run
	// scrolling past at the same weight as a clean one is how a bound gets read as a clean result.
	sev := SeverityInfo
	switch {
	case state == TaskFailed:
		sev = SeverityError
	case !finished.Complete():
		sev = SeverityWarn
	}
	detail := string(finished.Kind) + ": " + finished.Result.Summary()
	if finished.Note != "" {
		detail += " — " + finished.Note
	}
	h.reg.emit(finished.ID, EventTaskFinished, sev, detail)
}

// emit records one event against this registry's log, if it has one. Takes the read lock only to read
// the sink pointer, and calls the log with no lock held — see WithEvents.
func (r *Registry) emit(taskID uint64, kind string, sev Severity, detail string) {
	if r == nil {
		return
	}
	r.mu.RLock()
	log := r.events
	r.mu.RUnlock()
	log.RecordFor(taskID, kind, sev, detail)
}

// Finish marks the work done and attaches what it found.
//
// The result is required rather than optional: a task that reports a count on the dashboard must
// report what it did not look at, and an optional breakdown is one every caller would eventually
// omit. Pass Breakdown{} only when the work genuinely produced no count.
func (h *Handle) Finish(result Breakdown) { h.finish(TaskDone, result, "") }

// FinishWithNote is Finish plus the one line that explains a bounded result.
func (h *Handle) FinishWithNote(result Breakdown, note string) { h.finish(TaskDone, result, note) }

// Stop marks the work ended early by the operator or a cancelled context, keeping whatever it had
// found by then — a stopped run's partial findings are real findings.
func (h *Handle) Stop(result Breakdown, why string) { h.finish(TaskStopped, result, why) }

// Fail marks the work ended on an error.
func (h *Handle) Fail(err error) {
	why := "failed"
	if err != nil {
		why = err.Error()
	}
	h.finish(TaskFailed, Breakdown{Errored: 1}, why)
}
