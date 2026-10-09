package dash

import (
	"encoding/json"
	"sync"
	"time"
)

// ---- the event log (DASH-02) --------------------------------------------------------------------
//
// # Why this is not internal/toollog
//
// toollog was the obvious home and it is the wrong one, because the two logs count different things.
// A toollog.Entry is one *sent request*: host, port, method, path, status, duration. DASH-02 asks for
// "an event log of what the tool did", and most of what the tool does is not a request — a task
// started, the scope was edited, a crawl stopped at its frontier bound, live audit was switched on,
// three destructive links were refused. None of those has a host, a status, or a path.
//
// The evidence that they do not fit is already in the tree: the live sweep used to record its own
// completion into toollog as `Record(ToolScanner, host, port, tls, "LIVE", "/audit", 0, ...)` — a
// request row for something that is not a request, with a made-up method and a made-up path, so that
// an event could travel down a pipe shaped for requests. That row is gone; this type is what replaced
// it.
//
// So there are two logs, each honest about its unit, and neither able to disagree with the other
// about the same fact. It is the same argument Breakdown makes about never summing found and skipped.
//
// # Why it lives beside the task registry
//
// Most events are task lifecycle, and Registry.WithEvents emits them — so wiring one log into one
// registry gives every task in the process, including a crawl this package knows nothing about,
// start/finish events for free. Putting the log anywhere else would mean either the registry
// depending on another package or every caller emitting lifecycle events by hand, and the second one
// is how half the callers end up not doing it.
//
// # Why it must not be fed from a store observer
//
// It would be tempting to derive events from core.TrafficStore.ObserveExchanges. Don't:
// AddExchange runs its observers *under the store's write lock*, on the append path, so every
// proxied response and every crawler fetch waits behind them. Formatting a string and appending to a
// bounded slice under that lock makes the store lock both the crawl's throughput ceiling and a proxy
// latency tax. Events are recorded by explicit calls, at the point the thing happened, off that path.

// Severity is how loud an event is. Three levels, because the UI needs to distinguish "this happened"
// from "this happened and you should know" from "this failed", and a fourth would not change what an
// operator does about it.
type Severity int

const (
	// SeverityInfo is the ordinary course of events.
	SeverityInfo Severity = iota
	// SeverityWarn is something that bounded, stalled or was refused — the work continued, but not
	// over everything it was pointed at.
	SeverityWarn
	// SeverityError is something that failed.
	SeverityError
)

// SeverityAll is all three, so a caller can build a filter without hard-coding the set.
var SeverityAll = [3]Severity{SeverityInfo, SeverityWarn, SeverityError}

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityError:
		return "error"
	}
	return "unknown severity"
}

// MarshalJSON writes the name rather than the ordinal, matching TaskState and Disposition.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON reads the name back, so a persisted event round-trips to the severity it was written
// with rather than silently to info.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	for _, candidate := range SeverityAll {
		if candidate.String() == name {
			*s = candidate
			return nil
		}
	}
	// An unknown name is not info. Warn, so a severity this build does not recognise is visible
	// rather than quietly downgraded to the least interesting level.
	*s = SeverityWarn
	return nil
}

// Event kinds. Named constants rather than free strings at the call sites, so a UI can filter on them
// and a reader can grep for every place a kind is emitted. The set is open — an unrecognised kind
// renders under its own name rather than being dropped — but everything this tree emits is here.
const (
	EventTaskStarted       = "task.started"
	EventTaskFinished      = "task.finished"
	EventScopeChanged      = "scope.changed"
	EventLiveAuditEnabled  = "liveaudit.enabled"
	EventLiveAuditDisabled = "liveaudit.disabled"
	EventLiveAuditScoped   = "liveaudit.scoped"
	EventLiveAuditStalled  = "liveaudit.stalled"
	EventLiveAuditSkipped  = "liveaudit.skipped"
	EventLiveAuditBounded  = "liveaudit.bounded"
	EventLedgerReset       = "audit.ledger_reset"
	// EventAuditBounded is a bulk audit that stopped before it ran everything — the crawl-and-audit
	// scan's audit phase. Its own kind rather than reusing EventLiveAuditBounded: "liveaudit" names
	// the always-on sweep over proxied traffic, and an operator filtering the log for what the live
	// sweep did should not get rows from a scan they launched by hand.
	EventAuditBounded = "audit.bounded"
	// EventCrawlBounded and EventCrawlRefused are declared here, unused by this package, so the
	// crawler names its events rather than inventing spellings the UI has never seen.
	EventCrawlBounded = "crawl.bounded"
	EventCrawlRefused = "crawl.refused"
	// EventCrawlLogin is a crawl's recorded-login replay starting, succeeding or failing — Burp's
	// RECORDED_SEQUENCE_STARTED / RECORDED_SEQUENCE_ERROR crawl events (burpsy-react-ui-xhtk).
	EventCrawlLogin = "crawl.login"
)

// Event is one thing the tool did.
type Event struct {
	ID       uint64   `json:"id"`
	Kind     string   `json:"kind"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
	// TaskID links the event to a registry task, or 0 when it is not about one. Zero rather than a
	// pointer because task ids start at 1 — see Registry.Start.
	TaskID uint64 `json:"task_id,omitempty"`
	AtMs   uint64 `json:"at_ms"`
}

// DefaultEventCapacity bounds how many events are remembered.
//
// Two thousand rather than toollog's hundred thousand, because these are coarser: one per task, one
// per scope edit, one per bound hit. The exception that sizes it is a crawl refusing destructive
// links, which can emit a few thousand in one run — so the bound is generous enough to hold a whole
// crawl's refusals and small enough that a long engagement cannot grow it without limit. What is
// dropped is counted, and Dropped is reported, so a window is never presented as the whole history.
const DefaultEventCapacity = 2000

// EventLog is a bounded, oldest-first-evicting log of what the tool did.
//
// Every method tolerates a nil receiver, for the same reason Handle does: callers record events
// unconditionally, and a nil check someone forgets is a panic in the middle of a crawl.
type EventLog struct {
	mu       sync.Mutex
	events   []*Event
	capacity int
	dropped  uint64
	nextID   uint64
	// onChange is an optional signal that an event was recorded, for the live-update stream (see
	// OnChange). No payload: its consumer tells a browser that /api/dashboard is stale and lets that
	// handler render the event, so there stays one place that serialises one.
	onChange func()
}

// NewEventLog creates an empty log at the default capacity.
func NewEventLog() *EventLog { return &EventLog{capacity: DefaultEventCapacity} }

// WithCapacity overrides how many events are remembered.
func (l *EventLog) WithCapacity(c int) *EventLog {
	if l == nil {
		return nil
	}
	if c < 1 {
		c = 1
	}
	l.mu.Lock()
	l.capacity = c
	l.evictLocked()
	l.mu.Unlock()
	return l
}

// Record appends one event and returns its id.
func (l *EventLog) Record(kind string, sev Severity, detail string) uint64 {
	return l.RecordFor(0, kind, sev, detail)
}

// RecordFor is Record for an event about a specific task.
func (l *EventLog) RecordFor(taskID uint64, kind string, sev Severity, detail string) uint64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nextID++
	l.events = append(l.events, &Event{
		ID:       l.nextID,
		Kind:     kind,
		Severity: sev,
		Detail:   detail,
		TaskID:   taskID,
		AtMs:     uint64(time.Now().UnixMilli()),
	})
	l.evictLocked()
	if l.onChange != nil {
		l.onChange()
	}
	return l.nextID
}

// OnChange installs the signal called after an event is recorded, or nil to remove it. Single slot, so
// re-installing replaces rather than doubling.
//
// It runs under the log's lock, which is taken from Registry.emit — so from wherever a task started or
// finished, including a crawl. Held to the same contract as the traffic store's observers: increment a
// counter, signal non-blockingly, and do the work somewhere that is not this stack.
func (l *EventLog) OnChange(fn func()) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onChange = fn
}

// evictLocked trims to capacity, oldest first, counting what it drops. Unlike Registry.evictLocked
// there is nothing here that must be kept: an event is a record of something that already finished,
// so the oldest is always the least useful.
func (l *EventLog) evictLocked() {
	if over := len(l.events) - l.capacity; over > 0 {
		l.dropped += uint64(over)
		l.events = l.events[over:]
	}
}

// Recent returns the newest n events, newest first. n <= 0 returns all of them.
//
// Newest first because that is the order the dashboard reads them, and owned values rather than the
// stored pointers so a caller can hold the result after the lock is released.
func (l *EventLog) Recent(n int) []Event {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.events) {
		n = len(l.events)
	}
	out := make([]Event, 0, n)
	for i := len(l.events) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, *l.events[i])
	}
	return out
}

// Count reports how many events are remembered.
func (l *EventLog) Count() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

// Dropped reports how many were evicted at the capacity bound.
func (l *EventLog) Dropped() uint64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

// Restore replaces the log's contents with a previously persisted snapshot, resuming ids above the
// highest restored one so they stay unique. Mirrors toollog.Restore, including resetting dropped:
// what a previous process dropped is not something this one can report on.
func (l *EventLog) Restore(events []Event) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = make([]*Event, 0, len(events))
	for i := range events {
		e := events[i]
		l.events = append(l.events, &e)
		if e.ID >= l.nextID {
			l.nextID = e.ID
		}
	}
	l.dropped = 0
	l.evictLocked()
}

// Clear discards every remembered event, emptying the window the dashboard reads. It backs the
// "Clear event log" action (Burp's burp.Zbuz): the source the feed reads is cleared, not a
// client-side view of it, so after a clear the feed is genuinely empty and the next thing the tool
// does is its first row again.
//
// dropped is reset with it, following Restore rather than toollog.Clear. dropped counts what was
// evicted at the capacity bound so that a window is never presented as the whole history; once the
// operator has discarded the window on purpose there is no window left for that count to qualify,
// and reporting "0 events, 312 dropped at the bound" would be a caveat about history that was just
// thrown away deliberately. nextID is left untouched so ids stay unique across a clear, the same
// contract Restore keeps.
//
// onChange fires under the lock, the same contract as RecordFor: it tells the live stream the
// dashboard aggregate is stale, so a clear driven from one browser empties the feed in every other.
func (l *EventLog) Clear() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = nil
	l.dropped = 0
	if l.onChange != nil {
		l.onChange()
	}
}
