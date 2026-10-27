package persist

// mirror_health.go makes durable-mirror write failures VISIBLE. The mirror's contract is
// that its write errors are its own to absorb (core/store.go: "a mirror write error is the
// mirror's problem to log, never the traffic's") — but until this file they were absorbed
// into a Warn line and nothing else: no count, no surface, no memory across restarts. A
// process whose disk filled mid-engagement logged lines nobody watched, then restarted
// into state that silently lagged what memory had held — findings gone, rules reverted,
// and nothing anywhere said so (architecture review, weakness 9).
//
// What this file does and does not promise: failed writes are LOST — no reconciliation can
// recover a row the mirror never took, and this file does not pretend one can. What it
// guarantees instead is that the failure is counted, first-reported loudly through the
// installed hook the moment it happens, and reported again on the next Open, so the
// divergence is announced on both sides of the restart instead of on neither.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// mirrorFailuresSettingsKey carries the failure count from one run to the next. Open reads
// and clears it; a session that sees failures rewrites it (on the first failure, then every
// 64th — often enough that a crash loses little, rare enough that a failing disk is not
// hammered with one more write per failure).
const mirrorFailuresSettingsKey = "mirror_write_failures"

// MirrorHealth is the mirror's failure tally for this run. Failures == 0 is the healthy
// state and the overwhelmingly common one.
type MirrorHealth struct {
	Failures int64
	FirstOp  string
	FirstErr string
	FirstAt  time.Time
	LastAt   time.Time
}

// mirrorHealth is the Store's live half: an atomic count for the common question and a
// mutex-guarded detail block for the diagnostic one.
type mirrorHealth struct {
	count   atomic.Int64
	mu      sync.Mutex
	firstOp string
	first   error
	firstAt time.Time
	lastAt  time.Time
	// hook is called on every failure, after recording. The web server installs one that
	// puts the failure on the dashboard's event log — the surface an operator actually
	// watches. Nil in a store nobody wired, which keeps the library usable standalone.
	hook func(op string, err error)
}

// noteWriteFailure is the single recording point; Store.log calls it before logging.
func (s *Store) noteWriteFailure(op string, err error) {
	n := s.health.count.Add(1)
	s.health.mu.Lock()
	if s.health.first == nil {
		s.health.firstOp = op
		s.health.first = err
		s.health.firstAt = time.Now()
	}
	s.health.lastAt = time.Now()
	hook := s.health.hook
	s.health.mu.Unlock()
	// The marker is how the NEXT run learns this one diverged. Best-effort by definition —
	// the disk that just refused a write may refuse this one too, and a marker failure is
	// not a second problem worth logging over the first.
	if n == 1 || n%64 == 0 {
		_ = s.setSetting(mirrorFailuresSettingsKey, fmt.Sprintf("%d", n))
	}
	if hook != nil {
		hook(op, err)
	}
}

// MirrorHealth returns this run's failure tally. Safe on a nil Store, like the other
// accessors — a process with no database has no mirror failures to report.
func (s *Store) MirrorHealth() MirrorHealth {
	if s == nil {
		return MirrorHealth{}
	}
	s.health.mu.Lock()
	defer s.health.mu.Unlock()
	h := MirrorHealth{
		Failures: s.health.count.Load(),
		FirstOp:  s.health.firstOp,
		FirstAt:  s.health.firstAt,
		LastAt:   s.health.lastAt,
	}
	if s.health.first != nil {
		h.FirstErr = s.health.first.Error()
	}
	return h
}

// SetWriteFailureHook installs the callback every mirror write failure runs after being
// recorded. One slot, like the stores' persistence sinks: the durable mirror's owner is
// the process, and the process installs one reporter.
func (s *Store) SetWriteFailureHook(hook func(op string, err error)) {
	s.health.mu.Lock()
	s.health.hook = hook
	s.health.mu.Unlock()
}

// PriorSessionMirrorFailures reports the count the PREVIOUS run of this database recorded,
// read and cleared at Open. Zero means the last run's mirror took every write (or the
// marker could not be read, which Open already logged) — the absence of evidence is
// reported as absence, never as a false all-clear invented here.
func (s *Store) PriorSessionMirrorFailures() int64 {
	if s == nil {
		return 0
	}
	return s.priorMirrorFailures
}

// loadAndClearMirrorFailureMarker is Open's half of the marker protocol: read the previous
// run's count, then remove the row, so the marker always describes the run that just ended
// and never accretes across sessions. A cleared marker reappears only if THIS run sees a
// failure.
func (s *Store) loadAndClearMirrorFailureMarker() {
	v, err := s.getSetting(mirrorFailuresSettingsKey)
	if err != nil {
		s.note("read mirror-failure marker", err)
		return
	}
	if v == "" {
		return
	}
	var n int64
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		s.note("parse mirror-failure marker", fmt.Errorf("value %q: %w", v, err))
		return
	}
	s.priorMirrorFailures = n
	if _, err := s.db.Exec(`DELETE FROM settings WHERE key = ?`, mirrorFailuresSettingsKey); err != nil {
		s.note("clear mirror-failure marker", err)
	}
}
