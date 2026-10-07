package session

// The session-handling tracer (burpsy-react-ui-n29) — Burp's settings/sessions "Open sessions
// tracer": "a listing of every request that has been handled by the session handling
// functionality ... For each request handled, the tracer shows the sequence of rules and
// actions that were carried out. It also shows the changes made to the current request at each
// step in the sequence."
//
// # Opt-in, and why that is the design rather than a limitation
//
// Burp's own prose is the design input: "The session handling tracer imposes a processing and
// storage overhead on all affected HTTP requests. We recommend that you only use the tracer
// when troubleshooting issues with session handling rules." So the tracer is OFF by default,
// and the Session page says the overhead where the toggle is. While off, the only cost is one
// atomic load per handled request — the hot path pays nothing.
//
// # What an entry holds, and why the actions' own trace is reused
//
// Per handled request: when, the request identity (tool, host, path), the rule that matched,
// the recovery outcome, and the action walk — the []ActionRan the rule's own walk already
// records (index, kind, label, detail, changed, skipped), which IS "the sequence of actions
// and the change made at each step" in Burp's terms. Reusing it means the tracer and the
// recovery report can never disagree about what ran; a second trace implementation would be a
// second place the same run gets described.
import (
	"sync"
	"sync/atomic"
	"time"
)

// TraceEntry is one handled request's whole story.
type TraceEntry struct {
	At     time.Time `json:"at"`
	Tool   string    `json:"tool,omitempty"`
	Host   string    `json:"host"`
	Path   string    `json:"path"`
	Rule   string    `json:"rule"`
	RuleID RuleID    `json:"rule_id"`
	// Kind is the recovery outcome as a string: what the coordinator actually did for this
	// request. The enum has no String method; the tracer names it at record time so the wire
	// carries a readable kind without the UI learning an enum.
	Kind string `json:"kind"`
	// Actions is the rule's own walk, in the order it ran — see the package comment.
	Actions []ActionRan `json:"actions,omitempty"`
}

// traceRing is the bounded tracer: a fixed-capacity ring, newest overwriting oldest, written
// only while enabled. Burp's tracer is a listing with an overhead warning; a bound is what
// keeps "only use while troubleshooting" honest — an always-on tracer over a long engagement
// would be an unbounded log the operator never asked to keep.
const traceRingCap = 200

type traceRing struct {
	mu      sync.Mutex
	entries []TraceEntry
	next    int
	on      atomic.Bool
}

// Enable turns the tracer on or off. Off is the default; turning it off keeps what was
// recorded — the entries are the evidence an operator is reading, and a toggle that erased
// them on the way down would destroy the troubleshooting session it was enabled for.
func (t *traceRing) setEnabled(on bool) {
	t.on.Store(on)
}

func (t *traceRing) enabled() bool { return t.on.Load() }

// record appends one entry, dropping the oldest when the ring is full. Called only when
// enabled — the caller checks, so the disabled path costs the one atomic load and nothing else.
func (t *traceRing) record(e TraceEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = make([]TraceEntry, 0, traceRingCap)
	}
	if len(t.entries) < traceRingCap {
		t.entries = append(t.entries, e)
		return
	}
	t.entries[t.next] = e
	t.next = (t.next + 1) % traceRingCap
}

// snapshot returns the entries oldest-first. A copy, so the reader holds a stable answer
// while the ring keeps recording — an operator mid-read must not see the list reshuffle.
func (t *traceRing) snapshot() []TraceEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TraceEntry, 0, len(t.entries))
	if len(t.entries) < traceRingCap {
		out = append(out, t.entries...)
		return out
	}
	out = append(out, t.entries[t.next:]...)
	out = append(out, t.entries[:t.next]...)
	return out
}

// SetTracerEnabled turns the session-handling tracer on or off (burpsy-react-ui-n29). The
// coordinator is nil-safe like every other surface method.
func (c *Coordinator) SetTracerEnabled(on bool) {
	if c == nil {
		return
	}
	c.tracer.setEnabled(on)
}

// TracerEnabled reports whether the tracer is recording.
func (c *Coordinator) TracerEnabled() bool {
	if c == nil {
		return false
	}
	return c.tracer.enabled()
}

// TracerEntries returns the recorded trace, oldest first. Entries recorded before a disable
// are kept: they are the evidence the operator enabled the tracer to collect.
func (c *Coordinator) TracerEntries() []TraceEntry {
	if c == nil {
		return nil
	}
	return c.tracer.snapshot()
}

// recordTrace is the one writer, called from recover() when the tracer is on. The action walk
// rides the outcome Burp's tracer calls "the sequence of rules and actions that were carried
// out ... and the changes made to the current request at each step".
func (c *Coordinator) recordTrace(tool string, original MacroStep, id RuleID, rule *SessionRule, out RecoveryOutcome) {
	if !c.tracer.enabled() {
		return
	}
	identity := identityOf(original.URL)
	c.tracer.record(TraceEntry{
		At:      time.Now(),
		Tool:    tool,
		Host:    identity.Host,
		Path:    identity.Path,
		Rule:    rule.Name,
		RuleID:  id,
		Kind:    recoveryKindName(out.Kind),
		Actions: out.Actions,
	})
}

// recoveryKindName spells one outcome kind for the trace's wire. Named here rather than a
// String() on the enum because the enum is the recovery engine's vocabulary — the API layer
// that renders RecoveryOutcome elsewhere already has its own spellings, and the tracer must
// not become a second place that has to change when a kind is added without being noticed.
func recoveryKindName(k RecoveryOutcomeKind) string {
	switch k {
	case RecoveryNoRuleApplies:
		return "no rule applies"
	case RecoveryAlreadyValid:
		return "already valid"
	case RecoveryRecovered:
		return "recovered"
	case RecoveryStillInvalidAfterRelogin:
		return "still invalid after re-login"
	case RecoveryGaveUp:
		return "gave up"
	case RecoveryRetryFailed:
		return "retry failed"
	case RecoveryMacroFailed:
		return "macro failed"
	case RecoveryRuleApplied:
		return "rule applied"
	}
	return "unknown"
}
