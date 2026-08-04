// Runtime coverage for the passive check set: which checks actually ran, and for the ones that
// did not, why.
//
// # The gap this closes
//
// PassiveScanner.scanBChecks must not let one bad check silence the rest — a Java-only regex
// construct in check 40 cannot be allowed to stop checks 41 through 105 from running. That
// continue-past-an-error behaviour is correct and stays exactly as it was. What was missing is
// that nothing counted it: a check erroring on every single response was indistinguishable, from
// the outside, from a check that ran cleanly and never fired. CoverageTracker is the record that
// makes the two distinguishable.
//
// # Why per-check identity, not just a count
//
// "26 checks never ran" tells an operator nothing they can act on. "These 26, because their regex
// does not compile in this engine" does. LoadReport already has the weaker shape — counts only,
// identities dropped at classification time — and repeating that here would throw away the same
// information a second time.
//
// # Why the default is "not run", never "ran"
//
// CheckCoverage's zero value has every counter at zero, which State reads as NeverDispatched. A
// record only leaves that state when CoverageTracker.RecordScan is actually called with evidence
// for it — a check is never assumed to have run just because it was loaded. That is the fail-safe
// direction: an instrumentation bug that forgets to wire a call site leaves that check looking
// unknown, not clean.
//
// # Why one lock per scan, not one per check
//
// PassiveScanner can be scanned from several off-hot-path tasks concurrently, so the per-check
// table sits behind an RWMutex. Taking that lock once per check, per response, would mean 105 lock
// acquisitions for one proxied response. Instead scanBChecks evaluates every check against its
// local deltas buffer first — plain stack/heap memory, no lock involved — and RecordScan takes the
// write lock exactly once to fold the whole buffer in.
//
// This is a faithful port of crates/scanner/src/coverage.rs. The one deliberate divergence is that
// the Rust CoverageReport carries a `native` field for SCAN-01/SCAN-02; the Go port has no native
// check set yet, so there is nothing to report and the field is omitted rather than carried empty.
package scanner

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// Why Scan returned before any check even got a chance to run.
//
// Each of these used to collapse into a return of nil, the same value a response that was
// genuinely scanned and found clean produces. That collapse is the defect this type exists to
// name: a caller reading only the return value cannot tell "scanned, clean" from "never looked".
type ScanSkip int

const (
	// NoChecksLoaded means no passive checks are loaded, so there was nothing to run regardless
	// of the exchange.
	ScanSkipNoChecksLoaded ScanSkip = iota
	// ExchangeNotFound means the exchange is not in the store.
	ScanSkipExchangeNotFound
	// OutOfScope means the exchange's host/port/path/TLS falls outside the engagement scope.
	ScanSkipOutOfScope
	// ResponseNotFound means the response is not in the store.
	ScanSkipResponseNotFound
)

// ScanSkipAll is all four, in the order Scan tests them — so a caller iterating this slice sees
// skips in the same order the early returns would fire.
var ScanSkipAll = [4]ScanSkip{
	ScanSkipNoChecksLoaded,
	ScanSkipExchangeNotFound,
	ScanSkipOutOfScope,
	ScanSkipResponseNotFound,
}

// Explanation is one line an operator can act on.
func (s ScanSkip) Explanation() string {
	switch s {
	case ScanSkipNoChecksLoaded:
		return "no passive checks are loaded"
	case ScanSkipExchangeNotFound:
		return "the exchange id is not in the store"
	case ScanSkipOutOfScope:
		return "the host is outside the engagement scope"
	case ScanSkipResponseNotFound:
		return "the response id is not in the store"
	}
	return "unknown skip"
}

// slot is the position in ScanSkipAll, and the matching slot in CoverageTracker.skips. A switch
// rather than a slice-index search: the mapping must be total and exhaustive at compile time, not
// discovered by a runtime search that could come back empty.
func (s ScanSkip) slot() int {
	switch s {
	case ScanSkipNoChecksLoaded:
		return 0
	case ScanSkipExchangeNotFound:
		return 1
	case ScanSkipOutOfScope:
		return 2
	case ScanSkipResponseNotFound:
		return 3
	}
	panic("unknown ScanSkip")
}

// CoverageState is the bucket a reporting caller should actually show for one check, collapsed
// from the raw counters on CheckCoverage.
//
// Erroring beats a clean run: a check that errored on some responses and ran cleanly on others is
// Errored, not RanClean. A partly-broken check is not a trustworthy negative result, and picking
// whichever counter is larger would let one clean response paper over ninety-nine broken ones.
type CoverageState int

const (
	// CoverageStateNeverDispatched means no evidence this check was ever handed a response.
	CoverageStateNeverDispatched CoverageState = iota
	// CoverageStateRanClean means the check ran at least once, never errored, and never produced
	// a finding.
	CoverageStateRanClean
	// CoverageStateRanAndFound means the check ran at least once, never errored, and produced at
	// least one finding.
	CoverageStateRanAndFound
	// CoverageStateErrored means the check errored at least once; CheckCoverage.Errored and
	// CheckCoverage.LastError carry the detail.
	CoverageStateErrored
)

// CoverageStateAll is all four, so a caller can build a histogram without hard-coding which
// states exist — mirrors ScanSkipAll for the same reason.
var CoverageStateAll = [4]CoverageState{
	CoverageStateNeverDispatched,
	CoverageStateRanClean,
	CoverageStateRanAndFound,
	CoverageStateErrored,
}

func (s CoverageState) String() string {
	switch s {
	case CoverageStateNeverDispatched:
		return "never dispatched"
	case CoverageStateRanClean:
		return "ran clean"
	case CoverageStateRanAndFound:
		return "ran and found"
	case CoverageStateErrored:
		return "errored"
	}
	return "unknown state"
}

// CheckCoverage is runtime evidence for one loaded passive check.
//
// The zero value has every counter at zero, which State reads as NeverDispatched — the safe
// direction, covered in the package docs.
type CheckCoverage struct {
	Name string `json:"name"`
	// Ran counts responses this check evaluated without erroring, whether or not it found
	// anything.
	Ran uint64 `json:"ran"`
	// Findings counts findings produced across every response in Ran. It can exceed Ran: one
	// response can carry more than one match.
	Findings uint64 `json:"findings"`
	// Errored counts responses where the evaluator returned an error instead of a verdict. It is
	// kept as its own counter rather than folded into Ran, because a check erroring on every
	// response must never be read as having run cleanly.
	Errored uint64 `json:"errored"`
	// LastError is the most recently observed runtime error. Non-empty exactly when Errored > 0.
	LastError string `json:"last_error,omitempty"`
}

// State collapses the raw counters into the bucket a caller should render. See CoverageState for
// why errored takes priority over a nonzero Ran.
func (c CheckCoverage) State() CoverageState {
	if c.Errored > 0 {
		return CoverageStateErrored
	}
	if c.Ran == 0 {
		return CoverageStateNeverDispatched
	}
	if c.Findings > 0 {
		return CoverageStateRanAndFound
	}
	return CoverageStateRanClean
}

// SkipCount is one exchange-level skip reason and how many times it fired.
type SkipCount struct {
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
}

// CoverageReport is an owned, point-in-time snapshot of every loaded passive check's runtime
// coverage, plus how many times Scan returned before any check ran.
//
// Owned rather than a lock guard, so a reporting caller can hold this after the call returns
// instead of holding PassiveScanner locked while it renders — the same shape as
// PassiveScanner.Report and PassiveScanner.GetFindings.
type CoverageReport struct {
	// Checks holds one entry per loaded passive check, in load order.
	Checks []CheckCoverage `json:"checks"`
	// Skips holds one count per ScanSkip reason, in ScanSkipAll order.
	Skips []SkipCount `json:"skips"`
}

// Count reports how many loaded checks are in state.
func (r CoverageReport) Count(state CoverageState) int {
	n := 0
	for _, c := range r.Checks {
		if c.State() == state {
			n++
		}
	}
	return n
}

// CoverageCount pairs one state with how many checks landed in it.
type CoverageCount struct {
	State CoverageState `json:"state"`
	Count int           `json:"count"`
}

// Partition returns the full state histogram over every loaded check.
//
// A tested invariant: summing these must equal the number of loaded checks. CheckCoverage.State is
// catch a future state added to CoverageStateAll without being wired into that classification,
// rather than that gap silently under-reporting coverage.
func (r CoverageReport) Partition() [4]CoverageCount {
	var out [4]CoverageCount
	for i, st := range CoverageStateAll {
		out[i] = CoverageCount{State: st, Count: r.Count(st)}
	}
	return out
}

// Summary formats runtime coverage for reports and logs.
func (r CoverageReport) Summary() string {
	if len(r.Checks) == 0 {
		return "no passive checks loaded"
	}
	p := r.Partition()
	return fmt.Sprintf(
		"%d passive checks: %d never dispatched, %d ran clean, %d found, %d errored",
		len(r.Checks),
		p[0].Count,
		p[1].Count,
		p[2].Count,
		p[3].Count,
	)
}

// ScanDelta is one check's outcome for one scan: a findings count (0 is a clean run, not an
// error) or, when Err is non-empty, an error message.
type ScanDelta struct {
	Findings uint64
	Err      string
}

// CoverageTracker is the mutable coverage table PassiveScanner holds.
//
// Unexported: PassiveScanner.Coverage is the only way in, returning an owned CoverageReport rather
// than exposing the lock.
type CoverageTracker struct {
	mu       sync.RWMutex // guards perCheck
	perCheck []CheckCoverage
	// skips is indexed by ScanSkip.slot. Plain atomics rather than a lock: each early return in
	// Scan increments exactly one counter and nothing else, so there is no batch to fold in the
	// way RecordScan folds a whole check set.
	skips [4]atomic.Uint64
}

// NewCoverageTracker makes one record per check, named and zeroed, in the same order as the
// passive check set — so a check's position here always matches its position in the deltas passed
// to RecordScan.
func newCoverageTracker(checks []*bcheck.Check) *CoverageTracker {
	per := make([]CheckCoverage, len(checks))
	for i, c := range checks {
		per[i] = CheckCoverage{Name: c.Name}
	}
	return &CoverageTracker{perCheck: per}
}

// RecordSkip records one whole-exchange skip. Relaxed ordering: this is an independent counter
// with no other memory it needs to stay ordered against.
func (t *CoverageTracker) RecordSkip(why ScanSkip) {
	t.skips[why.slot()].Add(1)
}

// RecordScan folds one scan's worth of per-check outcomes into the table in a single write-lock
// acquisition.
//
// deltas is index-aligned with the passive check set: a delta with Err == "" means the check ran
// and produced Findings (0 is a clean run, not an error); Err != "" means it errored this time.
func (t *CoverageTracker) RecordScan(deltas []ScanDelta) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range deltas {
		if i >= len(t.perCheck) {
			break
		}
		rec := &t.perCheck[i]
		if deltas[i].Err != "" {
			rec.Errored++
			rec.LastError = deltas[i].Err
		} else {
			rec.Ran++
			rec.Findings += deltas[i].Findings
		}
	}
}

// Snapshot returns an owned copy of the current table, for PassiveScanner.Coverage.
func (t *CoverageTracker) Snapshot() CoverageReport {
	t.mu.RLock()
	checks := make([]CheckCoverage, len(t.perCheck))
	copy(checks, t.perCheck)
	t.mu.RUnlock()
	skips := make([]SkipCount, 0, len(ScanSkipAll))
	for _, s := range ScanSkipAll {
		skips = append(skips, SkipCount{
			Reason: s.Explanation(),
			Count:  t.skips[s.slot()].Load(),
		})
	}
	return CoverageReport{Checks: checks, Skips: skips}
}
