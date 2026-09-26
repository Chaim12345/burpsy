// The audit engine's driver: the check set, the dispatch plan, the per-item and per-session
// outcomes, and the admission gate that bounds them. audit.go holds the vocabulary this file
// dispatches with.
//
// This is the Go counterpart of `PassiveScanner::audit_item` / `audit_session` /
// `AuditOutcome` / `SessionOutcome` / `Run` / `Metered` in crates/scanner/src/lib.rs. It is split
// out from audit.go the same way the Rust original splits the model (audit.rs) from the driver
// (lib.rs).
//
// # What the check set is here
//
// Two sources, both dispatched by this engine. First, the built-in table: seven ScanConfig
// switches in front of five hand-written implementations, made explicit as activeCheckSet — one
// entry per switch, each with the dispatch scope its answer is keyed at and the function that
// runs it. Second, the loaded BCheck corpus's active checks (`given host/path/request`, plus the
// insertion-point set), which enter as activeCheck entries built by corpusActiveChecks from the
// checks WithCorpusChecks supplied. The engine above the table is scope-agnostic, which is what
// lets the corpus entries ride the same plan/ledger/disposition machinery as the built-ins.
//
// Two of the seven switches — CheckSSRF and CheckXXE — have no implementation behind them. They are
// in the table with a nil runner and dispatch as DispositionUnsupported, which is the honest answer:
// before this engine existed, NewActiveScanner switched CheckSSRF *on* by default and nothing ran,
// so an operator reading a clean audit had no way to know two of the checks they had enabled were
// not there. Leaving them out of the table entirely would have preserved exactly that silence.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// activeCheck is one built-in active check: its identity, the dispatch scope its answer is keyed at,
// the ScanConfig switch that puts it in the set, and the function that runs it.
//
// run is nil for a check that is configurable but not implemented. Such a check is still counted —
// see the file header for why that is the point rather than an oversight.
type activeCheck struct {
	name    string
	scope   DispatchScope
	enabled func(*ScanConfig) bool
	// invasiveness is the tier the `scan_type_*_active` keys select this check under. It is
	// snapshotted with the set rather than looked up per dispatch, so a check cannot change tier
	// between two items of one session.
	invasiveness CheckInvasiveness
	// passive marks a check that reads the request and its response without sending a probe of its
	// own. Those hang from `scan_type_passive`, not from the three active tiers, so a preset that
	// turns every active tier off still runs them — a passive check cannot change server state,
	// which is the property the intrusive tier exists to protect.
	passive bool
	// run executes the check. The error is the evaluator's refusal, not a transport detail: a
	// check the evaluator cannot run at all returns errCheckUnsupported so the audit engine
	// counts it DispositionUnsupported (Skipped) rather than a clean miss, and any other error
	// — a failed send, an impossible payload placement — counts as DispositionSendFailed.
	// A nil run stays the table's honest "configurable but not implemented" marker: counted as
	// undispatchable, never admitted.
	run func(*ActiveScanner, context.Context, *core.Exchange) ([]*Finding, error)
}

// activeCheckSet is the built-in active check set, adapted from the typed
// registry in check_registry.go. The audit ledger still receives a stable,
// ordered slice, while new check logic uses CheckDescriptor.
var activeCheckSet = nativeActiveCheckSet()

// enabledChecks is the check set one run dispatches: the built-in table entries whose ScanConfig
// switch is on, in table order, followed by the loaded corpus's active checks when the corpus
// switch is on.
//
// Snapshotted once per run, because a check's position in this slice is its identity in the
// AuditLedger. A set that changed size between two items of one session would make the ledger's
// bits describe different checks for different items. That also fixes the snapshot point for the
// corpus: a corpus loaded mid-session joins the next run, never a run already in flight.
func (s *ActiveScanner) enabledChecks() []activeCheck {
	if s == nil {
		return nil
	}
	cfg := s.ConfigSnapshot()
	s.mu.RLock()
	corpus := s.corpus
	s.mu.RUnlock()
	out := make([]activeCheck, 0, len(activeCheckSet)+len(corpus))
	for _, c := range activeCheckSet {
		if c.enabled(&cfg) {
			out = append(out, c)
		}
	}
	if cfg.CheckCorpus {
		out = append(out, s.corpusActiveChecks(corpus)...)
	}
	return out
}

// ActiveCheckCount reports how many checks are in the set this scanner would dispatch — the figure
// AuditOutcome.Considered must equal for a dispatched item.
func (s *ActiveScanner) ActiveCheckCount() int { return len(s.enabledChecks()) }

// auditLevelPassiveFamilies are the ScanConfig switches the passive check families hang from. They
// are what `scanner/issues_reported/scan_type_passive` gates: a shipped configuration that turns
// passive checking off zeroes exactly these, and a check survives only if its own family switch
// still admits it — so a family added without a row here would simply ignore the gate, which is
// why the test walks the ScanConfig switch list against these maps.
var auditLevelPassiveFamilies = []string{
	"CheckPassiveAnalysis",
	"CheckPassivePosture",
	"CheckHostDiscovery",
	"CheckHeaders",
}

// auditLevelJavaScriptFamilies is the DOM family.
var auditLevelJavaScriptFamilies = []string{"CheckDOM"}

// auditLevelNotesText is the honest statement of where the issues_reported overlay bends, reported
// beside the resolved configuration so an operator comparing burpsy against Burp's own preview of
// the same preset sees the difference explained rather than discovered.
//
// The light/medium/intrusive tiers are no longer part of it: each check carries a rank and each key
// selects its own set. What remains is the per-issue selection trio, which has no representation in
// this engine.
const auditLevelNotesText = tieredEngineNote

// auditLevelNotes reports the approximation text when the configuration narrows the check set, and
// nothing when it does not — a run under the base switches has nothing to disclaim.
func auditLevelNotes(cfg AuditConfig) string {
	if cfg.hasAuditLevelGate() {
		return auditLevelNotesText
	}
	return ""
}

// enabledChecksUnder is the check set one run dispatches under an audit-level overlay: the base
// switch set from ScanConfig, narrowed by the `scanner/issues_reported/*` keys the run's
// configuration carries. Unset keys leave the base alone, so a run without an overlay is exactly
// enabledChecks.
func (s *ActiveScanner) enabledChecksUnder(cfg AuditConfig) []activeCheck {
	if !cfg.hasAuditLevelGate() {
		return s.enabledChecks()
	}
	base := s.ConfigSnapshot()
	if cfg.PassiveChecks.Set && cfg.PassiveChecks.Value == 0 {
		zeroFamilies(&base, auditLevelPassiveFamilies)
	}
	if cfg.JavaScriptAnalysis.Set && cfg.JavaScriptAnalysis.Value == 0 {
		zeroFamilies(&base, auditLevelJavaScriptFamilies)
	}
	// activeTiers returns nil when no tier key was set, which leaves the base switches alone; a
	// non-nil set is three independent selections rather than one collapsed gate.
	return s.enabledChecksInTiers(base, activeTiers(cfg))
}

// hasAuditLevelGate reports whether the configuration narrows the check set at all.
func (cfg AuditConfig) hasAuditLevelGate() bool {
	if cfg.PassiveChecks.Set && cfg.PassiveChecks.Value == 0 {
		return true
	}
	if activeTiers(cfg) != nil {
		return true
	}
	return cfg.JavaScriptAnalysis.Set && cfg.JavaScriptAnalysis.Value == 0
}

// activeTiers is the tier selection a preset's three `scan_type_*_active` keys express. A tier set
// to 0 is absent from the result; a tier never named is absent too, and its checks are excluded
// because a key that was not written is an operator who said nothing about that tier, not one who
// asked for it to be off.
//
// A nil result means no tier key was set at all, and the base switches stand unchanged — the
// distinction matters because nil is the "inherit" signal enabledChecksInTiers reads, while an empty
// non-nil map would be "every tier off".
//
// The old gate returned one bool, "are all three off?", which made a preset that disabled only the
// light tier indistinguishable from one that disabled all three, and a preset that enabled light
// while disabling intrusive indistinguishable from one that enabled everything. Each key now
// selects its own set.
func activeTiers(cfg AuditConfig) map[CheckInvasiveness]bool {
	var light, medium, intrusive OptUint32
	light, medium, intrusive = cfg.LightActiveChecks, cfg.MediumActiveChecks, cfg.IntrusiveActiveChecks
	if !light.Set && !medium.Set && !intrusive.Set {
		return nil
	}
	out := make(map[CheckInvasiveness]bool, 3)
	if light.Set && light.Value != 0 {
		out[TierLight] = true
	}
	if medium.Set && medium.Value != 0 {
		out[TierMedium] = true
	}
	if intrusive.Set && intrusive.Value != 0 {
		out[TierIntrusive] = true
	}
	return out
}

// zeroFamilies flips the named ScanConfig switches off in place.
func zeroFamilies(cfg *ScanConfig, families []string) {
	for _, f := range families {
		switch f {
		case "CheckSqli":
			cfg.CheckSqli = false
		case "CheckXss":
			cfg.CheckXss = false
		case "CheckPathTraversal":
			cfg.CheckPathTraversal = false
		case "CheckSSRF":
			cfg.CheckSSRF = false
		case "CheckXXE":
			cfg.CheckXXE = false
		case "CheckJwtWeak":
			cfg.CheckJwtWeak = false
		case "CheckJSVulns":
			cfg.CheckJSVulns = false
		case "CheckCachePoisoning":
			cfg.CheckCachePoisoning = false
		case "CheckHeaders":
			cfg.CheckHeaders = false
		case "CheckCorpus":
			cfg.CheckCorpus = false
		case "CheckExtendedCoverage":
			cfg.CheckExtendedCoverage = false
		case "CheckReflectionProbes":
			cfg.CheckReflectionProbes = false
		case "CheckHostDiscovery":
			cfg.CheckHostDiscovery = false
		case "CheckResponseDependence":
			cfg.CheckResponseDependence = false
		case "CheckPassivePosture":
			cfg.CheckPassivePosture = false
		case "CheckPassiveAnalysis":
			cfg.CheckPassiveAnalysis = false
		case "CheckActiveInjection":
			cfg.CheckActiveInjection = false
		case "CheckDOM":
			cfg.CheckDOM = false
		case "CheckExtendedActive":
			cfg.CheckExtendedActive = false
		case "CheckOutOfBand":
			cfg.CheckOutOfBand = false
		case "CheckStored":
			cfg.CheckStored = false
		}
	}
}

// enabledChecksIn is enabledChecks against an explicit configuration snapshot instead of the
// scanner's own — the mechanism the audit-level gate overlays with. The ledger bit-stability rule
// is unchanged: the set is snapshotted once per run, before any item is admitted.
func (s *ActiveScanner) enabledChecksIn(cfg ScanConfig) []activeCheck {
	return s.enabledChecksInTiers(cfg, nil)
}

// enabledChecksInTiers is enabledChecksIn under a tier selection. A nil tiers map admits every
// check the base switches do, which is what a run with no `scan_type_*_active` key set means. A
// non-nil map admits a check only when its OWN tier is in the set — so light and medium are
// independent selections, and a preset that enables one does not inherit the others.
func (s *ActiveScanner) enabledChecksInTiers(cfg ScanConfig, tiers map[CheckInvasiveness]bool) []activeCheck {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	corpus := s.corpus
	s.mu.RUnlock()
	out := make([]activeCheck, 0, len(activeCheckSet)+len(corpus))
	for _, c := range activeCheckSet {
		if !c.enabled(&cfg) {
			continue
		}
		// A passive check is not under the three active-tier keys at all: it hangs from
		// `scan_type_passive`, and it sends no request, so "intrusive" has nothing to say about it.
		// Excluding it because every active tier was off would be the collapsed gate's old mistake in
		// a new place.
		if tiers != nil && !c.passive && !tiers[c.invasiveness] {
			continue
		}
		out = append(out, c)
	}
	if cfg.CheckCorpus {
		// Corpus checks are loaded by the operator rather than declared in the registry, so they
		// carry no rank. They join every tier: a preset that narrows the built-in checks has not
		// said anything about an operator's own corpus, and dropping it would silently change what
		// the corpus switch means.
		out = append(out, s.corpusActiveChecks(corpus)...)
	}
	return out
}

// UnimplementedCheckCount reports how many of those checks have no implementation behind them and
// can therefore only ever come back DispositionUnsupported.
//
// Reported separately from ActiveCheckCount so "seven checks configured" is never read as "seven
// checks can produce a verdict".
func (s *ActiveScanner) UnimplementedCheckCount() int {
	n := 0
	for _, c := range s.enabledChecks() {
		if c.run == nil {
			n++
		}
	}
	return n
}

// probeCounts is one snapshot of a meter, so a check's own send activity can be read as a delta
// across the call rather than threaded through every check signature.
type probeCounts struct {
	attempted uint32
	sent      uint32
	failed    uint32
	refused   uint32
}

// probeMeter counts the probes checks actually send, so the request budget bounds reality rather
// than an estimate of it, and so a check that never saw a probe response can be told apart from one
// that did.
//
// Atomics rather than a lock: the counters are independent and a check may fan out its own probes.
type probeMeter struct {
	attempted atomic.Uint32
	sent      atomic.Uint32
	failed    atomic.Uint32
	refused   atomic.Uint32
	// rateLimitedCount counts probes the target answered 429/503 (fkl8) — the honest half of
	// auto-backoff: the outcome reports how many times the target asked the audit to slow
	// down, because a sweep that ignored N rate-limit responses is a sweep an operator must
	// be able to distinguish from one the target never throttled.
	rateLimitedCount atomic.Uint32
	// limitedStatus is the most recent rate-limit status seen (0 = none), read by the
	// dispatch loop to decide the backoff wait. Only the LAST status matters: a mixed 429
	// then 503 sequence backs off the same either way.
	limitedStatus atomic.Uint32
}

// The methods are nil-safe: a check invoked outside an audit (a direct unit test, say) has no meter
// on its context, and metering must not be the thing that makes that panic.
func (m *probeMeter) attempt() {
	if m != nil {
		m.attempted.Add(1)
	}
}

func (m *probeMeter) succeeded() {
	if m != nil {
		m.sent.Add(1)
	}
}

func (m *probeMeter) failure() {
	if m != nil {
		m.failed.Add(1)
	}
}

// rateLimited records one 429/503 probe response (fkl8). Nil-safe like its siblings.
func (m *probeMeter) rateLimited(status int) {
	if m != nil {
		m.rateLimitedCount.Add(1)
		m.limitedStatus.Store(uint32(status))
	}
}

// refusal records a probe the scope gate refused. Counted as a failure too: the check saw no probe
// response either way, and a refusal that only incremented its own counter would leave the check
// looking like it ran.
func (m *probeMeter) refusal() {
	if m != nil {
		m.refused.Add(1)
		m.failed.Add(1)
	}
}

func (m *probeMeter) snapshot() probeCounts {
	if m == nil {
		return probeCounts{}
	}
	return probeCounts{
		attempted: m.attempted.Load(),
		sent:      m.sent.Load(),
		failed:    m.failed.Load(),
		refused:   m.refused.Load(),
	}
}

// since returns what happened between before and now — one check's own send activity.
func (m *probeMeter) since(before probeCounts) probeCounts {
	now := m.snapshot()
	return probeCounts{
		attempted: now.attempted - before.attempted,
		sent:      now.sent - before.sent,
		failed:    now.failed - before.failed,
		refused:   now.refused - before.refused,
	}
}

// meterKey is the context key the meter rides on.
//
// A context value rather than a parameter, deliberately: the meter has to reach sendTestRequest,
// which every check calls, and the check functions are shared with checks this file does not own.
// Threading a meter argument through all of them would put the accounting mechanism in the signature
// of every check — including future ones, which would then be able to forget it. A context value is
// unforgettable in exactly the way that matters: sendTestRequest is the only place a probe leaves,
// and it is the only place that reads the meter.
type meterKey struct{}

func withMeter(ctx context.Context, m *probeMeter) context.Context {
	return context.WithValue(ctx, meterKey{}, m)
}

// meterFrom returns the meter on ctx, or nil when there is none.
func meterFrom(ctx context.Context) *probeMeter {
	if ctx == nil {
		return nil
	}
	m, _ := ctx.Value(meterKey{}).(*probeMeter)
	return m
}

// runCfgKey is the context key the *run's* audit configuration rides on.
//
// It exists because AuditWithin and AuditSession take a configuration per call — that is how
// /api/audit/{id} honours `{"config": "<name>"}` — while NewCheckContext could only read
// ActiveScanner.AuditConfig(), the server-wide default set once at startup by -scan-config. So a
// named configuration reached the run's budgets, breakers and queue row and reached no check: an
// audit launched under a configuration that selects different insertion points enumerated the
// server default's points and reported the operator's name over them. The queue row said one thing
// and the wire did another.
//
// The same argument the meter makes applies here and is why this is a context value rather than a
// parameter: the dispatch closure wrapDescriptor builds has a fixed signature shared by every
// check, and widening it would put the configuration in the signature of every future check — which
// could then forget it. There is exactly one place a check context is built for a dispatched check,
// and it is the only place that reads this.
type runCfgKey struct{}

func withRunConfig(ctx context.Context, cfg AuditConfig) context.Context {
	return context.WithValue(ctx, runCfgKey{}, cfg)
}

// runConfigFrom returns the audit configuration this dispatch is running under, and whether ctx
// carried one. False means the caller reached a check outside a dispatched audit — a direct
// evaluator test, say — and the scanner's own configuration is the honest fallback.
func runConfigFrom(ctx context.Context) (AuditConfig, bool) {
	if ctx == nil {
		return AuditConfig{}, false
	}
	cfg, ok := ctx.Value(runCfgKey{}).(AuditConfig)
	return cfg, ok
}

// auditRun is the shared state for one audit run: the clock, the budgets, and the ledger.
//
// Mutex-guarded because Go's AuditSession dispatches items concurrently where the Rust original
// walks them in order. The bound is a property of the resident set, so it has to hold under
// contention or it is not a bound.
type auditRun struct {
	cfg      AuditConfig
	deadline time.Time
	ledger   *AuditLedger

	// lightAudit is the light-audit tier's per-run state (burpsy-react-ui-7bkj): how many
	// CLEAN same-(kind, host) points each type has produced this run. Burp's Zq5 bank calls
	// the outcome "Skipped due to repetitive behavior" — a cheap probe on the Nth occurrence
	// of an insertion-point TYPE, then skip the rest of that type on the same host. This is
	// the type-occurrence half only: Burp's content-similarity half needs response-diff
	// infrastructure this engine does not have, so it is declined rather than half-built —
	// a similarity rule that could not say what it compared would skip work it never
	// justified. Type-keyed, not content-keyed, exactly as Burp's own sentence is.
	//
	// On the run, not the scanner: one audit's repetition prior must not bound a different
	// audit against the same host — the same discipline the request meter and breakers hold.
	lightAudit map[lightAuditKey]uint32

	mu sync.Mutex
	// requestsSent counts probes from items that have already finished. The current item's probes
	// are counted separately, because its meter is still live.
	requestsSent uint32
}

// newAuditRun starts a run. A zero or negative TimeBudget means "no time budget", not "no time":
// collapsing them would make a caller that forgot to set the field audit nothing at all.
//
// The ledger comes from the config when the caller supplied one, so a repeating caller can keep scope
// collapse across runs — see AuditConfig.Ledger for why the live sweep must. Everything else on the
// run is per-run by construction: the deadline, the request meter and both breakers are properties of
// *this* batch, and sharing any of them would let one batch's failures bound the next one's work.
func newAuditRun(cfg AuditConfig) *auditRun {
	ledger := cfg.Ledger
	if ledger == nil {
		ledger = NewAuditLedger()
	}
	r := &auditRun{cfg: cfg, ledger: ledger}
	if cfg.TimeBudget > 0 {
		r.deadline = time.Now().Add(cfg.TimeBudget)
	}
	return r
}

// lightAuditKey identifies one insertion-point type on one host: the light-audit tier's
// repetition unit. The host is the full authority (host:port_tls), because the same
// parameter type on two hosts is two applications' handling and no prior of each other's.
type lightAuditKey struct {
	kind string
	host string
}

// lightAuditShouldSkip reports whether this point's type on this host has produced enough
// clean occurrences this run that the rest can be skipped as repetitive. First call for a
// point answers false (the point runs); the caller then records the point's outcome so the
// counter reaches the threshold over the run's own evidence.
func (r *auditRun) lightAuditShouldSkip(kind, host string, threshold uint32) bool {
	if threshold == 0 {
		return false // tier off: set-and-zero or unset-below-one both mean "never skip"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lightAudit[lightAuditKey{kind: kind, host: host}] >= threshold
}

// lightAuditRecordClean notes one more clean same-(kind, host) point.
func (r *auditRun) lightAuditRecordClean(kind, host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lightAudit == nil {
		r.lightAudit = make(map[lightAuditKey]uint32)
	}
	r.lightAudit[lightAuditKey{kind: kind, host: host}]++
}

// outOfTime reports whether the wall-clock budget is spent.
func (r *auditRun) outOfTime() bool {
	return !r.deadline.IsZero() && !time.Now().Before(r.deadline)
}

// overRequestBudget reports whether the outbound-probe budget is spent. currentItem is the live
// meter of the item being dispatched, which has not yet been folded into requestsSent; pass 0 to ask
// about the session total alone.
func (r *auditRun) overRequestBudget(currentItem uint32) bool {
	if !r.cfg.MaxRequests.Set {
		return false
	}
	r.mu.Lock()
	total := r.requestsSent
	r.mu.Unlock()
	sum := total + currentItem
	if sum < total { // saturating, matching the Rust original
		sum = ^uint32(0)
	}
	return sum >= r.cfg.MaxRequests.Value
}

// foldSent folds a finished item's probe count into the session total.
func (r *auditRun) foldSent(n uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sum := r.requestsSent + n
	if sum < r.requestsSent {
		sum = ^uint32(0)
	}
	r.requestsSent = sum
}

func (r *auditRun) sent() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requestsSent
}

// AuditOutcome is what one audit pass did. Reported rather than summed into a single number so a run
// where every send failed is distinguishable from a run that genuinely found nothing.
//
// The nine disposition counters partition the check set: Considered equals the number of enabled
// checks whenever the item was dispatched. Six of the nine mean the engine chose not to look, and a
// caller that ignores them is reading a bound as a clean result.
type AuditOutcome struct {
	// State is where the item ended up.
	State ItemState `json:"state"`
	// Ran counts checks that completed without a transport failure.
	Ran int `json:"ran"`
	// Findings counts findings this item produced.
	Findings int `json:"findings"`
	// SendFailures counts checks abandoned because no probe could be sent or read.
	SendFailures int `json:"send_failures"`
	// Skipped counts checks the engine could not run at all — no implementation, or a dispatch scope
	// with no addressable unit.
	Skipped int `json:"skipped"`
	// NotRun counts checks never attempted because the time budget ran out.
	NotRun int `json:"not_run"`
	// AlreadyCovered counts checks not admitted because an identical (dispatch unit, check) already
	// ran this session.
	AlreadyCovered int `json:"already_covered"`
	// RateLimited counts steps the dispatch loop delayed because the target answered a probe
	// 429 or 503 (fkl8). The work still ran — this is not a disposition — but an audit that
	// was slowed by the target N times says so in its outcome, because a sweep that ignored
	// N rate-limit responses is a sweep an operator must be able to distinguish from one the
	// target never throttled.
	RateLimited int `json:"rate_limited"`
	// PointsSkippedRepetitive counts insertion points the light-audit tier skipped because
	// their (kind, host) had produced enough clean points this run (7bkj). Not a
	// check-level disposition — the check ran, on fewer points — so it sits beside
	// RateLimited rather than in the Considered() partition: a check that probed 8 of 30
	// points because 20 clean ones came before has still been considered, run, and
	// answered; what it has not done is TEST the 22, and that is what this number says.
	PointsSkippedRepetitive int `json:"points_skipped_repetitive"`
	// RequestBudgetSpent counts checks not admitted because the outbound-request budget was spent.
	RequestBudgetSpent int `json:"request_budget_spent"`
	// UnitAbandoned counts checks not admitted because consecutive failures abandoned their dispatch
	// unit.
	UnitAbandoned int `json:"unit_abandoned"`
	// ItemFailed counts checks not admitted because the item breaker failed the whole item.
	ItemFailed int `json:"item_failed"`
	// SessionPaused counts checks not admitted because the session breaker paused the run before
	// this item.
	SessionPaused int `json:"session_paused"`
	// RequestsSent counts probe requests this item actually sent.
	RequestsSent uint32 `json:"requests_sent"`
	// RequestsRefused counts probes refused because the request's own path fell outside scope —
	// typically a check that rewrote the path onto something the operator excluded. Reported, never
	// silent: a refusal is the engine declining to look, not the target coming back clean.
	RequestsRefused uint32 `json:"requests_refused"`
	// FindingsDropped counts findings discarded because the check that produced them never saw a
	// probe response.
	//
	// Not in the Rust original, because it cannot happen there: a BCheck whose send fails returns
	// `EvalError::SendFailed` and produces no findings at all. Go's checks fall back to the stored
	// response when a probe fails, which would let a check report "SQL injection with payload X"
	// about a payload that never left the process. The engine drops those findings and counts the
	// drop, so the safety fix is not itself a silent one.
	FindingsDropped int `json:"findings_dropped"`
	// TimedOut is true when the time budget stopped the run. Reported so "found nothing" is
	// distinguishable from "never finished looking".
	TimedOut bool `json:"timed_out"`
	// Cancelled is true when the caller's context ended the run.
	//
	// Folded into DispositionTimeBudgetSpent for counting — a tenth disposition would break the
	// nine-way partition that is the whole parity contract — but kept as its own flag, because
	// "the operator navigated away" and "this host is too slow to audit in two minutes" are
	// different facts about the same stopped run.
	Cancelled bool `json:"cancelled"`
	// Unmeasurable counts checks included in Ran whose evidence was inconclusive, so their empty
	// verdict is undecided rather than clean. A qualifier on Ran, not a tenth disposition.
	Unmeasurable int `json:"unmeasurable"`
	// UnitsPlanned and UnitsAbandoned count dispatch *units*, not checks, and are deliberately not
	// part of the nine-way partition Considered() sums — a unit holds many checks, so adding them
	// there would double-count.
	//
	// They exist because "an abandoned unit" and "the checks inside abandoned units" are different
	// facts and the second one alone cannot answer an operator's question. UnitAbandoned says 40
	// checks were not started; UnitsAbandoned says that was 2 units, which against
	// ConsecutiveUnitFailuresToFailItem = 2 is exactly why the item then failed. Before these were
	// recorded that inference was not available anywhere, so a failed item could not be traced to the
	// threshold that failed it.
	UnitsPlanned   int `json:"units_planned"`
	UnitsAbandoned int `json:"units_abandoned"`
	// FollowUpPasses is how many extra passes a failed item was re-dispatched. Zero is the common
	// case and means the item failed and stopped, which is a coverage loss an operator has to be able
	// to see rather than infer from a request count.
	FollowUpPasses int `json:"follow_up_passes"`
	// Error names why an item was refused before any dispatch. Non-empty exactly for
	// ItemStateOutOfScope and ItemStateUnauditable.
	Error string `json:"error,omitempty"`
}

// Considered is every check that reached a disposition. Equals the size of the enabled check set
// whenever the item was dispatched, and zero when it was refused before any work.
func (o AuditOutcome) Considered() int {
	return o.Ran +
		o.SendFailures +
		o.Skipped +
		o.NotRun +
		o.AlreadyCovered +
		o.RequestBudgetSpent +
		o.UnitAbandoned +
		o.ItemFailed +
		o.SessionPaused
}

// NotAdmitted is the checks the engine declined to admit. Non-zero here means a clean result is not
// a clean bill of health.
func (o AuditOutcome) NotAdmitted() int {
	return o.NotRun +
		o.AlreadyCovered +
		o.RequestBudgetSpent +
		o.UnitAbandoned +
		o.ItemFailed +
		o.SessionPaused
}

// DispositionCount pairs one disposition with how many checks landed in it, and with the line an
// operator can act on. The reason travels with the count for the same reason SkipCount carries one:
// a bare histogram makes the caller re-derive what each bucket means, and a caller that gets that
// wrong reads a bound as a clean result.
type DispositionCount struct {
	Disposition Disposition `json:"disposition"`
	Reason      string      `json:"reason"`
	Count       int         `json:"count"`
	// StoppedLooking marks the six buckets that mean the engine declined to admit the work.
	StoppedLooking bool `json:"stopped_looking"`
}

// Dispositions is the full disposition histogram, in DispositionAll order, so a caller can render
// *why* the engine stopped without hard-coding which of the counters mean "did not look".
func (o AuditOutcome) Dispositions() [9]DispositionCount {
	counts := [9]int{
		o.Ran,
		o.Skipped,
		o.SendFailures,
		o.AlreadyCovered,
		o.NotRun,
		o.RequestBudgetSpent,
		o.UnitAbandoned,
		o.ItemFailed,
		o.SessionPaused,
	}
	var out [9]DispositionCount
	for i, d := range DispositionAll {
		out[i] = DispositionCount{
			Disposition:    d,
			Reason:         d.Explanation(),
			Count:          counts[i],
			StoppedLooking: d.StoppedLooking(),
		}
	}
	return out
}

// Summary formats one item's outcome for logs and the CLI. Every non-zero refusal reason is named:
// the point of the histogram is lost if the human-readable form collapses it back into a total.
func (o AuditOutcome) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d checks considered, %d ran, %d finding(s), %d probe(s) sent",
		o.State.Label(), o.Considered(), o.Ran, o.Findings, o.RequestsSent)
	var why []string
	for _, d := range o.Dispositions() {
		if d.Count > 0 && d.Disposition != DispositionRan {
			why = append(why, fmt.Sprintf("%d %s", d.Count, d.Disposition.String()))
		}
	}
	if len(why) > 0 {
		fmt.Fprintf(&b, "; %s", strings.Join(why, ", "))
	}
	if o.RequestsRefused > 0 {
		fmt.Fprintf(&b, "; %d probe(s) refused by scope", o.RequestsRefused)
	}
	if o.RateLimited > 0 {
		fmt.Fprintf(&b, "; %d step(s) delayed for rate limiting", o.RateLimited)
	}
	if o.PointsSkippedRepetitive > 0 {
		fmt.Fprintf(&b, "; %d point(s) skipped as repetitive (light audit)", o.PointsSkippedRepetitive)
	}
	if o.Unmeasurable > 0 {
		fmt.Fprintf(&b, "; %d check(s) undecided, not clean", o.Unmeasurable)
	}
	if o.FindingsDropped > 0 {
		fmt.Fprintf(&b, "; %d finding(s) dropped for want of a probe response", o.FindingsDropped)
	}
	if o.Error != "" {
		fmt.Fprintf(&b, " (%s)", o.Error)
	}
	return b.String()
}

// refuse marks an item refused before any dispatch. Nothing is counted against the check set: no
// check was considered, which is what Considered() == 0 means.
func (o AuditOutcome) refuse(state ItemState, why string) AuditOutcome {
	o.State = state
	o.Error = why
	return o
}

// ItemOutcome is one exchange's outcome inside a session, keeping the exchange id attached — the Go
// shape of Rust's `(u64, AuditOutcome)` tuple.
type ItemOutcome struct {
	ExchangeID core.ExchangeID `json:"exchange_id"`
	Outcome    AuditOutcome    `json:"outcome"`
}

// SessionOutcome is what one AuditSession did.
type SessionOutcome struct {
	// Items holds one entry per requested exchange, in the order given.
	Items []ItemOutcome `json:"items"`
	// Findings counts findings across the whole session.
	Findings int `json:"findings"`
	// RequestsSent counts probe requests sent across the whole session.
	RequestsSent uint32 `json:"requests_sent"`
	// DispatchUnits counts the distinct dispatch units the ledger saw — the real size of the work,
	// as opposed to the number of exchanges asked for.
	DispatchUnits int `json:"dispatch_units"`
	// FailedItems counts items the item breaker failed.
	FailedItems int `json:"failed_items"`
	// Paused is true when the session breaker stopped admitting items.
	Paused bool `json:"paused"`
	// TimedOut is true when the time budget stopped at least one item.
	TimedOut bool `json:"timed_out"`
}

// Completed counts items that ran every check they were given.
func (o *SessionOutcome) Completed() int {
	n := 0
	for _, it := range o.Items {
		if it.Outcome.State.CompletedAudit() {
			n++
		}
	}
	return n
}

// AlreadyCovered counts checks refused across the session because an identical
// `(dispatch unit, check)` had already run.
//
// Deliberately not part of NotAdmitted and deliberately not a caveat bucket in Breakdown: this is
// work that *ran*, against an earlier item covering the same unit, which is the argument
// ItemState.CompletedAudit already makes. It has its own accessor because it is the engine's largest
// saving, and a caller sharing a ledger across runs needs to be able to show the saving is happening
// rather than infer it from a request count that went down.
func (o *SessionOutcome) AlreadyCovered() int {
	if o == nil {
		return 0
	}
	n := 0
	for _, it := range o.Items {
		n += it.Outcome.AlreadyCovered
	}
	return n
}

// NotAdmitted counts checks the engine declined to admit across the session.
func (o *SessionOutcome) NotAdmitted() int {
	n := 0
	for _, it := range o.Items {
		n += it.Outcome.NotAdmitted()
	}
	return n
}

// Summary formats a session for logs and reports.
func (o *SessionOutcome) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d item(s): %d completed, %d dispatch unit(s), %d check(s) not admitted, %d finding(s), %d probe(s) sent",
		len(o.Items), o.Completed(), o.DispatchUnits, o.NotAdmitted(), o.Findings, o.RequestsSent)
	if o.FailedItems > 0 {
		fmt.Fprintf(&b, "; %d item(s) failed", o.FailedItems)
	}
	if o.Paused {
		b.WriteString("; session paused by the failure breaker")
	}
	if o.TimedOut {
		b.WriteString("; time budget spent")
	}
	return b.String()
}

// AuditConfig returns the budget and breaker configuration this scanner audits under.
//
// ScanConfig.Timeout is the source of the default wall-clock budget rather than a second, competing
// one. Before this engine existed that field was set by every caller and read by nobody in the tree,
// so adopting it here gives it its only meaning instead of leaving two timeouts that can disagree
// about when an audit should stop. WithAuditConfig overrides it outright, and that override wins
// whatever order the two setters are called in.
func (s *ActiveScanner) AuditConfig() AuditConfig {
	if s.auditCfg != nil {
		return *s.auditCfg
	}
	cfg := DefaultAuditConfig()
	snap := s.ConfigSnapshot()
	if snap.Timeout > 0 {
		cfg.TimeBudget = snap.Timeout
	}
	return cfg
}

// WithAuditConfig sets the budgets and breakers explicitly, in place of the ScanConfig-derived
// default.
func (s *ActiveScanner) WithAuditConfig(cfg AuditConfig) *ActiveScanner {
	s.auditCfg = &cfg
	return s
}

// WithSuiteGate attaches the dashboard's suite-wide pause. The audit calls it between checks; nil,
// the default, is an audit nothing can pause but its own context.
func (s *ActiveScanner) WithSuiteGate(gate func(context.Context)) *ActiveScanner {
	s.suiteGate = gate
	return s
}

// WithScope gives the scanner the engagement scope.
//
// Optional, and nil means "no scope was supplied" rather than "nothing is in scope": ActiveScanner
// had no scope at all before this engine, so refusing everything when a caller has not been updated
// yet would break audits rather than protect anyone. With a scope set, it is enforced twice — once
// on the captured exchange before any work is planned, and again inside sendTestRequest on the bytes
// actually going out, because a check that rewrites the path is sending somewhere else entirely.
func (s *ActiveScanner) WithScope(scope *core.Scope) *ActiveScanner {
	s.scope = scope
	return s
}

// AuditWithin audits one exchange under an explicit configuration, returning what the engine did
// alongside the findings.
//
// One-shot: a fresh AuditLedger admits everything, so re-auditing the same exchange really
// re-audits it. Scope collapse belongs to a *session*, not to a single operator-triggered audit — an
// operator who clicks audit again means it.
func (s *ActiveScanner) AuditWithin(ctx context.Context, exchangeID core.ExchangeID, cfg AuditConfig) (AuditOutcome, []*Finding) {
	run := newAuditRun(cfg)
	checks := s.enabledChecksUnder(cfg)
	// Queued before dispatch, not after it answers. An audit of a slow host holds this goroutine for
	// up to the whole time budget, and a queue that only showed items once they finished would be
	// empty for exactly as long as the operator most wanted to look at it.
	cfg.Items.Enqueue(exchangeID, len(checks))
	return s.auditItem(ctx, exchangeID, run, checks)
}

// AuditSession audits a batch of exchanges under one shared budget, ledger and set of circuit
// breakers.
//
// This is where bounding pays for itself. A per-URL check has one answer per URL, so auditing 500
// captures of one URL dispatches it once and refuses the other 499 as DispositionAlreadyCovered —
// refused before a request is built, and *counted*, so the saving is visible rather than looking
// like checks that quietly stopped firing.
//
// The time and request budgets are session-wide, not per exchange: once either is spent the loop
// stops admitting items rather than re-deciding the same thing for each remaining one. Every skipped
// item still comes back with its whole check set attributed to the reason.
//
// Scope is re-checked for every exchange, inside the loop. Hoisting that check would let one
// in-scope exchange authorise traffic to an out-of-scope host in the same batch.
//
// # Divergence: this runs items concurrently
//
// The Rust original walks the batch in order on one thread. Go's AuditMultiple has always audited
// concurrently under ScanConfig.MaxConcurrency, and taking that away would be a performance
// regression dressed up as parity. The ledger and both breakers are therefore mutex-guarded, so the
// resident set and the failure counts stay exact.
//
// Items are *started* in the order given — a fixed pool of workers pulls from an ordered queue,
// rather than every item racing for a semaphore — so with one worker this is exactly the Rust
// behaviour, and with more it is as close as concurrency allows. What is not deterministic above one
// worker is which of two items covering the same dispatch unit gets admitted and which is refused as
// DispositionAlreadyCovered: in Rust it is always the later one in the given order, here it is
// whichever worker reaches the admission gate first. The totals are identical either way; only the
// attribution moves. Items come back in the order requested regardless.
func (s *ActiveScanner) AuditSession(ctx context.Context, exchangeIDs []core.ExchangeID, cfg AuditConfig) (*SessionOutcome, []*Finding) {
	checks := s.enabledChecksUnder(cfg)
	run := newAuditRun(cfg)
	breaker := newSessionBreaker(cfg)
	out := &SessionOutcome{Items: make([]ItemOutcome, len(exchangeIDs))}

	// Index-aligned slots rather than an append under a mutex: the caller asked for these ids in
	// this order, and an outcome that landed under the wrong id is worse than no outcome at all.
	perItem := make([][]*Finding, len(exchangeIDs))
	var paused atomic.Bool

	workers := 1
	if snap := s.ConfigSnapshot(); snap.MaxConcurrency > 1 {
		workers = snap.MaxConcurrency
		if workers > len(exchangeIDs) {
			workers = len(exchangeIDs)
		}
	}
	// Every item joins the queue as Pending before any worker starts, which is what makes the queue a
	// queue rather than a log of finished work: a batch of 200 is 200 Pending rows the instant the
	// sweep tick begins, and they move to Auditing and then to a terminal state as workers reach
	// them. Enqueued in the order requested, so the queue's own order is the caller's order.
	for _, id := range exchangeIDs {
		cfg.Items.Enqueue(id, len(checks))
	}

	queue := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for slot := range queue {
				exchangeID := exchangeIDs[slot]

				// Three whole-item refusals, decided before the exchange is even looked up. Each
				// condition is monotone, so re-deriving it per check would mean planning every
				// remaining item only to refuse it. Every one of them is still counted: a remaining
				// item is never an item that came back clean.
				switch {
				case paused.Load():
					o := s.refuseWholeItem(ItemStatePaused, len(checks), func(o *AuditOutcome) *int { return &o.SessionPaused })
					out.Items[slot] = ItemOutcome{ExchangeID: exchangeID, Outcome: o}
					cfg.Items.Resolve(exchangeID, nil, o, cfg, auditItemNote(o, cfg))
					continue
				case run.outOfTime() || ctx.Err() != nil:
					o := s.refuseWholeItem(ItemStateBounded, len(checks), func(o *AuditOutcome) *int { return &o.NotRun })
					o.TimedOut = true
					o.Cancelled = ctx.Err() != nil
					out.Items[slot] = ItemOutcome{ExchangeID: exchangeID, Outcome: o}
					cfg.Items.Resolve(exchangeID, nil, o, cfg, auditItemNote(o, cfg))
					continue
				case run.overRequestBudget(0):
					o := s.refuseWholeItem(ItemStateBounded, len(checks), func(o *AuditOutcome) *int { return &o.RequestBudgetSpent })
					out.Items[slot] = ItemOutcome{ExchangeID: exchangeID, Outcome: o}
					cfg.Items.Resolve(exchangeID, nil, o, cfg, auditItemNote(o, cfg))
					continue
				}

				o, found := s.auditItem(ctx, exchangeID, run, checks)
				if o.State.Dispatched() && breaker.itemFinished(o.State == ItemStateFailed) {
					paused.Store(true)
				}
				out.Items[slot] = ItemOutcome{ExchangeID: exchangeID, Outcome: o}
				perItem[slot] = found
			}
		}()
	}
	// Fed in order. A cancelled context is not a reason to stop feeding: an item nobody looked at
	// must still come back with its check set attributed, and the refusals above are what do that.
	for i := range exchangeIDs {
		queue <- i
	}
	close(queue)
	wg.Wait()

	var findings []*Finding
	for i := range out.Items {
		out.Findings += out.Items[i].Outcome.Findings
		out.TimedOut = out.TimedOut || out.Items[i].Outcome.TimedOut
		findings = append(findings, perItem[i]...)
	}
	out.RequestsSent = run.sent()
	out.DispatchUnits = run.ledger.Units()
	out.FailedItems = int(breaker.failed())
	out.Paused = paused.Load()
	return out, findings
}

// refuseWholeItem builds an outcome for an item the session refused outright, with every check
// attributed to the reason it was refused. Nothing here is dispatched, so RequestsSent stays zero.
func (s *ActiveScanner) refuseWholeItem(state ItemState, checks int, counter func(*AuditOutcome) *int) AuditOutcome {
	o := AuditOutcome{State: state}
	*counter(&o) = checks
	return o
}

// dispatchUnit is one addressable unit of work: a scope and the key identifying one instance of it.
type dispatchUnit struct {
	scope DispatchScope
	key   string
}

// planStep is one `(dispatch unit, check)` pair in dispatch order. check indexes the run's check
// set, which is also its identity in the ledger.
type planStep struct {
	unit  int
	check int
}

// plan groups the check set into dispatch units for one exchange, coarsest scope first.
//
// Returns the units, a flat plan of steps in dispatch order, and the number of checks that have no
// dispatch unit at all. Those last are counted rather than dropped: a check that silently vanishes
// from the plan would make the outcome's counters stop summing to the check set, and the whole point
// of the counters is that they do.
func plan(ex *core.Exchange, checks []activeCheck) (units []dispatchUnit, steps []planStep, undispatchable int) {
	for _, scope := range DispatchScopeAll {
		var members []int
		for i, c := range checks {
			if c.scope != scope {
				continue
			}
			// A check with no implementation has nowhere to run, whatever its scope claims. Counted
			// here rather than admitted and then declined, because admitting it would spend a ledger
			// bit and a budget test on work that cannot happen.
			if c.run == nil {
				undispatchable++
				continue
			}
			members = append(members, i)
		}
		if len(members) == 0 {
			continue
		}
		key, ok := scope.UnitKey(ex)
		if !ok {
			// A check bound to a scope this engine cannot key is in the same position as one with no
			// implementation.
			undispatchable += len(members)
			continue
		}
		ix := len(units)
		units = append(units, dispatchUnit{scope: scope, key: key})
		for _, c := range members {
			steps = append(steps, planStep{unit: ix, check: c})
		}
	}
	return units, steps, undispatchable
}

// auditItem audits one exchange within a run's shared budget and ledger.
//
// The findings it returns are also folded into the scanner's own finding list, which is where
// GetFindings and Export read from — the same contract Audit has always had.
func (s *ActiveScanner) auditItem(ctx context.Context, exchangeID core.ExchangeID, run *auditRun, checks []activeCheck) (AuditOutcome, []*Finding) {
	var o AuditOutcome
	// refuse resolves the item in the queue as well as returning it, so an item the engine declined
	// before any dispatch is a row an operator can see rather than a return value one caller read.
	// Every path out of this prologue goes through it: a queue missing exactly the items nothing
	// looked at would be the honest-counting failure this whole surface exists to close.
	refuse := func(ex *core.Exchange, state ItemState, why string) (AuditOutcome, []*Finding) {
		refused := o.refuse(state, why)
		run.cfg.Items.Resolve(exchangeID, ex, refused, run.cfg, auditItemNote(refused, run.cfg))
		return refused, nil
	}
	if len(checks) == 0 {
		// Nothing was enabled, so nothing was declined either. Audited with zero considered is the
		// honest reading, and it is what the Rust original returns for an empty check set.
		o.State = ItemStateAudited
		run.cfg.Items.Resolve(exchangeID, nil, o, run.cfg, "")
		return o, nil
	}
	ex, err := s.store.GetExchange(exchangeID)
	if err != nil || ex == nil {
		return refuse(nil, ItemStateUnauditable, "no such exchange")
	}
	// An operator's cancel, read here rather than in the session loop so every dispatch path gets it
	// (AuditWithin and AuditMultiple both land in this function). Checked AFTER the exchange resolves
	// and BEFORE scope, because a cancelled item is still a real item about a real request: the row
	// must carry its host and path so the queue can show which URL the operator reclaimed, and a
	// cancel that arrived before the engine got here must not lose the identity to save one lookup.
	if run.cfg.Items.Cancelled(exchangeID) {
		// The row already holds ItemStateCancelled from Cancel, so this returns the state the
		// operator asked for rather than a second, differently-worded one.
		return refuse(ex, ItemStateCancelled, "cancelled by the operator")
	}
	// Scope first, before a single byte is built. Sending unsolicited requests to a host outside the
	// engagement is the one bug in this package that would matter outside the tool.
	if s.scope != nil && !s.scope.Contains(ex.Host, ex.Port, ex.Path, ex.TLS) {
		return refuse(ex, ItemStateOutOfScope, fmt.Sprintf("%s is out of scope", ex.Host))
	}
	// Every built-in check either reads this exchange's stored response or falls back to it when a
	// probe fails, so without one nothing here can produce evidence. Refused rather than run,
	// because a check set that inspected an empty body would come back clean.
	if ex.Response == nil {
		return refuse(ex, ItemStateUnauditable, "exchange has no response yet")
	}
	if _, err := s.store.Get(*ex.Response); err != nil {
		return refuse(ex, ItemStateUnauditable, "response not in store")
	}

	// Feed this response to the stored-input ledger before any check runs.
	//
	// This is the observation half of the second-order mechanism, and it was missing. Canaries
	// were planted by the stored checks and recorded, but nothing ever looked for them again, so
	// StoredLedger.SecondOrderObservations stayed permanently empty and every stored row was
	// wired, counted as coverage, and incapable of ever reporting anything — the exact failure
	// this project holds to be worse than an honest decline. Two comments elsewhere claimed the
	// feeding already happened; it did not, and only the tests called it.
	//
	// It belongs here rather than at capture time because the ledger is a property of a scan, not
	// of the proxy: an exchange captured before a scan started cannot carry that scan's canaries,
	// and an audit is the point at which this scan is looking at this response. Ordering matters
	// too — observing before dispatch means a stored check running on THIS exchange can already
	// see a canary that surfaced in it.
	s.ObserveStoredCanaries(ex)

	o.State = ItemStateAuditing
	meter := &probeMeter{}
	// The run's configuration travels with the dispatch context so every check enumerates under the
	// configuration this audit was launched with, not the server-wide default. See runCfgKey.
	// The light-audit tier's check-facing handle (7bkj): one per item, closed over the
	// run's shared counter so the repetition prior accumulates across the run's items —
	// Burp's tier is cross-request by construction ("the Nth occurrence of the type on
	// this host"). The threshold resolves here so the check side has no knob of its own.
	lightThreshold := run.cfg.LightAuditSamplePerKind.Value
	if !run.cfg.LightAuditSamplePerKind.Set {
		lightThreshold = DefaultLightAuditSamplePerKind
	}
	var lightSkipped int32
	lightHandle := &RunLightAudit{
		shouldSkip: func(kind, host string) bool {
			return run.lightAuditShouldSkip(kind, host, lightThreshold)
		},
		recordClean: run.lightAuditRecordClean,
		recordSkip:  func() {},
		skipped:     &lightSkipped,
	}
	ictx := withRunConfig(withLightAudit(withMeter(ctx, meter), lightHandle), run.cfg)
	breaker := newItemBreaker(run.cfg)

	// The plan is built before anything is dispatched, so "how much did we not do" is answerable at
	// every point rather than reconstructed afterwards.
	units, steps, undispatchable := plan(ex, checks)
	o.Skipped += undispatchable
	o.UnitsPlanned = len(units)

	// The queue's row for this item, filled in at the one moment every fact it needs is in hand: the
	// plan's shape, the configuration in force, and this request's insertion points. Enumeration is
	// skipped entirely when nothing is reading the queue — it is one request parse, cheap beside a
	// probe but not free, and a CLI audit should not pay for a table it has no way to show.
	if run.cfg.Items != nil {
		points, kinds := auditItemPoints([]byte(requestRaw(s, ex)), run.cfg.insertionKinds(), run.cfg.enumerateOptions())
		run.cfg.Items.Begin(exchangeID, ex, run.cfg, len(units), len(steps), points, kinds)
	}

	var found []*Finding
	var stop Disposition
	stopped := false

	// Follow-up passes (burpsy-react-ui-5efx). Burp re-dispatches a FAILED item, bounded by
	// number_of_follow_up_passes (Zxdx.java:27,36; default 1 at Zp0d.java:120-121) through a
	// re-pass driver (Zeeu.java:119,239-241, Zfkz.java:57,69-81). Without it a transient failure — a
	// timeout, a 502 from a backend mid-restart, a dropped connection — permanently loses that item's
	// coverage and is indistinguishable from a check that found nothing.
	//
	// The narrowing is the part that makes the loop safe, and it is why this lands after the
	// breaker's failure memory rather than with it: a pass REPEATS the dispatch, and without asking
	// the breaker which checks already failed, a re-pass would re-send every check the first pass
	// sent — including the ones whose failure the response cannot change — and multiply the traffic
	// against a broken target by the number of passes. Burp's own predicate is
	// `failedForEntireInsertionPoint < 1L` (Zwy6.java's Zz), which is the same question asked
	// per insertion point rather than per dispatch unit.
	//
	// So a pass resumes at the first step whose check has NOT already failed in this unit, and a
	// check that failed once is not tried again. What a pass buys is the retry of a check that was
	// blocked behind a FAILED one, which is the transient case the feature exists for.
	passes := run.cfg.followUpPasses()
	pass := 0
	pos := 0
	// The plan is exhausted, not merely re-entered: the condition is the ORIGINAL loop's, and it is
	// what makes `goto dispatch` safe. Without it a pass that ran out of steps would index past the
	// end, and a failed item whose last step is the failure is the common case, not a rare one.
	for pos < len(steps) {
		unitIx := steps[pos].unit
		abandoned := false
		for pos < len(steps) && steps[pos].unit == unitIx {
			// Hard stops. Each is monotone — once spent it stays spent — so the rest of the plan is
			// attributed in one go rather than re-tested per step.
			if run.outOfTime() || ctx.Err() != nil {
				o.TimedOut = true
				o.Cancelled = ctx.Err() != nil
				stop, stopped = DispositionTimeBudgetSpent, true
				break
			}
			if run.overRequestBudget(meter.snapshot().sent) {
				stop, stopped = DispositionRequestBudgetSpent, true
				break
			}
			// The dashboard's "Pause all tasks", between checks (burpsy-react-ui-cijs). Below the
			// hard stops on purpose: a time budget that has already expired must not be waited out
			// while paused, and the loop must not resume into an audit that should have stopped.
			if s.suiteGate != nil {
				s.suiteGate(ctx)
			}

			// Auto-backoff (fkl8): the target answered a probe 429/503, so the next step
			// waits a configured beat before it sends. One wait per rate-limited status,
			// re-checked every step, so a target that keeps 429ing keeps being waited on and
			// a target that recovers stops paying. The wait is bounded by the time budget's
			// own expiry — a backoff that outlived the budget would be a wait with no audit
			// on the other side of it.
			// Unset inherits the default; set-and-zero is the real off. Resolving the wait here,
			// at the read, keeps the field's wire shape one value with no second "enabled" flag
			// to fall out of sync.
			ms := DefaultAutoBackoffMs
			if run.cfg.AutoBackoffMs.Set {
				ms = run.cfg.AutoBackoffMs.Value
			}
			if ms > 0 && meter != nil && meter.limitedStatus.Load() != 0 {
				select {
				case <-time.After(time.Duration(ms) * time.Millisecond):
				case <-ctx.Done():
				}
				o.RateLimited++
			}

			check := steps[pos].check
			pos++
			// One call per step consumed, whatever disposition it lands in — placed here, at the single
			// point pos advances, rather than beside each of the nine outcomes below. A progress counter
			// maintained at nine sites is one that eventually disagrees with the plan it is a fraction of.
			run.cfg.Items.Step(exchangeID)
			if abandoned {
				o.UnitAbandoned++
				continue
			}
			if !run.ledger.Admit(units[unitIx].key, check) {
				o.AlreadyCovered++
				continue
			}
			// The narrowing that makes a follow-up pass bounded work rather than more of the same: a
			// check that already failed in this unit is not tried again (burpsy-react-ui-5efx). Burp asks
			// the same question per insertion point (Zwy6.java's Zz); this asks it per (unit, check),
			// which is the granularity the dispatch plan has.
			if pass > 0 && breaker.AlreadyFailed(units[unitIx].key, checks[check].name) {
				pos++
				continue
			}

			before := meter.snapshot()
			verdict, runErr := checks[check].run(s, ictx, ex)
			d := meter.since(before)

			// A check the evaluator declined is in the same position as one with no implementation:
			// nothing ran and nothing proved. Counted as Skipped (DispositionUnsupported) so the
			// check set still partitions and a clean outcome cannot be read as a clean bill of
			// health for this check.
			if errors.Is(runErr, errCheckUnsupported) {
				o.Skipped++
				if s.logger != nil {
					s.logger.Warn("active check could not run",
						zap.String("check", checks[check].name),
						zap.Uint64("exchange_id", uint64(exchangeID)),
						zap.Error(runErr))
				}
				continue
			}
			// Ran, but undecided. Before the error branch: not a failure, so the breaker must not trip.
			if errors.Is(runErr, errCheckInconclusive) {
				o.Ran++
				o.Unmeasurable++
				if s.logger != nil {
					s.logger.Info("active check ran but could not reach a verdict",
						zap.String("check", checks[check].name),
						zap.Uint64("exchange_id", uint64(exchangeID)),
						zap.Error(runErr))
				}
				continue
			}
			// A check that failed mid-way — a send failed, or payload placement was impossible —
			// produced no verdict. Whatever probes went out are already metered; the check itself
			// is a send failure, and findings it may have produced before the failure are dropped:
			// a finding about a probe that never completed is not evidence.
			if runErr != nil {
				o.SendFailures++
				o.FindingsDropped += len(verdict)
				if s.logger != nil {
					s.logger.Warn("active check failed before a verdict",
						zap.String("check", checks[check].name),
						zap.Uint64("exchange_id", uint64(exchangeID)),
						zap.Error(runErr))
				}
				// The unit and check names go in so a follow-up pass can tell a check that
				// already failed here from one that has not been tried (burpsy-react-ui-5efx).
				abandoned = breaker.checkFailed(units[unitIx].key, checks[check].name)
				continue
			}

			// A check that attempted probes and had every one of them fail or be refused saw no
			// evidence of its own. Its verdict came from the stored response instead, which says
			// nothing about the payload it meant to send, so the findings go and the reason is
			// recorded.
			if d.attempted > 0 && d.sent == 0 {
				o.SendFailures++
				o.FindingsDropped += len(verdict)
				if len(verdict) > 0 && s.logger != nil {
					s.logger.Warn("dropping findings from a check whose probes never went out",
						zap.String("check", checks[check].name),
						zap.Uint64("exchange_id", uint64(exchangeID)),
						zap.Int("dropped", len(verdict)))
				}
				// The same failure as above by a different cause: the check ran and every
				// probe it placed was refused. Recorded against the unit so a re-pass does not
				// re-send it blind.
				breaker.checkFailed(units[unitIx].key, checks[check].name)
				continue
			}
			o.Ran++
			breaker.checkSucceeded()
			o.Findings += len(verdict)
			found = append(found, verdict...)
		}
		// Counted before the stop test, not after it: a unit the check-failure breaker gave up on was
		// abandoned whether or not the budget then ended the item, and attributing it only in the
		// no-stop case would make the count that explains a failed item disappear in exactly the runs
		// where an operator is asking why.
		if abandoned {
			o.UnitsAbandoned++
		}
		if stopped {
			break
		}
		if breaker.unitFinished(abandoned) {
			break
		}
	}

	// The retry decision. A pass is worth spending only when the item FAILED and some step is still
	// retryable — which, after the narrowing above, means some check in this item has never been tried.
	//
	// A budget-spent item is NOT retried: the second pass would run out of the same budget, and
	// "retried once" would teach an operator nothing the run's own bounds had not already said.
	if breaker.failed() && pass < passes && pos < len(steps) {
		retryable := false
		for i := pos; i < len(steps); i++ {
			if !breaker.AlreadyFailed(units[steps[i].unit].key, checks[steps[i].check].name) {
				retryable = true
				break
			}
		}
		if retryable {
			pass++
			pos = 0
			// The breaker's CONSECUTIVE counters start clean so a pass is measured against the same
			// thresholds, while its failure MEMORY is kept -- that memory is what narrows the pass.
			breaker.beginPass()
			goto dispatch
		}
	}
	o.FollowUpPasses = pass

dispatch:
	// Everything left in the plan is work this engine chose not to admit. Attributing it is what
	// turns a bound into something a caller can see. The breaker owns whether the item failed; stop
	// owns why dispatch ended.
	remaining := len(steps) - pos
	switch {
	case breaker.failed():
		o.ItemFailed += remaining
		o.State = ItemStateFailed
	case stopped && stop == DispositionTimeBudgetSpent:
		o.NotRun += remaining
		o.State = ItemStateBounded
	case stopped && stop == DispositionRequestBudgetSpent:
		o.RequestBudgetSpent += remaining
		o.State = ItemStateBounded
	default:
		o.State = ItemStateAudited
	}

	counts := meter.snapshot()
	o.RequestsSent = counts.sent
	o.RequestsRefused = counts.refused
	run.foldSent(o.RequestsSent)

	// The Rust original asserts this in debug builds. A warning instead of a panic, because a
	// production audit that miscounts must still return the work it did — but it must not do so
	// silently, or the partition identity stops being something a caller can rely on.
	if o.Considered() != len(checks) && s.logger != nil {
		s.logger.Warn("audit outcome does not account for every check",
			zap.Uint64("exchange_id", uint64(exchangeID)),
			zap.Int("considered", o.Considered()),
			zap.Int("checks", len(checks)))
	}

	// Phase 12: the DOM dynamic confirmation tier (burpsy-react-ui-m97j), the half dom.go's
	// header promised and never had. It re-runs the STATIC DOM analysis on this exchange's own
	// response — the same free-standing pass Capture.ScanExchange runs — so the confirm sees the
	// same flows the passive path reported, then plants a canary in each URL-kind flow's source
	// and loads the page in the scan's browser. Promoted/retired verdicts ride the finding;
	// without a browser attached (or on an unsupported source kind) the finding stays tentative
	// AND SAYS SO in its evidence, because a caveat only in the operator's memory is the failure
	// DOM-03 exists to prevent. Only when the DOM families are enabled: the tier confirms THIS
	// pass's candidates, and running it with the families off would observe pages no static
	// finding came from.
	if s.DOMCapabilityConfigured() && s.config != nil && s.config.CheckDOM {
		if confirmed := s.confirmDOMFindingsFor(ex); len(confirmed) > 0 {
			found = append(found, confirmed...)
		}
	}

	// The tier's per-item skip count, folded once (7bkj): the checks ran and answered;
	// this number says how many points they did not test, and rides the outcome beside the
	// rate-limiting count.
	o.PointsSkippedRepetitive = int(lightHandle.SkippedPoints())
	if len(found) > 0 {
		s.findingsMu.Lock()
		s.findings = append(s.findings, found...)
		s.findingsMu.Unlock()
	}
	run.cfg.Items.Resolve(exchangeID, ex, o, run.cfg, auditItemNote(o, run.cfg))
	return o, found
}
