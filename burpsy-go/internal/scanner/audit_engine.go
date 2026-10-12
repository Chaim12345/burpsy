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
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// activeCheck is one built-in active check: its identity, the dispatch scope its answer is keyed at,
// the ScanConfig switch that puts it in the set, and the function that runs it.
//
// run is nil for a check that is configurable but not implemented. Such a check is still counted —
// see the file header for why that is the point rather than an oversight.
type activeCheck struct {
	name string
	// speed is the minimum run speed this check participates at (burpsy-react-ui-ev7y). Zero —
	// SpeedFast — is every run, so an unranked check is admitted everywhere.
	speed CheckSpeed
	// typeIndex is the catalogue's issue type, which is what an operator's SELECTED ISSUES list
	// names. Check names are the labels Burp's own UI shows and are stable enough to select by, but
	// the type index is the identity the catalogue and its coverage accounting use, so a selection
	// made against the catalogue and one made against the UI are the same selection rather than two
	// vocabularies that have to be kept in step (burpsy-react-ui-kvmx).
	//
	// Zero for a check the catalogue does not describe. Such a check is NOT selectable and NOT
	// excludable by a list, because "a list that silently did not apply to half the check set" is the
	// failure this exists to remove. A loaded corpus check is not one of them: it carries
	// BCheckGeneratedTypeIndex, the row Burp files and selects every BCheck under.
	typeIndex uint32
	scope     DispatchScope
	enabled   func(*ScanConfig) bool
	// invasiveness is the tier the `scan_type_*_active` keys select this check under. It is
	// snapshotted with the set rather than looked up per dispatch, so a check cannot change tier
	// between two items of one session.
	invasiveness CheckInvasiveness
	// phase is the descriptor's evidence-producing stage, carried here so the outcome can record
	// which stage each disposition happened in (burpsy-react-ui-0qhf). Until this field existed the
	// descriptor's Phase was read nowhere in the engine, so an item's outcome could say that four
	// checks were skipped but not whether the stored phase ever ran at all.
	phase CheckPhase
	// passive marks a check that reads the request and its response without sending a probe of its
	// own. Those hang from `scan_type_passive`, not from the three active tiers, so a preset that
	// turns every active tier off still runs them — a passive check cannot change server state,
	// which is the property the intrusive tier exists to protect.
	passive bool
	// methods are the Burp detection methods this check uses (CheckDescriptor.DetectionMethods). A run
	// whose configuration disabled one of them for typeIndex does not dispatch the check.
	methods []string
	// dynamicJS marks a check that drives the browser (the DOM families): it runs on the item's
	// dynamic JavaScript clock and leaves the set when the run turns dynamic analysis off.
	dynamicJS bool
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
		out = append(out, s.corpusActiveChecks(s.corpusChecksEnabled(corpus))...)
	}
	// The per-issue selection, applied LAST and to BOTH sources. Burp's dispatch is a two-stage
	// filter (Zwy6.java:36-75, with the per-check predicate at :170-184), so the type filter sits
	// after the family switches rather than inside them: a run restricted to SQLi and path traversal
	// still has to be able to turn the SQLi FAMILY off and select nothing of it, and the reverse.
	//
	// Applied here rather than in each source so a corpus check is subject to the same selection as a
	// native one. A list that filtered the built-in table and not the corpus would be a selection
	// with a hole in it exactly where the operator least expects one.
	return filterByIssueTypes(out, cfg.IssueTypes)
}

// filterByIssueTypes narrows a check set to the issue types an operator selected.
//
// An empty or unset selection means "no restriction" — the same reading every optional field on
// this configuration uses, and the one that keeps a preset that does not mention selection behaving
// exactly as before.
//
// A check with NO type index is EXCLUDED whenever a selection is in force, because it is not
// selectable and a selection that cannot name something must not silently keep it. That is the
// conservative direction: the operator asked for a set, and a check they could not have chosen
// either way is better reported as unselected than as selected.
func filterByIssueTypes(checks []activeCheck, selected []uint32) []activeCheck {
	if len(selected) == 0 {
		return checks
	}
	allow := make(map[uint32]bool, len(selected))
	for _, t := range selected {
		allow[t] = true
	}
	out := make([]activeCheck, 0, len(checks))
	for _, c := range checks {
		if c.typeIndex != 0 && allow[c.typeIndex] {
			out = append(out, c)
		}
	}
	return out
}

// ActiveCheckCount reports how many checks are in the set this scanner would dispatch — the figure
// AuditOutcome.Considered must equal for a dispatched item.
func (s *ActiveScanner) ActiveCheckCount() int { return len(s.enabledChecks()) }

// ActiveCheckCountUnder is the size of the check set a run under cfg dispatches — what
// AuditOutcome.Considered equals for a dispatched item of that run. ActiveCheckCount ignores the
// run's configuration, so a reply quoting it beside a run whose configuration removed issue types
// stated a larger check set than the one it accounted for (burpsy-react-ui-saq3.1).
func (s *ActiveScanner) ActiveCheckCountUnder(cfg AuditConfig) int {
	return len(s.enabledChecksUnder(cfg))
}

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
	// use_dynamic_analysis false (burpsy-react-ui-9mti): every DOM family check drives the browser, so
	// all of them leave the set. The static pass is not a check and is governed by its own key.
	if !cfg.dynamicJavaScriptOn() {
		zeroFamilies(&base, auditLevelJavaScriptFamilies)
	}
	// activeTiers returns nil when no tier key was set, which leaves the base switches alone; a
	// non-nil set is three independent selections rather than one collapsed gate.
	//
	// The per-issue filter is applied here as well as on the no-gate path, and must be LAST: it is
	// the second stage of Burp's two-stage dispatch, and a configuration may set either alone, both,
	// or neither.
	checks := s.enabledChecksInTiers(base, activeTiers(cfg), cfg.ScanSpeed)
	// The scanner's OWN selection (ScanConfig.IssueTypes, set through /api/scanner/config) narrows
	// this path exactly as it narrows the ungated one in enabledChecks. It was missing here, so any run
	// configuration with a gate — now including an imported deny-only selection — silently dropped an
	// operator's whitelist and dispatched every type.
	checks = filterByIssueTypes(checks, base.IssueTypes)
	return filterBySelection(checks, cfg)
}

// hasAuditLevelGate reports whether the configuration narrows the check set at all.
func (cfg AuditConfig) hasAuditLevelGate() bool {
	if cfg.PassiveChecks.Set && cfg.PassiveChecks.Value == 0 {
		return true
	}
	if activeTiers(cfg) != nil {
		return true
	}
	// The per-issue selection is itself a narrowing of the check set, so a configuration that
	// ONLY selects issue types has a gate. Leaving it out of this predicate is the difference
	// between a selection that applies and one that is computed and discarded, and it is invisible
	// from every other test: a preset with no family switch and a selection would quietly audit
	// everything (burpsy-react-ui-kvmx).
	if len(cfg.IssueTypes) > 0 {
		return true
	}
	// The deny half of the selection narrows the set exactly as the whitelist does, and leaving it out
	// of this predicate would be kvmx again: an imported "all except time-based" configuration would
	// take the ungated shortcut and dispatch the five issue types it removed.
	if len(cfg.DisabledIssueTypes) > 0 || len(cfg.DisabledDetectionMethods) > 0 {
		return true
	}
	if cfg.ScanSpeed.Set {
		// A speed selector narrows the check set on its own axis, so a configuration that sets ONLY
		// scan_speed still needs the gated path (burpsy-react-ui-ev7y). Without this the ungated
		// shortcut returns before the speed filter is ever consulted, and the key reaches the queue
		// row while every check still runs — a preset that reads as applied and changes nothing.
		return true
	}
	// use_dynamic_analysis false narrows the set by the DOM families (burpsy-react-ui-9mti); leaving it
	// out of this predicate would be kvmx again — the ungated shortcut would dispatch them.
	if !cfg.dynamicJavaScriptOn() {
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
		case "CheckFileUpload":
			cfg.CheckFileUpload = false
		case "CheckJwtForgery":
			cfg.CheckJwtForgery = false
		case "CheckIDOR":
			cfg.CheckIDOR = false
		case "CheckLoginRateLimit":
			cfg.CheckLoginRateLimit = false
		case "CheckUsernameEnumeration":
			cfg.CheckUsernameEnumeration = false
		}
	}
}

// enabledChecksIn is enabledChecks against an explicit configuration snapshot instead of the
// scanner's own — the mechanism the audit-level gate overlays with. The ledger bit-stability rule
// is unchanged: the set is snapshotted once per run, before any item is admitted.
func (s *ActiveScanner) enabledChecksIn(cfg ScanConfig) []activeCheck {
	return s.enabledChecksInTiers(cfg, nil, OptUint32{})
}

// enabledChecksInTiers is enabledChecksIn under a tier selection. A nil tiers map admits every
// check the base switches do, which is what a run with no `scan_type_*_active` key set means. A
// non-nil map admits a check only when its OWN tier is in the set — so light and medium are
// independent selections, and a preset that enables one does not inherit the others.
func (s *ActiveScanner) enabledChecksInTiers(cfg ScanConfig, tiers map[CheckInvasiveness]bool, speed OptUint32) []activeCheck {
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
		// The speed axis (burpsy-react-ui-ev7y), independent of the tier gate above and applied
		// after it: a check must satisfy BOTH, because they answer different questions — what this
		// check does to the target, and what it costs to run.
		//
		// Passive checks are exempt for the same reason they are exempt from the tiers: they send
		// nothing, so there is no cost for a speed selector to trade away. An unset ScanSpeed admits
		// everything, which is what a configuration that never mentioned speed means.
		if speed.Set && !c.passive && !c.speed.RunsAt(CheckSpeed(speed.Value)) {
			continue
		}
		out = append(out, c)
	}
	// Corpus checks are ranked where Burp ranks every BCheck: BCHECK_GENERATED carries the INTRUSIVE
	// scan type alone (/root/burp-re/out/deobf_merged/burp/Zcot.java:1189-1191), and in scan-type
	// mode a type runs only when every scan type it carries is enabled (Zx9y.java:24-58). The one
	// exception Burp makes is a BCheck's PASSIVE method under scan_type_passive (Zx9y.java:60-65),
	// and these are the corpus's ACTIVE checks.
	//
	// They used to join every tier on the reading that a preset "has not said anything about an
	// operator's own corpus". Burp's own presets do say: "Audit checks - passive" dispatched the
	// operator's active BChecks — probes against the target — under a configuration named for not
	// sending any (burpsy-react-ui-saq3.1). A tier map that never set the intrusive key (nil) still
	// leaves the corpus alone, as it leaves the built-in checks alone.
	if cfg.CheckCorpus && (tiers == nil || tiers[TierIntrusive]) {
		out = append(out, s.corpusActiveChecks(s.corpusChecksEnabled(corpus))...)
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

	// sender is the run's own derived sender when its configuration overrides the engagement's
	// timeouts (burpsy-react-ui-o2p3), nil otherwise. senderErr is why an override could not be
	// applied; every item of such a run is refused with it rather than run under the engagement's
	// timeouts the configuration said not to use.
	sender    *sender.Sender
	senderErr error

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

	// perHostLastProbe is the last time a probe was sent to each host (m0sv).
	perHostLastProbe map[string]time.Time
	// inFlightPerHost is the current in-flight probe count per host (m0sv).
	inFlightPerHost map[string]int
	// perHostThrottleMs is the resolved per-host throttle interval in ms (m0sv).
	perHostThrottleMs uint32
	// perHostMaxInFlight is the resolved per-host in-flight cap (m0sv).
	perHostMaxInFlight uint32

	// pointEffectiveness is the per-insertion-point effectiveness prior (y4om) and
	// pointEffective is the oracle handed to the enumerator — nil when the gate is off,
	// which is what makes "the operator turned it off" and "no run" indistinguishable
	// to a check, and correctly so.
	//
	// On the run for the reason lightAudit is: a place is only worth judging once
	// something has already probed it, so the evidence spans items. Per item it
	// could never fire.
	pointEffectiveness pointEffectiveness
	// gateEnabled is the resolved SkipIneffectiveChecks state, kept so the item that builds
	// the oracle does not have to re-read the unset-means-default rule.
	gateEnabled bool

	mu sync.Mutex
	// requestsSent counts probes from items that have already finished. The current item's probes
	// are counted separately, because its meter is still live.
	requestsSent uint32

	// admission is the MaxItemsInProgress gate (burpsy-react-ui-3ymo): a buffered channel used as a
	// counting semaphore, sized to the run's resolved cap. Acquiring blocks the caller rather than
	// refusing the item — an item over the cap is waiting to be admitted, not declined — and it is
	// sized once at run construction because the cap is a property of this run, same as the deadline.
	admission chan struct{}
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
	r := &auditRun{cfg: cfg, ledger: ledger, admission: make(chan struct{}, cfg.resolvedMaxItemsInProgress())}
	if cfg.TimeBudget > 0 {
		r.deadline = time.Now().Add(cfg.TimeBudget)
	}
	if cfg.PerHostThrottleMs.Set && cfg.PerHostThrottleMs.Value > 0 {
		r.perHostThrottleMs = cfg.PerHostThrottleMs.Value
	}
	if cfg.PerHostMaxInFlight.Set && cfg.PerHostMaxInFlight.Value > 0 {
		r.perHostMaxInFlight = cfg.PerHostMaxInFlight.Value
	}
	// The effectiveness gate is resolved once, here, for the same reason MaxItemsInProgress is:
	// the unset-means-default rule has one home, and a per-item re-read would let two items of one
	// run disagree about whether the gate is on.
	r.gateEnabled = true
	if cfg.SkipIneffectiveChecks.Set {
		r.gateEnabled = cfg.SkipIneffectiveChecks.Value != 0
	}
	return r
}

// acquireAdmission blocks until a slot under MaxItemsInProgress is free, or ctx ends first. False
// means the wait was cancelled: no slot was taken, no state changed, and the caller must treat the
// item as never claimed rather than as a failed check.
//
// The non-blocking send is tried FIRST, as a separate select, and that is the whole reason this
// function is not the obvious one-liner. A single select over both cases makes the outcome
// UNDETERMINED when both are ready — a pre-cancelled context and a free slot — and Go picks
// between ready cases at random. So the same audit reported ItemStateCancelled on some runs and
// ItemStateBounded on others, which is the flakiness a caller sees as "the cancel sometimes works".
//
// An already-cancelled context still takes the slot when one is free. That is deliberate: the
// dispatch loop checks ctx.Err() as its own first hard stop, so a cancelled audit is bounded and
// reported as bounded with Cancelled set, rather than refused before it is ever admitted. The
// contract is "cancelled while WAITING for a slot", and with a free slot there is no wait.
func (r *auditRun) acquireAdmission(ctx context.Context) bool {
	select {
	case r.admission <- struct{}{}:
		return true
	default:
	}
	select {
	case r.admission <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// releaseAdmission frees the slot acquireAdmission took. Called exactly once per successful
// acquireAdmission, via defer, so a panic mid-check still returns the slot.
func (r *auditRun) releaseAdmission() {
	<-r.admission
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

// perHostThrottle enforces the minimum interval between probes to the same host (m0sv).
// If PerHostThrottleRandom is set, the interval is jittered by up to 50%.
//
// Reads the RESOLVED r.perHostThrottleMs, for the same reason perHostInFlight reads its resolved
// cap: the raw config field is unset on a run that was never built by newAuditRun, and a throttle
// read from it silently became "no throttle" — a bound that reports itself in force and does not.
//
// The map is created under r.mu, not before it. AuditSession dispatches items concurrently and
// every worker calls this, so a check-then-create outside the lock is a concurrent map write: the
// race the Go gate is there to catch, reachable from a slow host with two workers.
func (r *auditRun) perHostThrottle(ctx context.Context, host string) {
	interval := time.Duration(r.perHostThrottleMs) * time.Millisecond
	if r.cfg.PerHostThrottleRandom {
		// Jitter by up to 50% so a fixed cadence is not fingerprintable. The bound is on the
		// jitter, never the interval: Int63n(0) panics, and a one-millisecond interval has a
		// zero-width jitter band.
		if half := int64(interval) / 2; half > 0 {
			interval += time.Duration(rand.Int63n(half))
		}
	}
	r.mu.Lock()
	if r.perHostLastProbe == nil {
		r.perHostLastProbe = make(map[string]time.Time)
	}
	last := r.perHostLastProbe[host]
	// Stamped BEFORE the wait, not after. Two workers pacing the same host would otherwise both
	// read the same pre-wait timestamp, both sleep the full interval, and then both fire together
	// — the exact burst the throttle exists to prevent.
	r.perHostLastProbe[host] = time.Now()
	r.mu.Unlock()

	// First probe to this host has no predecessor, so there is nothing to wait out.
	if last.IsZero() {
		return
	}
	if wait := interval - time.Since(last); wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
	}
}

// perHostInFlight enforces the per-host in-flight cap (m0sv). Blocks until a slot
// is free or the context is cancelled.
//
// Reads the RESOLVED r.perHostMaxInFlight, not r.cfg.PerHostMaxInFlight.Value. The two are the same
// number only after newAuditRun has run, and reading the raw config here made a cap of zero compare
// as "current < 0" — never true — so a run configured with a cap spun here forever instead of
// admitting work. A cap that cannot deadlock is resolved once, at construction, which is what the
// MaxItemsInProgress admission gate already does for the same reason.
func (r *auditRun) perHostInFlight(ctx context.Context, host string) {
	cap := int(r.perHostMaxInFlight)
	if cap <= 0 {
		// No cap configured. Admitting without counting is correct: the count exists only to
		// enforce the cap, and an absent cap is a supported state, not a cap of zero.
		return
	}
	for {
		r.mu.Lock()
		if r.inFlightPerHost == nil {
			r.inFlightPerHost = make(map[string]int)
		}
		current := r.inFlightPerHost[host]
		if current < cap {
			r.inFlightPerHost[host] = current + 1
			r.mu.Unlock()
			return
		}
		r.mu.Unlock()
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			return
		}
	}
}

// releasePerHostInFlight decrements the in-flight count for a host after a probe completes.
func (r *auditRun) releasePerHostInFlight(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inFlightPerHost[host] > 0 {
		r.inFlightPerHost[host]--
	}
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
	// Skipped counts checks the engine could not run at all — no implementation, a dispatch scope
	// with no addressable unit, an evaluator decline, or a capability this scan lacks.
	Skipped int `json:"skipped"`
	// CapabilityMissing counts the checks inside Skipped that are implemented but could not run in
	// this scan: no sender, browser, collaborator, session coordinator or ledger, or no authorised
	// sender for the exchange (errCapabilityMissing). A qualifier on Skipped, not a tenth disposition,
	// so an operator can tell "not implemented" from "implemented, but this scan could not run it".
	CapabilityMissing int `json:"capability_missing"`
	// NotRun counts checks never attempted because the time budget ran out.
	NotRun int `json:"not_run"`
	// AlreadyCovered counts checks not admitted because an identical (dispatch unit, check) already
	// ran this session.
	AlreadyCovered int `json:"already_covered"`
	// ByPhase is the same dispositions attributed to the phase that produced them
	// (burpsy-react-ui-0qhf). Burp tracks per-phase state per item because "this stage produced
	// nothing" and "this stage never ran" are different facts, and the totals above cannot tell
	// them apart: four skipped checks read the same whether they were all in the stored phase or
	// spread across three. Keyed by phase name so the JSON is readable without the enum table.
	ByPhase map[string]PhaseOutcome `json:"by_phase,omitempty"`
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
	// PointsJudgedIneffective counts the probes the per-point effectiveness gate spent on places
	// that answered nothing (burpsy-react-ui-y4om). Beside PointsSkippedRepetitive and not in
	// Considered(): the gate drops places on the NEXT dispatch, so the probes this run already
	// paid are neither a check disposition nor a skip — they are the run's own evidence, and a
	// request count that fell without this number says nothing about why.
	PointsJudgedIneffective int `json:"points_judged_ineffective"`
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
	// MethodsDeclined is every detection method a dispatched check of this item did not run, each
	// with its reason (burpsy-react-ui-2hze): a method the configuration disabled, with the probes
	// that were withheld because of it, and a method the configuration enabled that burpsy's check
	// does not implement — "Burp Infiltrator" above all. A qualifier on the checks that ran, not a
	// tenth disposition: the check was considered and dispatched, and what it did not do is listed
	// here rather than folded into a count that would read as a clean result. Marshals as [].
	MethodsDeclined MethodDeclines `json:"methods_declined"`
	// JavaScriptAnalysisSkips names each JavaScript-analysis pass of this item that a
	// javascript_analysis time limit cut short or never let start (burpsy-react-ui-9mti): the static
	// pass once, and each browser-driven check or tier by name. The checks it names are also counted
	// in Skipped — this is the reason beside the count, Burp's per-item alert. Marshals as [].
	JavaScriptAnalysisSkips JSAnalysisSkips `json:"javascript_analysis_skips"`
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
	if o.CapabilityMissing > 0 {
		fmt.Fprintf(&b, "; %d of the unsupported are implemented checks this scan lacked a capability for", o.CapabilityMissing)
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
	if n := len(o.MethodsDeclined); n > 0 {
		fmt.Fprintf(&b, "; %d detection method(s) declined", n)
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
	// StartOrder is the order items were started in, by priority score (ftk2), with each item's score.
	// Items is still in the order requested.
	StartOrder []AuditPriority `json:"start_order"`
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
	run.sender, run.senderErr = s.runSenderFor(cfg)
	defer run.sender.CloseIdleConnections()
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
// Items are *started* in priority order (ftk2) — a fixed pool of workers pulls from an ordered queue,
// rather than every item racing for a semaphore — so with one worker this is exactly the Rust
// behaviour, and with more it is as close as concurrency allows. What is not deterministic above one
// worker is which of two items covering the same dispatch unit gets admitted and which is refused as
// DispositionAlreadyCovered: in Rust it is always the later one in the given order, here it is
// whichever worker reaches the admission gate first. The totals are identical either way; only the
// attribution moves. Items come back in the order requested regardless.
func (s *ActiveScanner) AuditSession(ctx context.Context, exchangeIDs []core.ExchangeID, cfg AuditConfig) (*SessionOutcome, []*Finding) {
	checks := s.enabledChecksUnder(cfg)
	run := newAuditRun(cfg)
	// Built once per run, never per probe: a derived sender owns a transport, and one per probe would
	// throw away connection reuse for exactly the runs that set tight timeouts.
	run.sender, run.senderErr = s.runSenderFor(cfg)
	defer run.sender.CloseIdleConnections()
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
	// Started in priority order (burpsy-react-ui-ftk2, audit_priority.go): Burp's audit queue orders
	// items by attack-surface exposure and interest, so a time-bounded run spends its budget on the
	// items that expose the most, not on whatever was submitted first.
	order, priorities := s.priorityOrder(exchangeIDs, cfg)
	out.StartOrder = priorities

	// Every item joins the queue as Pending before any worker starts, which is what makes the queue a
	// queue rather than a log of finished work: a batch of 200 is 200 Pending rows the instant the
	// sweep tick begins, and they move to Auditing and then to a terminal state as workers reach
	// them. Enqueued in start order, so the queue's own order is the order items will run.
	for _, slot := range order {
		cfg.Items.Enqueue(exchangeIDs[slot], len(checks))
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
					o := s.refuseWholeItem(ItemStatePaused, len(checks), func(o *AuditOutcome) *int { return &o.SessionPaused }, func(po *PhaseOutcome) { po.SessionPaused++ })
					out.Items[slot] = ItemOutcome{ExchangeID: exchangeID, Outcome: o}
					cfg.Items.Resolve(exchangeID, nil, o, cfg, auditItemNote(o, cfg))
					continue
				case run.outOfTime() || ctx.Err() != nil:
					o := refuseWholeItemByPhase(ItemStateBounded, checks, func(o *AuditOutcome) *int { return &o.NotRun }, func(po *PhaseOutcome) { po.NotRun++ })
					o.TimedOut = true
					o.Cancelled = ctx.Err() != nil
					out.Items[slot] = ItemOutcome{ExchangeID: exchangeID, Outcome: o}
					cfg.Items.Resolve(exchangeID, nil, o, cfg, auditItemNote(o, cfg))
					continue
				case run.overRequestBudget(0):
					o := refuseWholeItemByPhase(ItemStateBounded, checks, func(o *AuditOutcome) *int { return &o.RequestBudgetSpent }, func(po *PhaseOutcome) { po.RequestBudgetSpent++ })
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
	// Fed in priority order. A cancelled context is not a reason to stop feeding: an item nobody looked
	// at must still come back with its check set attributed, and the refusals above are what do that.
	for _, slot := range order {
		queue <- slot
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
//
// The counter function determines which flat counter is bumped; the phaseBump determines which
// per-phase counter is bumped. Both are always called together so the two cannot drift.
func (s *ActiveScanner) refuseWholeItem(state ItemState, checks int, counter func(*AuditOutcome) *int, phaseBump func(*PhaseOutcome)) AuditOutcome {
	o := AuditOutcome{State: state}
	*counter(&o) = checks
	return o
}

// refuseWholeItemByPhase is refuseWholeItem for a caller that HAS the check set: it attributes the
// refusal to each check's phase as well as to the flat counter, so an item refused by the budget
// still says which stages went unrun. Without this the flat counters move and the phase table stays
// empty, which reads exactly like a phase that was never planned — the distinction this whole change
// exists to make (burpsy-react-ui-0qhf).
func refuseWholeItemByPhase(state ItemState, set []activeCheck, counter func(*AuditOutcome) *int, phaseBump func(*PhaseOutcome)) AuditOutcome {
	o := AuditOutcome{State: state}
	*counter(&o) = len(set)
	for i := range set {
		recordPhase(&o, set[i].phase, phaseBump)
	}
	return o
}

// recordPhase attributes one disposition to its check's phase, in both the flat counters and the
// per-phase table.
//
// ONE helper rather than a write at each site, because the two must not drift: a counter that moved
// without its phase attribution would make the per-phase table disagree with the totals, and a table
// that disagrees with the totals is worse than no table — an operator summing the phases and getting
// a different number than the run reports has been told two things at once.
func recordPhase(o *AuditOutcome, phase CheckPhase, bump func(*PhaseOutcome)) {
	if o.ByPhase == nil {
		o.ByPhase = make(map[string]PhaseOutcome, len(AllCheckPhases))
	}
	name := phase.String()
	po := o.ByPhase[name]
	bump(&po)
	o.ByPhase[name] = po
}

// bumpPhase is the ONE helper that bumps a flat counter and its per-phase counterpart together.
// Every disposition site routes through this so the two cannot drift.
func bumpPhase(o *AuditOutcome, phase CheckPhase, flat func(*AuditOutcome) *int, phaseBump func(*PhaseOutcome)) {
	*flat(o)++
	recordPhase(o, phase, phaseBump)
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
	if len(checks) == 0 && !s.javascriptTailRuns(run.cfg) {
		// Nothing was enabled, so nothing was declined either. Audited with zero considered is the
		// honest reading, and it is what the Rust original returns for an empty check set. A run whose
		// only DOM work is the static pass (use_dynamic_analysis false removed every DOM check) is not
		// such a run: the pass still has an item to read (burpsy-react-ui-9mti).
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
	// A run whose timeout override cannot be applied runs nothing (o2p3): the operator named the
	// bounds, and probing under the engagement's instead would be a run they did not configure.
	if run.senderErr != nil {
		return refuse(ex, ItemStateUnauditable, run.senderErr.Error())
	}
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

	// The MaxItemsInProgress gate (burpsy-react-ui-3ymo), claimed here rather than at the queue's
	// own scheduling point: everything above this line is a cheap refusal check that allocates
	// nothing, so an item that was going to be refused anyway (out of scope, no response, cancelled)
	// never counts against the cap. A cap applied after this line would already have flipped the
	// item to Auditing and started its meter, i.e. already have allocated the resources the cap
	// exists to bound — so it must gate the claim itself, not something claimed a moment earlier.
	if !run.acquireAdmission(ctx) {
		return refuse(ex, ItemStateCancelled, "cancelled while waiting for an admission slot")
	}
	defer run.releaseAdmission()

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
			// The per-kind opt-in, checked BEFORE the repetition threshold (burpsy-react-ui-02qi). A kind
			// the operator did not tick gets the FULL pass for every point of that kind -- which is the
			// whole control these eight keys are, and it is a different decision from
			// insertion_point_types: that one chooses WHICH points to enumerate, this one chooses which of
			// the enumerated ones get the cheap pass.
			//
			// A light run therefore narrows to the ticked kinds rather than being all-or-nothing, and an
			// operator who wants a light audit of URL parameters and a full audit of body parameters can
			// finally say so. Before this, the key table declined all eight as "redundant with
			// insertion_point_types", which is factually wrong -- they gate a different stage.
			if !run.cfg.LightAuditKinds.LightApplies(kind) {
				return false
			}
			return run.lightAuditShouldSkip(kind, host, lightThreshold)
		},
		recordClean: run.lightAuditRecordClean,
		recordSkip:  func() {},
		skipped:     &lightSkipped,
	}
	// The effectiveness gate's oracle, built from the item's OWN host so the same parameter on two
	// hosts is two applications' handling and neither judges the other. Nil when the gate is off,
	// which the checks read as "no gate" — the same nil-safe reading the light-audit tier uses.
	//
	// The item's configuration carries the oracle, because the enumerator reads it off
	// EnumerateOptions rather than off the context: it is enumeration-time advice, and a check that
	// builds a context by hand gets the engine default rather than a nil that would read as "drop
	// every point".
	itemCfg := run.cfg
	if run.gateEnabled {
		host := ex.Host
		prior := &run.pointEffectiveness
		itemCfg.PointEffective = func(check string, pt bcheck.InsertionPoint) bool {
			return prior.effective(check, pt, host)
		}
	}

	// The item's detection-method ledger (2hze): every check this item dispatches records into it,
	// both the probes a disabled method withheld and the enabled methods the check cannot run.
	methodDeclines := NewMethodDeclineLedger()
	ictx := withMethodDeclines(withRunConfig(withLightAudit(withMeter(ctx, meter), lightHandle), itemCfg), methodDeclines)
	// The run's own sender, when its configuration overrides the engagement's timeouts. probeGate is
	// the one reader, so every probe this item sends — and nothing else — leaves through it.
	ictx = withRunSender(ictx, run.sender)
	// The effectiveness ledger rides the context ONLY when the gate is on. A run with
	// skip_ineffective_checks set to zero must not even BUILD a prior: recording evidence
	// nobody will act on is not free, and the count it produced would then be reported
	// alongside a request count the gate never shaped.
	if run.gateEnabled {
		ictx = withPointEffectiveness(ictx, &run.pointEffectiveness)
	}
	breaker := newItemBreaker(run.cfg)
	// The item's dynamic JavaScript clock (burpsy-react-ui-9mti): one per item, started by its first
	// browser use, shared by its DOM checks and the confirmation tier, and the record of every pass a
	// javascript_analysis limit cut short.
	domClock := newDOMTimeBudget(itemCfg)

	// The plan is built before anything is dispatched, so "how much did we not do" is answerable at
	// every point rather than reconstructed afterwards.
	units, steps, undispatchable := plan(ex, checks)
	o.Skipped += undispatchable
	for _, c := range checks {
		if c.run == nil {
			bumpPhase(&o, c.phase, func(o *AuditOutcome) *int { return &o.Skipped }, func(po *PhaseOutcome) { po.Skipped++ })
		}
	}
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
	// counted[i] records whether steps[i] has already been given a disposition in SOME pass.
	//
	// A follow-up pass re-walks the plan from the start, so a step pass 0 abandoned or already
	// covered comes up again — and would be counted a second time, making Considered() exceed the
	// check set. That breaks the one identity the whole counter scheme exists to provide: an
	// operator adding up the buckets must get the enabled check set, not a multiple of it.
	//
	// Per-step rather than per-pass bookkeeping, and it is the only thing that makes the partition
	// hold across passes without threading a "which pass am I in" flag through nine dispositions.
	counted := make([]bool, len(steps))

	// countOnce gives a step its disposition at most once, across every pass. Every counting
	// site in the dispatch loop goes through it, because nine hand-maintained guards is eight
	// chances to miss one and one missed guard is one step counted twice — Considered() then
	// exceeds the check set, which is the identity every counter in this type exists to keep.
	countOnce := func(i int, phase CheckPhase, flat func(*AuditOutcome) *int, bump func(*PhaseOutcome)) {
		if counted[i] {
			return
		}
		counted[i] = true
		bumpPhase(&o, phase, flat, bump)
	}
	// The OUTER loop is the pass (burpsy-react-ui-krf5). It used to be a `goto dispatch` that
	// jumped to a label BELOW this loop, which meant a re-dispatched pass fell straight past the
	// loop that does the dispatching and into the tail that attributes what was left — so
	// FollowUpPasses was reported as 1 while no second pass ran, and the tail double-counted every
	// step as ItemFailed. An outer loop says the same thing structurally: a retry is another turn
	// of this loop, and falling out of it is what ends the item.
	for {
		// The plan is exhausted, not merely re-entered: the condition is the INNER loop's, and
		// without it a pass that ran out of steps would index past the end — a failed item whose
		// last step is the failure is the common case, not a rare one.
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

				// Per-host throttle (m0sv): the minimum interval between probes to one host, enforced
				// before the step dispatches. The in-flight cap is NOT taken here — see the send
				// region below for why it has to bracket the check rather than the loop iteration.
				run.perHostThrottle(ctx, ex.Host)

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
					bumpPhase(&o, checks[steps[pos].check].phase, func(o *AuditOutcome) *int { return &o.RateLimited }, func(po *PhaseOutcome) { po.RateLimited++ })
				}

				check := steps[pos].check
				pos++
				// One call per step consumed, whatever disposition it lands in — placed here, at the single
				// point pos advances, rather than beside each of the nine outcomes below. A progress counter
				// maintained at nine sites is one that eventually disagrees with the plan it is a fraction of.
				run.cfg.Items.Step(exchangeID)
				if abandoned {
					// `check`, not steps[pos]: pos was already advanced above, so steps[pos] is the
					// NEXT step and attributed this disposition to a phase that never reached it.
					//
					// countOnce guards the repeat: a follow-up pass re-walks the plan from the start,
					// so a step pass 0 abandoned comes up again and is abandoned again. Counting it
					// twice is how Considered() came to exceed the check set on a re-dispatched item.
					countOnce(pos-1, checks[check].phase, func(o *AuditOutcome) *int { return &o.UnitAbandoned }, func(po *PhaseOutcome) { po.UnitAbandoned++ })
					continue
				}
				if !run.ledger.Admit(units[unitIx].key, check) {
					countOnce(pos-1, checks[check].phase, func(o *AuditOutcome) *int { return &o.AlreadyCovered }, func(po *PhaseOutcome) { po.AlreadyCovered++ })
					continue
				}
				// The narrowing that makes a follow-up pass bounded work rather than more of the same: a
				// check that already failed in this unit is not tried again (burpsy-react-ui-5efx). Burp asks
				// the same question per insertion point (Zwy6.java's Zz); this asks it per (unit, check),
				// which is the granularity the dispatch plan has.
				//
				// No `pos++` here: pos was already advanced when this step was consumed, and
				// advancing it again silently ate the NEXT step's disposition (krf5). The narrowing
				// skips this check; the loop's own condition moves on.
				if pass > 0 && breaker.AlreadyFailed(units[unitIx].key, checks[check].name) {
					// Marked disposed though nothing is counted: pass 0 already gave this step its
					// disposition (a send failure, or the unit abandonment behind it). The mark is
					// what stops the TAIL below counting it a second time as ItemFailed.
					counted[pos-1] = true
					continue
				}

				// The per-host in-flight cap brackets the CHECK, not the loop iteration. Bracketing the
				// iteration with a defer would hold the slot until the whole auditItem returned —
				// AuditSession dispatches items concurrently, so every worker would hold one slot per
				// host for the item's entire duration and a cap of N would admit N items rather than N
				// probes. This region is deliberately linear, with no `continue` between the acquire and
				// the release, which is what makes the pairing safe here rather than only apparently safe.
				// The methods this configuration ENABLED for the check's type that burpsy's check does
				// not implement are declined on every item the check runs on, so an item's outcome says
				// what its SQL injection check did not try, not only what the configuration said.
				for _, d := range run.cfg.DeclinedDetectionMethods {
					if d.Method != "" && d.TypeIndex == checks[check].typeIndex {
						methodDeclines.Record(d)
					}
				}
				// A browser-driven check under a spent max_dynamic_time_per_item does not start: counted
				// Skipped with the reason, never clean (burpsy-react-ui-9mti).
				if checks[check].dynamicJS && domClock.spent() {
					countOnce(pos-1, checks[check].phase, func(o *AuditOutcome) *int { return &o.Skipped }, func(po *PhaseOutcome) { po.Skipped++ })
					domClock.skip(checks[check].name, domClock.dynamicLimitReason(false))
					continue
				}
				runCtx, stopClock := ictx, func() {}
				if checks[check].dynamicJS {
					runCtx, stopClock = domClock.ctx(ictx)
				}
				run.perHostInFlight(ctx, ex.Host)
				before := meter.snapshot()
				verdict, runErr := checks[check].run(s, runCtx, ex)
				stopClock()
				d := meter.since(before)
				run.releasePerHostInFlight(ex.Host)

				// Stopped by the item's dynamic time limit rather than by the target: Skipped with the
				// reason, BEFORE the failure branch, because a limit the run imposed on itself must not
				// trip the breaker that abandons units for a failing target.
				if runErr != nil && checks[check].dynamicJS && domClock.spent() && ictx.Err() == nil {
					countOnce(pos-1, checks[check].phase, func(o *AuditOutcome) *int { return &o.Skipped }, func(po *PhaseOutcome) { po.Skipped++ })
					o.FindingsDropped += len(verdict)
					domClock.skip(checks[check].name, domClock.dynamicLimitReason(true))
					continue
				}

				// A check the evaluator declined is in the same position as one with no implementation:
				// nothing ran and nothing proved. Counted as Skipped (DispositionUnsupported) so the
				// check set still partitions and a clean outcome cannot be read as a clean bill of
				// health for this check.
				if errors.Is(runErr, errCheckUnsupported) {
					first := !counted[pos-1]
					countOnce(pos-1, checks[check].phase, func(o *AuditOutcome) *int { return &o.Skipped }, func(po *PhaseOutcome) { po.Skipped++ })
					// The qualifier follows the Skipped count exactly once per step, so a re-dispatched
					// pass cannot count one missing capability twice.
					if first && errors.Is(runErr, errCapabilityMissing) {
						o.CapabilityMissing++
					}
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
					countOnce(pos-1, checks[check].phase, func(o *AuditOutcome) *int { return &o.Ran }, func(po *PhaseOutcome) { po.Ran++ })
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
					countOnce(pos-1, checks[check].phase, func(o *AuditOutcome) *int { return &o.SendFailures }, func(po *PhaseOutcome) { po.SendFailures++ })
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
					countOnce(pos-1, checks[check].phase, func(o *AuditOutcome) *int { return &o.SendFailures }, func(po *PhaseOutcome) { po.SendFailures++ })
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
				countOnce(pos-1, checks[check].phase, func(o *AuditOutcome) *int { return &o.Ran }, func(po *PhaseOutcome) { po.Ran++ })
				breaker.checkSucceeded()
				recordPhase(&o, checks[check].phase, func(po *PhaseOutcome) { po.Findings += len(verdict) })
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

		// The retry decision. A pass is worth spending only when the item FAILED and some step is
		// still retryable — which, after the narrowing above, means some check in this item has never
		// been tried.
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
				// Another turn of the OUTER pass loop, which is the dispatch loop. Not a jump to a
				// label below the loop: that is the defect krf5 removed, and it is why a re-dispatched
				// pass used to report itself while dispatching nothing.
				continue
			}
		}
		// No pass was worth spending. Break the outer loop, which is the only way out of it now that
		// the retry above continues it — the loop runs until a pass declines to retry.
		break
	}
	o.FollowUpPasses = pass

	// Everything left in the plan is work this engine chose not to admit. Attributing it is what
	// turns a bound into something a caller can see. The breaker owns whether the item failed; stop
	// owns why dispatch ended.
	// Kept for the log line below; the tail iterates the plan rather than a count.
	switch {
	case breaker.failed():
		// Only steps with no disposition yet. A follow-up pass re-walks the plan, so steps[pos:]
		// can include steps an earlier pass already counted; counting those again here is what
		// made Considered() exceed the check set on a re-dispatched item.
		for i := pos; i < len(steps); i++ {
			if counted[i] {
				continue
			}
			counted[i] = true
			bumpPhase(&o, checks[steps[i].check].phase, func(o *AuditOutcome) *int { return &o.ItemFailed }, func(po *PhaseOutcome) { po.ItemFailed++ })
		}
		o.State = ItemStateFailed
	case stopped && stop == DispositionTimeBudgetSpent:
		for i := pos; i < len(steps); i++ {
			if counted[i] {
				continue
			}
			counted[i] = true
			bumpPhase(&o, checks[steps[i].check].phase, func(o *AuditOutcome) *int { return &o.NotRun }, func(po *PhaseOutcome) { po.NotRun++ })
		}
		o.State = ItemStateBounded
	case stopped && stop == DispositionRequestBudgetSpent:
		for i := pos; i < len(steps); i++ {
			if counted[i] {
				continue
			}
			counted[i] = true
			bumpPhase(&o, checks[steps[i].check].phase, func(o *AuditOutcome) *int { return &o.RequestBudgetSpent }, func(po *PhaseOutcome) { po.RequestBudgetSpent++ })
		}
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

	// Phase 12: the item's JavaScript analysis tail — the static DOM pass over its own response and
	// the browser confirmation of what it found (burpsy-react-ui-m97j), now under the run's
	// javascript_analysis keys and issue selection (burpsy-react-ui-9mti; js_analysis.go). Only when
	// the DOM families are enabled for this run: scan_type_javascript_analysis false used to remove
	// the DOM checks and leave this tail running the browser anyway. The confirmation still needs a
	// browser; the static pass does not, so a run with dynamic analysis off reports its static
	// candidates without one.
	if s.javascriptTailRuns(run.cfg) {
		if jsFound := s.javascriptAnalysisFor(ictx, ex, itemCfg, domClock); len(jsFound) > 0 {
			found = append(found, jsFound...)
		}
	}
	o.JavaScriptAnalysisSkips = domClock.list()

	// The tier's per-item skip count, folded once (7bkj): the checks ran and answered;
	// this number says how many points they did not test, and rides the outcome beside the
	// rate-limiting count.
	o.PointsSkippedRepetitive = int(lightHandle.SkippedPoints())
	// The effectiveness gate's own accounting (y4om), folded the same way. Counted per ITEM
	// and summed into the run's outcome, because the gate's evidence is spread across the
	// items that probed and the items whose places it then dropped.
	o.PointsJudgedIneffective += run.pointEffectiveness.Count()
	o.MethodsDeclined = methodDeclines.List()
	if len(found) > 0 {
		s.findingsMu.Lock()
		s.findings = append(s.findings, found...)
		s.findingsMu.Unlock()
	}
	run.cfg.Items.Resolve(exchangeID, ex, o, run.cfg, auditItemNote(o, run.cfg))
	return o, found
}
