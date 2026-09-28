package scanner

import (
	"context"
	"sync/atomic"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// CheckImplementation describes where an evaluator comes from. These values are
// deliberately explicit: catalog metadata and a parsed BCheck are not proof that
// a check ran.
type CheckImplementation string

const (
	ImplementationNative   CheckImplementation = "native"
	ImplementationBCheck   CheckImplementation = "bcheck"
	ImplementationTool     CheckImplementation = "tool"
	ImplementationDeclined CheckImplementation = "declined"
)

// CheckPhase identifies the evidence-producing stage for an evaluator.
type CheckPhase uint8

const (
	PhasePassive CheckPhase = iota
	PhaseLightActive
	PhaseActive
	PhaseStored
	PhaseCollaborator
	PhaseJavaScript
)

// String names the phase for an outcome record and the audit queue's item row. Burp names its
// seven audit phases (Zefx) and an operator comparing a thin burpsy run against a Burp one needs
// to see which stage produced nothing; an unnameable enum cannot say.
//
// The names are burpsy's own stages, not Burp's seven: the two do not correspond one-to-one, and
// claiming a mapping this tree cannot evidence would be worse than naming what is actually here.
func (p CheckPhase) String() string {
	switch p {
	case PhasePassive:
		return "passive"
	case PhaseLightActive:
		return "light-active"
	case PhaseActive:
		return "active"
	case PhaseStored:
		return "stored"
	case PhaseCollaborator:
		return "collaborator"
	case PhaseJavaScript:
		return "javascript"
	default:
		return "unknown"
	}
}

// AllCheckPhases is every phase in declaration order, so a report can render a fixed table rather
// than a map whose key set varies with what happened to run.
var AllCheckPhases = [...]CheckPhase{
	PhasePassive, PhaseLightActive, PhaseActive, PhaseStored, PhaseCollaborator, PhaseJavaScript,
}

// PhaseOutcome is what one phase did for one audit item.
//
// Burp tracks per-phase state per item (its Zekf nibble) precisely because "this phase produced
// nothing" and "this phase never ran" are different facts, and an operator diagnosing a thin
// result needs to tell them apart. burpsy recorded a phase on every descriptor and read it
// nowhere, so both collapsed into the same silence (burpsy-react-ui-0qhf).
type PhaseOutcome struct {
	// Ran counts checks of this phase that completed without a transport failure.
	Ran int `json:"ran"`
	// Findings is what this phase contributed, so a phase that ran and found nothing is
	// distinguishable from one that never ran.
	Findings int `json:"findings"`
	// Skipped counts checks of this phase the engine could not run (no implementation, or a
	// dispatch scope with no addressable unit).
	Skipped int `json:"skipped"`
	// SendFailures counts checks of this phase abandoned because no probe could be sent or read.
	SendFailures int `json:"send_failures"`
	// NotRun counts checks of this phase never attempted because the budget ran out.
	NotRun int `json:"not_run"`
	// AlreadyCovered counts this phase's steps not admitted because an identical
	// (dispatch unit, check) had already run this session.
	AlreadyCovered int `json:"already_covered"`
	// RateLimited counts this phase's steps the dispatch loop delayed on a 429 or 503 (fkl8).
	RateLimited int `json:"rate_limited"`
	// Refused counts this phase's checks the session declined before dispatch, by the reason
	// recorded in the item's refusal list. Present so a phase whose checks were all refused is
	// not indistinguishable from a phase that was never planned.
	Refused int `json:"refused"`
	// RequestBudgetSpent counts this phase's checks not admitted because the outbound-request
	// budget was spent. Separate from NotRun so a request-budget cut is not reported per phase
	// as a time-budget one.
	RequestBudgetSpent int `json:"request_budget_spent"`
	// UnitAbandoned counts this phase's checks not admitted because consecutive failures
	// abandoned their dispatch unit.
	UnitAbandoned int `json:"unit_abandoned"`
	// ItemFailed counts this phase's checks not admitted because the item breaker failed the
	// whole item.
	ItemFailed int `json:"item_failed"`
	// SessionPaused counts this phase's checks not admitted because the session breaker paused
	// the run before this item.
	SessionPaused int `json:"session_paused"`
}

// Observed reports whether this phase did anything at all — ran a check, or was refused one. A
// phase with nothing observed is the case an operator must be able to see: it means the run never
// reached that stage for this item.
func (p PhaseOutcome) Observed() bool {
	return p.Ran > 0 || p.Skipped > 0 || p.SendFailures > 0 || p.NotRun > 0 ||
		p.AlreadyCovered > 0 || p.RateLimited > 0 || p.Refused > 0 ||
		p.RequestBudgetSpent > 0 || p.UnitAbandoned > 0 || p.ItemFailed > 0 ||
		p.SessionPaused > 0
}

// CheckInvasiveness is a check's rank in Burp's light/medium/intrusive active tiers. It is the
// per-check ranking the `scanner/issues_reported/scan_type_*_active` keys select on.
//
// The zero value is TierLight on purpose: a descriptor that does not declare a rank is admitted by
// the lightest tier, so adding a check without a rank cannot silently exclude it from a run that
// asked for the light tier. Raising a rank is a deliberate act with a test behind it; leaving one
// unset is not.
type CheckInvasiveness uint8

const (
	TierLight CheckInvasiveness = iota
	TierMedium
	TierIntrusive
)

// String names the tier for the configuration key matrix and the launch warning. The names are
// Burp's, so an operator reading "intrusive" here and "scan_type_intrusive_active" in their preset
// is reading the same word twice.
func (i CheckInvasiveness) String() string {
	switch i {
	case TierLight:
		return "light"
	case TierMedium:
		return "medium"
	case TierIntrusive:
		return "intrusive"
	default:
		return "unknown"
	}
}

// checkTierNote is what the approximation note says when every active tier is on. Once the engine
// ranks checks, the three keys are independent and this text is retired; the note remains only for
// per-issue selection, which still has no representation here.
const tieredEngineNote = "per-issue selection (scan_only_selected_issues, select_individual_issues, selected_issues) is not applied"

// CheckContext is the stable boundary between dispatch and check logic. It carries
// handles and shared services; evaluators must not own transport or persistence.
type CheckContext struct {
	Scanner        *ActiveScanner
	Exchange       *core.Exchange
	StoredExchange *core.Exchange
	InsertionPoint *bcheck.InsertionPoint
	Sender         *sender.Sender
	Config         *ScanConfig
	// InsertionKinds is the bcheck point classes this run may probe — the audit configuration's
	// `scanner/insertion_point_types/*` answer. Empty means the caller supplied none, and
	// ProbeInsertionKinds falls back to the engine default.
	//
	// It lives here because Config is *ScanConfig, which is deliberately not merged with
	// AuditConfig (see ScanConfig's doc), so there was no path from the operator's choice to a
	// check at all: every probe site passed the DefaultProbeInsertionKinds literal, and the
	// configuration reached only the audit-queue row. Turning cookie insertion off changed what
	// the queue displayed and not one byte of what was sent (burpsy-react-ui-povm).
	InsertionKinds []string
	// EnumerateOptions is the run's insertion-point tuning — the per-request ceiling
	// (`max_insertion_points_per_base_request`) and whether nested points are expanded
	// (`use_nested_insertion_points`). The zero value is the engine default, which is what a
	// context built outside a dispatched audit gets.
	//
	// Beside InsertionKinds rather than folded into it because the two answer different questions:
	// InsertionKinds is *which classes of place*, this is *how many and how deep*. A check reads
	// both through ProbeEnumerateOptions, which is the only spelling a probe site should use.
	EnumerateOptions bcheck.EnumerateOptions
	// PointEffectiveCheck names the check currently being enumerated, for the
	// per-point effectiveness gate (y4om). Set by the dispatcher before the
	// harness enumerates, so a probe site knows which check it is scoring.
	PointEffectiveCheck string
	// PointEffectiveness is the per-point effectiveness oracle (y4om): nil
	// when the gate is off, non-nil when the run should drop places that have
	// already been probed without a single answer.
	PointEffectiveness *pointEffectiveness
	// LightAudit is the run's light-audit tier handle (burpsy-react-ui-7bkj): nil in a
	// context built outside a dispatched audit, which ProbeHarness-equivalent consumers read
	// as "the tier is off" — a unit test or a direct check call must not skip points on the
	// strength of a run it never joined. Set by the dispatcher to the run's own state.
	LightAudit *RunLightAudit
}

// RunLightAudit is what a check context sees of the audit run's light-audit tier: the
// should-skip question and the clean-record, nothing else. The run keeps the map and the
// threshold resolution so a check cannot invent its own prior.
type RunLightAudit struct {
	// shouldSkip answers whether this (kind, host) has enough clean occurrences to skip.
	shouldSkip func(kind, host string) bool
	// recordClean notes one more clean occurrence.
	recordClean func(kind, host string)
	// recordSkip notes one more skipped point, so the item's outcome can carry the tier's
	// accounting without the check returning a second channel of numbers.
	recordSkip func()
	// skipped is the per-item count this handle has recorded. The handle is per item, so
	// the dispatcher reads it once, after the item's checks have run.
	skipped *int32
}

// ShouldSkipRepetitive is the check-facing question. Nil-safe by design: a nil tier
// (outside a dispatched audit) never skips.
func (la *RunLightAudit) ShouldSkipRepetitive(kind, host string) bool {
	if la == nil || la.shouldSkip == nil {
		return false
	}
	return la.shouldSkip(kind, host)
}

// RecordCleanPoint is the check-facing report of a clean point. Nil-safe by design.
func (la *RunLightAudit) RecordCleanPoint(kind, host string) {
	if la == nil || la.recordClean == nil {
		return
	}
	la.recordClean(kind, host)
}

// RecordSkippedPoint notes one point the tier skipped. Nil-safe by design.
func (la *RunLightAudit) RecordSkippedPoint() {
	if la == nil || la.skipped == nil {
		return
	}
	atomic.AddInt32(la.skipped, 1)
}

// SkippedPoints is the item's skip count, for the dispatcher to fold into the outcome.
func (la *RunLightAudit) SkippedPoints() int32 {
	if la == nil || la.skipped == nil {
		return 0
	}
	return atomic.LoadInt32(la.skipped)
}

// ProbeEnumerateOptions is the enumerator tuning an active probe must enumerate under: the run's
// when a dispatched audit supplied one, the engine default otherwise.
//
// Paired with ProbeInsertionKinds — a probe site needs both, and a site that passed the kinds but
// enumerated with a default cap would send probes the operator's ceiling had excluded.
func (cc *CheckContext) ProbeEnumerateOptions() bcheck.EnumerateOptions {
	if cc == nil {
		return bcheck.EnumerateOptions{}
	}
	opts := cc.EnumerateOptions
	// The gate's prior is keyed by (check, kind, name, host), and the enumerator reads the check
	// half off opts.CheckName. A check sets PointEffectiveCheck before it enumerates (runInjection
	// does), so the name has to be copied in HERE — the copy is what makes the drop side and the
	// record side agree on one key. Without it the enumerator consults the oracle under the empty
	// name while checks_injection.go records under the real one, every lookup misses, and
	// skip_ineffective_checks reports itself enabled while never dropping a single point.
	//
	// Overwritten rather than only-if-empty: a stale CheckName inherited from the run's config would
	// score this check's points against another check's prior, which is the exact cross-check
	// contamination the check half of the key exists to prevent.
	if cc.PointEffectiveCheck != "" {
		opts.CheckName = cc.PointEffectiveCheck
	}
	return opts
}

// ProbeInsertionKinds is the point classes an active probe may use: the audit configuration's when
// one was supplied, the engine default otherwise.
//
// The "none" sentinel a fully-disabled overlay writes is returned as-is and matches no kind, which
// is the point — a run configured to insert nowhere probes nowhere.
func (cc *CheckContext) ProbeInsertionKinds() []string {
	if cc == nil || len(cc.InsertionKinds) == 0 {
		return DefaultProbeInsertionKinds
	}
	return cc.InsertionKinds
}

// NewCheckContext builds the shared evaluator input without copying request or
// response bytes. StoredExchange is supplied by the phase dispatcher when a
// second-order check has evidence to thread through.
func NewCheckContext(scanner *ActiveScanner, exchange, stored *core.Exchange) *CheckContext {
	var snd *sender.Sender
	var cfg *ScanConfig
	if scanner != nil {
		snd = scanner.sender
		cfg = scanner.config
	}
	// The scanner's effective audit configuration is the fallback, not the answer. It is right for
	// a caller building a context outside a dispatched audit (a direct evaluator test), and it was
	// WRONG for every audit launched under a named configuration: AuditWithin and AuditSession take
	// a configuration per call, so `{"config": "<name>"}` reached the run's budgets and the queue
	// row while every check still enumerated the server-wide default's points. newCheckContextForRun
	// is the dispatched path and overrides both fields from the run — see runCfgKey.
	base := DefaultAuditConfig()
	if scanner != nil {
		base = scanner.AuditConfig()
	}
	return &CheckContext{
		Scanner:          scanner,
		Exchange:         exchange,
		StoredExchange:   stored,
		Sender:           snd,
		Config:           cfg,
		InsertionKinds:   base.insertionKinds(),
		EnumerateOptions: base.enumerateOptions(),
	}
}

// newCheckContextForRun builds the context for a check dispatched by an audit: NewCheckContext plus
// the configuration THIS run was launched under, which ctx carries.
//
// Separate from NewCheckContext, and not a replacement for it, because the exported constructor has
// callers that hold no run. Those callers keep the scanner's configuration; a dispatched check must
// not, or a named configuration is a label on a run that ignored it.
func newCheckContextForRun(ctx context.Context, scanner *ActiveScanner, exchange, stored *core.Exchange) *CheckContext {
	cc := NewCheckContext(scanner, exchange, stored)
	if cfg, ok := runConfigFrom(ctx); ok {
		cc.InsertionKinds = cfg.insertionKinds()
		cc.EnumerateOptions = cfg.enumerateOptions()
	}
	// The light-audit tier rides the same context (7bkj): the dispatcher puts the run's
	// state on, so every check the run dispatches sees one prior. Absent (a context built
	// outside an audit) reads nil, which the RunLightAudit methods treat as off.
	cc.LightAudit = lightAuditFrom(ctx)
	// The per-point effectiveness ledger rides it too (y4om), by the same route and for the same
	// reason. This assignment is load-bearing in both directions: without it the gate's RECORDING
	// side never sees a ledger, so effectivenessFrom in checks_injection.go returns nil, no place is
	// ever counted, and skip_ineffective_checks silently stops saving anything while still reading
	// as enabled. Nil when the run set it to zero, which is how "the operator turned it off" reaches
	// a check as an absent ledger rather than as a flag it has to honour.
	cc.PointEffectiveness = pointEffectivenessFrom(ctx)
	return cc
}

// pointEffectivenessKeyCtx is the context key for the run's per-point effectiveness ledger
// (burpsy-react-ui-y4om). Unexported struct key so no other package can collide with it.
type pointEffectivenessKeyCtx struct{}

// withPointEffectiveness attaches the run's ledger to a dispatch context. A run with the gate
// off attaches nothing, and the checks read the absent ledger as "no gate" — the same nil-safe
// reading the light-audit tier uses, and the reason no enabled flag is needed here.
func withPointEffectiveness(ctx context.Context, pe *pointEffectiveness) context.Context {
	return context.WithValue(ctx, pointEffectivenessKeyCtx{}, pe)
}

// pointEffectivenessFrom reads it back; nil when absent.
func pointEffectivenessFrom(ctx context.Context) *pointEffectiveness {
	if ctx == nil {
		return nil
	}
	pe, _ := ctx.Value(pointEffectivenessKeyCtx{}).(*pointEffectiveness)
	return pe
}

// lightAuditKeyCtx is the context key for the run's light-audit tier. Unexported struct key
// so no other package can collide with it.
type lightAuditKeyCtx struct{}

// withLightAudit attaches the run's light-audit state to a dispatch context.
func withLightAudit(ctx context.Context, la *RunLightAudit) context.Context {
	return context.WithValue(ctx, lightAuditKeyCtx{}, la)
}

// lightAuditFrom reads it back; nil when absent.
func lightAuditFrom(ctx context.Context) *RunLightAudit {
	if ctx == nil {
		return nil
	}
	la, _ := ctx.Value(lightAuditKeyCtx{}).(*RunLightAudit)
	return la
}

// CheckRunner evaluates one admitted check unit. A refusal is represented by the
// returned error and is classified by the audit engine; a nil finding slice is a
// clean result, not an implicit unsupported result.
type CheckRunner func(context.Context, *CheckContext) ([]*Finding, error)

// CheckDescriptor is the registry's complete declaration for one runnable or
// explicitly declined catalog issue.
type CheckDescriptor struct {
	TypeIndex      uint32
	Name           string
	Implementation CheckImplementation
	Phase          CheckPhase
	Scope          DispatchScope
	InsertionKinds []bcheck.IpKind
	Enabled        func(*ScanConfig) bool
	Run            CheckRunner
	DeclineReason  string
	Invasiveness   CheckInvasiveness
	// Passive marks a check that reads a captured exchange without sending a probe of its own. Those
	// hang from `scan_type_passive`, not from the three active tiers, so a preset that turns every
	// active tier off still runs them — a passive check cannot change server state, which is the
	// property the intrusive tier exists to protect.
	Passive bool
}

func (d CheckDescriptor) Runnable() bool {
	return d.Run != nil && d.DeclineReason == ""
}

func (d CheckDescriptor) Valid() bool {
	if d.Name == "" || d.TypeIndex == 0 {
		return false
	}
	if d.Implementation == ImplementationDeclined {
		return d.Run == nil && d.DeclineReason != ""
	}
	return d.Run != nil && d.DeclineReason == ""
}
