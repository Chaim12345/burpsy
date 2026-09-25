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
	return cc.EnumerateOptions
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
	return cc
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
