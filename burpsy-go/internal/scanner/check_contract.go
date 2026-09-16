package scanner

import (
	"context"

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
	return cc
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
