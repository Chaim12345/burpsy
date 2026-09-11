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
	// Read from the scanner's effective audit configuration, which is exactly what the audit entry
	// points run under: scanner.go's ActiveAudit and ActiveAuditSession both pass
	// s.AuditConfig() as the run's cfg. A caller invoking AuditWithin/AuditSession directly with a
	// bespoke config is the one case where this could differ from run.cfg, and it is stated here
	// rather than papered over — threading run.cfg to this constructor would mean widening the
	// dispatch closure signature that wrapDescriptor builds for every check.
	var kinds []string
	if scanner != nil {
		kinds = scanner.AuditConfig().insertionKinds()
	}
	return &CheckContext{
		Scanner:        scanner,
		Exchange:       exchange,
		StoredExchange: stored,
		Sender:         snd,
		Config:         cfg,
		InsertionKinds: kinds,
	}
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
