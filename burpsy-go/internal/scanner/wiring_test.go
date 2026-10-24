package scanner

// The two-engines regression guard for internal/scanner/wiring.go.
//
// The defect this file pins: the capability handles (stored/provenance ledgers, session
// coordinator, JS-library and JWT checks, bundled corpus, audit config) used to be wired by
// exactly one call site, cmd/burpsy/main.go. The desktop binary and the web server's lazy
// fallback built scanners without them, and every capability-gated check in those binaries
// filed Skipped under CapabilityMissing — same product, two audit engines, invisible until a
// check's disposition was read.
//
// These tests assert the shared recipe wires every handle by default, that each opt-out is
// honoured by name, and that a desktop-shaped recipe (no OOB server, no tool allowlist, no DOM
// engine) still produces a scanner whose capability-gated checks can run.

import (
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// capabilityHandles reports which capability handles a scanner ended up with, so the
// assertions below read as the wiring question itself.
type capabilityHandles struct {
	stored      bool
	provenance  bool
	sessions    bool
	jsLibrary   bool
	jwtWeak     bool
	browser     bool
	auditBudget time.Duration
}

func inspectCapabilities(t *testing.T, s *ActiveScanner) capabilityHandles {
	t.Helper()
	if s == nil {
		t.Fatal("nil scanner")
	}
	return capabilityHandles{
		stored:      s.StoredLedgerHandle() != nil,
		provenance:  s.ProvenanceLedgerHandle() != nil,
		sessions:    s.SessionCoordinatorHandle() != nil,
		jsLibrary:   s.JsLibraryCheckHandle() != nil,
		jwtWeak:     s.JwtWeakSecretCheckHandle() != nil,
		browser:     s.DOMCapabilityConfigured(),
		auditBudget: s.AuditConfig().TimeBudget,
	}
}

func TestWithCapabilitiesWiresEveryDefaultHandle(t *testing.T) {
	store := core.NewTrafficStore()
	coord := session.NewCoordinator(zap.NewNop())
	auditCfg := DefaultAuditConfig()

	s := NewActiveScanner(store, zap.NewNop()).WithCapabilities(CapabilityWiring{
		SessionCoordinator: coord,
		AuditConfig:        &auditCfg,
	})

	got := inspectCapabilities(t, s)
	if !got.stored {
		t.Error("stored ledger not wired: the 10 stored/second-order checks would file CapabilityMissing")
	}
	if !got.provenance {
		t.Error("provenance ledger not wired: second-order checks would file CapabilityMissing")
	}
	if !got.sessions {
		t.Error("session coordinator not wired: access-control and CSRF checks would file CapabilityMissing")
	}
	if !got.jsLibrary {
		t.Error("JS-library check not wired")
	}
	if !got.jwtWeak {
		t.Error("JWT weak-secret check not wired")
	}
	if got.browser {
		t.Error("browser provider wired without one being supplied: an audit could start a browser the operator never configured")
	}
	if got.auditBudget != auditCfg.TimeBudget {
		t.Errorf("audit config not applied: budget %v, want %v", got.auditBudget, auditCfg.TimeBudget)
	}
	if s.SessionCoordinatorHandle() != coord {
		t.Error("session coordinator handle is not the instance the caller supplied: two rule sets would drift")
	}
}

// The desktop-shaped recipe: no OOB server, no tool allowlist, no DOM engine, no audit-config
// flag surface — and still every self-constructed handle wired. This is the shape that used to
// produce a scanner with no capability handles at all.
func TestWithCapabilitiesDesktopShapeStillWiresDefaults(t *testing.T) {
	store := core.NewTrafficStore()
	coord := session.NewCoordinator(zap.NewNop())

	s := NewActiveScanner(store, zap.NewNop()).WithCapabilities(CapabilityWiring{
		SessionCoordinator: coord,
	})

	got := inspectCapabilities(t, s)
	if !got.stored || !got.provenance || !got.sessions || !got.jsLibrary || !got.jwtWeak {
		t.Errorf("desktop-shaped recipe left handles unwired: %+v", got)
	}
}

func TestWithCapabilitiesHonoursNamedOptOuts(t *testing.T) {
	store := core.NewTrafficStore()

	s := NewActiveScanner(store, zap.NewNop()).WithCapabilities(CapabilityWiring{
		NoStoredLedger:       true,
		NoProvenanceLedger:   true,
		NoJsLibraryCheck:     true,
		NoJwtWeakSecretCheck: true,
	})

	got := inspectCapabilities(t, s)
	if got.stored || got.provenance || got.jsLibrary || got.jwtWeak {
		t.Errorf("opt-outs not honoured: %+v", got)
	}
	if got.sessions {
		t.Error("session coordinator wired without one being supplied: a nil handle must stay an explicit opt-out")
	}
}

func TestBundledCorpus(t *testing.T) {
	// The compiled-in corpus ships with the binary, always: an operator's -bchecks
	// directory ADDS to it (Burp's own semantics for custom BChecks), it does not
	// replace it. The bundled answer therefore takes no directory argument, and a
	// loaded check sharing a bundled check's name replaces it at dispatch rather
	// than running beside it (TestTheBundledCorpusDispatchesByDefault pins that
	// half of the union).
	checks, err := BundledCorpus(zap.NewNop())
	if err != nil {
		t.Fatalf("bundled corpus failed to load: %v", err)
	}
	if len(checks) == 0 {
		t.Fatal("bundled corpus is empty: the binary ships no compiled-in checks")
	}
}
