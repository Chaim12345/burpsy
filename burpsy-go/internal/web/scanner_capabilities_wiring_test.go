package web

// The lazy-fallback half of the two-engines regression guard (the scanner-package half is
// internal/scanner/wiring_test.go).
//
// Server.activeScanner builds a scanner on first use for a server that was never handed one.
// That fallback used to wire scope, pace, the suite gate, the corpus and the tool runner —
// and nothing else: no ledgers, no session coordinator, no JS-library or JWT checks, no
// bundled corpus. Every capability-gated check an audit through such a server dispatched
// filed Skipped under CapabilityMissing while the CLI's scanner ran the same checks fine.
// These tests pin that the fallback builds from the installed CapabilityWiring recipe and
// falls back to the server's own handles for anything the recipe leaves unset.

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

func TestLazyScannerBuildsFromInstalledCapabilities(t *testing.T) {
	s := NewServer(core.NewTrafficStore(), core.NewScope())
	coord := session.NewCoordinator(zap.NewNop())
	auditCfg := scanner.DefaultAuditConfig()
	s.WithScannerCapabilities(scanner.CapabilityWiring{
		SessionCoordinator: coord,
		AuditConfig:        &auditCfg,
	})

	active := s.activeScanner()
	if active.StoredLedgerHandle() == nil {
		t.Error("lazy scanner has no stored ledger: stored/second-order checks would file CapabilityMissing")
	}
	if active.ProvenanceLedgerHandle() == nil {
		t.Error("lazy scanner has no provenance ledger")
	}
	if active.SessionCoordinatorHandle() != coord {
		t.Error("lazy scanner does not hold the installed session coordinator")
	}
	if active.JsLibraryCheckHandle() == nil {
		t.Error("lazy scanner has no JS-library check")
	}
	if active.JwtWeakSecretCheckHandle() == nil {
		t.Error("lazy scanner has no JWT weak-secret check")
	}
	if active.AuditConfig().TimeBudget != auditCfg.TimeBudget {
		t.Errorf("lazy scanner budget %v, want the installed %v", active.AuditConfig().TimeBudget, auditCfg.TimeBudget)
	}
}

func TestLazyScannerDefaultsToServerSessionCoordinator(t *testing.T) {
	s := NewServer(core.NewTrafficStore(), core.NewScope())
	// No WithScannerCapabilities at all: the recipe is empty, and the fallback must still
	// share the server's own coordinator rather than build a scanner with no session handle.
	coord := session.NewCoordinator(zap.NewNop())
	s.WithSessionCoordinator(coord)

	active := s.activeScanner()
	if active.SessionCoordinatorHandle() != coord {
		t.Error("lazy scanner with an empty recipe does not hold the server's session coordinator")
	}
	// The self-constructed handles still wire: the recipe's zero value opts into every
	// default, which is what makes an unconfigured server's fallback a full engine.
	if active.StoredLedgerHandle() == nil || active.JsLibraryCheckHandle() == nil || active.JwtWeakSecretCheckHandle() == nil {
		t.Error("lazy scanner with an empty recipe left default handles unwired")
	}
}
