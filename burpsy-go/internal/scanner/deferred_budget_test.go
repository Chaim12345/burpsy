package scanner

// The deferred phase (FinishScan) now carries its own wall clock (arch review W3), and the
// audit budget resolves through one rule on every binary (W2): an explicit WithAuditConfig
// wins, otherwise ScanConfig.Timeout, otherwise DefaultAuditBudget.

import (
	"context"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

func TestFinishScanHonorsTheDeferredBudget(t *testing.T) {
	s := NewActiveScanner(nil, zap.NewNop())
	if err := s.Pending().Register(PendingItem{
		Row:      "test row",
		Exchange: core.ExchangeID(1),
		What:     "a claim whose answer never arrives",
		Deadline: time.Now().Add(time.Hour), // outlives the deferred budget on purpose
	}, func(ctx context.Context) (*Finding, bool, error) {
		<-ctx.Done() // an answer that only the budget's expiry can produce
		return nil, false, nil
	}); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultAuditConfig()
	cfg.DeferredTimeBudget = 50 * time.Millisecond
	start := time.Now()
	_, c := s.FinishScan(context.Background(), cfg)
	if !c.DeferredBudgetSpent {
		t.Fatal("the deferred phase blew its own wall clock and said nothing")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the deferred phase outlived its 50ms budget by an unreasonable margin: %s", d)
	}
}

func TestFinishScanUnsetDeferredBudgetInheritsTheDefault(t *testing.T) {
	s := NewActiveScanner(nil, zap.NewNop())
	_, c := s.FinishScan(context.Background(), DefaultAuditConfig())
	if c.DeferredBudgetSpent {
		t.Fatal("an idle deferred phase reported its budget spent")
	}
}

func TestAuditBudgetResolutionOrder(t *testing.T) {
	s := NewActiveScanner(nil, zap.NewNop())
	if got := s.AuditConfig().TimeBudget; got != DefaultAuditBudget {
		t.Fatalf("a fresh scanner resolves through the unified ScanConfig default (%s), got %s", DefaultAuditBudget, got)
	}
	s.WithScanTimeout(5 * time.Second)
	if got := s.AuditConfig().TimeBudget; got != 5*time.Second {
		t.Fatalf("ScanConfig.Timeout must drive the budget when no audit config is set, got %s", got)
	}
	explicit := DefaultAuditConfig()
	explicit.TimeBudget = 9 * time.Second
	s.WithAuditConfig(explicit)
	if got := s.AuditConfig().TimeBudget; got != 9*time.Second {
		t.Fatalf("an explicit audit config must win over ScanConfig.Timeout, got %s", got)
	}
}
