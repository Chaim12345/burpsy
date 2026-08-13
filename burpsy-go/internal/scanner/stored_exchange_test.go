package scanner

// The stored-exchange dispatch path: a DispatchScopeStoredPerInsertionPoint check must receive a
// non-nil CheckContext.StoredExchange holding the prior same-endpoint capture when one exists, and
// nil when none does. This is the half of gap 3 that makes the second-order scope real for a future
// native check author — it threads the second request through CheckContext without touching the
// nil behaviour any other scope sees today.
//
// The test drives wrapDescriptor directly: the exact production wrapper nativeActiveCheckSet builds
// for every descriptor, so it pins the threading without un-declining a catalog issue (the 9
// declined rows stay declined; that is separate follow-up once native second-order checks exist).

import (
	"context"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// storedExchangeProbe is a synthetic descriptor runner that records the StoredExchange it received.
// It returns no findings and never sends a probe, so it is harmless to dispatch and isolates the
// one thing under test: what the wrapper put into the context.
func recordStoredExchange(t *testing.T, scope DispatchScope, store *core.TrafficStore, withPrior bool) (*core.Exchange, *core.Exchange) {
	t.Helper()

	// A prior same-endpoint capture must be added BEFORE the exchange under audit, so it precedes
	// it in index order — PriorExchange returns the most recent candidate added before the given
	// one (positions are ids).
	var priorID core.ExchangeID = ^core.ExchangeID(0) // sentinel: no prior seeded
	if withPrior {
		priorID = seedAuditExchange(t, store, "app.test", 443, "/login", "<form></form>")
	}
	underAudit := seedAuditExchange(t, store, "app.test", 443, "/login", "<form></form>")

	// The shared seed helper does not set TLS; mark both same-endpoint captures as https so the
	// origin (scheme+host+port) matches what PriorExchange keys on. The exchange is stored by
	// pointer, so mutating the fetched row updates the indexed copy PriorExchange reads.
	if withPrior {
		if p, err := store.GetExchange(priorID); err == nil {
			p.TLS = true
		}
	}
	if u, err := store.GetExchange(underAudit); err == nil {
		u.TLS = true
	}

	var gotExchange, gotStored *core.Exchange
	descriptor := CheckDescriptor{
		TypeIndex:      1,
		Name:           "probe-stored",
		Implementation: ImplementationNative,
		Phase:          PhaseStored,
		Scope:          scope,
		Enabled:        func(*ScanConfig) bool { return true },
		Run: func(_ context.Context, cc *CheckContext) ([]*Finding, error) {
			gotExchange = cc.Exchange
			gotStored = cc.StoredExchange
			return nil, nil
		},
	}

	scanner := NewActiveScanner(store, zap.NewNop())
	run := wrapDescriptor(descriptor)
	underAuditEx, err := store.GetExchange(underAudit)
	if err != nil {
		t.Fatalf("get under-audit exchange: %v", err)
	}
	if _, err := run(scanner, context.Background(), underAuditEx); err != nil {
		t.Fatalf("wrapDescriptor run: %v", err)
	}
	return gotExchange, gotStored
}

func TestStoredPerInsertionPointReceivesPriorExchangeWhenOneExists(t *testing.T) {
	store := core.NewTrafficStore()
	ex, stored := recordStoredExchange(t, DispatchScopeStoredPerInsertionPoint, store, true)

	if ex == nil {
		t.Fatal("the primary exchange was not threaded into CheckContext")
	}
	if stored == nil {
		t.Fatal("DispatchScopeStoredPerInsertionPoint check received nil StoredExchange despite a prior same-endpoint capture")
	}
	if stored.Host != "app.test" || stored.Port != 443 || stored.TLS != true || stored.Path != "/login" {
		t.Errorf("StoredExchange = %+v, want the prior /login capture on app.test:443", stored)
	}
	// The stored exchange must be a different capture than the one under audit.
	if stored.ID == ex.ID {
		t.Error("StoredExchange is the exchange under audit; it must be the earlier capture")
	}
}

func TestStoredPerInsertionPointReceivesNilWhenNoPriorExchange(t *testing.T) {
	store := core.NewTrafficStore()
	_, stored := recordStoredExchange(t, DispatchScopeStoredPerInsertionPoint, store, false)

	if stored != nil {
		t.Errorf("no prior capture exists, but StoredExchange was %+v; nil is required so the check falls back to today's behaviour", stored)
	}
}

func TestOtherScopesAlwaysReceiveNilStoredExchange(t *testing.T) {
	// Every non-stored scope must see nil StoredExchange regardless of whether a prior same-endpoint
	// capture exists — the threading is strictly scoped to second-order checks.
	for _, scope := range []DispatchScope{
		DispatchScopePerHost,
		DispatchScopePerPath,
		DispatchScopePerUrl,
		DispatchScopePerRequest,
		DispatchScopePerInsertionPoint,
	} {
		store := core.NewTrafficStore()
		// Seed a prior same-endpoint capture so the lookup would have something to return if the
		// scope were incorrectly honoured.
		_, stored := recordStoredExchange(t, scope, store, true)
		if stored != nil {
			t.Errorf("%s received a non-nil StoredExchange; only DispatchScopeStoredPerInsertionPoint may", scope.Label())
		}
	}
}

func TestStoredPerInsertionPointMatchesOriginNotJustHost(t *testing.T) {
	// A prior /login on a different origin (plaintext, or a different host) must not be threaded:
	// a stored check only compares same-endpoint traffic. With only those mismatched captures
	// present, StoredExchange must be nil.
	store := core.NewTrafficStore()
	seedAuditExchange(t, store, "app.test", 80, "/login", "<form></form>")    // plaintext origin
	seedAuditExchange(t, store, "other.test", 443, "/login", "<form></form>") // different host
	underAudit := seedAuditExchange(t, store, "app.test", 443, "/login", "<form></form>")
	// The under-audit capture is tls; the mismatched priors stay plaintext / different-host, so
	// neither shares its origin and StoredExchange must be nil.
	if u, err := store.GetExchange(underAudit); err == nil {
		u.TLS = true
	}

	var gotStored *core.Exchange
	descriptor := CheckDescriptor{
		TypeIndex:      1,
		Name:           "probe-stored-origin",
		Implementation: ImplementationNative,
		Phase:          PhaseStored,
		Scope:          DispatchScopeStoredPerInsertionPoint,
		Enabled:        func(*ScanConfig) bool { return true },
		Run: func(_ context.Context, cc *CheckContext) ([]*Finding, error) {
			gotStored = cc.StoredExchange
			return nil, nil
		},
	}
	scanner := NewActiveScanner(store, zap.NewNop())
	run := wrapDescriptor(descriptor)
	underAuditEx, err := store.GetExchange(underAudit)
	if err != nil {
		t.Fatalf("get under-audit exchange: %v", err)
	}
	if _, err := run(scanner, context.Background(), underAuditEx); err != nil {
		t.Fatalf("wrapDescriptor run: %v", err)
	}
	if gotStored != nil {
		t.Errorf("StoredExchange = %+v; mismatched-origin priors (plaintext / different host) must not match", gotStored)
	}
}
