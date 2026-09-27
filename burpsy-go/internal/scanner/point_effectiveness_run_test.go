package scanner

// The per-point effectiveness gate (burpsy-react-ui-y4om) ON A REAL AUDIT RUN.
//
// The enumerator tests in point_effectiveness_test.go pin the decision. What these pin is the
// decision's REACH: a gate that a run never consults produces a smaller request count for no
// stated reason, which is the silent coverage change this project refuses — so the run-level
// evidence has to be that the key, and nothing else, is what makes the difference.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// inertOrigin answers every request identically and with nothing any injection classifier can
// use, so every probe on every point is a silent one — the shape a parameter the application
// simply does not parse produces, and the only shape the gate is allowed to judge on.
func inertOrigin(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "nothing interesting")
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// The gate has to be observable as fewer probes on the same exchanges, with the same check set,
// and the difference has to be named in the outcome rather than merely happening.
func TestTheGateStopsProbingAPlaceThatHasProvenInert(t *testing.T) {
	srv, hits := inertOrigin(t)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse target port: %v", err)
	}

	// The SAME place, reached from many items. Each exchange carries the same three parameters,
	// so the second item's points are places the first already probed — which is the only
	// situation the gate exists for, and the one a single request can never show.
	store := core.NewTrafficStore()
	ids := make([]core.ExchangeID, 0, 8)
	for i := 0; i < 8; i++ {
		// Same path, same three parameters, distinct query id: eight items that each reach
		// the SAME three places, which is the condition the gate exists to exploit. The id
		// parameter is what keeps the store from folding them into one item.
		ids = append(ids, seedAuditExchange(t, store, host, port,
			fmt.Sprintf("/r?a=1&b=2&c=3&id=%d", i), "nothing interesting"))
	}

	// run returns the session's total probes and the sum of what the gate judged across its
	// items — the per-item AuditOutcome is where the counter lives, so a session-level total is
	// the sum rather than a field of its own.
	run := func(cfg AuditConfig) (int, int) {
		scan := NewActiveScanner(store, zap.NewNop()).
			WithSender(sender.NewSender(nil)).
			WithConfig(&ScanConfig{MaxConcurrency: 1, CheckSqli: true})
		// AuditSession, not AuditWithin: the gate's prior is the RUN's, and only a
		// multi-item session gives the second item a place the first already probed. One item
		// can never show the saving — a property of the mechanism, not a missing feature.
		out, _ := scan.AuditSession(context.Background(), ids, cfg)
		judged := 0
		for _, it := range out.Items {
			judged += it.Outcome.PointsJudgedIneffective
		}
		return judged, int(hits.Load())
	}

	hits.Store(0)
	offCfg := DefaultAuditConfig()
	offCfg.SkipIneffectiveChecks = SomeUint32(0)
	offJudged, offHits := run(offCfg)

	hits.Store(0)
	onJudged, onHits := run(DefaultAuditConfig())

	if onHits >= offHits {
		t.Fatalf("probes with the gate on = %d, gate off = %d: once a place has been probed silent "+
			"twice the gate must stop sending there, so the run must cost strictly less to say the "+
			"same thing about the second, third and fourth items", onHits, offHits)
	}
	if onJudged == 0 {
		t.Errorf("the run judged no place ineffective while still sending fewer probes: the " +
			"saving came from somewhere the report does not name")
	}
	if offJudged != 0 {
		t.Errorf("a run with the gate OFF judged %d place(s) ineffective; the key is the only "+
			"thing that may turn the gate on, so an off configuration must judge nothing", offJudged)
	}
}

// The key survives a Burp configuration import, and a file saying FALSE reads as "pay full price"
// rather than as unset — the distinction that would otherwise make a migrated preset silently
// re-enable the gate the operator turned off.
func TestTheKeyIsReadFromABurpConfiguration(t *testing.T) {
	raw := []byte(`{"scanner":{"audit_optimization":{"skip_ineffective_checks":false}}}`)
	cfg, err := ParseBurpConfig(raw)
	if err != nil {
		t.Fatalf("parse: %v — the key is spelled as a BOOLEAN in Burp's own files, so a numeric "+
			"reader rejects the whole configuration", err)
	}
	if len(cfg.UnrepresentableKeys) != 0 {
		t.Fatalf("unrepresentable = %v, want none: the key has both a field and a row", cfg.UnrepresentableKeys)
	}
	if !cfg.SkipIneffectiveChecks.Set || cfg.SkipIneffectiveChecks.Value != 0 {
		t.Fatalf("a configuration saying false read as %+v; the operator asked for full price on "+
			"every point, and reading that as unset silently re-enables Burp's default", cfg.SkipIneffectiveChecks)
	}

	// ApplyWithReport returns the keys it could NOT apply, so the assertions are two-sided: the
	// gate must not be in that list (a named key with no effect is the silent drop the path
	// exists to prevent), and its effect must be visible on the run configuration.
	audit, unapplied := cfg.ApplyWithReport(DefaultAuditConfig())
	for _, k := range unapplied {
		if k == "skip_ineffective_checks" {
			t.Errorf("the gate is listed as unapplied: a configuration that names it and gets no " +
				"effect is the silent drop this path exists to prevent")
		}
	}
	if !audit.SkipIneffectiveChecks.Set || audit.SkipIneffectiveChecks.Value != 0 {
		t.Errorf("the applied run configuration reads %+v, want the file's zero carried through",
			audit.SkipIneffectiveChecks)
	}
	// And the resolved state must be the one the dispatcher acts on: the key's own value is
	// "gate off", which is the opposite of unset. Asserted through the same expression the
	// dispatcher uses so a change to one cannot pass the other.
	if audit.SkipIneffectiveChecks.Set && audit.SkipIneffectiveChecks.Value == 0 {
		// off — and off is what this file said
	} else {
		t.Errorf("a file saying false must leave the gate OFF; read %+v", audit.SkipIneffectiveChecks)
	}
}
