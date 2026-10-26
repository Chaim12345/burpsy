package scanner

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// W4: volatility-aware unit keys and the run's per-unit content-variant cap.

func TestUnitKeyCollapsesCSRFOnlyRecaptures(t *testing.T) {
	a := &core.Exchange{ID: 1, Host: "h.test", Port: 80, Method: "GET", Path: "/p?csrf=AAA&x=1",
		RequestShapeFP: core.RequestShapeFingerprint([]byte("GET /p?csrf=AAA&x=1 HTTP/1.1\r\nHost: h.test\r\n\r\n"))}
	b := &core.Exchange{ID: 2, Host: "h.test", Port: 80, Method: "GET", Path: "/p?csrf=BBB&x=1",
		RequestShapeFP: core.RequestShapeFingerprint([]byte("GET /p?csrf=BBB&x=1 HTTP/1.1\r\nHost: h.test\r\n\r\n"))}
	ka, _ := DispatchScopePerUrl.UnitKey(a)
	kb, _ := DispatchScopePerUrl.UnitKey(b)
	if ka != kb {
		t.Errorf("two captures differing only in the CSRF value minted two units: %q vs %q", ka, kb)
	}
	// The pre-W4 behaviour for exchanges carrying only the raw fingerprint: different units.
	ra := &core.Exchange{ID: 3, Host: "h.test", Port: 80, Method: "GET", Path: "/p?csrf=AAA&x=1", RequestFP: 11}
	rb := &core.Exchange{ID: 4, Host: "h.test", Port: 80, Method: "GET", Path: "/p?csrf=BBB&x=1", RequestFP: 22}
	kra, _ := DispatchScopePerUrl.UnitKey(ra)
	krb, _ := DispatchScopePerUrl.UnitKey(rb)
	if kra == krb {
		t.Error("raw-fingerprint exchanges still key on exact content (fallback path must not change)")
	}
}

func TestTheVariantCapAdmitsUpToTheCapAndNoMore(t *testing.T) {
	run := newAuditRun(AuditConfig{MaxUnitVariantsPerUnit: 2})
	if run.unitVariantCapped("h/p#fp1") || run.unitVariantCapped("h/p#fp2") {
		t.Fatal("the first two variants of one endpoint are admitted")
	}
	if run.unitVariantCapped("h/p#fp1") {
		t.Error("an already-admitted variant is never capped (re-pass and identical re-capture)")
	}
	if !run.unitVariantCapped("h/p#fp3") {
		t.Error("the third distinct variant of one endpoint is over a cap of 2")
	}
	if run.unitVariantCapped("h/other#fp1") {
		t.Error("a different endpoint has its own variant budget")
	}
	if run.unitVariantCapped("h/p#fp9|passive") {
		t.Error("passive units are exempt: re-analysis of captured content costs no requests")
	}
	if run.unitVariantCapped("h/p#7") {
		t.Error("per-request units key by exchange id and are exempt by construction")
	}
	off := newAuditRun(AuditConfig{})
	for _, k := range []string{"h/p#fp1", "h/p#fp2", "h/p#fp3", "h/p#fp4"} {
		if off.unitVariantCapped(k) {
			t.Errorf("a zero cap is unlimited (pre-W4 behaviour): %s capped", k)
		}
	}
}

func TestACappedVariantIsCountedCoveredNotAbandoned(t *testing.T) {
	store := core.NewTrafficStore()
	// Two captures of one endpoint whose content differs in a way normalization does NOT mask
	// (a JSON timestamp): two distinct shape fingerprints, so the cap - not the mask - must act.
	seed := func(id int, ts string, shape uint64) core.ExchangeID {
		reqID, err := store.Put([]byte("POST /api HTTP/1.1\r\nHost: h2.test\r\nContent-Type: application/json\r\n\r\n{\"ts\":\""+ts+"\"}"), core.DirectionRequest)
		if err != nil {
			t.Fatal(err)
		}
		respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"), core.DirectionResponse)
		if err != nil {
			t.Fatal(err)
		}
		ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: "h2.test", Port: 80, Method: "POST", Path: "/api", RequestShapeFP: shape}
		store.AddExchange(ex)
		return ex.ID
	}
	first := seed(1, "1", 101)
	second := seed(2, "2", 102)

	ran := 0
	checks := []activeCheck{{
		name: "counting-probe", scope: DispatchScopePerUrl, phase: PhaseActive,
		run: func(*ActiveScanner, context.Context, *core.Exchange) ([]*Finding, error) { ran++; return nil, nil },
	}}
	scan := NewActiveScanner(store, zap.NewNop()).WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 5 * time.Second})
	cfg := DefaultAuditConfig()
	cfg.MaxUnitVariantsPerUnit = 1
	run := newAuditRun(cfg)

	o1, _ := scan.auditItem(context.Background(), first, run, checks)
	if o1.UnitsVariantCapped != 0 || o1.Ran != 1 {
		t.Fatalf("first variant: ran=%d capped=%d, want ran=1 capped=0", o1.Ran, o1.UnitsVariantCapped)
	}
	o2, _ := scan.auditItem(context.Background(), second, run, checks)
	if o2.UnitsVariantCapped != 1 {
		t.Errorf("second variant: units_variant_capped=%d, want 1", o2.UnitsVariantCapped)
	}
	if o2.AlreadyCovered != 1 || o2.UnitAbandoned != 0 || o2.ItemFailed != 0 {
		t.Errorf("second variant: already_covered=%d unit_abandoned=%d item_failed=%d, want 1/0/0 - "+
			"the cap is coverage, not failure", o2.AlreadyCovered, o2.UnitAbandoned, o2.ItemFailed)
	}
	if o2.Considered() != 1 {
		t.Errorf("Considered()=%d, want 1: the capped check is still inside the partition", o2.Considered())
	}
	if ran != 1 {
		t.Errorf("the check ran %d times across two variants under a cap of 1, want 1", ran)
	}
}

// The default is unlimited: on a single-URL API every distinct JSON operation is its own variant,
// so a default cap would silently stop auditing every operation after it.
func TestTheDefaultAuditConfigHasNoVariantCap(t *testing.T) {
	cfg := DefaultAuditConfig()
	if cfg.MaxUnitVariantsPerUnit != 0 {
		t.Fatalf("default MaxUnitVariantsPerUnit = %d, want 0 (unlimited)", cfg.MaxUnitVariantsPerUnit)
	}
	run := newAuditRun(cfg)
	for i := range 40 {
		if run.unitVariantCapped(fmt.Sprintf("h/graphql#fp%d", i)) {
			t.Fatalf("operation %d of one GraphQL endpoint capped under the default config", i)
		}
	}
}
