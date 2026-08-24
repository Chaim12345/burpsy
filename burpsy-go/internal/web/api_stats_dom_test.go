package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// ---- Stats reports whether DOM checks can run at all -------------------------------------------
//
// The defect this closes is the one that hid a dead capability: the binary wired no browser and
// left ScanConfig.CheckDOM false, so every DOM-based check reported a missing capability — and
// nothing an operator could see said so. A console that shows TLS interception but not this lets
// a scan of a JavaScript application look complete when no script ever ran.
//
// Two fields, not one, because the two facts can disagree: an engine can be named while the
// scanner that would use it is absent. Inferring either from the other would report a capability
// nobody has.

func decodeStats(t *testing.T, s *Server) StatsView {
	t.Helper()
	rec := get(t, s, "/api/stats")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/stats = %d", rec.Code)
	}
	var view StatsView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	return view
}

func TestStatsReportsNoDomEngineUntilOneIsNamed(t *testing.T) {
	view := decodeStats(t, newTestServer())
	if view.DOMEngine != "off" {
		t.Errorf(`dom_engine = %q, want "off": a blank field reads as "unknown", and an operator cannot act on unknown`, view.DOMEngine)
	}
	if view.DOMChecks {
		t.Error("dom_checks is true with no engine and no scanner; the console would promise DOM coverage this process cannot produce")
	}
}

func TestStatsReportsTheNamedEngineAndThatChecksAreAdmitted(t *testing.T) {
	audit := scanner.NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).
		// Lazy: naming an engine here starts no browser, which is why this test costs nothing.
		WithBrowserProvider(scanner.NewLazyBrowserProvider(domexec.Options{}))
	s := newTestServer().WithDOMEngine("chrome").WithScanner(audit)

	view := decodeStats(t, s)
	if view.DOMEngine != "chrome" {
		t.Errorf("dom_engine = %q, want the operator's own word for the engine", view.DOMEngine)
	}
	if !view.DOMChecks {
		t.Error("dom_checks is false while an engine is attached: the DOM families are gated, so the engine would launch for checks that cannot dispatch")
	}
}

func TestStatsSeparatesANamedEngineFromChecksThatCanUseIt(t *testing.T) {
	// An engine named on the command line, and no scanner attached to this server: reporting
	// dom_checks from the engine label alone would claim coverage that has no dispatcher.
	view := decodeStats(t, newTestServer().WithDOMEngine("ws://127.0.0.1:9226"))
	if view.DOMEngine != "ws://127.0.0.1:9226" {
		t.Errorf("dom_engine = %q, want the endpoint as given", view.DOMEngine)
	}
	if view.DOMChecks {
		t.Error("dom_checks is true with no scanner attached; the label was read as if it were a capability")
	}
}
