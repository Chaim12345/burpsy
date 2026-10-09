package web

// The Custom scan checks leaf's routes (burpsy-react-ui-kdqj, criterion 1).
//
// Three claims, each on the wire: the list counts its rows from the corpus loader (not a second
// list); the per-row enable/disable reaches the SAME set the audit engine dispatches (so a
// switched-off row is a check the next audit does not run — not a control that changes nothing);
// and a disable that names nothing is refused rather than recorded, because it would otherwise take
// effect silently on a corpus loaded later.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// corpusServer is a Server with a corpus loaded the way a live process loads one: two .bcheck files
// written to a temp dir and handed to scanner.LoadDir, exactly the call main.go makes. The passive
// scanner's ActiveChecks are handed to the ActiveScanner, which is main.go's wiring too — so the
// route reads the same loader a live process reads (criterion 3), rather than scanners assembled by
// hand in a shape no process ever builds.
func corpusServer(t *testing.T, name string) (*Server, int) {
	t.Helper()
	dir := t.TempDir()
	activeSrc := "metadata:\n  language: v2-beta\n  name: \"" + name + "\"\n" +
		"given host then\n  if {response.status_code} is \"200\" then\n    report issue:\n      severity: low\n      confidence: certain\n    end if\n"
	passiveSrc := "metadata:\n  language: v2-beta\n  name: \"" + name + " passive\"\n" +
		"given response then\n  if {response.status_code} is \"200\" then\n    report issue:\n      severity: info\n      confidence: certain\n    end if\n"
	if err := os.WriteFile(filepath.Join(dir, "active.bcheck"), []byte(activeSrc), 0o600); err != nil {
		t.Fatalf("write active corpus file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "passive.bcheck"), []byte(passiveSrc), 0o600); err != nil {
		t.Fatalf("write passive corpus file: %v", err)
	}

	store := core.NewTrafficStore()
	scope := core.NewScope()
	ps, err := scanner.LoadDir(dir, store, scope, zap.NewNop())
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	active := scanner.NewActiveScanner(store, zap.NewNop()).
		WithScope(scope).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithCorpusChecks(ps.ActiveChecks())
	s := newTestServer().WithScanner(active).WithPassiveScanner(ps)
	return s, len(active.CorpusChecks())
}

// Criterion 3: the list counts its rows from the corpus loader rather than a second list. Both
// checks the loader classified appear as rows, and the row's switch state comes from the same set
// the engine filters by.
func TestTheCorpusLeafCountsItsRowsFromTheLoader(t *testing.T) {
	s, _ := corpusServer(t, "list-test")

	rec := get(t, s, "/api/scanner/checks")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/scanner/checks = %d; body %s", rec.Code, rec.Body.String())
	}
	var res struct {
		Enabled      bool `json:"enabled"`
		PassiveCount int  `json:"passive_count"`
		ActiveCount  int  `json:"active_count"`
		Checks       []struct {
			Name     string `json:"name"`
			Active   bool   `json:"active"`
			Passive  bool   `json:"passive"`
			Loaded   bool   `json:"loaded"`
			Disabled bool   `json:"disabled"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v; body %s", err, rec.Body.String())
	}
	if !res.Enabled {
		t.Error("enabled = false with a corpus loaded; the leaf would render as though nothing was loaded")
	}
	if len(res.Checks) < 2 {
		t.Fatalf("checks = %d, want at least the two the loader classified", len(res.Checks))
	}
	var sawActive, sawPassive bool
	for _, c := range res.Checks {
		if c.Active {
			sawActive = true
		}
		if c.Passive {
			sawPassive = true
		}
		if c.Disabled {
			t.Errorf("check %q reported disabled on a fresh server; nothing was ever disabled", c.Name)
		}
	}
	if !sawActive || !sawPassive {
		t.Errorf("both buckets must be represented: active=%v passive=%v", sawActive, sawPassive)
	}
}

// The acceptance criterion's engine half: a check disabled through the route is NOT in the dispatch
// set the audit engine builds. Read through the scanner's own enabledChecks — the same set a run
// dispatches — rather than through a field the route invented.
func TestADisabledCheckIsNotInTheAuditDispatchSet(t *testing.T) {
	s, corpusSize := corpusServer(t, "dispatch-test")

	// Before: every corpus check dispatches. ActiveCheckCount is the exported count of the set a run
	// actually dispatches — the property the criterion names — not a flag the route set.
	before := s.wiredScanner().ActiveCheckCount()
	if before < corpusSize {
		t.Fatalf("dispatch set = %d before the disable, want at least the %d corpus checks", before, corpusSize)
	}

	rec := putJSON(t, s, "/api/scanner/checks/enable", map[string]any{"name": "dispatch-test", "enabled": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT enable = %d; body %s", rec.Code, rec.Body.String())
	}
	var confirm struct {
		Disabled bool `json:"disabled"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &confirm)
	if !confirm.Disabled {
		t.Error("the confirm read back enabled=true; a response that echoes the request instead of the state is a fake confirmation")
	}

	after := s.wiredScanner().ActiveCheckCount()
	if after != before-1 {
		t.Errorf("dispatch set = %d after disabling one check, want %d: a switch the audit engine does "+
			"not read is a control that changes nothing", after, before-1)
	}
	if !s.wiredScanner().CheckDisabled("dispatch-test") {
		t.Error("the named check is not marked disabled in the set the engine filters by")
	}

	// Re-enabling restores the dispatch set.
	rec = putJSON(t, s, "/api/scanner/checks/enable", map[string]any{"name": "dispatch-test", "enabled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT re-enable = %d; body %s", rec.Code, rec.Body.String())
	}
	if got := s.wiredScanner().ActiveCheckCount(); got != before {
		t.Errorf("dispatch set = %d after re-enabling, want %d", got, before)
	}
}

// A disable that names nothing is refused rather than recorded: it would otherwise take effect
// silently on a corpus loaded later and switch off a check the operator never saw.
func TestADisableNamingNothingIsRefused(t *testing.T) {
	s, _ := corpusServer(t, "refusal-test")

	rec := putJSON(t, s, "/api/scanner/checks/enable", map[string]any{"name": "no-such-check", "enabled": false})
	if rec.Code != http.StatusNotFound {
		t.Errorf("PUT naming an unknown check = %d, want 404: a disable that names nothing would "+
			"take effect silently on a corpus loaded later; body %s", rec.Code, rec.Body.String())
	}
	if rec := putJSON(t, s, "/api/scanner/checks/enable", map[string]any{"name": "  ", "enabled": false}); rec.Code != http.StatusBadRequest {
		t.Errorf("PUT with a blank name = %d, want 400", rec.Code)
	}
	if rec := postJSON(t, s, "/api/scanner/checks/enable", map[string]any{"name": "refusal-test"}); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT-only route answered POST = %d, want 405", rec.Code)
	}
}

// A server with no corpus loaded reports the state rather than an empty list nothing could ever have
// loaded, and the enable endpoint refuses rather than recording a name against a corpus that does
// not exist.
func TestNoCorpusLoadedIsAReportedStateNotAnEmptyList(t *testing.T) {
	s := newScannerServer()

	rec := get(t, s, "/api/scanner/checks")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET with no corpus = %d", rec.Code)
	}
	var res struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Enabled {
		t.Error("enabled = true with no corpus loaded; the leaf would read as though checks were loaded")
	}

	rec = putJSON(t, s, "/api/scanner/checks/enable", map[string]any{"name": "x", "enabled": false})
	if rec.Code != http.StatusNotFound {
		t.Errorf("enable with no corpus = %d, want 404 naming the missing corpus", rec.Code)
	}
}

// The two routes are wired: a request reaches them through the real mux. A handler defined and
// never registered is the wiring gap this file exists to close, so the test that proves the wiring
// is here rather than asserted in a comment.
func TestTheCorpusRoutesAreReachableThroughTheMux(t *testing.T) {
	s, _ := corpusServer(t, "wiring-test")
	for _, path := range []string{"/api/scanner/checks", "/api/scanner/checks/enable"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed && path != "/api/scanner/checks/enable" {
			t.Errorf("%s is not reachable through the mux (%d): a handler defined and never registered "+
				"is the wiring gap", path, rec.Code)
		}
	}
}
