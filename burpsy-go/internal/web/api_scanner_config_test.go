package web

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// ---- Runtime scan configuration -----------------------------------------------------------------
//
// Burp exposes every audit family switch live; burpsy's families were compile-time struct
// literals reachable only from Go code. GET returns the confirmed configuration; PUT accepts a
// partial patch of known keys, refuses anything else by name, applies it to the running scanner,
// persists it for the next start, and answers with the whole confirmed state so a client never
// has to merge.

func getScannerConfig(t *testing.T, s *Server) map[string]any {
	t.Helper()
	rec := get(t, s, "/api/scanner/config")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET config = %d; body %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return out
}

// The endpoint's whole point is editing the running engine, so every test builds the same minimal
// real scanner a live process would have rather than stubbing one.
func newScannerServer() *Server {
	s := newTestServer().WithScanner(scanner.NewActiveScanner(core.NewTrafficStore(), zap.NewNop()))
	return s
}

func TestConfigGetReportsDefaultsIncludingThePassiveFamiliesOnByDefault(t *testing.T) {
	cfg := getScannerConfig(t, newScannerServer())
	for key, want := range map[string]bool{
		"check_xss":              true,
		"check_passive_posture":  true,
		"check_passive_analysis": true,
		"check_host_discovery":   true,
		// The explicit counter-example: XXE ships off because its checks need a parser the
		// operator may not want exercised, and it is exactly the switch a runtime UI must be able
		// to turn on without a rebuild.
		"check_xxe": false,
	} {
		if got := cfg[key]; got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
	if _, ok := cfg["max_concurrency"]; !ok {
		t.Error("max_concurrency missing from the reported config; a runtime UI cannot tune what it cannot see")
	}
}

func TestConfigPutAppliesAValidPatchAndAnswersWithConfirmedState(t *testing.T) {
	s := newScannerServer()
	rec := putJSON(t, s, "/api/scanner/config", map[string]any{"check_xxe": true, "max_concurrency": 4})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT config = %d; body %s", rec.Code, rec.Body.String())
	}
	var confirmed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &confirmed); err != nil {
		t.Fatalf("decode confirmed: %v", err)
	}
	if confirmed["check_xxe"] != true || confirmed["max_concurrency"] != float64(4) {
		t.Fatalf("confirmed = %v/%v; an answer that does not carry the applied values makes the client guess", confirmed["check_xxe"], confirmed["max_concurrency"])
	}
	if again := getScannerConfig(t, s); again["check_xxe"] != true {
		t.Fatalf("GET after PUT = %v; the edit did not reach the running scanner", again["check_xxe"])
	}
}

func TestConfigPutRefusesUnknownKeysAndWrongTypesByName(t *testing.T) {
	s := newScannerServer()
	for name, body := range map[string]map[string]any{
		"unknown key": {"check_nosuchfamily": true},
		"wrong type":  {"check_xxe": "yes please"},
	} {
		if rec := putJSON(t, s, "/api/scanner/config", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: PUT = %d, want 400; %s would silently do nothing", name, rec.Code, name)
		}
	}
}

func TestConfigPutSurvivesARestartThroughPersistedOverrides(t *testing.T) {
	db := filepath.Join(t.TempDir(), "cfg.db")
	p, err := persist.Open(db, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	s1 := newScannerServer().WithPersist(p)
	if rec := putJSON(t, s1, "/api/scanner/config", map[string]any{"check_stored": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d", rec.Code)
	}
	p.Close()

	p2, err := persist.Open(db, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	// Phase two plays main.go's startup role: load what was saved and apply it onto a fresh
	// scanner, because restoring policy is a boot-time decision, not something the HTTP server
	// does implicitly behind callers' backs.
	loaded, err := p2.LoadScanConfig()
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil {
		t.Fatal("LoadScanConfig returned nil after a PUT saved it; absence and presence got confused")
	}
	s2 := newScannerServer()
	s2.scanner.UpdateScanConfig(func(c *scanner.ScanConfig) { *c = *loaded })
	if got := getScannerConfig(t, s2)["check_stored"]; got != true {
		t.Fatalf("check_stored after restart = %v; a policy the operator set that dies with the process was never really set", got)
	}
}
