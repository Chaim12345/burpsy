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
	s2.wiredScanner().UpdateScanConfig(func(c *scanner.ScanConfig) { *c = *loaded })
	if got := getScannerConfig(t, s2)["check_stored"]; got != true {
		t.Fatalf("check_stored after restart = %v; a policy the operator set that dies with the process was never really set", got)
	}
}

// The authentication rows' switches and burst size are on the wire, off by default, and the burst is
// refused outside the range the check would actually send rather than silently clamped.
func TestConfigCarriesTheAuthenticationChecks(t *testing.T) {
	s := newScannerServer()
	cfg := getScannerConfig(t, s)
	for _, k := range []string{"check_login_rate_limit", "check_username_enumeration"} {
		if cfg[k] != false {
			t.Errorf("%s = %v, want present and off by default", k, cfg[k])
		}
	}
	for _, bad := range []any{3, 101, -1, "x"} {
		if rec := putJSON(t, s, "/api/scanner/config", map[string]any{"login_rate_limit_attempts": bad}); rec.Code != http.StatusBadRequest {
			t.Errorf("login_rate_limit_attempts=%v answered %d, want 400", bad, rec.Code)
		}
	}
	rec := putJSON(t, s, "/api/scanner/config", map[string]any{"check_login_rate_limit": true,
		"check_username_enumeration": true, "login_rate_limit_attempts": 12})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d; body %s", rec.Code, rec.Body.String())
	}
	got := s.wiredScanner().ConfigSnapshot()
	if !got.CheckLoginRateLimit || !got.CheckUsernameEnumeration || got.LoginRateLimitAttempts != 12 {
		t.Errorf("the running scanner did not take the patch: %+v", got)
	}
}

// The password-reset checks' operator inputs: a list of test identities and a test-inbox URL, which
// must be an absolute http(s) URL; the switch itself is off by default.
func TestConfigPutTakesThePasswordResetInputs(t *testing.T) {
	s := newScannerServer()
	if cfg := getScannerConfig(t, s); cfg["check_password_reset"] != false {
		t.Fatalf("check_password_reset = %v, want off by default", cfg["check_password_reset"])
	}
	rec := putJSON(t, s, "/api/scanner/config", map[string]any{"check_password_reset": true,
		"reset_test_identities": []string{" tester@corp.test ", ""},
		"reset_mailbox_url":     "http://127.0.0.1:8025/inbox?to={identity}"})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d; %s", rec.Code, rec.Body.String())
	}
	got := s.wiredScanner().ConfigSnapshot()
	if !got.CheckPasswordReset || len(got.ResetTestIdentities) != 1 || got.ResetTestIdentities[0] != "tester@corp.test" ||
		got.ResetMailboxURL != "http://127.0.0.1:8025/inbox?to={identity}" {
		t.Fatalf("applied %v %q %q", got.CheckPasswordReset, got.ResetTestIdentities, got.ResetMailboxURL)
	}
	for name, body := range map[string]map[string]any{
		"identities not a list": {"reset_test_identities": "tester@corp.test"},
		"relative mailbox":      {"reset_mailbox_url": "/inbox"},
		"non-http mailbox":      {"reset_mailbox_url": "file:///etc/passwd"},
	} {
		if rec := putJSON(t, s, "/api/scanner/config", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: PUT = %d, want 400", name, rec.Code)
		}
	}
}

// The request smuggling switch is on the wire, off by default, and a PUT reaches the running scanner.
func TestConfigCarriesTheRequestSmugglingCheck(t *testing.T) {
	s := newScannerServer()
	if got := getScannerConfig(t, s)["check_request_smuggling"]; got != false {
		t.Fatalf("check_request_smuggling = %v, want present and off by default", got)
	}
	rec := putJSON(t, s, "/api/scanner/config", map[string]any{"check_request_smuggling": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d; body %s", rec.Code, rec.Body.String())
	}
	if !s.wiredScanner().ConfigSnapshot().CheckRequestSmuggling {
		t.Error("the running scanner did not take check_request_smuggling")
	}
}

// The Host header check's switch is on the wire, off by default, and reaches the running scanner.
func TestConfigCarriesTheHostHeaderCheck(t *testing.T) {
	s := newScannerServer()
	if cfg := getScannerConfig(t, s); cfg["check_host_header"] != false {
		t.Fatalf("check_host_header = %v, want present and off by default", cfg["check_host_header"])
	}
	if rec := putJSON(t, s, "/api/scanner/config", map[string]any{"check_host_header": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d; body %s", rec.Code, rec.Body.String())
	}
	if !s.wiredScanner().ConfigSnapshot().CheckHostHeader {
		t.Error("the running scanner did not take check_host_header")
	}
}
