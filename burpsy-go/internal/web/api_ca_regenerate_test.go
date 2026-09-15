package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/proxy"
)

// ---- POST /api/proxy/ca/regenerate (Burp's "Regenerate CA certificate") -------------------
//
// Regeneration replaces the trust root, so these tests care about the same three things import's do
// plus one more: that /ca.crt actually serves a different certificate afterwards (the operator's
// only proof the rotation took), and that the key never appears in a response.

func postCARegenerate(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/proxy/ca/regenerate", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func Test_regenerating_the_CA_replaces_the_downloadable_certificate_and_persists_it(t *testing.T) {
	ts, dir := newTestServerWithCA(t)

	before := get(t, ts, "/ca.crt")
	if before.Code != http.StatusOK {
		t.Fatalf("GET /ca.crt before = %d: %s", before.Code, before.Body.String())
	}
	beforePEM := before.Body.String()

	rec := postCARegenerate(t, ts)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}

	// The response never carries the private key — the whole point of generating it server-side.
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Error("the regenerate response contains private-key PEM")
	}

	var out caStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if !out.Configured {
		t.Error("regenerated CA reports configured=false")
	}
	if !out.Persisted {
		t.Errorf("persisted=false with a writable CA dir: %s", out.PersistError)
	}
	// The UI is required to tell operators clients must re-trust the new CA (acceptance criterion).
	if !strings.Contains(out.Hint, "must") || !strings.Contains(out.Hint, "/ca.crt") {
		t.Errorf("hint does not tell the operator clients must be re-given the CA: %q", out.Hint)
	}

	// /ca.crt now serves a different certificate. This is the operator-visible proof of rotation.
	after := get(t, ts, "/ca.crt")
	if after.Code != http.StatusOK {
		t.Fatalf("GET /ca.crt after = %d", after.Code)
	}
	if after.Body.String() == beforePEM {
		t.Error("/ca.crt serves the same certificate after regeneration — nothing rotated")
	}

	// The persisted pair on disk is the certificate now served, with the key at 0600, and it reloads
	// as a valid CA — so a restart keeps signing with the new CA rather than reverting.
	certOnDisk, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("reading ca.crt: %v", err)
	}
	if string(certOnDisk) != after.Body.String() {
		t.Error("ca.crt on disk is not the certificate now served at /ca.crt")
	}
	keyInfo, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("stat ca.key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode = %v, want 0600 — the signing key must not be world-readable", keyInfo.Mode().Perm())
	}
	reloaded, err := proxy.LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("reloading the persisted pair (a restart would fail): %v", err)
	}
	if _, _, ok := reloaded.CADescription(); !ok {
		t.Error("the reloaded engine holds no CA — the persisted pair did not survive a restart")
	}
}

// A regenerate over a mismatched-key handler with no engine cannot happen (there is no CA to
// regenerate), so the route refuses rather than pretending to rotate something.
func Test_regenerating_the_CA_with_interception_off_is_refused(t *testing.T) {
	ts := newTestServer()
	rec := postCARegenerate(t, ts)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("POST with no TLS engine = %d, want 503: %s", rec.Code, rec.Body.String())
	}
}

func Test_regenerating_the_CA_rejects_a_GET(t *testing.T) {
	ts, _ := newTestServerWithCA(t)
	req := httptest.NewRequest(http.MethodGet, "/api/proxy/ca/regenerate", nil)
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d, want 405", rec.Code)
	}
}
