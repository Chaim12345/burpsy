package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/proxy"
)

// ---- POST /api/proxy/ca/import (W6 #10) ----------------------------------------------------
//
// The route takes a private key, so the tests below care about three things beyond "does it work":
// that a bad pair changes nothing, that the key never appears in a response, and that a
// persistence failure is reported rather than folded into a success.

func caPair(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

// newTestServerWithCA gives the Server a real signing engine loaded from a generated CA directory,
// which is what LoadOrGenerateCA does at startup.
func newTestServerWithCA(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	engine, err := proxy.LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	return newTestServer().WithTLSEngine(engine, dir), dir
}

func postCAImport(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/proxy/ca/import", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func importBody(t *testing.T, certPEM, keyPEM string) string {
	t.Helper()
	raw, err := json.Marshal(caImportRequest{CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

func TestImportingACAReplacesTheSigningCAAndPersistsIt(t *testing.T) {
	ts, dir := newTestServerWithCA(t)
	certPEM, keyPEM := caPair(t, "operator CA")

	rec := postCAImport(t, ts, importBody(t, certPEM, keyPEM))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	var out caStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if !out.Configured || out.Subject != "operator CA" {
		t.Errorf("status reports configured=%v subject=%q", out.Configured, out.Subject)
	}
	if !out.Persisted {
		t.Errorf("persisted=false with a writable CA dir: %s", out.PersistError)
	}

	// On disk, with the modes the startup loader uses. The key's mode is the one that matters.
	certOnDisk, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("reading ca.crt: %v", err)
	}
	if string(certOnDisk) != certPEM {
		t.Error("ca.crt on disk is not the certificate that was imported")
	}
	keyInfo, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("stat ca.key: %v", err)
	}
	if mode := keyInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("ca.key mode is %#o, want 0600 — a CA private key must not be group- or "+
			"world-readable", mode)
	}

	// And a restart would load it back: the pair on disk is loadable and is the imported one.
	reloaded, err := proxy.LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("reloading the persisted CA: %v", err)
	}
	if subject, _, _ := reloaded.CADescription(); subject != "operator CA" {
		t.Errorf("a restart would load %q, not the imported CA", subject)
	}
}

// /ca.crt must serve the imported CA. Serving the startup one would have the operator install a
// certificate that signs nothing, which presents as every site failing.
func TestCACertDownloadServesTheImportedCA(t *testing.T) {
	ts, _ := newTestServerWithCA(t)

	before := get(t, ts, "/ca.crt")
	if before.Code != http.StatusOK {
		t.Fatalf("GET /ca.crt = %d", before.Code)
	}

	certPEM, keyPEM := caPair(t, "downloaded CA")
	if rec := postCAImport(t, ts, importBody(t, certPEM, keyPEM)); rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body.String())
	}

	after := get(t, ts, "/ca.crt")
	if after.Code != http.StatusOK {
		t.Fatalf("GET /ca.crt after import = %d", after.Code)
	}
	if after.Body.String() == before.Body.String() {
		t.Fatal("/ca.crt still serves the pre-import certificate")
	}

	block, _ := pem.Decode(after.Body.Bytes())
	if block == nil {
		t.Fatal("/ca.crt did not return PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing served certificate: %v", err)
	}
	if parsed.Subject.CommonName != "downloaded CA" {
		t.Errorf("/ca.crt serves %q, want the imported CA", parsed.Subject.CommonName)
	}
	// Content-Length must match the body it now serves, not the old one. This is the specific way a
	// stale-PEM bug would show up even if the right bytes were written: a truncated download.
	if cl := after.Header().Get("Content-Length"); cl != "" {
		if want := strconv.Itoa(len(after.Body.Bytes())); cl != want {
			t.Errorf("Content-Length %s but body is %s bytes", cl, want)
		}
	}
}

// A refused pair must leave the CA in place, and the refusal must say what was wrong without
// quoting key material back.
func TestARefusedImportLeavesTheCAAloneAndLeaksNothing(t *testing.T) {
	certA, _ := caPair(t, "cert A")
	_, keyB := caPair(t, "cert B")

	cases := []struct {
		name       string
		cert, key  string
		wantStatus int
	}{
		{"mismatched pair", certA, keyB, http.StatusBadRequest},
		{"cert not PEM", "not a certificate", keyB, http.StatusBadRequest},
		{"missing key", certA, "", http.StatusBadRequest},
		{"missing cert", "", keyB, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, _ := newTestServerWithCA(t)
			before, _, _ := ts.tlsEngine.CADescription()

			rec := postCAImport(t, ts, importBody(t, tc.cert, tc.key))
			if rec.Code != tc.wantStatus {
				t.Fatalf("POST = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}

			after, _, _ := ts.tlsEngine.CADescription()
			if after != before {
				t.Errorf("the CA changed from %q to %q on a refused import", before, after)
			}
			// The private key must never come back in an error body.
			if tc.key != "" && strings.Contains(rec.Body.String(), "PRIVATE KEY") {
				t.Error("the response body contains PEM key material")
			}
			if tc.key != "" {
				// Any substantial run of the key would do; check a distinctive slice of it.
				needle := strings.TrimSpace(strings.Split(tc.key, "\n")[1])
				if len(needle) > 16 && strings.Contains(rec.Body.String(), needle) {
					t.Error("the response body echoes bytes of the private key")
				}
			}
		})
	}
}

// With no engine there is nothing an imported CA would affect, so storing it would be a setting
// nothing reads.
func TestImportingACAWithInterceptionOffIsRefused(t *testing.T) {
	ts := newTestServer() // no WithTLSEngine
	certPEM, keyPEM := caPair(t, "unused CA")

	rec := postCAImport(t, ts, importBody(t, certPEM, keyPEM))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("POST = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "intercept-tls") {
		t.Errorf("the refusal does not say how to enable interception: %s", rec.Body.String())
	}
}

// The import succeeds but persistence fails. This must report success-with-a-caveat, not silent
// success: the CA is signing now and will vanish on restart, and those are different situations for
// an operator who has just installed it in a trust store.
func TestAnUnwritableCADirIsReportedRatherThanHidden(t *testing.T) {
	ts, _ := newTestServerWithCA(t)

	// The unwritable directory is made unwritable by *type*, not by mode: caDir points at a path
	// underneath a regular file, so MkdirAll fails with ENOTDIR.
	//
	// The first draft used chmod 0500 and skipped when the mode was ignored — which is always, in
	// this container, because the suite runs as root. That left the branch this test exists for
	// completely unexercised while reporting SKIP, which is the same class of thing as a passing
	// vacuous test. ENOTDIR is refused for root as well, so the premise now holds for every user.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("regular file"), 0o600); err != nil {
		t.Fatalf("creating the blocking file: %v", err)
	}
	ts.caDir = filepath.Join(blocker, "ca")

	certPEM, keyPEM := caPair(t, "in-memory only CA")
	rec := postCAImport(t, ts, importBody(t, certPEM, keyPEM))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d, want 200 — the import itself succeeded: %s", rec.Code, rec.Body.String())
	}

	var out caStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Subject != "in-memory only CA" {
		t.Errorf("subject = %q; the CA should be in force", out.Subject)
	}
	if out.Persisted {
		t.Error("persisted=true for an unwritable directory")
	}
	if out.PersistError == "" {
		t.Error("persisted=false with no reason given")
	}
	if !strings.Contains(out.Hint, "restart") {
		t.Errorf("the hint does not warn that a restart loses this CA: %q", out.Hint)
	}
}

func TestCAStatusReportsTheCurrentCA(t *testing.T) {
	ts, _ := newTestServerWithCA(t)

	rec := get(t, ts, "/api/proxy/ca")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	var out caStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Configured || out.Subject == "" || out.NotAfter == "" {
		t.Errorf("status = %+v, want a configured CA with a subject and expiry", out)
	}
	if _, err := time.Parse(time.RFC3339, out.NotAfter); err != nil {
		t.Errorf("not_after %q is not RFC 3339: %v", out.NotAfter, err)
	}
}

func TestCAStatusWithInterceptionOffSaysSo(t *testing.T) {
	ts := newTestServer()
	rec := get(t, ts, "/api/proxy/ca")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200 — \"off\" is an answer, not a failure", rec.Code)
	}
	var out caStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Configured {
		t.Error("configured=true with no engine")
	}
	if out.Hint == "" {
		t.Error("no hint explaining why there is no CA")
	}
}

func TestCARoutesRejectTheWrongMethods(t *testing.T) {
	ts, _ := newTestServerWithCA(t)
	for path, bad := range map[string][]string{
		"/api/proxy/ca":        {http.MethodPost, http.MethodPut},
		"/api/proxy/ca/import": {http.MethodGet, http.MethodDelete},
	} {
		for _, method := range bad {
			req := httptest.NewRequest(method, path, nil)
			rec := httptest.NewRecorder()
			ts.mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 405", method, path, rec.Code)
			}
		}
	}
}
