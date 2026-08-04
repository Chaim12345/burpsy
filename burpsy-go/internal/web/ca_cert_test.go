package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The UI has always linked to /ca.crt (`#ca-link` in index.html) and gated the link on a HEAD of
// that route (app.ts refreshCaLink). The route did not exist, so the HEAD 404'd, the link stayed
// hidden, and the operator had no way to reach the CA — which on an HSTS host means no way to use
// the proxy at all, since HSTS forbids clicking through a certificate warning. These pin the
// contract the shipped frontend already expects.
func TestCACertIsServedWhenInterceptionIsOn(t *testing.T) {
	pem := []byte("-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n")
	s := newTestServer().WithCACertPEM(pem)

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ca.crt", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ca.crt = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != string(pem) {
		t.Errorf("body = %q, want the CA PEM verbatim", got)
	}
	// A browser only offers to import a download it recognises as a CA.
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-x509-ca-cert" {
		t.Errorf("Content-Type = %q, want application/x-x509-ca-cert", ct)
	}
}

func TestCACertHeadIsTheLinkGateTheUIActuallyUses(t *testing.T) {
	s := newTestServer().WithCACertPEM([]byte("pem"))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/ca.crt", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD /ca.crt = %d, want 200 — app.ts shows the CA link only when this is ok", rec.Code)
	}
}

// Absence must be a 404, not an empty 200. A zero-byte certificate downloads fine and then fails to
// import, which sends the operator looking for the fault in their browser rather than in their flags.
func TestCACertIsA404WhenInterceptionIsOffRatherThanAnEmptyFile(t *testing.T) {
	s := newTestServer()
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, httptest.NewRequest(method, "/ca.crt", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s /ca.crt with no CA = %d, want 404", method, rec.Code)
		}
		if rec.Body.Len() > 0 && rec.Header().Get("Content-Type") == "application/x-x509-ca-cert" {
			t.Errorf("%s /ca.crt served a certificate body while reporting absence", method)
		}
	}
}
