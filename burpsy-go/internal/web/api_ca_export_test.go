package web

// The CA export route (burpsy-react-ui-j92x), and the claim it exists to make honest: an operator
// can point another tool at this proxy's own interception, and getting the private key out is the
// only way to do that.
//
// Every test here goes through s.guarded, not s.mux. s.guarded is the outer handler that carries the
// confirmation gate; s.mux is the inner one it protects. Posting to s.mux directly would answer a
// question nobody asks — it would prove the handler works while proving nothing about whether an
// unattended caller can reach it, which is the property that makes this route safe to have at all.

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

// postCAExport sends a body to the export route with the given confirmation token. An empty token is
// the unconfirmed case, which is the default most callers will hit.
//
// The Host/Origin pair is the console presenting itself, and it is set even for the unconfirmed cases
// because that is the layering the gate is built on: the origin gate is OUTER, so an unconfirmed
// request from the console reaches the 428 and a request from a hostile page is refused before it
// can learn whether the confirm header exists at all. Testing without it would be testing the outer
// gate with the inner one still hidden, and would pass for the wrong reason.
func postCAExport(t *testing.T, s *Server, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/proxy/ca/export", strings.NewReader(body))
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	if token != "" {
		req.Header.Set(ConfirmHeader, token)
	}
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	return rec
}

// parseExportedCert and parseExportedKey are the assertion the whole route exists to enable: the two
// artifacts an operator exports are halves of one pair, and if they were not, the export would be a
// way to break TLS interception while looking like a way to extend it.
func parseExportedCert(t *testing.T, body []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(body)
	if blk == nil {
		t.Fatalf("the exported certificate is not PEM; got %d bytes of %q", len(body), string(body[:min(len(body), 60)]))
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parsing the exported certificate: %v", err)
	}
	return cert
}

func parseExportedKey(t *testing.T, body []byte) *rsa.PrivateKey {
	t.Helper()
	blk, _ := pem.Decode(body)
	if blk == nil {
		t.Fatalf("the exported key is not PEM; got %d bytes of %q", len(body), string(body[:min(len(body), 60)]))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatalf("parsing the exported key: %v", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("the exported key is a %T, not an RSA key", parsed)
	}
	return key
}

// The acceptance criterion, stated as the failure it prevents: the exported key parses, and its
// public half is the certificate's public half. A key that parses but belongs to a different CA is
// the worst shape this bug could take, because every downstream tool would accept the certificate
// and then silently fail to verify a single leaf.
func TestTheExportedKeyParsesAndItsPublicHalfMatchesTheExportedCert(t *testing.T) {
	ts, _ := newTestServerWithCA(t)

	// A fresh confirmation per export. Tokens are one-time by design, so reusing one here would be
	// testing the token's lifecycle rather than the pair — which the test below already does.
	certRec := postCAExport(t, ts, confirm(t, ts, "/api/proxy/ca/export"), `{"kind":"cert"}`)
	if certRec.Code != http.StatusOK {
		t.Fatalf("exporting the certificate = %d, want 200: %s", certRec.Code, certRec.Body.String())
	}
	keyRec := postCAExport(t, ts, confirm(t, ts, "/api/proxy/ca/export"), `{"kind":"key"}`)
	if keyRec.Code != http.StatusOK {
		t.Fatalf("exporting the key = %d, want 200: %s", keyRec.Code, keyRec.Body.String())
	}

	cert := parseExportedCert(t, certRec.Body.Bytes())
	key := parseExportedKey(t, keyRec.Body.Bytes())

	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("the exported key does not sign for the exported certificate: an operator who pointed " +
			"another tool at these two artifacts would have every leaf rejected")
	}
	if !cert.IsCA {
		t.Error("the exported certificate is not a CA; whoever exported it cannot use it as a trust anchor")
	}
	if cert.Subject.CommonName == "" {
		t.Error("the exported certificate has no common name, so a trust store will show the operator " +
			"an unnamed entry and cannot tell it apart from any other proxy's")
	}
}

// The gate is the reason this route is safe to ship at all, so it is asserted here rather than left
// to confirm_gate_test.go: that file proves the gate works in general, this proves the export is
// actually behind it.
func TestTheExportRouteRefusesAnUnconfirmedCall(t *testing.T) {
	ts, _ := newTestServerWithCA(t)

	rec := postCAExport(t, ts, "", `{"kind":"key"}`)

	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("an unconfirmed export answered %d, want 428: the private key left without an "+
			"explicit confirmation", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Error("the refusal carries key material; a 428 that echoed the secret would be a second way out")
	}
}

// A token minted for one call spends on one call. Reuse is what would turn a per-call confirmation
// into a standing permission, so the second export must be refused even though the first succeeded.
func TestAConfirmationTokenIsSpentByOneCallAndCannotBeReplayed(t *testing.T) {
	ts, _ := newTestServerWithCA(t)
	token := confirm(t, ts, "/api/proxy/ca/export")

	if rec := postCAExport(t, ts, token, `{"kind":"cert"}`); rec.Code != http.StatusOK {
		t.Fatalf("the first export = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	rec := postCAExport(t, ts, token, `{"kind":"key"}`)

	if rec.Code == http.StatusOK {
		t.Fatal("a spent confirmation token exported the key on its second use; one confirmation " +
			"would then cover an arbitrary number of exports")
	}
}

// A PKCS#12 with an empty password is a keystore that opens for anyone who has the file. The file's
// whole purpose is to be carried to another machine, so "no protection" must not look like success.
func TestAPKCS12ExportRefusesAnEmptyPassword(t *testing.T) {
	ts, _ := newTestServerWithCA(t)
	token := confirm(t, ts, "/api/proxy/ca/export")

	rec := postCAExport(t, ts, token, `{"kind":"pkcs12"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a PKCS#12 export with no password = %d, want 400: the keystore would open for "+
			"anyone who obtained the file", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Error("the password refusal carries key material")
	}
}

// The keystore round-trips: it is decoded with the operator's password, and both halves come back
// matching the exported certificate. An unreadable keystore is the failure an operator only finds
// after they have already pointed another tool at it.
func TestAPKCS12ExportProducesAKeystoreCarryingBothHalvesOfTheLiveCA(t *testing.T) {
	ts, _ := newTestServerWithCA(t)
	token := confirm(t, ts, "/api/proxy/ca/export")

	rec := postCAExport(t, ts, token, `{"kind":"pkcs12","password":"hunter2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("the PKCS#12 export = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	key, cert, err := pkcs12.Decode(rec.Body.Bytes(), "hunter2")
	if err != nil {
		t.Fatalf("the exported keystore does not decode with the password it was made with: %v", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("the keystore's key is a %T, not an RSA key", key)
	}
	if cert == nil {
		t.Fatal("the keystore carries no certificate, so nothing in it can verify a leaf")
	}
	if !rsaKey.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("the keystore's key does not sign for its own certificate")
	}
	if cert.Subject.CommonName != mustCADescriptionCN(t, ts) {
		t.Error("the keystore carries a different CA than the one this proxy is signing with; an " +
			"operator who installed it would trust a CA that signs nothing here")
	}
}

// An unknown kind is refused by name rather than guessed at. Guessing would be the difference
// between "export the certificate" and "export the key" — the one distinction on this route that
// matters.
func TestTheExportRouteRefusesAnUnknownKindWithoutEchoingAnything(t *testing.T) {
	ts, _ := newTestServerWithCA(t)
	token := confirm(t, ts, "/api/proxy/ca/export")

	rec := postCAExport(t, ts, token, `{"kind":"everything"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown export kind = %d, want 400", rec.Code)
	}
	for _, leak := range []string{"PRIVATE KEY", "BEGIN"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("the unknown-kind refusal contains %q; the refusal must name the kind and the "+
				"accepted set and nothing else", leak)
		}
	}
}

// With no CA there is nothing to export, and the answer says why rather than returning an empty
// file — the same distinction handleCACert draws at /ca.crt, for the same reason.
func TestExportingWithNoCAExplainsWhyRatherThanReturningAnEmptyFile(t *testing.T) {
	ts := newTestServer()
	// Confirmed, so the call reaches the handler: what is under test is the no-CA branch, not the
	// gate that stands in front of it (asserted separately above).
	token := confirm(t, ts, "/api/proxy/ca/export")

	rec := postCAExport(t, ts, token, `{"kind":"key"}`)

	if rec.Code == http.StatusOK {
		t.Fatalf("an export with no CA answered 200 with %d bytes; an operator would download an "+
			"empty file and go looking for the fault in their tooling", len(rec.Body.Bytes()))
	}
	if !strings.Contains(rec.Body.String(), "intercept") {
		t.Errorf("the no-CA refusal does not say interception is off: %q", rec.Body.String())
	}
}

// mustCADescriptionCN is the CA's common name as the engine reports it, so the keystore test can
// assert the keystore carries *this* CA rather than merely a self-consistent one.
func mustCADescriptionCN(t *testing.T, s *Server) string {
	t.Helper()
	cert := parseExportedCert(t, s.currentCACertPEM())
	if cert.Subject.CommonName == "" {
		t.Fatal("the live CA has no common name, so this assertion cannot be made")
	}
	return cert.Subject.CommonName
}
