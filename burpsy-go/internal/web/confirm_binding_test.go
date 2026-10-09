package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// burpsy-react-ui-e0yq: a confirmation is bound to the resolved call, not to the route.

// The bead's acceptance criterion, on the route where the difference matters most: a token minted to
// export the CA's public certificate must not export its private key, though both are the same route
// and the same verb. Before the binding, the approver of "POST /api/proxy/ca/export" had approved
// both.
func TestATokenMintedForOneCallCannotAuthoriseAnotherOnTheSameRoute(t *testing.T) {
	s, _ := newTestServerWithCA(t)
	token := confirm(t, s, http.MethodPost, "/api/proxy/ca/export", `{"kind":"cert"}`)

	rec := spendOn(t, s, token, http.MethodPost, "/api/proxy/ca/export", `{"kind":"key"}`)
	if rec.Code != http.StatusPreconditionRequired || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("a token minted for a certificate export authorised a key export (%d): the approver saw "+
			"one request and another ran", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "different request") {
		t.Errorf("the refusal does not say a token is bound to its request: %s", rec.Body.String())
	}
	// Burned by the mismatched attempt: a token presented with the wrong call is not left live for a
	// second try with the right one.
	if rec := spendOn(t, s, token, http.MethodPost, "/api/proxy/ca/export", `{"kind":"cert"}`); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("a token tried on the wrong call was still spendable on its own call (%d)", rec.Code)
	}
	// And the call it was minted for goes through with a fresh token for exactly that call.
	if rec := spendOn(t, s, confirm(t, s, http.MethodPost, "/api/proxy/ca/export", `{"kind":"cert"}`),
		http.MethodPost, "/api/proxy/ca/export", `{"kind":"cert"}`); rec.Code != http.StatusOK {
		t.Fatalf("a token minted for the certificate export was refused on that export (%d): %s", rec.Code, rec.Body.String())
	}
}

// The same for an attack route, and for the path of a subtree route: a crawl confirmed for one seed
// is not a crawl of another, and an audit confirmed for exchange 1 is not an audit of exchange 2.
func TestATokenIsBoundToTheTargetAsWellAsTheRoute(t *testing.T) {
	s := newScannerServer()
	token := confirm(t, s, http.MethodPost, "/api/crawl", `{"seeds":["http://in-scope.test/"]}`)
	if rec := spendOn(t, s, token, http.MethodPost, "/api/crawl", `{"seeds":["http://elsewhere.test/"]}`); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("a crawl confirmed for one seed ran against another (%d): %s", rec.Code, rec.Body.String())
	}
	token = confirm(t, s, http.MethodPost, "/api/audit/1", "")
	if rec := spendOn(t, s, token, http.MethodPost, "/api/audit/2", ""); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("an audit confirmed for /api/audit/1 ran on /api/audit/2 (%d): %s", rec.Code, rec.Body.String())
	}
	// The positive control for the subtree path: the confirmed path itself is admitted.
	token = confirm(t, s, http.MethodPost, "/api/audit/1", "")
	if rec := spendOn(t, s, token, http.MethodPost, "/api/audit/1", ""); rec.Code == http.StatusPreconditionRequired {
		t.Fatalf("an audit confirmed for /api/audit/1 was refused on /api/audit/1: %s", rec.Body.String())
	}
}

// Every part of the call is in the binding, and each one alone is enough to refuse: method, path,
// query and body. Driven at the store so each dimension is varied with the others held fixed.
func TestEachPartOfTheCallIsBound(t *testing.T) {
	s := newTestServer()
	base := newCallBinding(http.MethodPost, "/api/audit/1", "mode=fast", []byte(`{"a":1}`))
	for name, other := range map[string]callBinding{
		"method": newCallBinding(http.MethodPut, "/api/audit/1", "mode=fast", []byte(`{"a":1}`)),
		"path":   newCallBinding(http.MethodPost, "/api/audit/2", "mode=fast", []byte(`{"a":1}`)),
		"query":  newCallBinding(http.MethodPost, "/api/audit/1", "mode=slow", []byte(`{"a":1}`)),
		"body":   newCallBinding(http.MethodPost, "/api/audit/1", "mode=fast", []byte(`{"a":2}`)),
		"number": newCallBinding(http.MethodPost, "/api/audit/1", "mode=fast", []byte(`{"a":1.0}`)),
		"nobody": newCallBinding(http.MethodPost, "/api/audit/1", "mode=fast", nil),
	} {
		if s.confirms.spend(mustIssue(t, s, "/api/audit/", base), "/api/audit/", other) {
			t.Errorf("a token bound to %+v was spent on a call differing only in its %s", base, name)
		}
	}
	if !s.confirms.spend(mustIssue(t, s, "/api/audit/", base), "/api/audit/", base) {
		t.Error("a token was refused on the very call it was bound to")
	}
}

// Canonical, not byte-exact: an MCP host re-serialising the arguments between the confirm and the
// call (key order, whitespace) and a query built from a map in another order are the same call, and
// refusing them would make the binding fail exactly the callers it exists to cover. Through the gate,
// so the gate's own reading of the request is what is compared.
func TestSpellingsOfTheSameCallShareOneBinding(t *testing.T) {
	s, _ := newTestServerWithCA(t)
	token := confirm(t, s, http.MethodPost, "/api/proxy/ca/export", `{"password":"hunter2","kind":"pkcs12"}`)
	if rec := spendOn(t, s, token, http.MethodPost, "/api/proxy/ca/export", "{\n  \"kind\" : \"pkcs12\",\n  \"password\" : \"hunter2\"\n}"); rec.Code != http.StatusOK {
		t.Fatalf("a reformatted but identical body was refused (%d): %s", rec.Code, rec.Body.String())
	}
	a := newCallBinding(http.MethodPost, "/api/x", "b=2&a=1", nil)
	b := newCallBinding("post", "/api/x", "a=1&b=2", nil)
	if a.digest() != b.digest() {
		t.Error("two orderings of one query (and two spellings of one verb) bind differently")
	}
	// The canonical form never equates bytes that decode differently: invalid UTF-8 is compared raw.
	if canonicalBody([]byte("\"\xff\"")) == nil || string(canonicalBody([]byte("\"\xff\""))) == string(canonicalBody([]byte("\"\xfe\""))) {
		t.Error("two different invalid-UTF-8 bodies canonicalised to one value")
	}
}

// The approver is shown the call: the mint's answer carries the resolved request — method, the bound
// URL, the body as it will be compared — and a password in it is withheld from the preview while
// still being covered by the hash.
func TestTheMintShowsThePreviewOfTheCallItAuthorises(t *testing.T) {
	s, _ := newTestServerWithCA(t)
	body := `{"kind":"pkcs12","password":"hunter2"}`
	rec := mintAt(t, s, "/api/proxy/ca/export", confirmDescription(http.MethodPost, "/api/proxy/ca/export", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("mint = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("the preview echoes the keystore password: %s", rec.Body.String())
	}
	var minted confirmMinted
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	p := minted.Call
	if p.Method != http.MethodPost || p.URL != "/api/proxy/ca/export" || p.BodyKind != "json" || p.BodyBytes != len(body) {
		t.Fatalf("preview = %+v, want POST /api/proxy/ca/export, a %d-byte json body", p, len(body))
	}
	if !strings.Contains(p.Body, `"kind": "pkcs12"`) || len(p.Redacted) != 1 || p.Redacted[0] != "password" {
		t.Fatalf("preview body %q redacted %v, want the kind shown and the password withheld", p.Body, p.Redacted)
	}
	sum := sha256.Sum256([]byte(`{"kind":"pkcs12","password":"hunter2"}`))
	if p.BodySHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("body_sha256 %s is not the hash of the canonical body", p.BodySHA256)
	}
	if minted.Binding != newCallBinding(http.MethodPost, "/api/proxy/ca/export", "", []byte(body)).digest() {
		t.Error("the binding the mint reports is not the binding the gate will compute for the call")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("a preview that may carry request content is cacheable")
	}
}

// A mint that describes no call, or a call the gate could never match, is refused rather than turned
// into a token that authorises "anything on this route" — the unbound token this bead removes.
func TestAMintRefusesADescriptionItCannotBind(t *testing.T) {
	s := newScannerServer()
	for name, desc := range map[string]string{
		"no description":   "",
		"no method":        `{"url":"/api/crawl"}`,
		"a read":           `{"method":"GET","url":"/api/crawl"}`,
		"no url":           `{"method":"POST"}`,
		"another route":    `{"method":"POST","url":"/api/scope"}`,
		"an absolute url":  `{"method":"POST","url":"http://evil.test/api/crawl"}`,
		"two bodies":       `{"method":"POST","url":"/api/crawl","body":"{}","body_base64":"e30="}`,
		"not base64":       `{"method":"POST","url":"/api/crawl","body_base64":"%%%"}`,
		"a confirm path":   `{"method":"POST","url":"/api/crawl/confirm"}`,
		"a sibling prefix": `{"method":"POST","url":"/api/crawlx"}`,
	} {
		if rec := mintAt(t, s, "/api/crawl", desc); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: mint = %d, want 400: %s", name, rec.Code, rec.Body.String())
		}
	}
	// A base64 body binds to its decoded bytes.
	rec := mintAt(t, s, "/api/crawl", `{"method":"POST","url":"/api/crawl","body_base64":"e30="}`)
	var minted confirmMinted
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &minted) != nil ||
		minted.Binding != newCallBinding(http.MethodPost, "/api/crawl", "", []byte("{}")).digest() {
		t.Fatalf("a base64 body did not bind to its bytes (%d): %s", rec.Code, rec.Body.String())
	}
}

// A presented token whose call cannot be read in full (here, a body over the server's cap) is refused
// and burned — the gate never admits a call it could not compare.
func TestAnOversizedBodyIsRefusedAndBurnsItsToken(t *testing.T) {
	s := newScannerServer()
	token := confirm(t, s, http.MethodPost, "/api/crawl", `{}`)
	big := strings.Repeat("a", maxRequestBodyBytes+1)
	if rec := spendOn(t, s, token, http.MethodPost, "/api/crawl", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an over-cap body with a token = %d, want 413", rec.Code)
	}
	if s.confirms.pending(token) {
		t.Error("the token survived an attempt whose body could not be compared")
	}
}
