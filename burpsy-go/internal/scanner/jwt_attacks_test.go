package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// The JWT forgery rows against vulnapp's JWT family (vulnapp_jwt.go). Each vulnerable endpoint
// verifies signatures in general and fails on exactly one technique, so a row firing there is that
// technique working; each safe twin verifies correctly, so a row firing there is a false positive.
// /rm/jwt verifies nothing, and is where the "report once" rule is asserted.

var jwtRows = []string{
	"JWT signature not verified", "JWT none algorithm supported", "JWT self-signed JWK header supported",
	"JWT arbitrary jku header supported", "JWT arbitrary x5u header supported", jwtExpiredIssue,
}

func TestJWTForgeryRowsEachFireOnTheirOwnDefect(t *testing.T) {
	rt := startRuntimeTarget(t)
	cases := []struct {
		path, row, evidence string
	}{
		{"/jw/none", "JWT none algorithm supported", ""},
		{"/jw/jwk", "JWT self-signed JWK header supported", ""},
		{"/jw/confusion", "JWT signature not verified", "algorithm confusion"},
		{"/jw/kid", "JWT signature not verified", "kid path traversal"},
		{"/jw/kidsql", "JWT signature not verified", "kid injection"},
		{"/jw/empty", "JWT signature not verified", "all empty"},
		{"/rm/jwt", "JWT signature not verified", "altered"},
		// Garbage accepted, stripped signature rejected: the garbage control alone must stand the
		// jwk (and jku/x5u) rows down here.
		{"/jw/anysig", "JWT signature not verified", "altered"},
		// Altered signature rejected, missing signature accepted: the stripped-token stand-down
		// must keep the none row (whose tokens are also unsigned) from double-reporting it.
		{"/jw/nosig", "JWT signature not verified", "signature removed"},
	}
	for _, c := range cases {
		got := rt.findingsFor(t, c.path, false)
		f := got[c.row]
		if f == nil {
			t.Errorf("%s: %q not reported; rows: %s", c.path, c.row, joinRows(got))
			continue
		}
		if !strings.Contains(f.Description, c.evidence) {
			t.Errorf("%s: %q does not name the technique %q: %s", c.path, c.row, c.evidence, f.Description)
		}
		// One defect, one row: every other JWT forgery row stays down on these endpoints.
		for _, other := range jwtRows {
			if other != c.row && got[other] != nil {
				t.Errorf("%s: %q also reported (%s); only %q is this endpoint's defect", c.path, other, got[other].Description, c.row)
			}
		}
	}
}

func TestJWTForgeryRowsStayQuietOnVerifiersThatWork(t *testing.T) {
	rt := startRuntimeTarget(t)
	if rt.findingsFor(t, "/jw/confusion", false)["JWT signature not verified"] == nil {
		t.Fatal("algorithm confusion did not fire on /jw/confusion in this run, so the safe twins' silence proves nothing")
	}
	for _, path := range []string{"/jw/safe/hs", "/jw/safe/rs", "/jw/safe/kid", "/rm/safe/jwt"} {
		got := rt.findingsFor(t, path, false)
		for _, row := range jwtRows {
			if f := got[row]; f != nil {
				t.Errorf("%s: %q reported against a verifier that rejects every forgery: %s", path, row, f.Description)
			}
		}
	}
}

func TestJWTExpiredTokenAcceptedIsProvedAndDeniedOnTwins(t *testing.T) {
	rt := startRuntimeTarget(t)
	vuln, safe, _ := vulnapp.JWTExpiryEndpoints()
	for _, path := range vuln {
		got := rt.findingsFor(t, path, false)
		if got[jwtExpiredIssue] == nil {
			t.Errorf("%s ignores exp but %q was not reported; rows: %s", path, jwtExpiredIssue, joinRows(got))
		}
	}
	for _, path := range safe {
		if f := rt.findingsFor(t, path, false)[jwtExpiredIssue]; f != nil {
			t.Errorf("%s enforces exp but %q was reported: %s", path, jwtExpiredIssue, f.Description)
		}
	}
}

func TestSessionTokenInURLRecognisesAJWTByItsValue(t *testing.T) {
	rt := startRuntimeTarget(t)
	var vulnPath, safePath string
	for _, e := range vulnapp.Vulnerabilities() {
		if strings.HasPrefix(e.Path, "/jw/url?") {
			vulnPath = e.Path
		}
		if strings.HasPrefix(e.Path, "/jw/safe/url?") {
			safePath = e.Path
		}
	}
	vuln := rt.findingsFor(t, vulnPath, false)
	if f := vuln["Session token in URL"]; f == nil || !strings.Contains(f.Evidence, "JWT") {
		t.Errorf("a signed JWT in an innocuously named query parameter was not reported as a session token in the URL: %+v", f)
	}
	// The page ignores the token entirely: the tokenless control answers like the baseline, so no
	// forgery row may read "the altered signature was accepted" as a verification failure.
	for _, row := range jwtRows {
		if f := vuln[row]; f != nil {
			t.Errorf("%q reported on a page that never reads the token: %s", row, f.Description)
		}
	}
	if f := rt.findingsFor(t, safePath, false)["Session token in URL"]; f != nil {
		t.Errorf("a dotted non-token value was reported as a session token: %s", f.Evidence)
	}
}

// check_jwt_forgery is the rows' own switch: on alone it admits them, and with it and the extended
// family both off they do not run.
func TestJWTForgeryRunsUnderItsOwnSwitchAndNotWithout(t *testing.T) {
	rt := startRuntimeTarget(t)
	audit := func(cfg *ScanConfig) map[string]*Finding {
		scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, findings := scan.AuditWithin(ctx, rt.exchanges["/jw/none"], scan.AuditConfig())
		out := map[string]*Finding{}
		for _, f := range findings {
			if f != nil {
				out[f.Name] = f
			}
		}
		return out
	}
	on := audit(&ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckJwtForgery: true})
	if on["JWT none algorithm supported"] == nil {
		t.Errorf("check_jwt_forgery alone did not admit the none row; rows: %s", joinRows(on))
	}
	off := audit(&ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute})
	for _, row := range jwtRows {
		if off[row] != nil {
			t.Errorf("%q reported with check_jwt_forgery and check_extended_active both off", row)
		}
	}
}

func TestJWTAlteredSignatureChangesEveryByteAndKeepsTheLength(t *testing.T) {
	sig := b64urlEncode([]byte("0123456789abcdef0123456789abcdef"))
	got := jwtAlteredSignature(sig)
	if len(got) != len(sig) {
		t.Fatalf("length %d, want %d", len(got), len(sig))
	}
	a, _ := b64urlDecode(sig)
	b, ok := b64urlDecode(got)
	if !ok {
		t.Fatalf("altered signature %q is not base64url", got)
	}
	for i := range a {
		if a[i] == b[i] {
			t.Fatalf("byte %d unchanged", i)
		}
	}
	if jwtAlteredSignature("") == "" {
		t.Error("an empty signature must become a non-empty control, or the control replays an unsigned token")
	}
}

func TestJWTReplaceTokenRecomputesTheBodyLength(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\ntoken=aaaa"
	got := string(jwtReplaceToken(raw, "aaaa", "bbbbbbbb"))
	if !strings.Contains(got, "Content-Length: 14\r\n") || !strings.HasSuffix(got, "token=bbbbbbbb") {
		t.Errorf("body token replaced without fixing its length:\n%s", got)
	}
	hdr := "GET /x HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer aaaa\r\n\r\n"
	if got := string(jwtReplaceToken(hdr, "aaaa", "")); got != "GET /x HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer \r\n\r\n" {
		t.Errorf("header token replacement changed more than the token:\n%q", got)
	}
}

func TestIsSignedJWTWantsAHeaderAnAlgAndASignature(t *testing.T) {
	signed := b64urlEncode([]byte(`{"alg":"HS256"}`)) + "." + b64urlEncode([]byte(`{"sub":"a"}`)) + ".c2ln"
	unsigned := b64urlEncode([]byte(`{"alg":"none"}`)) + "." + b64urlEncode([]byte(`{"sub":"a"}`)) + "."
	for v, want := range map[string]bool{signed: true, unsigned: false, "release-2.4.1-build.7": false, "a.b.c": false} {
		if got := isSignedJWT(v); got != want {
			t.Errorf("isSignedJWT(%q) = %v, want %v", v, got, want)
		}
	}
}
