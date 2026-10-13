package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// The JWT credential-exposure and null-byte rows (jwt_exposure.go) against vulnapp_jwt_exposure.go.

func TestJWTCredentialExposureNamesEachVectorItProved(t *testing.T) {
	rt := startRuntimeTarget(t)
	cases := []struct {
		path      string
		want, not []string
	}{
		// Cleartext, a cookie set without HttpOnly or Secure.
		{"/jx/cookie", []string{"CWE-1004", "CWE-614", "CWE-319", `cookie "session"`}, []string{"CWE-598"}},
		// HTTPS, the token in the query string and nowhere else.
		{"/jx/url?access_token=" + jwtTestToken(t, "/jx/url?access_token="), []string{"CWE-598"}, []string{"CWE-319", "CWE-1004", "CWE-614"}},
		// HTTPS, no Set-Cookie on the page: the cookie's attributes come from the earlier login.
		{"/jx/session", []string{"CWE-1004"}, []string{"CWE-614", "CWE-319", "CWE-598"}},
	}
	for _, c := range cases {
		got := rt.findingsFor(t, c.path, false)
		f := got[IssueJWTCredentialExposed]
		if f == nil {
			t.Errorf("%s: %q not reported; rows: %s", c.path, IssueJWTCredentialExposed, joinRows(got))
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(f.Description, w) {
				t.Errorf("%s: the finding does not name %s: %s", c.path, w, f.Description)
			}
		}
		for _, n := range c.not {
			if strings.Contains(f.Description, n) {
				t.Errorf("%s: the finding names %s, which this exchange does not have: %s", c.path, n, f.Description)
			}
		}
		if !strings.Contains(f.Description, "signature altered") {
			t.Errorf("%s: the finding does not state the verification differential: %s", c.path, f.Description)
		}
	}
}

func TestJWTCredentialExposureStaysQuietOnProtectedOrUnverifiedTokens(t *testing.T) {
	rt := startRuntimeTarget(t)
	if rt.findingsFor(t, "/jx/cookie", false)[IssueJWTCredentialExposed] == nil {
		t.Fatal("the row did not fire on /jx/cookie in this run, so the twins' silence proves nothing")
	}
	for _, path := range []string{"/jx/safe/cookie", "/jx/safe/session", "/jx/safe/unverified", "/jx/safe/optional", "/rm/jwt"} {
		if f := rt.findingsFor(t, path, false)[IssueJWTCredentialExposed]; f != nil {
			t.Errorf("%s: %q reported: %s", path, IssueJWTCredentialExposed, f.Description)
		}
	}
}

func TestJWTNullByteTruncationIsProvedAgainstATrailingBytesControl(t *testing.T) {
	rt := startRuntimeTarget(t)
	got := rt.findingsFor(t, "/jx/nullbyte", false)
	f := got[IssueJWTNullByteSignature]
	if f == nil {
		t.Fatalf("/jx/nullbyte: %q not reported; rows: %s", IssueJWTNullByteSignature, joinRows(got))
	}
	if !strings.Contains(f.Evidence, "%00bsy") {
		t.Errorf("the evidence is not the accepted NUL-suffixed token: %s", f.Evidence)
	}
	for _, row := range jwtRows {
		if got[row] != nil {
			t.Errorf("/jx/nullbyte: %q also reported (%s); the verifier checks signatures otherwise", row, got[row].Description)
		}
	}
	// /jx/safe/trailing accepts trailing bytes with or without a NUL: the no-NUL control must stand
	// the row down. /jx/safe/nullbyte reads the whole segment.
	for _, path := range []string{"/jx/safe/nullbyte", "/jx/safe/trailing", "/jw/safe/hs"} {
		if f := rt.findingsFor(t, path, false)[IssueJWTNullByteSignature]; f != nil {
			t.Errorf("%s: %q reported: %s", path, IssueJWTNullByteSignature, f.Description)
		}
	}
}

// check_jwt_exposure admits the exposure row on its own, without the forgery rows; with both
// switches off neither runs.
func TestJWTExposureRunsUnderItsOwnSwitch(t *testing.T) {
	rt := startRuntimeTarget(t)
	audit := func(cfg *ScanConfig) map[string]*Finding {
		scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, findings := scan.AuditWithin(ctx, rt.exchanges["/jx/cookie"], scan.AuditConfig())
		out := map[string]*Finding{}
		for _, f := range findings {
			if f != nil {
				out[f.Name] = f
			}
		}
		return out
	}
	on := audit(&ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckJwtExposure: true})
	if on[IssueJWTCredentialExposed] == nil {
		t.Errorf("check_jwt_exposure alone did not admit the row; rows: %s", joinRows(on))
	}
	off := audit(&ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute})
	if off[IssueJWTCredentialExposed] != nil {
		t.Errorf("%q reported with check_jwt_exposure off", IssueJWTCredentialExposed)
	}
}

func TestJWTCookieInReadsTheCookieThatHoldsTheToken(t *testing.T) {
	tok := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln"
	name, attrs, ok := jwtCookieIn([]string{
		"theme=dark; Path=/",
		"sid=" + tok + "; Path=/; Max-Age=0",
		"auth=" + tok + "; Path=/; secure; HttpOnly",
	}, tok)
	if !ok || name != "auth" || !attrs["httponly"] || !attrs["secure"] {
		t.Errorf("got %q %v %v; want the live auth cookie with both attributes (the deletion skipped)", name, attrs, ok)
	}
	if _, _, ok := jwtCookieIn([]string{"theme=dark"}, tok); ok {
		t.Error("a cookie not holding the token was taken for it")
	}
}

// The cookie that stored the token is looked up only on the request's own origin: a Set-Cookie for the
// same token from the plain-HTTP port or another host says nothing about the cookie this request sent.
func TestJWTCookieSettingIsLookedUpOnTheSameOriginOnly(t *testing.T) {
	tok := testJWT()
	cc := postureFixture(t, "GET /me HTTP/1.1\r\nHost: app.test\r\nCookie: session="+tok+"\r\n\r\n",
		htmlResponse("<html><body>hi</body></html>"), true)
	add := func(host string, port uint16, tls bool, setCookie string) {
		t.Helper()
		store := cc.Scanner.store
		req, err := store.Put([]byte("GET /login HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := store.Put([]byte(htmlResponse("ok", "Set-Cookie: "+setCookie)), core.DirectionResponse)
		if err != nil {
			t.Fatal(err)
		}
		store.AddExchange(&core.Exchange{Request: core.MsgPtr(req), Response: &resp, Host: host, Port: port, TLS: tls,
			Method: "GET", Path: "/login"})
	}
	has := func(cwe string) bool {
		for _, v := range jwtExposureVectors(cc, tok) {
			if fmt.Sprintf("CWE-%d", v.cwe) == cwe {
				return true
			}
		}
		return false
	}
	add("app.test", 80, false, "session="+tok+"; Path=/")
	add("other.test", 443, true, "session="+tok+"; Path=/")
	if has("CWE-1004") || has("CWE-614") {
		t.Fatalf("a cookie set on another origin was attributed to this request: %+v", jwtExposureVectors(cc, tok))
	}
	add("app.test", 443, true, "session="+tok+"; Path=/; Secure")
	if !has("CWE-1004") || has("CWE-614") {
		t.Errorf("the same-origin login's cookie (Secure, no HttpOnly) was not read: %+v", jwtExposureVectors(cc, tok))
	}
}

// jwtTestToken returns the token vulnapp put in the query of the manifest path starting with prefix.
func jwtTestToken(t *testing.T, prefix string) string {
	t.Helper()
	for _, e := range vulnapp.Vulnerabilities() {
		if strings.HasPrefix(e.Path, prefix) {
			return strings.TrimPrefix(e.Path, prefix)
		}
	}
	t.Fatalf("no manifest path starts with %s", prefix)
	return ""
}
