package scanner

// OAuth/OIDC check tests (burpsy-react-ui-0vzb.9).

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// oauthAudit audits one OAuth fixture path with the bundle's switch on.
func oauthAudit(t *testing.T, path string, mod func(*ScanConfig)) []*Finding {
	t.Helper()
	rt := startRuntimeTarget(t)
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckOAuth: true}
	if mod != nil {
		mod(cfg)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	exchange, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("no captured exchange for %s", path)
	}
	outcome, findings := scan.AuditWithin(ctx, exchange, scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", path, outcome.Error)
	}
	return findings
}

func oauthFind(fs []*Finding, name string) *Finding {
	for _, f := range fs {
		if f.Name == name {
			return f
		}
	}
	return nil
}

const oauthRegisteredEnc = "https%3A%2F%2Fclient.example%2Fcallback"

func TestOAuthImplicitFlowFiresOnTheVulnerableServer(t *testing.T) {
	fs := oauthAudit(t, "/oauth/authorize?response_type=token&client_id=demo&redirect_uri="+oauthRegisteredEnc, nil)
	f := oauthFind(fs, IssueOAuthImplicitFlow)
	if f == nil {
		t.Fatalf("no implicit-flow finding (got %v)", fs)
	}
	if f.Severity != "medium" || f.Confidence != "firm" {
		t.Fatalf("severity/confidence = %s/%s", f.Severity, f.Confidence)
	}
}

func TestOAuthStateMissingFiresOnTheVulnerableServer(t *testing.T) {
	fs := oauthAudit(t, "/oauth/authorize?response_type=code&client_id=demo&redirect_uri="+oauthRegisteredEnc, nil)
	if oauthFind(fs, IssueOAuthStateMissing) == nil {
		t.Fatalf("no state-missing finding (got %v)", fs)
	}
	// The same request carries no PKCE either: that row fires here as well.
	if oauthFind(fs, IssueOAuthPKCEAbsentOrPlain) == nil {
		t.Fatalf("no PKCE finding on the plain code grant (got %v)", fs)
	}
}

func TestOAuthPKCEPlainFiresOnTheVulnerableServer(t *testing.T) {
	fs := oauthAudit(t, "/oauth/authorize?response_type=code&client_id=demo&redirect_uri="+oauthRegisteredEnc+"&state=seedstate&code_challenge=abc&code_challenge_method=plain", nil)
	if oauthFind(fs, IssueOAuthPKCEAbsentOrPlain) == nil {
		t.Fatalf("no PKCE finding (got %v)", fs)
	}
	// state was present: no login-CSRF row here.
	if oauthFind(fs, IssueOAuthStateMissing) != nil {
		t.Fatal("state was present; the state row must stay quiet")
	}
}

func TestOAuthRedirectURIBypassFiresOnTheVulnerableServer(t *testing.T) {
	fs := oauthAudit(t, "/oauth/authorize?response_type=code&client_id=demo&redirect_uri="+oauthRegisteredEnc+"&state=seedstate&code_challenge=abc&code_challenge_method=S256", nil)
	f := oauthFind(fs, IssueOAuthRedirectURIBypass)
	if f == nil {
		t.Fatalf("no redirect_uri bypass finding (got %v)", fs)
	}
	if f.Severity != "high" || f.Confidence != "firm" {
		t.Fatalf("severity/confidence = %s/%s", f.Severity, f.Confidence)
	}
	// A fully strapped request: no passive row fires on this one.
	if oauthFind(fs, IssueOAuthImplicitFlow) != nil || oauthFind(fs, IssueOAuthStateMissing) != nil ||
		oauthFind(fs, IssueOAuthPKCEAbsentOrPlain) != nil {
		t.Fatalf("passive rows fired on a strapped request: %v", fs)
	}
}

func TestOAuthStaysQuietOnTheSafeTwin(t *testing.T) {
	fs := oauthAudit(t, "/oauth/safe/authorize?response_type=code&client_id=demo&redirect_uri="+oauthRegisteredEnc+"&state=seedstate&code_challenge=abc&code_challenge_method=S256", nil)
	for _, row := range []string{IssueOAuthImplicitFlow, IssueOAuthStateMissing, IssueOAuthPKCEAbsentOrPlain, IssueOAuthRedirectURIBypass} {
		if oauthFind(fs, row) != nil {
			t.Fatalf("safe twin reported %s", row)
		}
	}
}

func TestOAuthBundleIsOffByDefault(t *testing.T) {
	rt := startRuntimeTarget(t)
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	path := "/oauth/authorize?response_type=code&client_id=demo&redirect_uri=" + oauthRegisteredEnc
	outcome, findings := scan.AuditWithin(ctx, rt.exchanges[path], scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit failed: %s", outcome.Error)
	}
	for _, f := range findings {
		switch f.Name {
		case IssueOAuthImplicitFlow, IssueOAuthStateMissing, IssueOAuthPKCEAbsentOrPlain, IssueOAuthRedirectURIBypass:
			t.Fatalf("switch off, still reported %s", f.Name)
		}
	}
}

func TestOAuthAuthorizeShape(t *testing.T) {
	authorize := "GET /oauth/authorize?response_type=code&client_id=demo&redirect_uri=https%3A%2F%2Fx HTTP/1.1\r\nHost: h\r\n\r\n"
	if _, ok := oauthAuthorizeShape(authorize); !ok {
		t.Fatal("an authorize request was not recognised")
	}
	if _, ok := oauthAuthorizeShape("GET /other?a=b HTTP/1.1\r\nHost: h\r\n\r\n"); ok {
		t.Fatal("a plain request matched the authorize shape")
	}
	if _, ok := oauthAuthorizeShape("GET /noquery HTTP/1.1\r\nHost: h\r\n\r\n"); ok {
		t.Fatal("a query-less request matched the authorize shape")
	}
}

func TestOAuthRedirectVariantsSpellTheBypasses(t *testing.T) {
	vs := oauthRedirectVariants("https://client.example/callback")
	if len(vs) != 4 {
		t.Fatalf("got %d variants: %v", len(vs), vs)
	}
}

// The redirect_uri pair is found by name whatever spelling the client used for its value; a
// request without one reports that nothing could be substituted instead of resending it unchanged.
func TestOAuthWithRedirectURIFindsAnyValueSpelling(t *testing.T) {
	for _, spelled := range []string{"https://app.example/cb", "https%3a%2f%2fapp.example%2fcb", "https%3A%2F%2Fapp.example%2Fcb"} {
		raw := "GET /oauth/authorize?response_type=code&client_id=c&redirect_uri=" + spelled + "&scope=a HTTP/1.1\r\nHost: idp\r\n\r\n"
		out, ok := oauthWithRedirectURI(raw, "https://attacker.burpsy.invalid/cb", false)
		if !ok || !strings.Contains(out, "redirect_uri=https%3A%2F%2Fattacker.burpsy.invalid%2Fcb&scope=a HTTP/1.1") {
			t.Errorf("%s: ok=%v out=%q", spelled, ok, out)
		}
		dup, ok := oauthWithRedirectURI(raw, "https://attacker.burpsy.invalid/cb", true)
		if !ok || !strings.Contains(dup, "redirect_uri="+spelled+"&redirect_uri=https%3A%2F%2Fattacker") {
			t.Errorf("%s duplicate: ok=%v out=%q", spelled, ok, dup)
		}
	}
	if _, ok := oauthWithRedirectURI("GET /oauth/authorize?client_id=c HTTP/1.1\r\n\r\n", "x", false); ok {
		t.Error("substituted a redirect_uri the request does not carry")
	}
}

// Only a redirect TO the manipulated URI counts: a login bounce or an error redirect that echoes
// the canary inside its own query is not one.
func TestOAuthLocationTargetsTheVariantOnly(t *testing.T) {
	resp := func(loc string) string { return "HTTP/1.1 302 Found\r\nLocation: " + loc + "\r\n\r\n" }
	v := "https://attacker.burpsy.invalid/cb"
	if !oauthLocationTargets(resp(v+"?code=abc"), v) {
		t.Error("the redirect to the canary itself was not recognised")
	}
	for _, loc := range []string{
		"/login?return_to=%2Foauth%2Fauthorize%3Fredirect_uri%3Dhttps%253A%252F%252Fattacker.burpsy.invalid%252Fcb",
		"https://app.example/cb?error=invalid_request&redirect_uri=https%3A%2F%2Fattacker.burpsy.invalid%2Fcb",
	} {
		if oauthLocationTargets(resp(loc), v) {
			t.Errorf("counted as a bypass: %s", loc)
		}
	}
	trav := "https://app.example/cb/../cb-burpsy-canary"
	if !oauthLocationTargets(resp("https://app.example/cb-burpsy-canary?code=1"), trav) ||
		oauthLocationTargets(resp("https://app.example/cb?code=1"), trav) {
		t.Error("traversal variant judged wrongly")
	}
}

// RFC 6749 4.1.2.1: rejecting a request without state is a 302 carrying error=, not a grant.
func TestOAuthLocationGrant(t *testing.T) {
	for loc, want := range map[string]bool{
		"https://app.example/cb?code=abc":                         true,
		"https://app.example/cb#access_token=t&token_type=bearer": true,
		"https://app.example/cb?error=invalid_request&state=":     false,
		"/login?next=%2Foauth%2Fauthorize":                        false,
		"https://app.example/cb?code=abc&error=access_denied":     false,
	} {
		if got := oauthLocationGrant(loc); got != want {
			t.Errorf("oauthLocationGrant(%q) = %v, want %v", loc, got, want)
		}
	}
}
