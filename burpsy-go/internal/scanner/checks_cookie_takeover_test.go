package scanner

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// The cookie prefix / SameSite rows and the subdomain-takeover row, run directly against the vulnapp
// fixtures. Each guard has a twin that fails when the guard is removed:
//
//   - prefixes are matched case-insensitively (/cookie/prefix/upper), and only as prefixes
//     (/cookie/safe/prefix/lookalike);
//   - an empty Domain leaves a __Host- cookie host-only (/cookie/safe/prefix/empty-domain);
//   - SameSite: only session cookies (/cookie/safe/samesite/nonsession), never a deletion
//     (/cookie/safe/samesite/logout), and None is acceptable only with Secure;
//   - takeover: a CNAME into the service's domain at a dot boundary (/takeover/safe/lookalike), the
//     fingerprint (/takeover/safe/s3-live, /takeover/safe/s3-nokey) with its status (/takeover/safe/s3-docs), a CNAME at all (/takeover/safe/no-cname), and an
//     authoritative NXDOMAIN rather than any lookup failure (/takeover/safe/azure-flaky).

func cookieRows(t *testing.T, paths ...string) *checkTarget {
	t.Helper()
	return vulnappTarget(t, &ScanConfig{CheckCookieAttributes: true}, paths...)
}

func TestCookiePrefixRowFiresOnEachBrokenRule(t *testing.T) {
	want := map[string]string{
		"/cookie/prefix/host-insecure":   "__Host-sid: no Secure attribute",
		"/cookie/prefix/host-path":       "__Host-sid: Path=/account, not /",
		"/cookie/prefix/host-nopath":     "__Host-sid: no Path attribute",
		"/cookie/prefix/host-domain":     "__Host-sid: a Domain attribute (takeover.test)",
		"/cookie/prefix/secure-insecure": "__Secure-sid: no Secure attribute",
		"/cookie/prefix/upper":           "__HOST-sid: no Secure attribute",
		"/cookie/prefix/logout":          "__Host-sid: no Secure attribute, no Path attribute",
	}
	var paths []string
	for p := range want {
		paths = append(paths, p)
	}
	ct := cookieRows(t, paths...)
	for path, ev := range want {
		fs := ct.run(t, path, checkCookiePrefixViolated)
		if len(fs) != 1 || fs[0].Name != IssueCookiePrefixViolated {
			t.Errorf("%s: got %v, want one %q", path, fs, IssueCookiePrefixViolated)
			continue
		}
		if !strings.Contains(fs[0].Evidence, ev) {
			t.Errorf("%s: evidence %q lacks %q", path, fs[0].Evidence, ev)
		}
	}
}

func TestCookiePrefixRowQuietWhenThePrefixIsHonoured(t *testing.T) {
	paths := []string{"/cookie/safe/prefix/host", "/cookie/safe/prefix/secure",
		"/cookie/safe/prefix/lookalike", "/cookie/safe/prefix/empty-domain"}
	ct := cookieRows(t, paths...)
	for _, p := range paths {
		if fs := ct.run(t, p, checkCookiePrefixViolated); len(fs) != 0 {
			t.Errorf("%s keeps its prefix's rules, yet: %s", p, fs[0].Evidence)
		}
	}
}

func TestCookiePrefixNamelessValueMimic(t *testing.T) {
	if why := CookiePrefixViolations("__Host-sid; Secure; Path=/"); len(why) != 1 {
		t.Errorf("a nameless cookie whose value is __Host-sid: got %v, want one reason", why)
	}
	if why := CookiePrefixViolations("=__Secure-x"); len(why) != 1 {
		t.Errorf("=__Secure-x: got %v, want one reason", why)
	}
	if why := CookiePrefixViolations("flag"); len(why) != 0 {
		t.Errorf("a nameless cookie without a prefix: got %v", why)
	}
}

func TestSessionCookieSameSiteRow(t *testing.T) {
	vuln := map[string]string{
		"/cookie/samesite/missing":       "sessionid: no SameSite attribute",
		"/cookie/samesite/none-insecure": "auth_token: SameSite=None without Secure",
		"/cookie/samesite/jwt":           "pref: SameSite has an unrecognised value (Relaxed)",
	}
	safe := []string{"/cookie/safe/samesite/lax", "/cookie/safe/samesite/none-secure",
		"/cookie/safe/samesite/nonsession", "/cookie/safe/samesite/logout"}
	paths := append([]string(nil), safe...)
	for p := range vuln {
		paths = append(paths, p)
	}
	ct := cookieRows(t, paths...)
	for path, ev := range vuln {
		fs := ct.run(t, path, checkSessionCookieSameSite)
		if len(fs) != 1 || fs[0].Name != IssueSessionCookieSameSite || !strings.Contains(fs[0].Evidence, ev) {
			t.Errorf("%s: got %v, want one %q naming %q", path, fs, IssueSessionCookieSameSite, ev)
		}
	}
	for _, p := range safe {
		if fs := ct.run(t, p, checkSessionCookieSameSite); len(fs) != 0 {
			t.Errorf("%s: got %s", p, fs[0].Evidence)
		}
	}
}

func TestLooksLikeSessionCookie(t *testing.T) {
	for _, n := range []string{"sessionid", "PHPSESSID", "connect.sid", "auth_token", "accessToken", "__Host-session", "JWT", "user-session"} {
		if !LooksLikeSessionCookie(n, "x") {
			t.Errorf("%s should look like a session cookie", n)
		}
	}
	for _, n := range []string{"theme", "consent", "csrftoken", "XSRF-TOKEN", "aside", "author", "lang"} {
		if LooksLikeSessionCookie(n, "x") {
			t.Errorf("%s should not look like a session cookie", n)
		}
	}
}

// capturedOn builds a check context for one stored response captured from host.
func capturedOn(t *testing.T, host, rawResp string, cfg *ScanConfig) *CheckContext {
	t.Helper()
	store := core.NewTrafficStore()
	reqID, err := store.Put([]byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, err := store.Put([]byte(rawResp), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: 443, TLS: true, Method: "GET", Path: "/"}
	store.AddExchange(ex)
	return NewCheckContext(NewActiveScanner(store, zap.NewNop()).WithConfig(cfg), ex, nil)
}

// The parent-domain row prefers the session cookie and names the cookie-tossing consequence; for a
// non-session cookie it keeps its old statement.
func TestParentDomainRowNamesCookieTossingForASessionCookie(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nSet-Cookie: theme=dark; Domain=example.com; Path=/\r\n" +
		"Set-Cookie: sid=8b1a9953c4611296; Domain=.example.com; Path=/; Secure; HttpOnly\r\n\r\nok"
	cc := capturedOn(t, "app.example.com", resp, &ScanConfig{CheckPassiveAnalysis: true})
	fs, _ := checkCookieScopedToParentDomain(context.Background(), cc)
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence, "sid") || !strings.Contains(fs[0].Description, "cookie tossing") {
		t.Fatalf("got %+v, want the sid cookie named with the tossing consequence", fs)
	}
	resp = "HTTP/1.1 200 OK\r\nSet-Cookie: theme=dark; Domain=example.com; Path=/\r\n\r\nok"
	cc = capturedOn(t, "app.example.com", resp, &ScanConfig{CheckPassiveAnalysis: true})
	fs, _ = checkCookieScopedToParentDomain(context.Background(), cc)
	if len(fs) != 1 || strings.Contains(fs[0].Description, "tossing") {
		t.Fatalf("got %+v, want the plain parent-domain statement", fs)
	}
}

// The descriptor's runner keeps Burp's row and the burpsy rows on their own switches.
func TestCookieRiderHonoursBothSwitches(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nSet-Cookie: sessionid=1; Domain=example.com; Path=/\r\n" +
		"Set-Cookie: __Host-x=1; Path=/\r\n\r\nok"
	run := cookieScopedOrAttributes(checkCookieScopedToParentDomain)
	names := func(cfg *ScanConfig) string {
		fs, _ := run(context.Background(), capturedOn(t, "app.example.com", resp, cfg))
		var n []string
		for _, f := range fs {
			n = append(n, f.Name)
		}
		return strings.Join(n, "|")
	}
	if got := names(&ScanConfig{CheckPassiveAnalysis: true}); got != "Cookie scoped to parent domain" {
		t.Errorf("passive analysis only: %q", got)
	}
	if got := names(&ScanConfig{CheckCookieAttributes: true}); got != IssueCookiePrefixViolated+"|"+IssueSessionCookieSameSite {
		t.Errorf("cookie attributes only: %q", got)
	}
}

// --- subdomain takeover ---

func takeoverTarget(t *testing.T, r DNSResolver, paths ...string) *checkTarget {
	t.Helper()
	return vulnappTarget(t, &ScanConfig{CheckSubdomainTakeover: true, DNSResolver: r}, paths...)
}

func TestSubdomainTakeoverFires(t *testing.T) {
	ct := takeoverTarget(t, vulnapp.NewTakeoverResolver(), "/takeover/s3", "/takeover/azure")
	for path, want := range map[string]string{
		"/takeover/s3":    "assets.takeover.test CNAME burpsy-gone-assets.s3.amazonaws.com (AWS S3); the response (HTTP 404)",
		"/takeover/azure": "app.takeover.test CNAME burpsy-gone-app.azurewebsites.net (Microsoft Azure); the CNAME target burpsy-gone-app.azurewebsites.net does not resolve",
	} {
		fs := ct.run(t, path, checkSubdomainTakeover)
		if len(fs) != 1 || fs[0].Name != IssueSubdomainTakeover {
			t.Fatalf("%s: got %v, want one %q", path, fs, IssueSubdomainTakeover)
		}
		if !strings.Contains(fs[0].Evidence, want) {
			t.Errorf("%s: evidence %q lacks %q", path, fs[0].Evidence, want)
		}
		if fs[0].MergeKey == "" {
			t.Errorf("%s: no MergeKey, so every URL of the host would be its own finding", path)
		}
	}
}

func TestSubdomainTakeoverSafeTwins(t *testing.T) {
	paths := []string{"/takeover/safe/s3-live", "/takeover/safe/s3-docs", "/takeover/safe/s3-nokey", "/takeover/safe/no-cname", "/takeover/safe/lookalike",
		"/takeover/safe/azure-live", "/takeover/safe/azure-flaky"}
	ct := takeoverTarget(t, vulnapp.NewTakeoverResolver(), paths...)
	for _, p := range paths {
		if fs := ct.run(t, p, checkSubdomainTakeover); len(fs) != 0 {
			t.Errorf("%s: got %s", p, fs[0].Evidence)
		}
	}
}

// countingResolver records every lookup, so a test can show the resolver was asked (or not).
type countingResolver struct {
	inner DNSResolver
	cname []string
	hosts []string
}

func (c *countingResolver) LookupCNAME(ctx context.Context, h string) (string, error) {
	c.cname = append(c.cname, h)
	return c.inner.LookupCNAME(ctx, h)
}

func (c *countingResolver) LookupHost(ctx context.Context, h string) ([]string, error) {
	c.hosts = append(c.hosts, h)
	return c.inner.LookupHost(ctx, h)
}

// The NXDOMAIN proof is two lookups, and the hostname comes from the Host header only because the
// connection target is an IP literal; an IP-literal Host is never looked up.
func TestSubdomainTakeoverLookups(t *testing.T) {
	r := &countingResolver{inner: vulnapp.NewTakeoverResolver()}
	ct := takeoverTarget(t, r, "/takeover/azure")
	if fs := ct.run(t, "/takeover/azure", checkSubdomainTakeover); len(fs) != 1 {
		t.Fatalf("got %v", fs)
	}
	if len(r.cname) != 1 || r.cname[0] != "app.takeover.test" {
		t.Errorf("CNAME lookups %v, want exactly app.takeover.test", r.cname)
	}
	if len(r.hosts) != 2 {
		t.Errorf("address lookups %v, want two of the CNAME target", r.hosts)
	}

	r2 := &countingResolver{inner: vulnapp.NewTakeoverResolver()}
	ct2 := vulnappTarget(t, &ScanConfig{CheckSubdomainTakeover: true, DNSResolver: r2}, "/cookie/samesite/missing")
	_ = ct2.run(t, "/cookie/samesite/missing", checkSubdomainTakeover)
	if len(r2.cname) != 0 {
		t.Errorf("an exchange addressed to an IP literal with an IP-literal Host was looked up: %v", r2.cname)
	}
}

func TestTakeoverServiceDomainBoundary(t *testing.T) {
	for target, want := range map[string]bool{
		"bucket.s3.amazonaws.com":                   true,
		"bucket.s3-website-us-east-1.amazonaws.com": true,
		"bucket.s3.eu-west-1.amazonaws.com":         true,
		"s3-1-w.amazonaws.com.":                     true,
		"bucket.s3.amazonaws.com.cdn.test":          false,
		"ec2-1-2-3-4.compute-1.amazonaws.com":       false,
		"x.azurewebsites.net":                       true,
		"notazurewebsites.net":                      false,
		"azurewebsites.net.attacker.test":           false,
		"blog.ghost.io":                             true,
		"ghost.io.example.test":                     false,
		"user.github.io":                            false, // GitHub Pages is an edge case upstream
		"app.herokuapp.com":                         false, // so is Heroku
	} {
		if _, got := TakeoverServiceFor(target); got != want {
			t.Errorf("TakeoverServiceFor(%q) = %v, want %v", target, got, want)
		}
	}
}

// A real *net.Resolver satisfies the interface the check takes.
var _ DNSResolver = (*net.Resolver)(nil)
