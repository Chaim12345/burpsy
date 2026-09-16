package session

import (
	"testing"
)

// The cookie jar's RFC 6265 semantics, tested at the level the operator's table and the send
// path both observe. Each test states a fact a real Set-Cookie header produces and checks that
// the jar's behaviour matches the RFC — because the old jar dropped every attribute, so every
// test here would have been vacuous.

// absorb keeps every §5.3 attribute the jar models — read back through Cookies(), the same
// read path the Session page's table uses, because the old jar dropped them all at the semicolon.
func TestAbsorbKeepsTheAttributesTheOldJarDropped(t *testing.T) {
	c := NewCoordinator(nil)
	c.AbsorbCookie("app.test", 443, true, "SID=abc; Path=/admin; Domain=.app.test; Secure; HttpOnly")
	jars := c.Cookies()
	if len(jars) != 1 {
		t.Fatalf("Cookies() returned %d jars, want 1 for a single authority", len(jars))
	}
	got, ok := jars[0].Cookies["SID"]
	if !ok {
		t.Fatal("the absorbed cookie is not in the jar the operator reads")
	}
	if got.Path != "/admin" || got.Domain != "app.test" || !got.Secure || !got.HTTPOnly {
		t.Errorf("stored attributes = Path:%q Domain:%q Secure:%v HTTPOnly:%v, want Path:/admin Domain:app.test Secure:true HTTPOnly:true — the old jar dropped every attribute at the first semicolon", got.Path, got.Domain, got.Secure, got.HTTPOnly)
	}
	if got.Value != "abc" {
		t.Errorf("stored value = %q, want abc", got.Value)
	}
}

// §5.4 path-match: a cookie scoped to /admin is not sent to /login.
func TestAPathScopedCookieIsNotSentToADifferentPath(t *testing.T) {
	c := NewCoordinator(nil)
	c.AbsorbCookie("app.test", 443, true, "SID=admin-cookie; Path=/admin")
	if h := c.CookieHeader("app.test", 443, true, "/admin/users"); h != "SID=admin-cookie" {
		t.Errorf("cookie header for /admin/users = %q, want SID=admin-cookie", h)
	}
	if h := c.CookieHeader("app.test", 443, true, "/login"); h != "" {
		t.Errorf("cookie header for /login = %q, want empty: a Path=/admin cookie must not be sent to /login", h)
	}
}

// Two cookies differing only by path coexist — the case the old name-keyed jar could not hold.
func TestTwoCookiesDifferingOnlyByPathCoexist(t *testing.T) {
	c := NewCoordinator(nil)
	c.AbsorbCookie("app.test", 443, true, "SID=admin; Path=/admin")
	c.AbsorbCookie("app.test", 443, true, "SID=root; Path=/")
	if h := c.CookieHeader("app.test", 443, true, "/admin"); h == "" {
		t.Fatal("the /admin-scoped cookie did not survive a root-scoped Set-Cookie for the same name")
	}
	if h := c.CookieHeader("app.test", 443, true, "/"); h != "SID=root" {
		t.Errorf("cookie header for / = %q, want SID=root: the root-scoped cookie must not be overwritten by the admin one", h)
	}
}

// §5.4 domain-match: a domain cookie covers subdomains; a host-only cookie does not.
func TestADomainCookieCoversSubdomains(t *testing.T) {
	c := NewCoordinator(nil)
	c.AbsorbCookie("app.test", 443, true, "SID=dc; Domain=.app.test")
	if h := c.CookieHeader("sub.app.test", 443, true, "/"); h != "SID=dc" {
		t.Errorf("cookie header for sub.app.test = %q, want SID=dc: a Domain=.app.test cookie covers subdomains", h)
	}
	if h := c.CookieHeader("other.test", 443, true, "/"); h != "" {
		t.Errorf("cookie header for other.test = %q, want empty", h)
	}
}

// §5.4 expiry: a Max-Age in the past means the cookie is gone, and the header stops sending it.
func TestAnExpiredCookieIsNotSent(t *testing.T) {
	c := NewCoordinator(nil)
	c.AbsorbCookie("app.test", 443, true, "SID=dead; Max-Age=0")
	if h := c.CookieHeader("app.test", 443, true, "/"); h != "" {
		t.Errorf("cookie header after Max-Age=0 = %q, want empty: a Max-Age=0 cookie is expired and must not be sent", h)
	}
}

// §5.4 Secure: a Secure cookie is not sent over a plaintext connection.
func TestASecureCookieIsNotSentOverPlaintext(t *testing.T) {
	c := NewCoordinator(nil)
	c.AbsorbCookie("app.test", 443, true, "SID=s; Secure")
	if h := c.CookieHeader("app.test", 443, false, "/"); h != "" {
		t.Errorf("cookie header over plaintext = %q, want empty: a Secure cookie must not be sent over a plaintext connection", h)
	}
	if h := c.CookieHeader("app.test", 443, true, "/"); h != "SID=s" {
		t.Errorf("cookie header over TLS = %q, want SID=s", h)
	}
}

// §5.4's Secure rule is independent of the authority boundary: a Domain cookie crosses
// authorities — that is what the cross-jar scan is for — so nothing about the jar it lives in
// shields the plaintext judgement. Only the Secure branch itself can answer this one.
func TestADomainCookieMarkedSecureIsNotSentOverPlaintext(t *testing.T) {
	c := NewCoordinator(nil)
	c.AbsorbCookie("app.test", 443, true, "SID=dc; Domain=.app.test; Secure")
	if h := c.CookieHeader("sub.app.test", 443, false, "/"); h != "" {
		t.Errorf("cookie header for sub.app.test over plaintext = %q, want empty: a Secure domain cookie must not cross to a plaintext request", h)
	}
	if h := c.CookieHeader("sub.app.test", 443, true, "/"); h != "SID=dc" {
		t.Errorf("cookie header for sub.app.test over TLS = %q, want SID=dc", h)
	}
}

// remove deletes every cookie the name covers, not one path at a time.
func TestRemoveDeletesEveryPathScopedInstance(t *testing.T) {
	c := NewCoordinator(nil)
	c.AbsorbCookie("app.test", 443, true, "SID=a; Path=/admin")
	c.AbsorbCookie("app.test", 443, true, "SID=b; Path=/login")
	c.RemoveCookie("app.test", 443, true, "SID")
	for _, path := range []string{"/admin", "/login", "/"} {
		if h := c.CookieHeader("app.test", 443, true, path); h != "" {
			t.Errorf("cookie header after remove for %s = %q, want empty", path, h)
		}
	}
}

// The pre-migration shape: a cookie set through the old API (name+value only) lands with
// a default path and no attributes, and is sent to every path — the old behaviour preserved
// exactly for an operator edit that predates the attributes.
func TestAnOperatorSetCookieWithoutAttributesIsSentEverywhere(t *testing.T) {
	c := NewCoordinator(nil)
	c.SetCookie("app.test", 443, true, "SID", "manual")
	if h := c.CookieHeader("app.test", 443, true, "/admin"); h != "SID=manual" {
		t.Errorf("cookie header for /admin = %q, want SID=manual", h)
	}
	if h := c.CookieHeader("app.test", 443, true, "/login"); h != "SID=manual" {
		t.Errorf("cookie header for /login = %q, want SID=manual", h)
	}
}
