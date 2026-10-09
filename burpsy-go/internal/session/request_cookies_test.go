package session

import (
	"strings"
	"testing"
)

// A request cookie updates the jar cookie it would be sent as, keeping that cookie's attributes,
// instead of adding a second, attribute-less copy (sm1k).
func TestARequestCookieUpdatesTheMatchingJarCookieAndKeepsItsAttributes(t *testing.T) {
	m := NewCookieJarManager()
	m.AbsorbSetCookie("app.test", 443, true, "sid=one; Domain=app.test; Path=/app; Secure; HttpOnly")
	m.AbsorbRequestCookie("app.test", 443, true, "/app/x", "sid", "two")

	jars := m.Jars()
	if len(jars) != 1 || len(jars[0].Cookies) != 1 {
		t.Fatalf("jar = %+v, want exactly one sid cookie (updated, not duplicated)", jars)
	}
	c := jars[0].Cookies[0]
	if c.Value != "two" || c.Path != "/app" || c.Domain != "app.test" || !c.Secure || !c.HTTPOnly {
		t.Errorf("cookie = %+v, want value two with Path=/app, Domain=app.test, Secure and HttpOnly kept", c)
	}

	// Not sent to /other (path mismatch), so a browser cookie there is a different cookie: added host-only at /.
	m.AbsorbRequestCookie("app.test", 443, true, "/other", "sid", "three")
	if h := m.CookieHeader("app.test", 443, true, "/other"); h != "sid=three" {
		t.Errorf("cookie header at /other = %q, want sid=three", h)
	}
	if h := m.CookieHeader("app.test", 443, true, "/app/x"); !strings.Contains(h, "sid=two") {
		t.Errorf("cookie header at /app/x = %q, still wants the /app cookie's value two", h)
	}
}

func TestRequestCookiePairsReadsEveryCookieHeaderAndThePath(t *testing.T) {
	raw := []byte("GET http://app.test/a/b?q=1 HTTP/1.1\r\nHost: app.test\r\nCookie: a=1; b = 2 ;bad; =x\r\nCookie: c=3\r\n\r\n")
	path, pairs := requestCookiePairs(raw)
	var got []string
	for _, p := range pairs {
		got = append(got, p.name+"="+p.value)
	}
	if path != "/a/b" || strings.Join(got, ",") != "a=1,b=2,c=3" {
		t.Errorf("path %q pairs %v, want /a/b and a=1,b=2,c=3", path, got)
	}
}
