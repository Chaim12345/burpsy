package session

import (
	"testing"

	"go.uber.org/zap"
)

// The two facts this file pins, both of which were false before internal/session/absorb.go existed:
// a raw response's Set-Cookie headers can be absorbed at all (there was no method taking bytes), and
// *every* one of them is absorbed (the map-shaped HandleResponse can carry one).

func TestAbsorbResponseCookiesTakesEverySetCookieLine(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	raw := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Set-Cookie: sessid=abc123; Path=/; HttpOnly\r\n" +
		"Set-Cookie: csrf=deadbeef; Path=/\r\n" +
		"\r\n<html></html>")

	if n := c.AbsorbResponseCookies("example.com", 443, true, raw); n != 2 {
		t.Fatalf("absorbed %d Set-Cookie lines, want 2", n)
	}
	got := c.CookieHeader("example.com", 443, true, "/")
	// Order within the header is the jar's, not the response's, so both memberships are asserted
	// rather than a single formatted string.
	for _, want := range []string{"sessid=abc123", "csrf=deadbeef"} {
		if !containsSub(got, want) {
			t.Errorf("cookie header %q is missing %q", got, want)
		}
	}
}

func TestAbsorbResponseCookiesIsKeyedByAuthority(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	raw := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: sessid=abc\r\n\r\n")
	c.AbsorbResponseCookies("example.com", 443, true, raw)

	// A different port, and the same host over plaintext, are different jars. A cookie leaking
	// across them would send an engagement's session to a service it was never issued for.
	if h := c.CookieHeader("example.com", 8443, true, "/"); h != "" {
		t.Errorf("port 8443 jar returned %q, want empty", h)
	}
	if h := c.CookieHeader("example.com", 443, false, "/"); h != "" {
		t.Errorf("plaintext jar returned %q, want empty", h)
	}
	if h := c.CookieHeader("other.example", 443, true, "/"); h != "" {
		t.Errorf("other host jar returned %q, want empty", h)
	}
}

func TestAbsorbResponseCookiesNoHeadersIsObservedNotAbsorbed(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	c.AttachAbsorptionSource(SourceProxy)
	c.AbsorbResponseCookies("example.com", 443, true, []byte("HTTP/1.1 204 No Content\r\n\r\n"))

	obs := c.Observation()
	// The distinction the Session page's empty state could not previously make: traffic reached the
	// jar and carried nothing, which is a measurement, not "we never looked".
	if obs.ResponsesObserved != 1 {
		t.Errorf("responses observed = %d, want 1", obs.ResponsesObserved)
	}
	if obs.SetCookiesAbsorbed != 0 {
		t.Errorf("set-cookies absorbed = %d, want 0", obs.SetCookiesAbsorbed)
	}
	if len(obs.Sources) != 1 || obs.Sources[0] != SourceProxy {
		t.Errorf("sources = %v, want [proxy]", obs.Sources)
	}
}

func TestObservationOnAFreshCoordinatorNamesNoSource(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	obs := c.Observation()
	if len(obs.Sources) != 0 {
		t.Errorf("sources = %v, want none: nothing has registered", obs.Sources)
	}
	if obs.ResponsesObserved != 0 || obs.SetCookiesAbsorbed != 0 {
		t.Errorf("observation = %+v, want zeroes", obs)
	}
}

func TestAbsorbResponseCookiesUnframedResponseAbsorbsNothing(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	// Headers cut off mid-block. A partial Set-Cookie is not a cookie, and guessing at one would put
	// a truncated session token in the jar and send it to the target.
	c.AbsorbResponseCookies("example.com", 443, true, []byte("HTTP/1.1 200 OK\r\nSet-Cookie: sessid=abc"))
	if h := c.CookieHeader("example.com", 443, true, "/"); h != "" {
		t.Errorf("cookie header %q, want empty for an unterminated head", h)
	}
	if obs := c.Observation(); obs.ResponsesObserved != 1 {
		t.Errorf("responses observed = %d, want 1: the offer happened", obs.ResponsesObserved)
	}
}

func TestAbsorbResponseCookiesNilCoordinator(t *testing.T) {
	var c *Coordinator
	if n := c.AbsorbResponseCookies("example.com", 443, true, []byte("HTTP/1.1 200 OK\r\n\r\n")); n != 0 {
		t.Errorf("nil coordinator absorbed %d, want 0", n)
	}
	c.AttachAbsorptionSource(SourceProxy)
	if obs := c.Observation(); len(obs.Sources) != 0 {
		t.Errorf("nil coordinator reported sources %v", obs.Sources)
	}
}

func containsSub(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && indexOf(hay, needle) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
