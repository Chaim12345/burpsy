package core

import (
	"strings"
	"testing"
)

// Ports burpsy-core::scope's two-layer authorisation tests (scope.rs:580-760). The Go scope model
// keeps two documented divergences from the Rust original: rules match host/port/path-prefix with
// excludes-first (not last-match-wins), and an empty scope defaults to allow (not deny). The tests
// below pin the shared behaviour — the spliced-path refusal — and say nothing the divergences would
// contradict.

// shop is the Rust test's canonical scope: host authorised, one path excluded.
func shop() *Scope {
	sc := NewScope()
	sc.AddInclude("shop.test")
	sc.Add(NewScopeRuleWithPath(ScopeExclude, "shop.test", "/admin"))
	return sc
}

func TestRequestPathReadsBothOriginAndAbsoluteForm(t *testing.T) {
	if got, ok := requestPath([]byte("GET /a?b=1 HTTP/1.1\r\n")); !ok || got != "/a" {
		t.Fatalf("origin form: got %q, %v; want /a", got, ok)
	}
	if got, ok := requestPath([]byte("GET http://h.test/a?b=1 HTTP/1.1\r\n")); !ok || got != "/a" {
		t.Fatalf("absolute form: got %q, %v; want /a", got, ok)
	}
	// A proxied absolute-form request with no path at all addresses the root.
	if got, ok := requestPath([]byte("GET http://h.test HTTP/1.1\r\n")); !ok || got != "/" {
		t.Fatalf("absolute form without a path: got %q, %v; want /", got, ok)
	}
	if got, ok := requestPath([]byte("POST /x HTTP/1.1")); !ok || got != "/x" {
		t.Fatalf("no trailing newline: got %q, %v; want /x", got, ok)
	}
	if _, ok := requestPath([]byte("")); ok {
		t.Fatal("empty bytes must not read as a path")
	}
}

func TestAnExcludedPathIsRefusedEvenThoughTheHostIsAllowed(t *testing.T) {
	sc := shop()
	err := sc.AuthoriseRaw("shop.test", 443, true, []byte("GET /admin/delete-all HTTP/1.1\r\nHost: shop.test\r\n\r\n"))
	if err == nil {
		t.Fatal("an excluded path must not be authorised")
	}
	if !strings.Contains(err.Error(), "/admin/delete-all") {
		t.Fatalf("unhelpful refusal: %v", err)
	}
	if err := sc.AuthoriseRaw("shop.test", 443, true, []byte("GET /search HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("the ordinary path on the same host must still work: %v", err)
	}
}

func TestAHostScopedToAPathPrefixIsNotRefusedWholesale(t *testing.T) {
	sc := NewScope()
	sc.Add(NewScopeRuleWithPath(ScopeInclude, "api.test", "/v1/"))
	if err := sc.AuthoriseRaw("api.test", 443, true, []byte("GET /v1/orders HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("/v1/ is inside the included prefix: %v", err)
	}
	if err := sc.AuthoriseRaw("api.test", 443, true, []byte("GET /v2/orders HTTP/1.1\r\n\r\n")); err == nil {
		t.Fatal("/v2/ is outside the included prefix and must be refused")
	}
}

func TestTheQueryStringCannotSmuggleAPathPastAPrefixRule(t *testing.T) {
	// /search?next=/admin is a request for /search. The rule is about the path, and a query that
	// merely mentions the excluded prefix must not trip it.
	sc := shop()
	if err := sc.AuthoriseRaw("shop.test", 443, true, []byte("GET /search?next=/admin HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("the query string must not count as the path: %v", err)
	}
}

func TestARequestWithNoReadableStartLineIsRefusedNotWavedThrough(t *testing.T) {
	// Absence of a path must never read as "nothing to check".
	sc := NewScope()
	sc.AddInclude("shop.test")
	if err := sc.AuthoriseRaw("shop.test", 443, true, nil); err == nil {
		t.Fatal("empty bytes must be refused")
	}
	if err := sc.AuthoriseRaw("shop.test", 443, true, []byte("GARBAGE")); err == nil {
		t.Fatal("a line with no target must be refused")
	}
}

func TestAHostOnlyRuleStillMatchesAnyPath(t *testing.T) {
	// Backward compatibility: rules built without a path prefix keep their old host-only reach.
	sc := NewScope()
	sc.AddInclude("shop.test")
	if err := sc.AuthoriseRaw("shop.test", 443, true, []byte("GET /anything HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("a host-only include must authorise any path: %v", err)
	}
	sc2 := NewScope()
	sc2.AddInclude("shop.test")
	sc2.AddExclude("shop.test")
	if err := sc2.AuthoriseRaw("shop.test", 443, true, []byte("GET / HTTP/1.1\r\n\r\n")); err == nil {
		t.Fatal("a whole-host exclude still wins over the include")
	}
}

func TestExplainNamesTheRuleThatRefused(t *testing.T) {
	sc := shop()
	why := sc.Explain("shop.test", 443, "/admin/x", true)
	if !strings.Contains(why, "/admin") && !strings.Contains(why, "excluded") {
		t.Fatalf("the explanation must say what excluded it: %q", why)
	}
	err := sc.AuthoriseRaw("shop.test", 443, true, []byte("GET /admin/x HTTP/1.1\r\n\r\n"))
	if err == nil || !strings.Contains(err.Error(), why) {
		t.Fatalf("the refusal must carry the explanation: %v", err)
	}
}
