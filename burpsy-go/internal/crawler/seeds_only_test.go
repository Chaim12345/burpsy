package crawler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The seeds-only mode is what the API-only scan runs on: the frontier is *given* rather than
// discovered, so the whole question these tests answer is what the run does not do. Every one of them
// is therefore an assertion about the target's own record of what it was asked for, or about a count
// in the report — never about the requests the run was told to send, which would pass just as well if
// it also sent fifty more.

// TestASeedsOnlyRunSendsExactlyTheRequestsItWasGiven is the mode's whole contract: one request per
// SeedRequest, with its method and its body, and nothing else.
func TestASeedsOnlyRunSendsExactlyTheRequestsItWasGiven(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/items":   `<html><body>items</body></html>`,
		"/items/1": `<html><body>item</body></html>`,
	})
	h := newHarness()
	cfg := h.config()
	cfg.SeedsOnly = true
	cfg.SeedRequests = []SeedRequest{
		{Method: "GET", URL: tg.URL + "/items"},
		{Method: "POST", URL: tg.URL + "/items", Body: []byte(`{"name":"Rex"}`), ContentType: "application/json"},
		{Method: "DELETE", URL: tg.URL + "/items/1"},
	}
	rep := run(t, cfg)

	got := tg.recorded()
	if len(got) != 3 {
		t.Fatalf("a seeds-only run of three requests must send three; the target saw %d: %+v", len(got), got)
	}
	// Order matters as much as the set: the definition's operations are sent in the order they were
	// built, so a run whose frontier reordered them would be a different sweep of the same document.
	want := []hit{
		{method: "GET", uri: "/items"},
		{method: "POST", uri: "/items", body: `{"name":"Rex"}`},
		{method: "DELETE", uri: "/items/1"},
	}
	for i, w := range want {
		if got[i].method != w.method || got[i].uri != w.uri {
			t.Errorf("request %d: sent %s %s, want %s %s", i, got[i].method, got[i].uri, w.method, w.uri)
		}
		if got[i].body != w.body {
			t.Errorf("request %d (%s %s): body %q, want %q", i, w.method, w.uri, got[i].body, w.body)
		}
	}
	if rep.Fetched != 3 || rep.Refused != 0 || rep.Failed != 0 {
		t.Errorf("expected 3 fetched and nothing else, got fetched=%d refused=%d failed=%d", rep.Fetched, rep.Refused, rep.Failed)
	}
}

// TestASeedsOnlyRunFollowsNothingItWasNotGiven is the difference between this mode and a crawl. The
// target's response carries a link and a form; a crawl would queue both, and this must not — including
// no robots.txt probe, which a crawl makes per seed authority.
func TestASeedsOnlyRunFollowsNothingItWasNotGiven(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/entry": `<html><body>
			<a href="/should-not-be-fetched">link</a>
			<form action="/also-not" method="post"><input name="q" value="x"></form>
			</body></html>`,
		"/should-not-be-fetched": `<html><body>oops</body></html>`,
	})
	h := newHarness()
	cfg := h.config()
	cfg.SeedsOnly = true
	cfg.SeedRequests = []SeedRequest{{Method: "GET", URL: tg.URL + "/entry"}}
	rep := run(t, cfg)

	if tg.sawPath("/should-not-be-fetched") {
		t.Error("the run followed a link out of a response body; a seeds-only run's attack surface is the list it was given")
	}
	if tg.sawPath("/also-not") {
		t.Error("the run submitted a form it found")
	}
	if tg.sawPath("/robots.txt") {
		t.Error("the run probed robots.txt; the probe is a request nobody described, which is the thing this mode exists to exclude")
	}
	if len(tg.recorded()) != 1 {
		t.Errorf("expected exactly one request, the one given; the target saw %+v", tg.recorded())
	}
	if rep.LinksFound != 0 || rep.FormsFound != 0 {
		t.Errorf("a seeds-only run extracts nothing: links=%d forms=%d", rep.LinksFound, rep.FormsFound)
	}
	if rep.Locations != 0 {
		t.Errorf("a seeds-only run records no location fingerprint, so its location count must be 0, got %d", rep.Locations)
	}
	// Both directions of the mode's record, because a report that said "seeds only" for every run and a
	// report that never said it are equally useless.
	if !rep.SeedsOnly {
		t.Error("the report does not say the run was seeds-only, so a reader cannot tell it from a crawl that found no links")
	}
}

// TestACrawlReportsItselfAsNotSeedsOnly is the other half of the previous assertion, and it is not
// decoration: `SeedsOnly` makes the report's link and location counts mean different things, so a
// plain crawl that claimed it would be read as a scan that never looked.
func TestACrawlReportsItselfAsNotSeedsOnly(t *testing.T) {
	tg := newTarget(t, map[string]string{"/": `<html><body>plain</body></html>`})
	rep := run(t, newHarness().config(tg.URL+"/"))
	if rep.SeedsOnly {
		t.Error("a plain crawl reported itself as seeds-only")
	}
	if !tg.sawPath("/robots.txt") {
		t.Error("a plain crawl must still probe robots.txt; the mode is opt-in, not a global change")
	}
}

// TestASeedRequestIsRefusedWithoutSeedsOnly closes the one way this mode could be set wrong: a crawl
// that follows links has nowhere to put a method or a body, so accepting the requests and ignoring
// them would send a GET at a path the caller meant to POST to.
func TestASeedRequestIsRefusedWithoutSeedsOnly(t *testing.T) {
	h := newHarness()
	cfg := h.config("http://example.com/")
	cfg.SeedRequests = []SeedRequest{{Method: "POST", URL: "http://example.com/thing"}}
	if _, err := New(cfg); err == nil {
		t.Fatal("New accepted SeedRequests without SeedsOnly, so the method and body would be silently dropped")
	} else if !strings.Contains(err.Error(), "SeedsOnly") {
		t.Errorf("the refusal must name the flag that is missing, got: %v", err)
	}
}

// TestASeedRequestIsValidatedLikeASeedURL keeps the *input* boundary honest: a document is a file, and
// a file is not more trustworthy than a URL an operator typed. A method and a body change nothing
// about which schemes may be dialled or what may be smuggled into a header.
func TestASeedRequestIsValidatedLikeASeedURL(t *testing.T) {
	h := newHarness()
	cases := []struct {
		name string
		req  SeedRequest
		want string
	}{
		{"a scheme the transport cannot dial", SeedRequest{URL: "file:///etc/passwd"}, "http or https"},
		{"no host", SeedRequest{URL: "http:///thing"}, "no host"},
		{"credentials in the URL", SeedRequest{URL: "http://user:pass@example.com/"}, "credentials"},
		{"a header that would split the request", SeedRequest{URL: "http://example.com/", Headers: map[string]string{"X-Thing": "a\r\nHost: evil"}}, "split the request"},
		{"a header the crawler computes itself", SeedRequest{URL: "http://example.com/", Headers: map[string]string{"Content-Length": "99"}}, "framing"},
		{"a body with no media type", SeedRequest{URL: "http://example.com/", Body: []byte("x")}, "no Content-Type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := h.config()
			cfg.SeedsOnly = true
			cfg.SeedRequests = []SeedRequest{tc.req}
			_, err := New(cfg)
			if err == nil {
				t.Fatalf("New accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal must say what is wrong; want %q in: %v", tc.want, err)
			}
		})
	}
}

// TestASeedRequestsOwnHeadersGoOnItsOwnRequestOnly is why the headers live on the frontier item rather
// than on Config: an API definition's declared header parameter belongs to the operation that declared
// it, and putting it in Config.Headers would send a token every other operation's request as well —
// traffic the document does not describe, on endpoints that never asked for it.
//
// It reads the header off the target's own record rather than out of the store, because the question
// is what went on the wire and not what was kept afterwards.
func TestASeedRequestsOwnHeadersGoOnItsOwnRequestOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, headerSeen{uri: r.URL.Path, apiKey: r.Header.Get("X-Api-Key")})
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// A fresh slice per test, so a parallel run elsewhere in this package cannot contribute to it.
	received = nil

	h := newHarness()
	cfg := h.config()
	cfg.SeedsOnly = true
	cfg.SeedRequests = []SeedRequest{
		{Method: "GET", URL: srv.URL + "/one", Headers: map[string]string{"X-Api-Key": "from-the-document"}},
		{Method: "GET", URL: srv.URL + "/two"},
	}
	rep := run(t, cfg)
	if rep.Fetched != 2 {
		t.Fatalf("expected both requests to be sent, got %d", rep.Fetched)
	}
	if len(received) != 2 {
		t.Fatalf("expected two requests at the target, got %d: %+v", len(received), received)
	}
	byPath := map[string]string{}
	for _, h := range received {
		byPath[h.uri] = h.apiKey
	}
	if byPath["/one"] != "from-the-document" {
		t.Errorf("the request that declared the header must carry it, /one sent %q", byPath["/one"])
	}
	if byPath["/two"] != "" {
		t.Errorf("the request that declared nothing must carry nothing, /two sent %q", byPath["/two"])
	}
}

// headerSeen and its slice are the two-test-wide recorder the header test needs. Package-level rather
// than shared with `target`, which records methods and bodies and deliberately not headers.
var received []headerSeen

type headerSeen struct {
	uri    string
	apiKey string
}
