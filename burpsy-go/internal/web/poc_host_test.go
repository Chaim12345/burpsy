package web

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The PoC host (burpsy-react-ui-0z10) exists for one property: "Test in
// browser" serves the generated PoC from an origin that is not the console's.
// A generated PoC is attacker-shaped HTML — it embeds bytes captured from a
// target — so it must not inherit a single privilege of the console: not its
// origin, not a route in its mux, not a path under its /api tree.

// Test in browser mints a one-shot URL off the console origin, serves the
// exact generated HTML once, and answers every later fetch with 410 — a spent
// token must not keep replaying an attack page after the operator is done
// with it.
func TestTestInBrowserServesThePoCOnceFromItsOwnOrigin(t *testing.T) {
	s := newTestServer()
	id := seedCSRFExchange(t, s,
		"POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\nuser=admin",
		&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "POST", Path: "/login"},
	)

	rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf?test_url=true")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET csrf?test_url=true answered %d (%s)", rec.Code, rec.Body.String())
	}
	var view csrfTestView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode csrf view: %v", err)
	}
	if view.TestURL == "" {
		t.Fatal("test_url=true did not mint a test URL")
	}

	// The URL is the PoC host's: loopback, its own port, a /poc/ path — and
	// never anything under the console's /api tree.
	urlPattern := regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]+/poc/[0-9a-f]{64}$`)
	if !urlPattern.MatchString(view.TestURL) {
		t.Fatalf("test_url = %q; want a loopback /poc/<token> URL on the PoC host's own port", view.TestURL)
	}
	if strings.Contains(view.TestURL, "/api/") {
		t.Fatalf("test_url = %q; a PoC must never be served under the console's /api origin", view.TestURL)
	}

	// The console itself does not know the path: the same URL through the
	// console mux is a 404, which is the whole point of a separate listener.
	pocPath := view.TestURL[strings.Index(view.TestURL, "/poc/"):]
	if rec := get(t, s, pocPath); rec.Code != http.StatusNotFound {
		t.Errorf("the console mux answered the PoC path with %d; it must not serve PoC HTML from the console origin", rec.Code)
	}

	// The first fetch through the PoC host serves the exact generated HTML.
	first, err := http.Get(view.TestURL)
	if err != nil {
		t.Fatalf("fetching the minted PoC URL: %v", err)
	}
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("the first fetch of the PoC URL answered %d, want 200", first.StatusCode)
	}
	if ct := first.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("the PoC host served Content-Type %q; the page must be HTML", ct)
	}
	served, err := io.ReadAll(first.Body)
	if err != nil {
		t.Fatalf("reading the served PoC: %v", err)
	}
	if string(served) != view.HTML {
		t.Errorf("the served page is not the generated PoC:\n served %q\nwant    %q", served, view.HTML)
	}

	// Every later fetch is 410 Gone — the token was spent by the first one.
	second, err := http.Get(view.TestURL)
	if err != nil {
		t.Fatalf("refetching the minted PoC URL: %v", err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusGone {
		t.Errorf("the second fetch answered %d; a spent token must read as gone, not as a page", second.StatusCode)
	}

	// And a token that was never minted is gone the same way, without
	// leaking whether it ever existed.
	unknown := view.TestURL
	if strings.HasSuffix(unknown, "a") {
		unknown = unknown[:len(unknown)-1] + "b"
	} else {
		unknown = unknown[:len(unknown)-1] + "a"
	}
	third, err := http.Get(unknown)
	if err != nil {
		t.Fatalf("fetching a never-minted token: %v", err)
	}
	third.Body.Close()
	if third.StatusCode != http.StatusGone {
		t.Errorf("an unknown token answered %d, want 410", third.StatusCode)
	}
}

// Without test_url the response carries no URL and no PoC host starts — the
// host is started by the first mint, not by every console boot.
func TestNoPoCHostStartsWithoutATestURL(t *testing.T) {
	s := newTestServer()
	id := seedCSRFExchange(t, s,
		"POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\nuser=admin",
		&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "POST", Path: "/login"},
	)
	rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET csrf answered %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"test_url"`) {
		t.Error("the plain generation carries a test_url field nobody asked for")
	}
	s.pocMu.Lock()
	started := s.poc != nil
	s.pocMu.Unlock()
	if started {
		t.Error("a PoC host started although no test URL was requested")
	}
}

// The PoC host holds a bounded number of unfetched pages, and an expired page is gone (review
// finding: every refetch minted a page that was held forever).
func TestThePocHostIsBounded(t *testing.T) {
	s := newTestServer()
	var urls []string
	for i := 0; i < maxPocPages+5; i++ {
		u, err := s.mintPocURL("<p>x</p>")
		if err != nil {
			t.Fatal(err)
		}
		urls = append(urls, u)
	}
	s.poc.mu.Lock()
	n := len(s.poc.pages)
	for token, page := range s.poc.pages {
		page.expires = page.expires.Add(-2 * pocPageTTL)
		s.poc.pages[token] = page
		break
	}
	s.poc.mu.Unlock()
	if n != maxPocPages {
		t.Errorf("%d pages held, want the bound %d", n, maxPocPages)
	}
	gone := 0
	for _, u := range urls {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusGone {
			gone++
		}
	}
	// The five evicted by the bound, plus the one expired above.
	if gone != 6 {
		t.Errorf("%d URLs answered 410, want 6 (5 evicted, 1 expired)", gone)
	}
}
