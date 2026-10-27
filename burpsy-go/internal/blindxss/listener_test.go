package blindxss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/domexec"
)

// newTestListener binds an ephemeral loopback port and closes it with the test.
func newTestListener(t *testing.T, opts Options) *Listener {
	t.Helper()
	l, err := NewListener(context.Background(), opts)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestGeneratePayloadMintsDistinctTokens(t *testing.T) {
	l := newTestListener(t, Options{})

	seen := make(map[string]struct{})
	for i := 0; i < 64; i++ {
		p, err := l.GeneratePayload()
		if err != nil {
			t.Fatalf("GeneratePayload: %v", err)
		}
		if !strings.HasPrefix(p.Token, tokenPrefix) {
			t.Fatalf("token %q does not carry the %q prefix the stored ledger uses", p.Token, tokenPrefix)
		}
		if len(p.Token) != len(tokenPrefix)+tokenEntropyChars {
			t.Fatalf("token %q is %d chars, want %d", p.Token, len(p.Token), len(tokenPrefix)+tokenEntropyChars)
		}
		for _, r := range p.Token[len(tokenPrefix):] {
			if !strings.ContainsRune(tokenAlphabet, r) {
				t.Fatalf("token %q carries %q, outside the [a-z0-9] alphabet", p.Token, r)
			}
		}
		if _, dup := seen[p.Token]; dup {
			t.Fatalf("token %q minted twice", p.Token)
		}
		seen[p.Token] = struct{}{}

		wantURL := l.BaseURL() + scriptPathPrefix + p.Token + scriptPathSuffix
		if p.ScriptURL != wantURL {
			t.Fatalf("ScriptURL = %q, want %q", p.ScriptURL, wantURL)
		}
		if want := `<script src="` + wantURL + `"></script>`; p.ScriptTag() != want {
			t.Fatalf("ScriptTag() = %q, want %q", p.ScriptTag(), want)
		}
	}
}

// loopbackGate is the render scope for these tests: the victim page and the listener both live on
// 127.0.0.1, on different ports, and nothing else may be reached.
type loopbackGate struct{}

func (loopbackGate) AllowURL(u *url.URL) error {
	return loopbackGate{}.AllowAuthority(u.Hostname(), 0, false)
}

func (loopbackGate) AllowAuthority(host string, _ uint16, _ bool) error {
	if host != "127.0.0.1" {
		return fmt.Errorf("%s is not loopback", host)
	}
	return nil
}

// TestCaptureThroughRealBrowser is the test the rest exist to support: it serves a page
// carrying the payload exactly as an injection would, renders it in headless Chrome, and
// asserts HitsFor returns what that browser actually sent. Nothing about the callback
// body is hand-constructed, so a change to the script template that breaks the real
// capture path fails here rather than passing against a hand-typed guess of its output.
func TestCaptureThroughRealBrowser(t *testing.T) {
	browser, err := domexec.NewBrowser(context.Background(), domexec.Options{Timeout: 30 * time.Second})
	if err != nil {
		t.Skipf("no headless browser available: %v", err)
	}
	t.Cleanup(func() { _ = browser.Close() })

	l := newTestListener(t, Options{})
	payload, err := l.GeneratePayload()
	if err != nil {
		t.Fatalf("GeneratePayload: %v", err)
	}

	// The "vulnerable" page: a distinct origin from the listener, setting a cookie and
	// rendering the payload the way a stored-XSS sink would.
	const marker = "victim-admin-panel-marker"
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "victim-session-value", Path: "/"})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><head><title>admin</title></head>
<body><div id=%q>pending comment</div>%s</body></html>`, marker, payload.ScriptTag())
	}))
	t.Cleanup(victim.Close)

	// The victim page and the listener are on different ports, so the callback the
	// browser makes is genuinely cross-origin — the path a real blind-XSS hit takes.
	pageURL := victim.URL + "/inbox"

	if _, err := browser.RenderedDOM(context.Background(), pageURL, loopbackGate{}); err != nil {
		t.Fatalf("rendering the victim page: %v", err)
	}

	hits := waitForHits(t, l, payload.Token, 15*time.Second)
	if len(hits) != 1 {
		t.Fatalf("HitsFor returned %d hits, want exactly 1", len(hits))
	}
	hit := hits[0]

	if hit.Token != payload.Token {
		t.Fatalf("hit token = %q, want %q", hit.Token, payload.Token)
	}
	if hit.Location != pageURL {
		t.Fatalf("hit location = %q, want the rendering page %q", hit.Location, pageURL)
	}
	if !strings.Contains(hit.Cookies, "session=victim-session-value") {
		t.Fatalf("hit cookies = %q, want the victim page's session cookie", hit.Cookies)
	}
	if !strings.Contains(hit.DOM, marker) {
		t.Fatalf("hit DOM does not carry the victim page's marker %q; got %q", marker, hit.DOM)
	}
	if !strings.Contains(strings.ToLower(hit.UserAgent), "chrome") &&
		!strings.Contains(strings.ToLower(hit.UserAgent), "headless") {
		t.Fatalf("hit userAgent = %q, want the rendering browser's own", hit.UserAgent)
	}
	if hit.HeaderUserAgent != hit.UserAgent {
		t.Fatalf("header UA %q and page-reported UA %q disagree for a genuine browser callback",
			hit.HeaderUserAgent, hit.UserAgent)
	}
	if hit.RemoteAddress == "" {
		t.Fatal("hit carries no remote address")
	}
	if hit.ReceivedAt.IsZero() {
		t.Fatal("hit carries no receive time")
	}
	if hit.Truncated {
		t.Fatalf("a %d-byte page reported truncation against a %d-byte cap", len(hit.DOM), defaultMaxDOMBytes)
	}
}

// TestDOMSnippetIsCapped renders a page far larger than the cap and asserts the payload
// truncated it in the browser and said so, rather than exfiltrating the whole document.
func TestDOMSnippetIsCapped(t *testing.T) {
	browser, err := domexec.NewBrowser(context.Background(), domexec.Options{Timeout: 30 * time.Second})
	if err != nil {
		t.Skipf("no headless browser available: %v", err)
	}
	t.Cleanup(func() { _ = browser.Close() })

	const domCap = 2048
	l := newTestListener(t, Options{MaxDOMBytes: domCap})
	payload, err := l.GeneratePayload()
	if err != nil {
		t.Fatalf("GeneratePayload: %v", err)
	}

	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><body><p>%s</p>%s</body></html>`,
			strings.Repeat("padding ", 4000), payload.ScriptTag())
	}))
	t.Cleanup(victim.Close)

	if _, err := browser.RenderedDOM(context.Background(), victim.URL, loopbackGate{}); err != nil {
		t.Fatalf("rendering the oversized page: %v", err)
	}

	hits := waitForHits(t, l, payload.Token, 15*time.Second)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	if got := len(hits[0].DOM); got > domCap {
		t.Fatalf("DOM snippet is %d bytes, over the %d cap", got, domCap)
	}
	if !hits[0].Truncated {
		t.Fatalf("an oversized page did not report truncation against a %d-byte cap", domCap)
	}
}

func TestHitsForUnknownTokenReturnsNothing(t *testing.T) {
	l := newTestListener(t, Options{})
	minted, err := l.GeneratePayload()
	if err != nil {
		t.Fatalf("GeneratePayload: %v", err)
	}

	// A token this listener never minted gets neither a script nor a stored hit.
	const stranger = "bsyaaaaaaaaaaaaa"
	resp, err := http.Get(l.BaseURL() + scriptPathPrefix + stranger + scriptPathSuffix)
	if err != nil {
		t.Fatalf("fetching the script for an unminted token: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("script for an unminted token returned %d, want 404", resp.StatusCode)
	}

	body := strings.NewReader(`{"token":"` + stranger + `","dom":"<html></html>","location":"http://x/"}`)
	resp, err = http.Post(l.BaseURL()+scriptPathPrefix+stranger+reportPathSuffix, "text/plain", body)
	if err != nil {
		t.Fatalf("posting a report for an unminted token: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("report for an unminted token returned %d, want 404", resp.StatusCode)
	}

	hits, err := l.HitsFor(stranger)
	if err != nil {
		t.Fatalf("HitsFor: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("HitsFor(unminted) returned %d hits, want 0", len(hits))
	}
	// And the minted token is not credited with the stranger's traffic either.
	hits, err = l.HitsFor(minted.Token)
	if err != nil {
		t.Fatalf("HitsFor: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("the minted token picked up %d hits it did not earn", len(hits))
	}

	if _, err := l.HitsFor(""); err == nil {
		t.Fatal("HitsFor(\"\") returned no error; an empty token must not be a wildcard")
	}
}

// TestReportTokenMustMatchURL covers the one ambiguity the store refuses to resolve: a
// body claiming a different token than the URL it arrived at.
func TestReportTokenMustMatchURL(t *testing.T) {
	l := newTestListener(t, Options{})
	a, err := l.GeneratePayload()
	if err != nil {
		t.Fatalf("GeneratePayload: %v", err)
	}
	b, err := l.GeneratePayload()
	if err != nil {
		t.Fatalf("GeneratePayload: %v", err)
	}

	body := strings.NewReader(`{"token":"` + b.Token + `","dom":"x"}`)
	resp, err := http.Post(l.BaseURL()+scriptPathPrefix+a.Token+reportPathSuffix, "text/plain", body)
	if err != nil {
		t.Fatalf("posting a mismatched report: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched report returned %d, want 400", resp.StatusCode)
	}

	for _, tok := range []string{a.Token, b.Token} {
		hits, err := l.HitsFor(tok)
		if err != nil {
			t.Fatalf("HitsFor(%s): %v", tok, err)
		}
		if len(hits) != 0 {
			t.Fatalf("token %s was credited with a mismatched report", tok)
		}
	}
}

// TestBindFailureIsATypedError is the honest-failure contract: a port already in use
// must surface as an error, never as a listener that quietly reports no hits.
func TestBindFailureIsATypedError(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	defer held.Close()

	l, err := NewListener(context.Background(), Options{Addr: held.Addr().String()})
	if err == nil {
		_ = l.Close()
		t.Fatal("NewListener succeeded on an address already in use")
	}
	if l != nil {
		t.Fatal("NewListener returned both a listener and an error")
	}

	var bindErr *BindError
	if !errors.As(err, &bindErr) {
		t.Fatalf("error %v (%T) is not a *BindError; callers cannot distinguish it from an empty result", err, err)
	}
	if bindErr.Addr != held.Addr().String() {
		t.Fatalf("BindError names %q, want the address it tried, %q", bindErr.Addr, held.Addr().String())
	}
	if !strings.Contains(err.Error(), "no blind-XSS callback channel") {
		t.Fatalf("error text %q does not say the channel is unavailable", err.Error())
	}
}

func TestBaseURLOverrideReachesThePayload(t *testing.T) {
	l := newTestListener(t, Options{BaseURL: "https://collab.example.net:8443/"})
	p, err := l.GeneratePayload()
	if err != nil {
		t.Fatalf("GeneratePayload: %v", err)
	}
	if !strings.HasPrefix(p.ScriptURL, "https://collab.example.net:8443"+scriptPathPrefix) {
		t.Fatalf("ScriptURL = %q, want the configured BaseURL with no doubled slash", p.ScriptURL)
	}

	// The report URL inside the served script must use the same origin, or a payload
	// behind a tunnel would load fine and then call home to an address the victim's
	// browser cannot reach.
	js := renderScript(p.Token, l.BaseURL()+scriptPathPrefix+p.Token+reportPathSuffix, defaultMaxDOMBytes)
	if !strings.Contains(js, "https://collab.example.net:8443"+scriptPathPrefix+p.Token+reportPathSuffix) {
		t.Fatalf("served script does not post back to the configured BaseURL:\n%s", js)
	}
}

// TestServedScriptEscapesForInlineUse guards the property that keeps the template from
// becoming an injection vector of its own.
func TestServedScriptEscapesForInlineUse(t *testing.T) {
	const hostile = `http://x/</script><!--`
	js := renderScript("bsyabc123", hostile, 128)

	if strings.Contains(js, "</script") {
		t.Fatalf("rendered script contains a raw </script and would break out of an inline block:\n%s", js)
	}
	if strings.Contains(js, "<!--") {
		t.Fatalf("rendered script contains a raw <!-- and would comment out the page:\n%s", js)
	}

	// Escaped, not dropped: the literal must still parse back to exactly what went in, or a
	// payload behind an awkwardly-spelled BaseURL would post to a mangled address.
	const marker = "var URL_ = "
	i := strings.Index(js, marker)
	if i < 0 {
		t.Fatalf("rendered script has no %q line:\n%s", marker, js)
	}
	rest := js[i+len(marker):]
	end := strings.Index(rest, ";")
	if end < 0 {
		t.Fatalf("rendered script's URL literal is unterminated:\n%s", js)
	}
	var got string
	if err := json.Unmarshal([]byte(rest[:end]), &got); err != nil {
		t.Fatalf("URL literal %q is not a valid JS/JSON string: %v", rest[:end], err)
	}
	if got != hostile {
		t.Fatalf("URL literal round-tripped to %q, want %q", got, hostile)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	l, err := NewListener(context.Background(), Options{})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// waitForHits polls HitsFor until at least one hit lands or the deadline passes. The
// callback is asynchronous by nature — the browser posts it after the page renders — so
// this is the same shape as the scanner's pending-registry wait, not a sleep.
func waitForHits(t *testing.T, l *Listener, token string, within time.Duration) []Hit {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		hits, err := l.HitsFor(token)
		if err != nil {
			t.Fatalf("HitsFor: %v", err)
		}
		if len(hits) > 0 {
			return hits
		}
		if time.Now().After(deadline) {
			t.Fatalf("no callback for token %s within %s", token, within)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
