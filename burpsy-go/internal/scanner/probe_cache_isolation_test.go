package scanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
)

func TestWithCacheBusterRawRewritesOnlyTheRequestTarget(t *testing.T) {
	req := "GET /a/b?x=1 HTTP/1.1\r\nHost: h\r\nX-Q: /a/b?x=1\r\n\r\n"
	cases := []struct {
		name string
		raw  string
		loc  cacheBusterLocation
		want string
	}{
		{"query", req, busterQuery, "GET /a/b?x=1&burpsy_cb=V HTTP/1.1\r\nHost: h\r\nX-Q: /a/b?x=1\r\n\r\n"},
		{"path parameter", req, busterPathParam, "GET /a/b;burpsy_cb=V?x=1 HTTP/1.1\r\nHost: h\r\nX-Q: /a/b?x=1\r\n\r\n"},
		{"no query", "GET /a HTTP/1.1\r\n\r\n", busterPathParam, "GET /a;burpsy_cb=V HTTP/1.1\r\n\r\n"},
		{"absolute form", "GET http://h:8/a?x=1 HTTP/1.1\r\n\r\n", busterPathParam, "GET http://h:8/a;burpsy_cb=V?x=1 HTTP/1.1\r\n\r\n"},
		{"absolute form, no path", "GET http://h:8 HTTP/1.1\r\n\r\n", busterQuery, "GET http://h:8/?burpsy_cb=V HTTP/1.1\r\n\r\n"},
		{"bare LF", "GET /a HTTP/1.1\nHost: h\n\n", busterQuery, "GET /a?burpsy_cb=V HTTP/1.1\nHost: h\n\n"},
		{"authority form untouched", "CONNECT h:443 HTTP/1.1\r\n\r\n", busterQuery, "CONNECT h:443 HTTP/1.1\r\n\r\n"},
	}
	for _, tc := range cases {
		if got := string(withCacheBusterRaw([]byte(tc.raw), tc.loc, "V")); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

func TestRawResponseHeaderMapFeedsTheCacheStateReader(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nX-Cache-Status: HIT\r\nContent-Type: application/json\r\n\r\nX-Cache: MISS\r\n")
	if got := observeCacheState(rawResponseHeaderMap(raw)); got != cacheHit {
		t.Fatalf("cache state = %s, want hit", got)
	}
	// The body is not headers: a body line that looks like one must not be read.
	raw = []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nX-Cache: HIT\r\n")
	if got := observeCacheState(rawResponseHeaderMap(raw)); got != cacheUnknown {
		t.Fatalf("cache state = %s from a body line, want unknown", got)
	}
}

func TestXSSLocateFragmentFindsTheApplicationsMarkupInsideAJSONEnvelope(t *testing.T) {
	const c = "zxssabc123"
	cases := []struct {
		name     string
		body     string
		wantOK   bool
		wantSite string
		wantView string
	}{
		{"envelope with a markup value", `{"ok":true,"content":"<section class=\"b\"><p>Banner: ` + c + `</p></section>"}`,
			true, "JSON value content", `<section class="b"><p>Banner: ` + c + `</p></section>`},
		{"nested array", `{"items":[{"html":"<li>` + c + `</li>"}]}`, true, "JSON value items[0].html", `<li>` + c + `</li>`},
		{"plain fragment body", `<div>` + c + `</div>`, true, "the response body", `<div>` + c + `</div>`},
		// The value echoed into a field of its own is a string, not the application's markup.
		{"echo field", `{"banner":"` + c + `","content":"<p>static</p>"}`, false, "", ""},
		// Markup the value never reaches says nothing about the value.
		{"markup without the canary", `{"content":"<p>static</p>","n":"` + c + `x"}`, false, "", ""},
		{"text that merely starts with <", `{"content":"< ` + c + `"}`, false, "", ""},
		{"not JSON", `ok ` + c, false, "", ""},
	}
	for _, tc := range cases {
		site, view, ok := xssLocateFragment(tc.body, c)
		if ok != tc.wantOK {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if site.String() != tc.wantSite || view != tc.wantView {
			t.Errorf("%s: site %q view %q, want %q %q", tc.name, site, view, tc.wantSite, tc.wantView)
		}
		// The same site extracts the same field from a later answer, decoded.
		later := strings.ReplaceAll(tc.body, c, c+`\"><svg>`)
		if site.isJSON() {
			if v, ok := site.extract(later); !ok || !strings.Contains(v, c+`"><svg>`) {
				t.Errorf("%s: extract from a later answer = %q, %v", tc.name, v, ok)
			}
		}
	}
}

func TestCachePoisonCookieInputsReplaceOneCookieAndKeepTheRest(t *testing.T) {
	ins := cachePoisonCookieInputs("theme=light; display_name=alice; theme=dup")
	if len(ins) != 2 {
		t.Fatalf("inputs = %d, want 2 (one per distinct name)", len(ins))
	}
	if ins[1].label != "cookie display_name" {
		t.Fatalf("label = %q", ins[1].label)
	}
	path, h, body := ins[1].build("/p;burpsy_cb=b", "CAN")
	if path != "/p;burpsy_cb=b" || body != nil {
		t.Fatalf("path/body = %q %q", path, body)
	}
	if got := h["Cookie"]; got != "theme=light; display_name=CAN; theme=dup" {
		t.Fatalf("Cookie = %q", got)
	}
	if got := cachePoisonCookieInputs(""); len(got) != 0 {
		t.Fatalf("no cookies must give no inputs, got %d", len(got))
	}
}

// The vulnapp pair end to end: a route-keyed shared cache in front of a JSON envelope whose markup
// value reflects the parameter. Without per-probe busters every probe is answered with the first
// one's stored page and the reflection is never seen; without the envelope rule the fragment is
// never entered. The twins keep both and remove the defect.
func TestReflectedXSSBehindARouteKeyedCacheInAJSONEnvelope(t *testing.T) {
	rt := startRuntimeTarget(t)
	if !rt.chrome {
		domexectest.Skip(t, "no Chrome on PATH: the fragment render is untested")
	}
	got := rt.findingsFor(t, "/cx/banner/view?banner=hello", true)
	f := got[xssReflectedIssue]
	if f == nil {
		t.Fatalf("reflected XSS not reported behind the cache; rows: %s", joinRows(got))
	}
	for _, want := range []string{"JSON value content", "path parameter cache buster", "executed"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("description lacks %q: %s", want, f.Description)
		}
	}
	for _, safe := range []string{"/safe/cx/banner/view?banner=hello", "/safe/cx/field/view?banner=hello"} {
		if f := rt.findingsFor(t, safe, true)[xssReflectedIssue]; f != nil {
			t.Errorf("reflected XSS reported on the safe twin %s: %s", safe, f.Description)
		}
	}
}

func TestWebCachePoisoningThroughACarriedCookie(t *testing.T) {
	rt := startRuntimeTarget(t)
	f := rt.findingsFor(t, "/hd/cache-poison-cookie", false)[cachePoisonIssue]
	if f == nil || !strings.Contains(f.Evidence, "cookie display_name") {
		t.Fatalf("cookie-driven poisoning not reported with its input: %+v", f)
	}
	if f := rt.findingsFor(t, "/hd/safe/cache-poison-cookie", false)[cachePoisonIssue]; f != nil {
		t.Errorf("poisoning reported on the Vary: Cookie twin: %s", f.Evidence)
	}
}

// cacheFront is a test shared cache keyed by keyOf, recording every request URI the origin saw.
type cacheFront struct {
	mu     sync.Mutex
	stored map[string]string
	seen   []string
}

func (c *cacheFront) handler(keyOf func(*http.Request) string, cacheable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.seen = append(c.seen, r.RequestURI)
		if c.stored == nil {
			c.stored = map[string]string{}
		}
		k := keyOf(r)
		if body, ok := c.stored[k]; ok && cacheable {
			w.Header().Set("X-Cache", "HIT")
			_, _ = io.WriteString(w, body)
			return
		}
		body := "<p>" + r.URL.Query().Get("q") + "</p>"
		if cacheable {
			c.stored[k] = body
		}
		w.Header().Set("X-Cache", "MISS")
		_, _ = io.WriteString(w, body)
	}
}

func TestIsolateFromSharedCacheVerifiesABusterOrRefuses(t *testing.T) {
	ctx := context.Background()
	pathOnly := func(r *http.Request) string { p, _, _ := strings.Cut(r.RequestURI, "?"); return p }
	cases := []struct {
		name       string
		key        func(*http.Request) string
		cacheable  bool
		noHeaders  bool
		wantErr    bool
		wantBuster string // substring every later probe's URI must carry; "" for none
		wantNote   string
	}{
		{name: "route-keyed cache: path parameter verified", key: pathOnly, cacheable: true,
			wantBuster: ";burpsy_cb=", wantNote: "path parameter cache buster"},
		{name: "full-URL cache: query verified", key: func(r *http.Request) string { return r.RequestURI }, cacheable: true,
			wantBuster: "burpsy_cb=", wantNote: "query parameter cache buster"},
		// A cache that keys neither location while storing the answer: every probe would be stored
		// where other visitors are served it, so nothing is probed.
		{name: "unkeyable cache: refused", key: func(r *http.Request) string { return strings.SplitN(r.URL.Path, ";", 2)[0] },
			cacheable: true, wantErr: true},
		{name: "cache that stores nothing: unbustered", key: pathOnly, cacheable: false, wantNote: "served no repeat from cache"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			front := &cacheFront{}
			cc := harnessAgainst(t, front.handler(tc.key, tc.cacheable), "/page?q=hello")
			h, err := NewProbeHarness(ctx, cc, []string{"query"})
			if err != nil {
				t.Fatal(err)
			}
			note, err := h.IsolateFromSharedCache(ctx)
			if tc.wantErr {
				if !errors.Is(err, errSharedCacheUnisolated) {
					t.Fatalf("err = %v, want the refusal", err)
				}
				return
			}
			if err != nil || !strings.Contains(note, tc.wantNote) {
				t.Fatalf("note %q err %v, want note containing %q", note, err, tc.wantNote)
			}
			front.mu.Lock()
			before := len(front.seen)
			front.mu.Unlock()
			var q bcheck.InsertionPoint
			for _, p := range h.Points() {
				if p.Name == "q" {
					q = p
				}
			}
			r1, _ := h.Send(ctx, q, "AAA111")
			r2, _ := h.Send(ctx, q, "BBB222")
			if !strings.Contains(r1.Body, "AAA111") || !strings.Contains(r2.Body, "BBB222") {
				t.Fatalf("each probe must be answered for itself: %q, %q", r1.Body, r2.Body)
			}
			front.mu.Lock()
			sent := append([]string(nil), front.seen[before:]...)
			front.mu.Unlock()
			if len(sent) != 2 {
				t.Fatalf("origin saw %d probe requests, want 2: %v", len(sent), sent)
			}
			for _, uri := range sent {
				if tc.wantBuster == "" && strings.Contains(uri, "burpsy_cb") || tc.wantBuster != "" && !strings.Contains(uri, tc.wantBuster) {
					t.Errorf("probe URI %q, want buster %q", uri, tc.wantBuster)
				}
			}
			if tc.wantBuster != "" && sent[0] == sent[1] {
				t.Errorf("two probes shared a buster value: %v", sent)
			}
		})
	}

	// No cache state reported at all: nothing changes.
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }, "/plain?q=1")
	h, err := NewProbeHarness(ctx, cc, []string{"query"})
	if err != nil {
		t.Fatal(err)
	}
	if note, err := h.IsolateFromSharedCache(ctx); note != "" || err != nil || h.buster != nil {
		t.Fatalf("a target reporting no cache must be left alone: %q %v", note, err)
	}
}
