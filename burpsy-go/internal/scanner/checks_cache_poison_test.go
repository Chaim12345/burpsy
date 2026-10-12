package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// simCache is a shared cache in front of an origin handler, for the poisoning check's behaviour
// tests. key decides what the cache keys on; signals decides whether it reports X-Cache.
type simCache struct {
	mu      sync.Mutex
	entries map[string]simEntry
	key     func(*http.Request) string
	signals bool
	origin  http.HandlerFunc
	// seen records every request that reached the cache, for the safety assertions.
	seen []seenRequest
}

type simEntry struct {
	status int
	header http.Header
	body   []byte
}

type seenRequest struct {
	uri    string
	header http.Header
	body   string
}

func (c *simCache) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body bytes.Buffer
	_, _ = body.ReadFrom(r.Body)
	c.mu.Lock()
	c.seen = append(c.seen, seenRequest{uri: r.RequestURI, header: r.Header.Clone(), body: body.String()})
	k := c.key(r)
	e, hit := c.entries[k]
	c.mu.Unlock()
	if !hit {
		rec := httptest.NewRecorder()
		r.Body = http.NoBody
		if body.Len() > 0 {
			r.Body = nopCloser{bytes.NewReader(body.Bytes())}
		}
		c.origin(rec, r)
		e = simEntry{status: rec.Code, header: rec.Header().Clone(), body: rec.Body.Bytes()}
		c.mu.Lock()
		if c.entries == nil {
			c.entries = map[string]simEntry{}
		}
		c.entries[k] = e
		c.mu.Unlock()
	}
	for name, vs := range e.header {
		for _, v := range vs {
			w.Header().Add(name, v)
		}
	}
	if c.signals {
		if hit {
			w.Header().Set("X-Cache", "HIT")
		} else {
			w.Header().Set("X-Cache", "MISS")
		}
	}
	w.WriteHeader(e.status)
	_, _ = w.Write(e.body)
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

// poisonedRequests are the recorded requests that carried any poisoning input.
func (c *simCache) poisonedRequests() []seenRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []seenRequest
	for _, s := range c.seen {
		carried := strings.Contains(s.uri, "bcp") || strings.Contains(s.body, "bcp")
		for _, in := range cachePoisonHeaderInputs() {
			name := strings.TrimPrefix(in.label, "header ")
			if s.header.Get(name) != "" {
				carried = true
			}
		}
		if carried {
			out = append(out, s)
		}
	}
	return out
}

func keyFullURI(r *http.Request) string { return r.RequestURI }

// keyRouteOnly keys on the raw path without the query, path parameters included (as a servlet
// container's getRequestURI does).
func keyRouteOnly(r *http.Request) string {
	p, _, _ := strings.Cut(r.RequestURI, "?")
	return p
}

func reflectHeader(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get(name)
		if host == "" {
			host = "static.example"
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, `<html><script src="https://%s/app.js"></script></html>`, host)
	}
}

func runPoisonCheck(t *testing.T, c *simCache, path string) []*Finding {
	t.Helper()
	cc := harnessAgainst(t, c.ServeHTTP, path)
	got, err := checkWebCachePoisoning(context.Background(), cc)
	if err != nil {
		t.Fatalf("checkWebCachePoisoning: %v", err)
	}
	return got
}

func TestCachePoisoningAnUnkeyedHeaderIsProvedByACleanReplay(t *testing.T) {
	c := &simCache{key: keyFullURI, signals: true, origin: reflectHeader("X-Forwarded-Host")}
	got := runPoisonCheck(t, c, "/page")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(got), describeFindings(got))
	}
	f := got[0]
	if f.Param != "header X-Forwarded-Host" || f.Confidence != "certain" {
		t.Fatalf("param %q confidence %q, want header X-Forwarded-Host / certain\n%s", f.Param, f.Confidence, f.Evidence)
	}
	if !strings.Contains(f.Evidence, "query parameter buster verified keyed") {
		t.Fatalf("evidence does not state the verified buster:\n%s", f.Evidence)
	}
	// Every poisoned request went to a bustered key, never the real one.
	for _, s := range c.poisonedRequests() {
		if !strings.Contains(s.uri, cachePoisonBusterName+"=") {
			t.Fatalf("a poisoned request reached the unbustered key: %s", s.uri)
		}
	}
}

// The cache keys only the route, so the query buster is unkeyed and must be refused; the path
// parameter is keyed and carries the probe. The reflected query parameter is the unkeyed input.
func TestCachePoisoningAnUnkeyedQueryParameterIsFoundBehindARouteOnlyKey(t *testing.T) {
	c := &simCache{key: keyRouteOnly, signals: true, origin: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "<p>banner: %s</p>", r.URL.Query().Get("msg"))
	}}
	got := runPoisonCheck(t, c, "/notice?msg=hello")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(got), describeFindings(got))
	}
	if got[0].Param != "query parameter msg" {
		t.Fatalf("param %q, want query parameter msg\n%s", got[0].Param, got[0].Evidence)
	}
	if !strings.Contains(got[0].Evidence, "query parameter buster is not in the cache key") ||
		!strings.Contains(got[0].Evidence, "path parameter buster verified keyed") {
		t.Fatalf("evidence does not show the buster selection:\n%s", got[0].Evidence)
	}
	for _, s := range c.poisonedRequests() {
		if !strings.Contains(s.uri, ";"+cachePoisonBusterName+"=") {
			t.Fatalf("a poisoned request reached a key the path buster did not isolate: %s", s.uri)
		}
	}
}

// The safe twin: the header is reflected but the cache keys on it, so the clean replay is served
// its own entry. Reflection alone must not be reported.
func TestCachePoisoningAReflectedButKeyedHeaderIsNotReported(t *testing.T) {
	c := &simCache{signals: true, origin: reflectHeader("X-Forwarded-Host"),
		key: func(r *http.Request) string { return r.RequestURI + "|" + r.Header.Get("X-Forwarded-Host") }}
	if got := runPoisonCheck(t, c, "/page"); len(got) != 0 {
		t.Fatalf("reflection of a keyed header was reported: %s", describeFindings(got))
	}
}

// No cache at all: the application stores the last forwarded host and serves it to everyone. The
// canary reaches the clean replay, but also the fresh-buster control, so it is not cache poisoning.
func TestCachePoisoningServerSidePersistenceIsNotCachePoisoning(t *testing.T) {
	var mu sync.Mutex
	last := "static.example"
	h := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if v := r.Header.Get("X-Forwarded-Host"); v != "" {
			last = v
		}
		v := last
		mu.Unlock()
		fmt.Fprintf(w, `<script src="https://%s/app.js"></script>`, v)
	}
	cc := harnessAgainst(t, h, "/page")
	got, err := checkWebCachePoisoning(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("server-side persistence was reported as cache poisoning: %s", describeFindings(got))
	}
}

// One key for everything: no buster can isolate a probe, so nothing may be poisoned at all.
func TestCachePoisoningNothingIsPoisonedWhenNoBusterIsKeyed(t *testing.T) {
	c := &simCache{key: func(*http.Request) string { return "one" }, signals: true,
		origin: reflectHeader("X-Forwarded-Host")}
	if got := runPoisonCheck(t, c, "/page"); len(got) != 0 {
		t.Fatalf("got findings: %s", describeFindings(got))
	}
	if p := c.poisonedRequests(); len(p) != 0 {
		t.Fatalf("%d poisoned request(s) were sent although no buster was keyed; first: %s %v",
			len(p), p[0].uri, p[0].header)
	}
}

// A cache that reports nothing: the query buster is used unverified, the control still guards it.
func TestCachePoisoningWithoutCacheHeadersFallsBackToTheQueryBuster(t *testing.T) {
	c := &simCache{key: keyFullURI, signals: false, origin: reflectHeader("X-Forwarded-Host")}
	got := runPoisonCheck(t, c, "/page")
	if len(got) != 1 || got[0].Confidence != "firm" {
		t.Fatalf("want one firm finding, got %s", describeFindings(got))
	}
}

func TestCachePoisoningACachedRedirectIsProved(t *testing.T) {
	c := &simCache{key: keyFullURI, signals: true, origin: func(w http.ResponseWriter, r *http.Request) {
		if s := r.Header.Get("X-Forwarded-Scheme"); s != "" && s != "https" {
			w.Header().Set("Location", "https://app.example/")
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "<html>home</html>")
	}}
	got := runPoisonCheck(t, c, "/")
	if len(got) != 1 || got[0].Param != "header X-Forwarded-Scheme" {
		t.Fatalf("want one X-Forwarded-Scheme finding, got %s", describeFindings(got))
	}
}

func TestCachePoisoningFatGetBodyParameter(t *testing.T) {
	c := &simCache{key: keyFullURI, signals: true, origin: func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("lang")
		var body bytes.Buffer
		_, _ = body.ReadFrom(r.Body)
		if b := body.String(); strings.HasPrefix(b, "lang=") {
			v = strings.TrimPrefix(b, "lang=")
		}
		fmt.Fprintf(w, "<html lang=%q></html>", v)
	}}
	got := runPoisonCheck(t, c, "/home?lang=en")
	if len(got) != 1 || !strings.Contains(got[0].Description, "fat GET") {
		t.Fatalf("want a fat-GET finding, got %s", describeFindings(got))
	}
}

func TestObserveCacheState(t *testing.T) {
	cases := []struct {
		h    map[string]string
		want cacheState
	}{
		{map[string]string{"X-Cache": "HIT"}, cacheHit},
		{map[string]string{"x-cache": "MISS, HIT"}, cacheHit},
		{map[string]string{"X-Cache": "TCP_MISS from a"}, cacheMiss},
		{map[string]string{"X-Cache-Status": "MISS"}, cacheMiss},
		{map[string]string{"Cf-Cache-Status": "DYNAMIC"}, cacheMiss},
		{map[string]string{"Cache-Status": "Edge; hit; ttl=30"}, cacheHit},
		{map[string]string{"Cache-Status": "Edge; fwd=uri-miss"}, cacheMiss},
		{map[string]string{"X-Varnish": "123 456"}, cacheHit},
		{map[string]string{"X-Varnish": "123"}, cacheMiss},
		{map[string]string{"Age": "12"}, cacheHit},
		{map[string]string{"Age": "0"}, cacheUnknown},
		{map[string]string{"Content-Type": "text/html"}, cacheUnknown},
		// "Whitelist" is not "hit": words are matched whole.
		{map[string]string{"X-Cache": "whitelisted"}, cacheUnknown},
	}
	for _, tc := range cases {
		if got := observeCacheState(tc.h); got != tc.want {
			t.Errorf("observeCacheState(%v) = %s, want %s", tc.h, got, tc.want)
		}
	}
}

func TestApplyCacheBuster(t *testing.T) {
	cases := []struct {
		path string
		loc  cacheBusterLocation
		want string
	}{
		{"/a?x=1", busterQuery, "/a?x=1&burpsy_cb=v"},
		{"/a", busterQuery, "/a?burpsy_cb=v"},
		{"/a?x=1", busterPathParam, "/a;burpsy_cb=v?x=1"},
		{"/a/", busterPathParam, "/a/;burpsy_cb=v"},
	}
	for _, tc := range cases {
		if got := applyCacheBuster(tc.path, tc.loc, "v"); got != tc.want {
			t.Errorf("applyCacheBuster(%q, %s) = %q, want %q", tc.path, tc.loc, got, tc.want)
		}
	}
}
