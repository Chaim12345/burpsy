package vulnapp

// Header rows and web-cache rows.
//
// The header rows are passive: the endpoint simply serves the offending header (or
// omits the protecting one). The two cache rows are active — the scanner sends
// probes and the endpoint must genuinely behave like a cache.
//
// The CORS all-subdomains endpoint serves a literal wildcard-subdomain
// Access-Control-Allow-Origin, which the passive classifier reads straight out of
// the seeded response. (The unencrypted-origin CORS row is NOT declared here: its
// check can only fire via a live http://-Origin probe, and the probe reader in
// checks_headers.go looks up a lowercased header key against a canonicalized-keys
// map, so it never sees the reflected value. See the final report.)
//
// The cache endpoints implement real, if deliberately broken, caching. The
// poisoning endpoints sit behind vaSharedCache, which reports X-Cache HIT/MISS
// the way a CDN does; the defect is what each one leaves out of its key. The
// deception endpoint serves the same dynamic body on a static-looking .css path —
// exactly the signature the check looks for.

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"
	"time"
)

// hdDynamicBody is the sensitive, per-user content a cache should never store
// under a static key.
const hdDynamicBody = "<html><body>account: user123, balance: 500</body></html>"

// headerEndpoints returns this family's manifest entries.
func headerEndpoints() []Endpoint {
	return []Endpoint{
		// Re-added after the coordinator fixed probeCORSOrigin, which looked the probe's response
		// header up by a lowercase key while net/http had canonicalised it - so the probe returned
		// empty for every target and this row could not fire.
		{Path: "/hd/cors-unenc", Row: "Cross-origin resource sharing: unencrypted origin trusted",
			Note: "reflects any submitted Origin into Access-Control-Allow-Origin, cleartext included"},
		{Path: "/hd/safe/cors-unenc", Row: "Cross-origin resource sharing: unencrypted origin trusted", Safe: true,
			Note: "reflects an Origin only when it is https, so a cleartext origin is never trusted"},

		{Path: "/hd/cors-subs", Row: "Cross-origin resource sharing: all subdomains trusted",
			Note: "Access-Control-Allow-Origin: https://*.evil.example trusts every subdomain"},
		{Path: "/hd/safe/cors-subs", Row: "Cross-origin resource sharing: all subdomains trusted", Safe: true,
			Note: "no Access-Control-Allow-Origin, so no cross-origin policy is exposed"},

		{Path: "/hd/csp-none", Row: "Content security policy: not enforced",
			Note: "serves HTML with no Content-Security-Policy header"},
		{Path: "/hd/safe/csp-enforced", Row: "Content security policy: not enforced", Safe: true,
			Note: "serves an enforcing Content-Security-Policy header"},

		{Path: "/hd/csp-click", Row: "Content security policy: allows clickjacking",
			Note: "CSP without frame-ancestors and no X-Frame-Options, so the page is framable"},
		{Path: "/hd/safe/csp-click", Row: "Content security policy: allows clickjacking", Safe: true,
			Note: "X-Frame-Options: DENY and frame-ancestors 'none' block framing"},

		{Path: "/hd/dup-cookie", Row: "Duplicate cookies set",
			Note: "two Set-Cookie headers set the same name to different values"},
		{Path: "/hd/safe/dup-cookie", Row: "Duplicate cookies set", Safe: true,
			Note: "a single Set-Cookie, so no name is set to conflicting values"},

		{Path: "/hd/cache-poison", Row: "Web cache poisoning",
			Note: "a cache keyed on the full URL serves a body built from X-Forwarded-Host, which it does not key"},
		{Path: "/hd/safe/cache-poison", Row: "Web cache poisoning", Safe: true,
			Note: "reflects X-Forwarded-Host too, but the cache keys on it, so no other request is served it"},
		{Path: "/hd/cache-poison-route/notice?msg=hello", Row: "Web cache poisoning",
			Note: "a cache keyed on the route only (query excluded) serves a body that reflects the msg parameter"},
		{Path: "/hd/safe/cache-poison-route/notice?msg=hello", Row: "Web cache poisoning", Safe: true,
			Note: "reflects msg too, but the cache keys on the full URL including the query"},

		{Path: "/hd/cache-poison-cookie", Row: "Web cache poisoning",
			RequestHeaders: map[string]string{"Cookie": "theme=light; display_name=alice"},
			Note:           "a cache keyed on the URL only serves a page personalised from the display_name cookie, so the first visitor's name is served to everyone"},
		{Path: "/hd/safe/cache-poison-cookie", Row: "Web cache poisoning", Safe: true,
			RequestHeaders: map[string]string{"Cookie": "theme=light; display_name=alice"},
			Note:           "personalises from the cookie identically, but the cache keys on the Cookie header (Vary: Cookie), so no visitor is served another's page"},

		{Path: "/hd/cache-decept", Row: "Web cache deception",
			Note: "a static-looking .css path returns the same dynamic body as the directory root"},
		{Path: "/hd/safe/cache-decept", Row: "Web cache deception", Safe: true,
			Note: "the static-looking path returns 404, not the dynamic body"},
	}
}

// registerHeaders serves this family's routes.
func registerHeaders(mux *http.ServeMux) {
	mux.HandleFunc("/hd/cors-unenc", hdCORSUnencrypted)
	mux.HandleFunc("/hd/safe/cors-unenc", hdSafeCORSUnencrypted)
	mux.HandleFunc("/hd/cors-subs", hdCORSSubs)
	mux.HandleFunc("/hd/safe/cors-subs", hdSafeCORSSubs)
	mux.HandleFunc("/hd/csp-none", hdCSPNone)
	mux.HandleFunc("/hd/safe/csp-enforced", hdSafeCSPEnforced)
	mux.HandleFunc("/hd/csp-click", hdCSPClick)
	mux.HandleFunc("/hd/safe/csp-click", hdSafeCSPClick)
	mux.HandleFunc("/hd/dup-cookie", hdDupCookie)
	mux.HandleFunc("/hd/safe/dup-cookie", hdSafeDupCookie)
	mux.HandleFunc("/hd/cache-poison", hdCachePoison)
	mux.HandleFunc("/hd/safe/cache-poison", hdSafeCachePoison)
	mux.HandleFunc("/hd/cache-poison-route/", hdCachePoisonRoute)
	mux.HandleFunc("/hd/safe/cache-poison-route/", hdSafeCachePoisonRoute)
	mux.HandleFunc("/hd/cache-poison-cookie", hdCachePoisonCookie)
	mux.HandleFunc("/hd/safe/cache-poison-cookie", hdSafeCachePoisonCookie)
	mux.HandleFunc("/hd/cache-decept", hdCacheDecept)
	mux.HandleFunc("/hd/cache-decept/", hdCacheDecept)
	mux.HandleFunc("/hd/safe/cache-decept", hdSafeCacheDecept)
	mux.HandleFunc("/hd/safe/cache-decept/", hdSafeCacheDeceptStatic)
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

// hdCORSSubs trusts every subdomain of the host by echoing a wildcard-subdomain
// ACAO. That literal value is what the passive all-subdomains classifier reads.
func hdCORSSubs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "https://*.evil.example")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":1}`))
}

// hdSafeCORSSubs exposes no cross-origin policy, so no subdomain is trusted.
func hdSafeCORSSubs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":1}`))
}

// ---------------------------------------------------------------------------
// CSP
// ---------------------------------------------------------------------------

// hdCSPNone serves HTML with no CSP header at all.
func hdCSPNone(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte("<html><body>account page</body></html>"))
}

// hdSafeCSPEnforced serves an enforcing CSP, so the policy is not "not enforced".
func hdSafeCSPEnforced(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	_, _ = w.Write([]byte("<html><body>account page</body></html>"))
}

// hdCSPClick has a CSP but no frame-ancestors directive and no X-Frame-Options,
// so the page can be framed.
func hdCSPClick(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	_, _ = w.Write([]byte("<html><body>account page</body></html>"))
}

// hdSafeCSPClick blocks framing with both X-Frame-Options and frame-ancestors.
func hdSafeCSPClick(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	_, _ = w.Write([]byte("<html><body>account page</body></html>"))
}

// ---------------------------------------------------------------------------
// Duplicate cookies
// ---------------------------------------------------------------------------

// hdDupCookie sets the same cookie name to two different values.
func hdDupCookie(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Set-Cookie", "session=alpha; Path=/")
	w.Header().Add("Set-Cookie", "session=beta; Path=/")
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte("<html><body>ok</body></html>"))
}

// hdSafeDupCookie sets a single cookie, so no name is set to conflicting values.
func hdSafeDupCookie(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Set-Cookie", "sid=single; Path=/")
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte("<html><body>ok</body></html>"))
}

// ---------------------------------------------------------------------------
// Web cache poisoning
// ---------------------------------------------------------------------------

// vaSharedCache is a minimal shared cache: entries live 60 seconds under whatever key the endpoint
// computes, and every response says HIT or MISS in X-Cache, as CDNs and reverse proxies do. Only
// what a key leaves out differs between the vulnerable endpoints and their twins.
type vaSharedCache struct {
	mu sync.Mutex
	m  map[string]vaCacheEntry
}

type vaCacheEntry struct {
	body    string
	expires time.Time
}

const vaCacheTTL = 60 * time.Second

func (c *vaSharedCache) serve(w http.ResponseWriter, key string, render func() string) {
	c.serveAs(w, key, "text/html", render)
}

// serveAs is serve with the answer's content type named, for the endpoints that answer JSON.
func (c *vaSharedCache) serveAs(w http.ResponseWriter, key, contentType string, render func() string) {
	now := time.Now()
	c.mu.Lock()
	if c.m == nil {
		c.m = map[string]vaCacheEntry{}
	}
	e, hit := c.m[key]
	if hit && now.After(e.expires) {
		hit = false
	}
	if !hit {
		// Expired entries are swept on the way past so the map cannot grow without bound.
		for k, old := range c.m {
			if now.After(old.expires) {
				delete(c.m, k)
			}
		}
		e = vaCacheEntry{body: render(), expires: now.Add(vaCacheTTL)}
		c.m[key] = e
	}
	c.mu.Unlock()
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=60")
	if hit {
		w.Header().Set("X-Cache", "HIT")
	} else {
		w.Header().Set("X-Cache", "MISS")
	}
	_, _ = w.Write([]byte(e.body))
}

// One cache per endpoint, so no endpoint can be served another's body.
var (
	cachePoisonHeaderStore     vaSharedCache
	cachePoisonHeaderSafeStore vaSharedCache
	cachePoisonRouteStore      vaSharedCache
	cachePoisonRouteSafeStore  vaSharedCache
	cachePoisonCookieStore     vaSharedCache
	cachePoisonCookieSafeStore vaSharedCache
)

// cookieGreetingBody personalises the page from the display_name cookie, escaped: the defect these
// endpoints carry is whose page is served, not markup injection.
func cookieGreetingBody(r *http.Request) string {
	name := "guest"
	if c, err := r.Cookie("display_name"); err == nil && c.Value != "" {
		name = c.Value
	}
	return "<html><body><p>Signed in as " + html.EscapeString(name) + "</p></body></html>"
}

// hdCachePoisonCookie keys on the request URI alone while the body is built from a cookie, which is
// the "personalised page cached as public" defect: one request's cookie decides every later visitor's page.
func hdCachePoisonCookie(w http.ResponseWriter, r *http.Request) {
	cachePoisonCookieStore.serve(w, r.RequestURI, func() string { return cookieGreetingBody(r) })
}

// hdSafeCachePoisonCookie personalises identically but keys on the Cookie header too, which is what
// Vary: Cookie makes a shared cache do, so a request is only ever served a page built from its own cookies.
func hdSafeCachePoisonCookie(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Vary", "Cookie")
	cachePoisonCookieSafeStore.serve(w, r.RequestURI+"|"+r.Header.Get("Cookie"), func() string { return cookieGreetingBody(r) })
}

func assetHostBody(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = "static.vulnapp.local"
	}
	return `<html><head><script src="https://` + html.EscapeString(host) + `/app.js"></script></head><body>home</body></html>`
}

// hdCachePoison keys on the full request URI but builds the page from X-Forwarded-Host, which is
// not in the key: a request carrying it plants its body for every later request to that URI.
func hdCachePoison(w http.ResponseWriter, r *http.Request) {
	cachePoisonHeaderStore.serve(w, r.RequestURI, func() string { return assetHostBody(r) })
}

// hdSafeCachePoison reflects X-Forwarded-Host identically, but keys on it (what Vary:
// X-Forwarded-Host achieves), so a request without the header never receives a body built with it.
func hdSafeCachePoison(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Vary", "X-Forwarded-Host")
	cachePoisonHeaderSafeStore.serve(w, r.RequestURI+"|"+r.Header.Get("X-Forwarded-Host"),
		func() string { return assetHostBody(r) })
}

func noticeBody(r *http.Request) string {
	return "<html><body><p>Notice: " + html.EscapeString(r.URL.Query().Get("msg")) + "</p></body></html>"
}

// hdCachePoisonRoute keys on the raw path alone, as a cache configured to ignore the query string
// does; path parameters (";x=y") are part of that raw path, as in a servlet container's request URI.
// The page reflects the msg query parameter, so any msg value is served to every visitor of the route.
func hdCachePoisonRoute(w http.ResponseWriter, r *http.Request) {
	key, _, _ := strings.Cut(r.RequestURI, "?")
	cachePoisonRouteStore.serve(w, key, func() string { return noticeBody(r) })
}

// hdSafeCachePoisonRoute reflects msg identically but keys on the full URI, query included.
func hdSafeCachePoisonRoute(w http.ResponseWriter, r *http.Request) {
	cachePoisonRouteSafeStore.serve(w, r.RequestURI, func() string { return noticeBody(r) })
}

// ---------------------------------------------------------------------------
// Web cache deception
// ---------------------------------------------------------------------------

// hdCacheDecept serves the same dynamic, per-user body on the root and on any
// static-looking suffix (e.g. /nonexistent.css), which is the deception signature.
func hdCacheDecept(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write([]byte(hdDynamicBody))
}

// hdSafeCacheDecept serves the dynamic body on the exact path (the "original"),
// matching the vulnerable twin's seeding.
func hdSafeCacheDecept(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write([]byte(hdDynamicBody))
}

// hdSafeCacheDeceptStatic answers the static-looking suffix with a 404 rather than
// the dynamic body, so the decorated URL is not served sensitive content.
func hdSafeCacheDeceptStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("<html><body>not found</body></html>"))
}

// hdCORSUnencrypted reflects whatever Origin arrives, which is the defect: a cleartext origin is
// trusted just as readily as a secure one, so anyone able to tamper with plain HTTP can read the
// response cross-origin.
func hdCORSUnencrypted(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"balance":1000}`)
}

// hdSafeCORSUnencrypted reflects an Origin only when it is already secure. It still reflects, so a
// detector keying on "the Origin came back" rather than on the scheme is caught here.
func hdSafeCORSUnencrypted(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); strings.HasPrefix(origin, "https://") {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"balance":1000}`)
}
