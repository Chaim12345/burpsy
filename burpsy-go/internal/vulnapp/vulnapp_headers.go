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
// poisoning endpoint keys its store on the path only, so the cache-buster the
// scanner appends is ignored and a follow-up without the unkeyed header is served
// the poisoned body. The deception endpoint serves the same dynamic body on a
// static-looking .css path — exactly the signature the check looks for.

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// poisonCache is keyed on the request path only. Ignoring the cache-buster query
// parameter is the defect: a follow-up request that never sent the unkeyed header
// is served the poisoned response, which is web cache poisoning.
//
// Entries are written only when a probe carries an unkeyed header and expired
// immediately, so no entry outlives a single audit pass and the safe twin (which
// holds no shared state at all) can never inherit a body it did not produce.
var poisonCache sync.Map

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
			Note: "a cache keyed only on the path reflects an unkeyed header into a cacheable body"},
		{Path: "/hd/safe/cache-poison", Row: "Web cache poisoning", Safe: true,
			Note: "reflects the unkeyed header into its own response only; no cross-request cache"},

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
func hdCachePoison(w http.ResponseWriter, r *http.Request) {
	if v, ok := poisonCache.Load(r.URL.Path); ok {
		writePoisonResponse(w, v.(string))
		return
	}
	val := unkeyedHeader(r)
	if val == "" {
		val = "default"
	}
	body := "<html><body>served: " + val + "</body></html>"
	if val != "default" {
		// A probe carrying an unkeyed header poisoned this path keyed only on the
		// path, so the follow-up (which sends no such header) is served it from the
		// cache. The entry persists for the process; the safe twin uses a distinct
		// path and holds no state, so it can never read this body.
		poisonCache.Store(r.URL.Path, body)
	}
	writePoisonResponse(w, body)
}

// hdSafeCachePoison is stateless: it reflects the unkeyed header into THIS
// response only. A follow-up request sends no such header and receives only
// "default", so the poisoning check cannot find its injected value in a response
// that never sent it. No shared cache means no cross-request contamination.
func hdSafeCachePoison(w http.ResponseWriter, r *http.Request) {
	val := unkeyedHeader(r)
	if val == "" {
		val = "default"
	}
	writePoisonResponse(w, "<html><body>served: "+val+"</body></html>")
}

// unkeyedHeader returns the value of the first of the headers a front-end cache
// commonly excludes from its key — the inputs the poisoning probes inject.
func unkeyedHeader(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-Host", "X-Forwarded-Scheme", "X-Original-URL"} {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	return ""
}

func writePoisonResponse(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write([]byte(body))
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
