package vulnapp

// passive posture: response headers, cookies, forms and transport.
//
// One file per check family, holding that family's vulnerable endpoints, their safe counterparts and
// the routes serving both. The manifest entries returned here are appended to Vulnerabilities() by
// familyEndpoints in vulnapp.go; the routes are registered by familyRegistrars.
//
// The contract every entry has to meet:
//
//   - Row must match a catalog row name in internal/scanner exactly. The runtime test resolves every
//     Row against the shipped registry before auditing anything, so a typo fails loudly rather than
//     exempting the endpoint from its own assertion.
//   - A vulnerable endpoint needs a safe twin: same Row, Safe: true, reflecting or echoing the same
//     input WITHOUT the defect. That twin is what catches a detector firing on reflection alone.
//     Where no such thing can exist, say why in SafeTwinNotApplicable rather than omitting it.
//   - Handlers must be the real mechanism, not a payload matcher. An endpoint that pattern-matches
//     the payloads it expects grades the check against the fixture author's guesses and passes
//     whether or not the detector works.
//
// Corresponding scanner descriptors: PassivePostureCheckDescriptors.
//
// Three of the fifteen rows are scoped to TLS responses
// (CacheableHTTPSResponse, MixedContent, StrictTransportSecurityNotEnforced) and one needs a request
// header the harness cannot inject (RequestURLOverrides). The harness serves only plain HTTP with
// exchange.TLS always false, so those four cannot be demonstrated here; they are reported, not
// faked. Unencrypted communications fires on plain HTTP (it is the TLS-absence row) but has no safe
// twin for the same reason, so it is declared with SafeTwinNotApplicable.

import (
	"fmt"
	"net/http"
	"strings"
)

// postureEndpoints returns this family's manifest entries.
func postureEndpoints() []Endpoint {
	return []Endpoint{
		// Cleartext submission of password: a password form posting to an http:// action.
		{Path: "/px/cleartext", Row: "Cleartext submission of password",
			Note: "form with a password field whose action is an http:// URL"},
		{Path: "/px/safe/cleartext", Row: "Cleartext submission of password", Safe: true,
			Note: "same form but the action is https://, so the password is not submitted in cleartext"},

		// Password field with autocomplete enabled.
		{Path: "/px/autocomplete", Row: "Password field with autocomplete enabled",
			Note: "form with a password field and no autocomplete=off"},
		{Path: "/px/safe/autocomplete", Row: "Password field with autocomplete enabled", Safe: true,
			Note: "password field carries autocomplete=off"},

		// Password submitted using GET method.
		{Path: "/px/getpw", Row: "Password submitted using GET method",
			Note: "form with a password field and method GET"},
		{Path: "/px/safe/getpw", Row: "Password submitted using GET method", Safe: true,
			Note: "form with a password field but method POST"},

		// Password value set in cookie.
		{Path: "/px/pwdcookie", Row: "Password value set in cookie",
			Note: "cookie named user_password carries a value"},
		{Path: "/px/safe/pwdcookie", Row: "Password value set in cookie", Safe: true,
			Note: "cookie is named session and carries no password-like value"},

		// Password returned in URL query string.
		{Path: "/px/pwdquery?password=hunter2", Row: "Password returned in URL query string",
			Note: "request URL carries a password-like parameter with a value"},
		{Path: "/px/safe/pwdquery?user=alice", Row: "Password returned in URL query string", Safe: true,
			Note: "request URL has no password-like parameter"},

		// Cross-domain POST.
		{Path: "/px/xdomain", Row: "Cross-domain POST",
			Note: "POST form whose action points to a different host"},
		{Path: "/px/safe/xdomain", Row: "Cross-domain POST", Safe: true,
			Note: "POST form whose action is same-origin"},

		// Cross-domain Referer leakage.
		{Path: "/px/referer?token=seed", Row: "Cross-domain Referer leakage",
			Note: "page URL has a query string and links off-site with no Referrer-Policy"},
		{Path: "/px/safe/referer", Row: "Cross-domain Referer leakage", Safe: true,
			Note: "page URL has no query string, so nothing leaks in the Referer"},

		// Long redirection response.
		{Path: "/px/longredirect", Row: "Long redirection response",
			Note: "a 301 redirect carrying a body larger than the long-redirect threshold"},
		{Path: "/px/safe/longredirect", Row: "Long redirection response", Safe: true,
			Note: "a 301 redirect with a short courtesy body"},

		// Multiple content types specified.
		{Path: "/px/multict", Row: "Multiple content types specified",
			Note: "Content-Type header lists two media types"},
		{Path: "/px/safe/multict", Row: "Multiple content types specified", Safe: true,
			Note: "Content-Type declares a single media type"},

		// Content type is not specified.
		{Path: "/px/noct", Row: "Content type is not specified",
			Note: "a body is returned with no Content-Type header"},
		{Path: "/px/safe/noct", Row: "Content type is not specified", Safe: true,
			Note: "the response declares an explicit Content-Type"},

		// Unencrypted communications: fires on every plain-HTTP exchange, which is exactly what the
		// row describes (use over an unencrypted connection). No safe twin can exist because the
		// harness serves only HTTP, so there is no encrypted endpoint to stay silent.
		// Strict transport security not enforced: an HTTPS response with no HSTS header. The safe
		// twin sends a committing header (max-age above zero), so a detector keying on evidence
		// rather than on "it is TLS" stays quiet.
		{Path: "/px/hsts", Row: "Strict transport security not enforced", TLS: true,
			Note: "served over https:// with no Strict-Transport-Security header"},
		{Path: "/px/safe/hsts", Row: "Strict transport security not enforced", TLS: true, Safe: true,
			Note: "same TLS response but with a committing Strict-Transport-Security header"},

		// Cacheable HTTPS response: an HTTPS response with no no-store directive. The safe twin sets
		// Cache-Control: no-store, which is the one directive that stops the browser writing it to disk.
		{Path: "/px/cacheable", Row: "Cacheable HTTPS response", TLS: true,
			Note: "served over https:// with no no-store directive"},
		{Path: "/px/safe/cacheable", Row: "Cacheable HTTPS response", TLS: true, Safe: true,
			Note: "same TLS response but with Cache-Control: no-store"},

		// Mixed content: an HTTPS page referencing a cleartext http:// subresource. The safe twin
		// references only same-origin (relative) resources, so nothing crosses the scheme boundary.
		{Path: "/px/mixed", Row: "Mixed content", TLS: true,
			Note: "an HTTPS page loads a cleartext http:// script subresource"},
		{Path: "/px/safe/mixed", Row: "Mixed content", TLS: true, Safe: true,
			Note: "an HTTPS page that loads only same-origin resources"},

		// Request URL override: the captured request carries an X-Original-URL header. The safe twin
		// sends no such header, so a detector reading the request line alone would not fire here.
		{Path: "/px/override", Row: "Request URL override",
			RequestHeaders: map[string]string{"X-Original-URL": "/px/override"},
			Note:           "the captured request carries an X-Original-URL override header"},
		{Path: "/px/safe/override", Row: "Request URL override", Safe: true,
			Note: "the captured request carries no URL-override header"},

		// Unencrypted communications: fires on every plain-HTTP exchange, which is exactly what the
		// row describes (use over an unencrypted connection). No safe twin can exist because the
		// harness serves only HTTP, so there is no encrypted endpoint to stay silent.
		{Path: "/px/unencrypted", Row: "Unencrypted communications",
			SafeTwinNotApplicable: "the runtime harness serves only plain HTTP (exchange.TLS is always false), so no endpoint can present an encrypted response to silence this per-host row",
			Note:                  "served over http://, so the application is used over an unencrypted connection"},
	}
}

// registerPosture serves this family's routes.
func registerPosture(mux *http.ServeMux) {
	// Cleartext submission of password: the defect is the action scheme, so the twins differ only
	// in http:// vs https://. autocomplete=off keeps the password row from also firing.
	mux.HandleFunc("/px/cleartext", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><form action="http://auth.internal.example/login" method="POST"><input type="password" name="pw" autocomplete="off"></form></body></html>`)
	})
	mux.HandleFunc("/px/safe/cleartext", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><form action="https://auth.internal.example/login" method="POST"><input type="password" name="pw" autocomplete="off"></form></body></html>`)
	})

	// Password field with autocomplete enabled: a password input with no autocomplete=off.
	mux.HandleFunc("/px/autocomplete", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><form action="https://app.internal.example/ac" method="POST"><input type="password" name="pw"></form></body></html>`)
	})
	mux.HandleFunc("/px/safe/autocomplete", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><form action="https://app.internal.example/ac" method="POST"><input type="password" name="pw" autocomplete="off"></form></body></html>`)
	})

	// Password submitted using GET method: method GET on a password form; twin uses POST.
	mux.HandleFunc("/px/getpw", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><form action="https://app.internal.example/gp" method="GET"><input type="password" name="pw" autocomplete="off"></form></body></html>`)
	})
	mux.HandleFunc("/px/safe/getpw", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><form action="https://app.internal.example/gp" method="POST"><input type="password" name="pw" autocomplete="off"></form></body></html>`)
	})

	// Password value set in cookie: a Set-Cookie with a password-like name.
	mux.HandleFunc("/px/pwdcookie", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "user_password", Value: "hunter2-secret"})
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>ok</body></html>`)
	})
	mux.HandleFunc("/px/safe/pwdcookie", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>ok</body></html>`)
	})

	// Password returned in URL query string: the request URL query carries a password-like param.
	mux.HandleFunc("/px/pwdquery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>query seen</body></html>`)
	})
	mux.HandleFunc("/px/safe/pwdquery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>query seen</body></html>`)
	})

	// Cross-domain POST: a POST form whose action host differs from the page host.
	mux.HandleFunc("/px/xdomain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><form action="http://other.example/collect" method="POST"><input type="text" name="data"></form></body></html>`)
	})
	mux.HandleFunc("/px/safe/xdomain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><form action="/px/safe/xdomain" method="POST"><input type="text" name="data"></form></body></html>`)
	})

	// Cross-domain Referer leakage: the page URL has a query string (so RawQuery is set) and links
	// off-site. The safe twin drops the query string, which is what stops the leak.
	mux.HandleFunc("/px/referer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><a href="https://other.example/page">external</a></body></html>`)
	})
	mux.HandleFunc("/px/safe/referer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><a href="https://other.example/page">external</a></body></html>`)
	})

	// Long redirection response: a 3xx whose body exceeds the long-redirect threshold. The safe
	// twin is a 3xx with only a short courtesy stub.
	mux.HandleFunc("/px/longredirect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusMovedPermanently)
		fmt.Fprint(w, strings.Repeat("This content should have been served at the redirected location. ", 80))
	})
	mux.HandleFunc("/px/safe/longredirect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusMovedPermanently)
		fmt.Fprint(w, "<p>moved permanently</p>")
	})

	// Multiple content types specified: one Content-Type header listing two media types.
	mux.HandleFunc("/px/multict", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html, application/json")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>data</body></html>`)
	})
	mux.HandleFunc("/px/safe/multict", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>data</body></html>`)
	})

	// Content type is not specified: a body with no declared media type. Setting Content-Type to an
	// empty string suppresses Go's content sniffing (the key is present, so Write skips detection)
	// yet records no value, so the response reaches the client with no Content-Type line of value.
	mux.HandleFunc("/px/noct", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "")
		fmt.Fprint(w, "<!DOCTYPE html><html><body>untyped</body></html>")
	})
	mux.HandleFunc("/px/safe/noct", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!DOCTYPE html><html><body>typed</body></html>")
	})

	// Strict transport security not enforced: a TLS response with no HSTS header, and no other
	// transport defect. Cache-Control: no-store rules out the cacheable-HTTPS row, and the page
	// references no cleartext subresource so the mixed-content row cannot fire here either.
	mux.HandleFunc("/px/hsts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><p>secure page</p></body></html>`)
	})
	mux.HandleFunc("/px/safe/hsts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><p>secure page</p></body></html>`)
	})

	// Cacheable HTTPS response: a TLS response with no no-store directive, and no other transport
	// defect. A committing HSTS header rules out the HSTS row, and no cleartext subresource rules
	// out the mixed-content row.
	mux.HandleFunc("/px/cacheable", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><p>account</p></body></html>`)
	})
	mux.HandleFunc("/px/safe/cacheable", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><p>account</p></body></html>`)
	})

	// Mixed content: a TLS page referencing one cleartext http:// subresource, and no other transport
	// defect. A committing HSTS header and Cache-Control: no-store rule out the other two rows, so
	// only the mixed-content condition is present. The safe twin references only a same-origin
	// (relative) resource, so nothing crosses the scheme boundary.
	mux.HandleFunc("/px/mixed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><script src="http://mixed.internal.example/lib.js"></script></body></html>`)
	})
	mux.HandleFunc("/px/safe/mixed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><script src="/px/safe/mixed.js"></script></body></html>`)
	})

	// Request URL override: the captured request carries X-Original-URL (set by the harness from the
	// Endpoint.RequestHeaders field), which the check reads from the request. The safe twin sends none.
	mux.HandleFunc("/px/override", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><p>admin</p></body></html>`)
	})
	mux.HandleFunc("/px/safe/override", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><p>admin</p></body></html>`)
	})

	// Unencrypted communications: served over plain HTTP, which is the condition the row reports.
	mux.HandleFunc("/px/unencrypted", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body><p>served over plain HTTP</p></body></html>`)
	})
}
