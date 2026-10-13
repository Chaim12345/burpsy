package vulnapp

// passive analysis: cookie flags, header attributes, information disclosure, CSP.
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
// Corresponding scanner descriptors: PassiveAnalysisCheckDescriptors.
//
// Three catalog rows in this family cannot be demonstrated against the runtime target and are
// deliberately omitted (not faked) — see the report for the harness-level reason:
//   - "Cookie scoped to parent domain": ScopedToParentDomain needs the response host to be a domain
//     with a registrable parent; the harness serves on 127.0.0.1 (an IP), so no Domain attribute can
//     be a real parent of it.

// The other two previously-omitted rows ("TLS cookie without secure flag set" and
// "Spoofable client IP address") are now demonstrable: the harness gained TLS-seeded exchanges
// (Endpoint.TLS) and request-header capture (Endpoint.RequestHeaders), which both checks require.

import "net/http"

// analysisEndpoints returns this family's manifest entries.
func analysisEndpoints() []Endpoint {
	return []Endpoint{
		// --- cookies ---------------------------------------------------------
		{Path: "/an/cookie-no-httponly", Row: "Cookie without HttpOnly flag set",
			Note: "sets a session cookie with no HttpOnly attribute"},
		{Path: "/an/safe/cookie-httponly", Row: "Cookie without HttpOnly flag set", Safe: true,
			Note: "same cookie issued with the HttpOnly attribute set"},
		{Path: "/an/cookie-no-secure", Row: "TLS cookie without secure flag set", TLS: true,
			Note: "over TLS, sets a session cookie with no Secure attribute"},
		{Path: "/an/safe/cookie-secure", Row: "TLS cookie without secure flag set", TLS: true, Safe: true,
			Note: "over TLS, same cookie issued with the Secure attribute set"},

		{Path: "/an/spoofable-ip", Row: "Spoofable client IP address",
			RequestHeaders: map[string]string{"X-Forwarded-For": "10.1.2.3"},
			Note:           "request carries an X-Forwarded-For the app may trust as the client IP"},
		{Path: "/an/safe/spoofable-ip", Row: "Spoofable client IP address", Safe: true,
			Note: "same request with no client-IP header"},

		// --- response / header attributes -----------------------------------
		{Path: "/an/frameable", Row: "Frameable response (potential Clickjacking)",
			Note: "HTML with no X-Frame-Options and no CSP frame-ancestors"},
		{Path: "/an/safe/framed", Row: "Frameable response (potential Clickjacking)", Safe: true,
			Note: "same page carrying X-Frame-Options: DENY"},
		{Path: "/an/frameable/any-ancestor", Row: "Frameable response (potential Clickjacking)",
			Note: "X-Frame-Options: DENY overridden by CSP frame-ancestors *, which a browser obeys instead " +
				"(0vzb.32, observed in Chrome)"},
		{Path: "/an/safe/framed/conflicting", Row: "Frameable response (potential Clickjacking)", Safe: true,
			Note: "two X-Frame-Options headers, SAMEORIGIN and DENY: a conflict a browser resolves by blocking " +
				"(0vzb.32, observed in Chrome)"},

		{Path: "/an/xss-filter-disabled", Row: "Browser cross-site scripting filter disabled",
			Note: "sends X-XSS-Protection: 0"},
		{Path: "/an/safe/xss-filter", Row: "Browser cross-site scripting filter disabled", Safe: true,
			Note: "sends X-XSS-Protection: 1; mode=block"},

		{Path: "/an/no-charset", Row: "HTML does not specify charset",
			Note: "text/html response with no charset in header or meta"},
		{Path: "/an/safe/charset", Row: "HTML does not specify charset", Safe: true,
			Note: "same response declaring charset=utf-8"},

		{Path: "/an/bad-charset", Row: "HTML uses unrecognized charset",
			Note: "declares a charset no browser implements (iso-99999)"},
		{Path: "/an/safe/charset-known", Row: "HTML uses unrecognized charset", Safe: true,
			Note: "declares a recognised charset (utf-8)"},

		{Path: "/an/wrong-content-type", Row: "Content type incorrectly stated",
			Note: "Content-Type text/plain but body sniffs as HTML"},
		{Path: "/an/safe/content-type", Row: "Content type incorrectly stated", Safe: true,
			Note: "Content-Type text/html matching an HTML body"},

		{Path: "/an/cross-domain-script", Row: "Cross-domain script include",
			Note: "page loads a <script> from another domain"},
		{Path: "/an/safe/same-domain-script", Row: "Cross-domain script include", Safe: true,
			Note: "page loads a same-origin <script>"},

		// --- request-URL attributes (read from the captured request) --------
		{Path: "/an/session?sid=abc123def456", Row: "Session token in URL",
			Note: "session id travels in the query string (sid=)"},
		{Path: "/an/safe/session?user=alice", Row: "Session token in URL", Safe: true,
			Note: "query carries a non-session parameter (user=)"},

		{Path: "/an/b64-param?token=Lm9Np0Qr1St2Uv3Wx4Yz5Ab6Cd7Ef8Gh", Row: "Base64-encoded data in parameter",
			Note: "query carries base64-encoded random-looking data (token=)"},
		{Path: "/an/safe/b64-param?name=alice", Row: "Base64-encoded data in parameter", Safe: true,
			Note: "query carries an ordinary word, not base64"},

		// --- information disclosure (read from the response body) -----------
		{Path: "/an/disclosure/email", Row: "Email addresses disclosed",
			Note: "body contains a real-looking email address"},
		{Path: "/an/safe/disclosure/email", Row: "Email addresses disclosed", Safe: true,
			Note: "body mentions contact with no address"},

		{Path: "/an/disclosure/private-ip", Row: "Private IP addresses disclosed",
			Note: "body contains an RFC 1918 internal address (10.0.0.5)"},
		{Path: "/an/safe/disclosure/private-ip", Row: "Private IP addresses disclosed", Safe: true,
			Note: "body references an RFC 5737 documentation address, not a private range"},

		{Path: "/an/disclosure/ssn", Row: "Social security numbers disclosed",
			Note: "body contains a well-formed SSN-shaped number"},
		{Path: "/an/safe/disclosure/ssn", Row: "Social security numbers disclosed", Safe: true,
			Note: "body has no AAA-GG-SSSS shaped number"},

		{Path: "/an/disclosure/cc", Row: "Credit card numbers disclosed",
			Note: "body contains a Luhn-valid 16-digit PAN"},
		{Path: "/an/safe/disclosure/cc", Row: "Credit card numbers disclosed", Safe: true,
			Note: "body has no long digit run"},

		{Path: "/an/disclosure/key", Row: "Private key disclosed",
			Note: "body contains a PEM private-key armour header (test material)"},
		{Path: "/an/safe/disclosure/key", Row: "Private key disclosed", Safe: true,
			Note: "body shows a public certificate, never a PRIVATE KEY header"},

		{Path: "/an/disclosure/jwks", Row: "Json Web Key Set disclosed",
			Note: "body is a JSON Web Key Set with a kty-bearing keys array"},
		{Path: "/an/safe/disclosure/jwks", Row: "Json Web Key Set disclosed", Safe: true,
			Note: "body is JSON with no keys array"},

		{Path: "/an/disclosure/dir", Row: "Directory listing",
			Note: "body is a server-generated directory listing"},
		{Path: "/an/safe/disclosure/dir", Row: "Directory listing", Safe: true,
			Note: "body reports no such directory"},

		{Path: "/an/disclosure/source", Row: "Source code disclosure",
			Note: "body leaks a server-side scriptlet delimiter"},
		{Path: "/an/safe/disclosure/source", Row: "Source code disclosure", Safe: true,
			Note: "body reports a rendered error with no scriptlet"},

		// --- view state / serialized objects -------------------------------
		{Path: "/an/viewstate", Row: "ASP.NET ViewState without MAC enabled",
			Note: "form carries a LOSFormatter __VIEWSTATE with no trailing MAC"},
		{Path: "/an/safe/viewstate", Row: "ASP.NET ViewState without MAC enabled", Safe: true,
			Note: "same form carries a __VIEWSTATE whose tail looks digest-like (MAC present)"},

		{Path: "/an/serialized", Row: "Serialized object in HTTP message",
			Note: "response body embeds a Java serialized-object magic (base64)"},
		{Path: "/an/safe/serialized", Row: "Serialized object in HTTP message", Safe: true,
			Note: "response body carries no serialization magic"},

		// --- CSP directive evaluation --------------------------------------
		{Path: "/an/csp/allowlisted", Row: "Content security policy: allowlisted script resources",
			Note: "script-src allowlists an external host"},
		{Path: "/an/safe/csp/allowlisted", Row: "Content security policy: allowlisted script resources", Safe: true,
			Note: "script-src restricts to 'self'"},

		{Path: "/an/csp/untrusted-script", Row: "Content security policy: allows untrusted script execution",
			Note: "script-src allows 'unsafe-inline'"},
		{Path: "/an/safe/csp/untrusted-script", Row: "Content security policy: allows untrusted script execution", Safe: true,
			Note: "script-src 'self' only"},

		{Path: "/an/csp/untrusted-style", Row: "Content security policy: allows untrusted style execution",
			Note: "style-src allows 'unsafe-inline'"},
		{Path: "/an/safe/csp/untrusted-style", Row: "Content security policy: allows untrusted style execution", Safe: true,
			Note: "style-src 'self' only"},

		{Path: "/an/csp/form-hijack", Row: "Content security policy: allows form hijacking",
			Note: "policy sets no form-action, so forms are unrestricted"},
		{Path: "/an/safe/csp/form-hijack", Row: "Content security policy: allows form hijacking", Safe: true,
			Note: "policy restricts form-action to 'self'"},

		{Path: "/an/csp/malformed", Row: "Content security policy: malformed syntax",
			Note: "policy declares script-src with no source expressions"},
		{Path: "/an/safe/csp/malformed", Row: "Content security policy: malformed syntax", Safe: true,
			Note: "policy is syntactically valid (default-src 'self')"},
	}
}

// registerAnalysis serves this family's routes.
func registerAnalysis(mux *http.ServeMux) {
	// Cookie: missing HttpOnly vs set.
	mux.HandleFunc("/an/cookie-no-httponly", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456; Path=/")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/an/safe/cookie-httponly", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456; HttpOnly; Path=/")
		_, _ = w.Write([]byte("ok"))
	})
	// Cookie: missing Secure (over TLS) vs Secure set.
	mux.HandleFunc("/an/cookie-no-secure", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456; Path=/")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/an/safe/cookie-secure", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456; Secure; Path=/")
		_, _ = w.Write([]byte("ok"))
	})

	// Spoofable client IP: the defect lives in the captured request's X-Forwarded-For header,
	// supplied by Endpoint.RequestHeaders. The handler itself is inert; it just answers.
	mux.HandleFunc("/an/spoofable-ip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/an/safe/spoofable-ip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// Frameable vs X-Frame-Options: DENY.
	mux.HandleFunc("/an/frameable", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>frameable content</body></html>"))
	})
	mux.HandleFunc("/an/safe/framed", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>protected content</body></html>"))
	})

	mux.HandleFunc("/an/frameable/any-ancestor", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors *")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>frameable content</body></html>"))
	})
	mux.HandleFunc("/an/safe/framed/conflicting", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("X-Frame-Options", "SAMEORIGIN")
		w.Header().Add("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>protected content</body></html>"))
	})

	// X-XSS-Protection: 0 vs 1; mode=block.
	mux.HandleFunc("/an/xss-filter-disabled", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-XSS-Protection", "0")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/an/safe/xss-filter", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		_, _ = w.Write([]byte("ok"))
	})

	// HTML charset: none vs utf-8.
	mux.HandleFunc("/an/no-charset", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>no charset declared</body></html>"))
	})
	mux.HandleFunc("/an/safe/charset", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>charset declared</body></html>"))
	})

	// HTML charset: unrecognised vs recognised.
	mux.HandleFunc("/an/bad-charset", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=iso-99999")
		_, _ = w.Write([]byte("<html><body>x</body></html>"))
	})
	mux.HandleFunc("/an/safe/charset-known", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>x</body></html>"))
	})

	// Content-Type mismatch: text/plain body that sniffs as HTML.
	mux.HandleFunc("/an/wrong-content-type", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>this is actually html</body></html>"))
	})
	mux.HandleFunc("/an/safe/content-type", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>this is html</body></html>"))
	})

	// Cross-domain script include vs same-origin.
	mux.HandleFunc("/an/cross-domain-script", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script src="https://cdn.example.com/lib.js"></script></body></html>`))
	})
	mux.HandleFunc("/an/safe/same-domain-script", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script src="/an/local/app.js"></script></body></html>`))
	})

	// Session token in URL: the defect is in the request query string, read from the captured request.
	mux.HandleFunc("/an/session", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("dashboard"))
	})
	mux.HandleFunc("/an/safe/session", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("dashboard"))
	})

	// Base64 in parameter: likewise read from the request query string.
	mux.HandleFunc("/an/b64-param", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("decoded below"))
	})
	mux.HandleFunc("/an/safe/b64-param", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("decoded below"))
	})

	// --- disclosure bank (response body) -----------------------------------
	mux.HandleFunc("/an/disclosure/email", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Contact the administrator at admin@example.com for help."))
	})
	mux.HandleFunc("/an/safe/disclosure/email", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Contact the administrator for help."))
	})

	mux.HandleFunc("/an/disclosure/private-ip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Backend service is reachable at 10.0.0.5 on the internal network."))
	})
	mux.HandleFunc("/an/safe/disclosure/private-ip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Backend service is described at 203.0.113.10 (documentation range)."))
	})

	mux.HandleFunc("/an/disclosure/ssn", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Customer record SSN 123-45-6789 is on file."))
	})
	mux.HandleFunc("/an/safe/disclosure/ssn", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Customer record is on file."))
	})

	mux.HandleFunc("/an/disclosure/cc", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Payment card 4539578763621486 was charged."))
	})
	mux.HandleFunc("/an/safe/disclosure/cc", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Payment processed, order 7781."))
	})

	// PEM private-key armour. The body is clearly labelled test material; only the armour header
	// is what the detector keys on. No real key is present.
	mux.HandleFunc("/an/disclosure/key", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("-----BEGIN RSA PRIVATE KEY-----\n" +
			"MIIEowIBAAKCAQEAt3stfixture-not-a-real-key-please-ignore\n" +
			"-----END RSA PRIVATE KEY-----\n"))
	})
	mux.HandleFunc("/an/safe/disclosure/key", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Public certificate:\n-----BEGIN CERTIFICATE-----\n" +
			"MIIBfixture-not-a-real-cert-please-ignore\n-----END CERTIFICATE-----\n"))
	})

	mux.HandleFunc("/an/disclosure/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"test-key","n":"0a1b2c3d","e":"AQAB"}]}`))
	})
	mux.HandleFunc("/an/safe/disclosure/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","count":3}`))
	})

	mux.HandleFunc("/an/disclosure/dir", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Index of /an/uploads\n\nfile1.txt  file2.txt  notes.md"))
	})
	mux.HandleFunc("/an/safe/disclosure/dir", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("No such directory."))
	})

	mux.HandleFunc("/an/disclosure/source", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Error: <% out.println(\"leaked template source\"); %>"))
	})
	mux.HandleFunc("/an/safe/disclosure/source", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Error: template rendered successfully."))
	})

	// --- view state / serialized objects -----------------------------------
	mux.HandleFunc("/an/viewstate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// /wEFAQAA decodes to the LOSFormatter signature (0xFF 0x01) plus a 4-byte graph and no
		// room for a trailing digest, so the MAC heuristic reports no MAC.
		_, _ = w.Write([]byte(`<form><input type="hidden" name="__VIEWSTATE" value="/wEFAQAA"></form>`))
	})
	mux.HandleFunc("/an/safe/viewstate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// 26 bytes: signature + graph + 20 distinct trailing bytes that read as a digest, so the
		// MAC heuristic reports a MAC present.
		_, _ = w.Write([]byte(`<form><input type="hidden" name="__VIEWSTATE" value="/wEFAQAAAAECAwQFBgcICQoLDA0ODxAREhM="></form>`))
	})

	mux.HandleFunc("/an/serialized", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("state=rO0ABXNyABFjb20uZXhhbXBsZS5PYmplY3QAAAAAAAAAAAA="))
	})
	mux.HandleFunc("/an/safe/serialized", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("state=plaintext-object-graph"))
	})

	// --- CSP directive evaluation -----------------------------------------
	mux.HandleFunc("/an/csp/allowlisted", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src https://cdn.example.com 'self'")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/an/safe/csp/allowlisted", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'self'")
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/an/csp/untrusted-script", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'unsafe-inline'")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/an/safe/csp/untrusted-script", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'self'")
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/an/csp/untrusted-style", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "style-src 'unsafe-inline'")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/an/safe/csp/untrusted-style", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "style-src 'self'")
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/an/csp/form-hijack", func(w http.ResponseWriter, _ *http.Request) {
		// No form-action directive at all: forms are unrestricted.
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/an/safe/csp/form-hijack", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "form-action 'self'")
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/an/csp/malformed", func(w http.ResponseWriter, _ *http.Request) {
		// script-src with no source expressions is a malformed directive.
		w.Header().Set("Content-Security-Policy", "script-src")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/an/safe/csp/malformed", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		_, _ = w.Write([]byte("ok"))
	})
}
