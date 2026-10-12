// Package vulnapp is a deliberately vulnerable HTTP application, and a machine-readable
// declaration of what it is vulnerable to.
//
// # Why this is a package and not a cmd
//
// It began as cmd/demo-target, a binary you ran by hand and inspected by eye. That made it
// useless as evidence: nothing could assert the scanner found what the target exposed, so
// "burpsy detects reflected XSS" rested on somebody having looked once. Moving the handlers here
// lets a test start the same application in-process and check the claim on every run, while the
// binary still exists for manual work.
//
// # The manifest is the point
//
// Vulnerabilities() pairs each endpoint with the exact catalog row name it is meant to trigger.
// That turns coverage from a number somebody maintains into a fact somebody can check: for every
// entry, either the scanner reports that row against this app or the entry fails. A count of
// wired checks says a function exists; this says a vulnerability was planted and found.
//
// The reverse direction matters as much. Endpoints marked Safe carry no defect for their row, so
// a finding against one is a false positive with a name attached — the case a fires-on-vulnerable
// test alone can never catch.
//
// # No real damage, ever
//
// Nothing here executes a command, touches the filesystem or opens a database. The SQL, traversal
// and OS-command endpoints pattern-match their input and return a fixed artifact that looks like
// the real thing, which is all an evidence-based detector reads. A test target that could
// actually be exploited would be a liability in a repository.
package vulnapp

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Endpoint is one route of the application together with what it is for.
type Endpoint struct {
	// Path including any query string needed to reach the vulnerable behaviour. The parameter
	// value present here is inert; the scanner replaces it with its own payloads.
	Path string
	// Row is the catalog issue name this endpoint is built to trigger. Empty for a support
	// route that exists only to be crawled.
	Row string
	// Method is the HTTP method the vulnerability needs. Empty means GET.
	Method string
	// Safe marks an endpoint that reflects or echoes input WITHOUT the defect, so a finding
	// for Row against this path is a false positive.
	Safe bool
	// DOM marks an endpoint whose vulnerability lives in page script, so detecting it needs a
	// headless browser.
	DOM bool
	// Body and ContentType are the request the vulnerability needs. The insertion-point
	// enumerator can only find a body point if the captured request had a body, so an XML row
	// is unreachable without one. Empty Body on a POST falls back to a form, which is what the
	// form-field rows need.
	Body        string
	ContentType string
	// Stored marks a row that can only be confirmed after the scan's deferred phase. Planting
	// happens during the audit, so the sighting cannot exist until FinishScan has re-fetched the
	// pages that might render it; the harness routes these through that phase.
	Stored bool
	// SafeTwinNotApplicable justifies a vulnerable endpoint with no safe counterpart.
	//
	// Most rows need one: an endpoint reflecting the same input without the defect is what catches
	// a detector firing on reflection alone. A few rows have no such thing - an informational
	// "input came back in a later response" row is true whether or not the value was escaped, so a
	// "safe" version would report it too and be a legitimate finding rather than a false positive.
	//
	// A written reason rather than a bool, so the exemption is auditable. Empty keeps the pairing
	// requirement, which is the default and should stay the norm.
	SafeTwinNotApplicable string
	// TLS marks an endpoint that must be captured over https. Several transport rows are gated on
	// the exchange having been encrypted - a cacheable HTTPS response, mixed content, HSTS not
	// enforced - so on a cleartext-only harness they can never fire, which is a property of the
	// fixture rather than of the check.
	TLS bool
	// RequestHeaders are headers the CAPTURE must carry. A check reading a request header can only
	// find one the seeded request actually sent: the URL-override rows read X-Original-URL and
	// X-Rewrite-URL, and are unreachable unless the captured request carried them.
	RequestHeaders map[string]string
	// Note explains the mechanism, so a failing assertion can be read without opening the
	// handler.
	Note string
}

// Vulnerabilities returns every endpoint and the catalog row it exposes.
//
// Row names must match internal/scanner's catalog exactly. A typo here would silently exempt an
// endpoint from its own assertion, so the runtime test resolves every Row against the shipped
// catalog before it runs anything.
//
// The list is assembled from one file per check family. That split is not cosmetic: a family's
// endpoints, safe twins and routes grow together, and keeping them in one file means a family can be
// worked on and reviewed without reading the others.
func Vulnerabilities() []Endpoint {
	out := coreEndpoints()
	for _, f := range familyEndpoints {
		out = append(out, f()...)
	}
	return out
}

// familyEndpoints is every family's manifest contribution, in a fixed order.
var familyEndpoints = []func() []Endpoint{
	postureEndpoints,
	analysisEndpoints,
	headerEndpoints,
	reflectionEndpoints,
	discoveryEndpoints,
	domFamilyEndpoints,
	remainingEndpoints,
	finalEndpoints,
	storedFamilyEndpoints,
	storedDOMFamilyEndpoints,
	injectionEndpoints,
	nativeEndpoints,
	uploadEndpoints,
}

// familyRegistrars mirrors familyEndpoints: every family serves its own routes.
var familyRegistrars = []func(*http.ServeMux){
	registerPosture,
	registerAnalysis,
	registerHeaders,
	registerReflection,
	registerDiscovery,
	registerDOMFamily,
	registerRemaining,
	registerFinal,
	registerStoredFamily,
	registerStoredDOMFamily,
	registerInjection,
	registerNative,
	registerUpload,
}

func coreEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/", Note: "crawlable home page carrying both forms; no declared row of its own"},

		// Parameter names are deliberately NOT `xss`, `test` or `file`.
		//
		// Those were the three constants the predecessor checks appended by hand, and while they
		// were still the fixture names this corpus could not tell a fixed check from a working one:
		// reintroducing appendQueryParam(path, "test", payload) would have kept every assertion
		// green. A fixture named after the implementation grades the implementation on its own
		// terms. These names are what an application would plausibly call them instead.
		{Path: "/search?q=seed", Row: "Cross-site scripting (reflected)",
			Note: "reflects q into HTML with no escaping"},
		{Path: "/account?greeting=seed", Row: "Cross-site scripting (reflected)",
			Note: "reflects into an HTML attribute and a JavaScript string literal"},

		{Path: "/products?sort_col=seed", Row: "SQL injection",
			Note: "an odd number of unescaped quotes in sort_col yields a verbose SQL error"},
		{Path: "/login", Method: "POST", Row: "SQL injection",
			Note: "a quote in either form field yields a verbose SQL error"},

		{Path: "/download?doc=report.txt", Row: "File path traversal",
			Note: "any traversal sequence returns /etc/passwd content"},

		{Path: "/ping?host=127.0.0.1", Row: "OS command injection",
			Note: "shell metacharacters produce command-output artefacts"},

		{Path: "/redirect?url=/", Row: "Open redirection (reflected)",
			Note: "redirects to an unvalidated absolute URL"},
		{Path: "/redirect/origin?path=/", Row: "Open redirection (reflected)",
			Note: "prefixes path with its own scheme and authority; a value starting with @ turns that authority into userinfo"},

		{Path: "/echo?msg=seed", Row: "HTTP response header injection",
			Note: "reflects msg into a response header, so CRLF splits it"},

		{Path: "/api/data", Row: "Cross-origin resource sharing: arbitrary origin trusted",
			Note: "reflects any Origin and allows credentials"},
		// A real twin, replacing an exemption that claimed none was possible. It is: an endpoint
		// that answers CORS from a fixed allowlist reflects nothing the check crafts, so it is
		// genuinely quiet while still exercising the same code path. The old exemption said a twin
		// would be "an endpoint with no CORS policy", which is a different thing entirely - it
		// would prove only that a check keyed on a header cannot fire without the header.
		{Path: "/safe/api/data", Row: "Cross-origin resource sharing: arbitrary origin trusted", Safe: true,
			Note: "answers CORS only for an allowlisted origin, so a crafted Origin is never reflected"},

		{Path: "/api/debug", Row: "Database connection string disclosed",
			SafeTwinNotApplicable: "tested rather than assumed: a twin serving the same diagnostic " +
				"page with the credentials redacted still fires, because the detector keys on the " +
				"mysql:// URI itself and a credential-free connection string still discloses the " +
				"database's internal host, port and schema. That is the check being right rather " +
				"than sloppy, so the only quiet twin is a response with no connection string at " +
				"all - which is every other endpoint here",
			Note: "exposes a mysql:// URI with credentials"},

		// DOM-based rows. These need a headless browser, so the runtime harness gates them on
		// Chrome being present.
		{Path: "/dom/innerhtml", Row: "Cross-site scripting (DOM-based)", DOM: true,
			Note: "location.hash copied into innerHTML"},
		{Path: "/dom/eval", Row: "JavaScript injection (DOM-based)", DOM: true,
			Note: "location.hash passed to eval"},
		{Path: "/dom/storage", Row: "HTML5 storage manipulation (DOM-based)", DOM: true,
			Note: "location.hash written to localStorage"},
		{Path: "/dom/cookie", Row: "Cookie manipulation (DOM-based)", DOM: true,
			Note: "location.hash written to document.cookie"},
		{Path: "/dom/redirect", Row: "Open redirection (DOM-based)", DOM: true,
			Note: "location.hash passed to location.assign"},

		{Path: "/safe/dom/innerhtml", Row: "Cross-site scripting (DOM-based)", DOM: true, Safe: true,
			Note: "same source, assigned to textContent instead of innerHTML"},
		{Path: "/safe/dom/eval", Row: "JavaScript injection (DOM-based)", DOM: true, Safe: true,
			Note: "same source, rendered as text instead of evaluated"},
		{Path: "/safe/dom/storage", Row: "HTML5 storage manipulation (DOM-based)", DOM: true, Safe: true,
			Note: "same source, stored only when it matches a strict allowlist"},
		{Path: "/safe/dom/cookie", Row: "Cookie manipulation (DOM-based)", DOM: true, Safe: true,
			Note: "reads the same source but writes a fixed cookie value"},
		{Path: "/safe/xml/parse", Row: "XML external entity injection", Method: "POST", Safe: true,
			Body: "<order><item>seed</item></order>", ContentType: "application/xml",
			Note: "echoes the document but refuses any SYSTEM entity"},
		{Path: "/safe/xml/expand", Row: "XML entity expansion", Method: "POST", Safe: true,
			Body: "<order><item>seed</item></order>", ContentType: "application/xml",
			Note: "echoes the document but caps entity expansion"},
		{Path: "/safe/search/xpath?name=seed", Row: "XPath injection", Safe: true,
			Note: "reflects the name without ever emitting a parser error"},
		{Path: "/safe/directory?uid=alice", Row: "LDAP injection", Safe: true,
			Note: "escapes the filter metacharacters, so no input changes the entry count"},
		{Path: "/safe/greet?greeting=seed", Row: "Server-side template injection", Safe: true,
			Note: "reflects the value as data, never as template source"},
		{Path: "/safe/profile?website=https://example.com/x", Row: "Link manipulation (reflected)", Safe: true,
			Note: "reflects the URL as text but links only to a same-origin path"},
		{Path: "/safe/note?note=seed", Row: "Unidentified code injection", Safe: true,
			Note: "reflects the expression without evaluating it"},
		{Path: "/safe/include?tpl=seed", Row: "SSI injection", Safe: true,
			Note: "reflects the directive without running it through the processor"},
		{Path: "/safe/dom/redirect", Row: "Open redirection (DOM-based)", DOM: true, Safe: true,
			Note: "navigates only to same-origin paths, rejecting any value naming an authority"},

		// XML, XPath, LDAP and server-side template rows. The XML pair carries a document body
		// because the checks look for a body insertion point; without one the row is unreachable.
		{Path: "/xml/parse", Row: "XML external entity injection", Method: "POST",
			Body: "<order><item>seed</item></order>", ContentType: "application/xml",
			Note: "resolves declared SYSTEM entities and substitutes them into the echoed document"},
		{Path: "/xml/expand", Row: "XML entity expansion", Method: "POST",
			Body: "<order><item>seed</item></order>", ContentType: "application/xml",
			Note: "expands nested internal entities with no total-size limit"},
		{Path: "/search/xpath?name=seed", Row: "XPath injection",
			Note: "concatenates into //user[name='...'] and leaks the parser exception"},
		{Path: "/directory?uid=alice", Row: "LDAP injection",
			Note: "concatenates into (uid=...) and evaluates it, so an appended always-true term still matches while a negation does not"},
		{Path: "/greet?greeting=seed", Row: "Server-side template injection",
			Note: "evaluates an arithmetic expression inside template delimiters"},

		{Path: "/profile?website=https://example.com/x", Row: "Link manipulation (reflected)",
			Note: "reflects a submitted absolute URL straight into an href value"},
		{Path: "/note?note=seed", Row: "Unidentified code injection",
			Note: "evaluates an arithmetic expression inside expression-language delimiters"},
		{Path: "/include?tpl=seed", Row: "SSI injection",
			Note: "runs reflected input through a Server-Side Includes processor"},

		// The stored pair. /comment persists and declares no row of its own - storing untrusted
		// input is not the defect. /comments renders it, and is listed as a crawlable target so the
		// scan-end re-fetch has a GET to go back to; without that the canary could never be seen.
		{Path: "/comment?comment=seed", Row: "Input returned in response (stored)", Stored: true,
			SafeTwinNotApplicable: "an informational \"the value came back later\" row is true whether " +
				"or not the output was escaped, so a safe twin would report it too and be a correct " +
				"finding rather than a false positive",
			Note: "a value submitted here is rendered by /comments on a later request"},
		{Path: "/comments", Note: "renders every stored comment; re-fetched by the deferred phase"},

		// The safe counterparts. Each reflects input for the same row without the defect, so a
		// detector that fires on reflection alone is caught here rather than in the field.
		{Path: "/safe/search?q=seed", Row: "Cross-site scripting (reflected)", Safe: true,
			Note: "reflects q HTML-escaped"},
		{Path: "/safe/products?sort_col=seed", Row: "SQL injection", Safe: true,
			Note: "echoes the parameter without ever emitting a database error"},
		{Path: "/safe/download?doc=report.txt", Row: "File path traversal", Safe: true,
			Note: "echoes traversal sequences back without serving file content"},
		{Path: "/safe/ping?host=127.0.0.1", Row: "OS command injection", Safe: true,
			Note: "echoes metacharacters without any command-output artefact"},
		{Path: "/safe/redirect?url=/", Row: "Open redirection (reflected)", Safe: true,
			Note: "redirects only to same-origin paths, rejecting absolute URLs"},
		{Path: "/safe/redirect/origin?path=/", Row: "Open redirection (reflected)", Safe: true,
			Note: "prefixes path with its own origin AND a slash, so the value always lands in the path, whatever it spells"},
		{Path: "/safe/echo?msg=seed", Row: "HTTP response header injection", Safe: true,
			Note: "strips CR and LF before reflecting into the header"},
	}
}

// Handler returns the application. Every route in Vulnerabilities() is served here.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", home)
	mux.HandleFunc("/search", search)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/api/debug", debug)
	mux.HandleFunc("/products", products)
	mux.HandleFunc("/account", account)
	mux.HandleFunc("/download", download)
	mux.HandleFunc("/ping", ping)
	mux.HandleFunc("/redirect", redirect)
	mux.HandleFunc("/redirect/origin", originRedirect)
	mux.HandleFunc("/echo", echo)
	mux.HandleFunc("/api/data", cors)
	mux.HandleFunc("/safe/api/data", safeCORS)

	mux.HandleFunc("/safe/search", safeSearch)
	mux.HandleFunc("/safe/products", safeProducts)
	mux.HandleFunc("/safe/download", safeDownload)
	mux.HandleFunc("/safe/ping", safePing)
	mux.HandleFunc("/safe/redirect", safeRedirect)
	mux.HandleFunc("/safe/redirect/origin", safeOriginRedirect)
	mux.HandleFunc("/safe/echo", safeEcho)

	// DOM sinks reading location.hash. No server involvement, which is what makes the rows
	// "(DOM-based)".
	mux.HandleFunc("/dom/innerhtml", domInnerHTML)
	mux.HandleFunc("/dom/eval", domEval)
	mux.HandleFunc("/dom/storage", domStorage)
	mux.HandleFunc("/dom/cookie", domCookie)
	mux.HandleFunc("/dom/redirect", domRedirect)
	mux.HandleFunc("/safe/dom/innerhtml", safeDOMInnerHTML)
	mux.HandleFunc("/safe/dom/eval", safeDOMEval)
	mux.HandleFunc("/safe/dom/storage", safeDOMStorage)
	mux.HandleFunc("/safe/dom/cookie", safeDOMCookie)
	mux.HandleFunc("/safe/dom/redirect", safeDOMRedirect)

	// XML, XPath, LDAP and template rows.
	mux.HandleFunc("/xml/parse", parseXML)
	mux.HandleFunc("/xml/expand", parseXML)
	mux.HandleFunc("/search/xpath", xpathSearch)
	mux.HandleFunc("/directory", ldapLookup)
	mux.HandleFunc("/greet", renderTemplate)
	mux.HandleFunc("/safe/xml/parse", safeParseXML)
	mux.HandleFunc("/safe/xml/expand", safeExpandXML)
	mux.HandleFunc("/safe/search/xpath", safeXPathSearch)
	mux.HandleFunc("/safe/directory", safeLDAPLookup)
	mux.HandleFunc("/safe/greet", safeRenderTemplate)

	// Stored pair: one page persists, another renders.
	mux.HandleFunc("/comment", postComment)
	mux.HandleFunc("/comments", listComments)
	mux.HandleFunc("/safe/comments", safeListComments)

	// Link manipulation, code injection, SSI.
	mux.HandleFunc("/profile", profileLink)
	mux.HandleFunc("/note", evalNote)
	mux.HandleFunc("/include", includePage)
	mux.HandleFunc("/safe/profile", safeProfileLink)
	mux.HandleFunc("/safe/note", safeEvalNote)
	mux.HandleFunc("/safe/include", safeIncludePage)

	// Run-configuration fixtures: served, deliberately not in the manifest (vulnapp_runconfig.go).
	registerRunConfigFixtures(mux)
	// Hidden-input guesser fixtures: served, deliberately not in the manifest (vulnapp_hidden_inputs.go).
	registerHiddenInputFixtures(mux)
	// Out-of-band fixtures: served, deliberately not in the manifest (vulnapp_oob.go).
	registerOOBFixtures(mux)

	for _, r := range familyRegistrars {
		r(mux)
	}
	return mux
}

func home(w http.ResponseWriter, r *http.Request) {
	// TRACE echoes the request back, which is the defect the "HTTP TRACE method is enabled" row is
	// about. It lives here rather than in a family file because the check sends TRACE to "/"
	// specifically, and "/" is this handler - a family file cannot serve it without shadowing the
	// home page every other row depends on.
	if r.Method == http.MethodTrace {
		w.Header().Set("Content-Type", "message/http")
		fmt.Fprintf(w, "TRACE %s %s\r\n", r.URL.RequestURI(), r.Proto)
		for name, values := range r.Header {
			for _, v := range values {
				fmt.Fprintf(w, "%s: %s\r\n", name, v)
			}
		}
		return
	}
	// No CSP, no X-Frame-Options, no charset: the passive posture rows have something to say
	// about this page, which is deliberate.
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Vulnerable Demo</title></head>
<body>
	<h1>burpsy runtime test target</h1>
	<p>This app is intentionally vulnerable.</p>
	<form action="/search" method="GET">
		<input type="text" name="q" placeholder="Search...">
		<button type="submit">Search</button>
	</form>
	<form action="/login" method="POST">
		<input type="text" name="user" placeholder="Username">
		<input type="password" name="pass" placeholder="Password">
		<button type="submit">Login</button>
	</form>
	<a href="/api/debug">Debug endpoint</a>
</body>
</html>`)
}

func search(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h2>Results for: %s</h2>", r.URL.Query().Get("q"))
}

func safeSearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h2>Results for: %s</h2>", htmlEscape(r.URL.Query().Get("q")))
}

func login(w http.ResponseWriter, r *http.Request) {
	user, pass := r.FormValue("user"), r.FormValue("pass")
	if strings.Contains(user, "'") || strings.Contains(pass, "'") {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "SQL Error: You have an error in your SQL syntax near '%s' at line 1", user)
		return
	}
	fmt.Fprintf(w, "Login attempted for user: %s", htmlEscape(user))
}

// products approximates a database column sort: an odd number of unescaped quotes in sort_col is
// unbalanced syntax and errors, an escaped pair is not.
//
// # One named parameter, on purpose
//
// This used to iterate every query parameter and every value. That made the endpoint vulnerable
// through a parameter of ANY name, which quietly defeated the corpus: a check that appended its own
// parameter with a guessed name still triggered the error branch, so the assertion passed whether
// or not the check enumerated real insertion points. Reading exactly one named parameter is what
// makes the test able to tell those apart.
//
// # It models a parser, not a payload list
//
// It also used to branch on the literal strings `order by 999`, `or '1'='1` and `and '1'='2` —
// lowercased copies of the scanner's own probe table. That is a target shaped around the tool: it
// would answer those exact payloads and nothing else, which proves the payloads were sent rather
// than that a database was reachable. The quote-balance rule is a property of SQL syntax and any
// payload that unbalances a quote reaches it, so it is the only rule left.
func products(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	v := r.URL.Query().Get("sort_col")
	if strings.Count(strings.ReplaceAll(v, "''", ""), "'") > 0 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "SQL syntax error: you have an error in your SQL syntax near '%s' at line 1", v)
		return
	}
	fmt.Fprintf(w, "Products sorted by %s: Widget, Gadget, Gizmo", v)
}

// safeProducts reflects sort_col but never emits anything resembling a database error, so a
// detector keying on reflection rather than on evidence fires here and is caught.
func safeProducts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Products sorted by %s: Widget, Gadget, Gizmo", r.URL.Query().Get("sort_col"))
}

func account(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("greeting")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><body>
	<div data-value="%s">Account settings</div>
	<script>var lastSearch = '%s';</script>
</body></html>`, value, value)
}

func debug(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{
	"status": "debug_mode_enabled",
	"database": "mysql://root:password@localhost:3306/prod",
	"aws_key": "AKIAIOSFODNN7EXAMPLE",
	"internal_ip": "10.0.0.5"
}`)
}

// download returns fixed /etc/passwd-shaped content for any traversal sequence. Nothing reads
// the filesystem.
func download(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if strings.Contains(strings.ToLower(r.URL.Query().Get("doc")), "..") {
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
		return
	}
	fmt.Fprintf(w, "report for %s: 42 rows", r.URL.Query().Get("doc"))
}

// safeDownload reflects the traversal string without ever serving file content — the difference
// between "the payload came back" and "the file came back", which is what the traversal check
// must key on.
func safeDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "report for %s: 42 rows", r.URL.Query().Get("doc"))
}

// ping simulates `ping <host>` run through a shell. No process is ever spawned.
//
// Fidelity matters more than it looks. This handler originally answered any metacharacter with a
// fixed `uid=0(root)` string, which looks like command output to a human and is invisible to a
// detector: the OS-command check confirms by planting `echo <marker>` and looking for the marker
// coming back, so a target that never echoes the marker can never be detected no matter how
// vulnerable it pretends to be. The runtime scan reported exactly that — the endpoint declared
// vulnerable was the one endpoint OS command injection did not fire on.
//
// So the simulation now does what a shell does with the payloads that actually get sent: it
// interprets a separator, finds an `echo` command, and emits its argument. That is the behaviour
// the check reasons about, reproduced without an exec.
func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	w.Header().Set("Content-Type", "text/plain")
	if out, ran := simulateShell(host); ran {
		fmt.Fprintf(w, "PING: %s\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64", out)
		return
	}
	fmt.Fprintf(w, "PING %s: 64 bytes from 127.0.0.1: icmp_seq=1 ttl=64", host)
}

// simulateShell interprets the shell metacharacter forms an injected command arrives in and
// returns what the command would have printed.
//
// Only `echo` is understood, because `echo <marker>` is what a scanner plants: it is the one
// command whose output proves execution while doing nothing. Anything else returns ran=false, so
// the endpoint stays quiet rather than inventing output for a command it did not model.
func simulateShell(input string) (string, bool) {
	// A separator has to be present, or nothing was injected — `ping echo x` runs no echo.
	if !strings.ContainsAny(input, ";|&`$()\n") {
		return "", false
	}
	// POSIX arithmetic expansion happens before the command runs, so `echo x$((3*4))` prints
	// `x12`. The scanner's OS-command proof is computed this way (j1mk.34) precisely because a
	// reflection can never produce it; a shell simulation that skipped the expansion would stop
	// being detectable for the same reason.
	input = shellArithmetic.ReplaceAllStringFunc(input, func(m string) string {
		p := shellArithmetic.FindStringSubmatch(m)
		a, _ := strconv.Atoi(p[1])
		b, _ := strconv.Atoi(p[3])
		switch p[2] {
		case "+":
			return strconv.Itoa(a + b)
		case "-":
			return strconv.Itoa(a - b)
		}
		return strconv.Itoa(a * b)
	})
	// Split on the separators a shell would honour, then look for an echo command in any
	// resulting segment. $(...) and `...` wrap their contents, so the delimiters are simply
	// separators for this purpose.
	segments := strings.FieldsFunc(input, func(r rune) bool {
		switch r {
		case ';', '|', '&', '`', '$', '(', ')', '\n':
			return true
		}
		return false
	})
	for _, seg := range segments {
		fields := strings.Fields(seg)
		if len(fields) >= 2 && fields[0] == "echo" {
			return strings.Join(fields[1:], " "), true
		}
	}
	return "", false
}

// shellArithmetic is a `$((a op b))` arithmetic expansion over two integers.
var shellArithmetic = regexp.MustCompile(`\$\(\(\s*(-?\d+)\s*([*+-])\s*(-?\d+)\s*\)\)`)

func safePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "PING %s: 64 bytes from 127.0.0.1: icmp_seq=1 ttl=64", r.URL.Query().Get("host"))
}

func redirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// safeRedirect accepts only same-origin paths, so an off-site target is refused rather than
// followed.
//
// The backslash rejection is not decoration. The first version of this handler tested only
// `HasPrefix(target, "/") && !HasPrefix(target, "//")`, and the scanner reported it as an open
// redirect — correctly. `/\evil.example/` starts with a single `/`, so a naive same-origin check
// accepts it, and browsers then normalise `\` to `/`, making the effective target `//evil.example/`
// — a protocol-relative URL pointing off-site. That is precisely why `/\a` and `\a` are in
// openRedirectPrefixes, recovered from Burp's own bank.
//
// It is worth leaving the story here: this endpoint is the "safe" half of a false-positive guard,
// and it was itself vulnerable. A hand-written origin check is the wrong tool; the point of the
// runtime corpus is that it caught it.
func safeRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	offSite := target == "" ||
		!strings.HasPrefix(target, "/") ||
		strings.HasPrefix(target, "//") ||
		strings.ContainsAny(target, `\`) ||
		strings.Contains(target, "://")
	if offSite {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "refused: off-site redirect")
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// originRedirect keeps the user "on our origin" the way many applications try to: it writes its
// own scheme and authority and appends the value. Nothing separates the authority from the value,
// so "@evil.example/" makes the application's host:port the userinfo and evil.example the host
// (RFC 3986 section 3.2). Every prefix that assumes the value starts the Location misses this.
func originRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", requestOrigin(r)+r.URL.Query().Get("path"))
	w.WriteHeader(http.StatusFound)
}

// safeOriginRedirect is the same pattern with the separator in place: the origin is followed by
// "/", which ends the authority before the value starts, so "@host", "//host" and "\host" all
// land in the path of this origin. Its Location still CONTAINS whatever host the value names, which
// is the point of the twin: a detector that matches the host as a substring fires here wrongly.
func safeOriginRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", requestOrigin(r)+"/"+strings.TrimPrefix(r.URL.Query().Get("path"), "/"))
	w.WriteHeader(http.StatusFound)
}

func requestOrigin(r *http.Request) string {
	if r.TLS != nil {
		return "https://" + r.Host
	}
	return "http://" + r.Host
}

// echo reflects msg into a response header, so a value carrying CRLF splits it.
//
// This writes the response bytes directly through http.Hijacker rather than using
// w.Header().Set, and it has to. net/http sanitises header values — it replaces CR and LF before
// writing — so a handler built the obvious way CANNOT be made vulnerable to response-header
// injection no matter what it reflects. The scanner was right to report nothing against the
// earlier version of this endpoint; the target was the thing that was wrong.
//
// Hijacking takes the connection out of net/http's hands and writes a raw response, which is the
// only way to reproduce a server that concatenates untrusted input into its header block. Nothing
// unsafe happens to the host: the bytes go to a test client on a loopback listener.
func echo(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// No hijack available (HTTP/2, or a wrapped ResponseWriter). Say so rather than quietly
		// serving a sanitised response that looks like a target which is not vulnerable.
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprint(w, "this endpoint needs a hijackable connection to be vulnerable")
		return
	}
	conn, buf, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	// The raw header block, with msg concatenated in unsanitised. A CRLF in msg ends the X-Echo
	// header and begins whatever the attacker wrote next.
	body := "echoed"
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"X-Echo: " + msg + "\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n" +
		"\r\n" + body
	_, _ = buf.WriteString(raw)
	_ = buf.Flush()
}

// safeEcho strips CR and LF, so the header cannot be split.
func safeEcho(w http.ResponseWriter, r *http.Request) {
	msg := strings.NewReplacer("\r", "", "\n", "").Replace(r.URL.Query().Get("msg"))
	w.Header().Set("X-Echo", msg)
	fmt.Fprint(w, "echoed")
}

func cors(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"balance": 1000, "account": "victim"}`)
}

// safeCORS answers CORS from a fixed allowlist. The crafted origins the CORS checks probe with are
// not on it, so nothing is reflected and the row is genuinely quiet.
func safeCORS(w http.ResponseWriter, r *http.Request) {
	const allowed = "https://app.example.com"
	if r.Header.Get("Origin") == allowed {
		w.Header().Set("Access-Control-Allow-Origin", allowed)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"balance": 1000, "account": "victim"}`)
}

// htmlEscape is the minimal escaping the safe endpoints need. html/template is deliberately not
// used: these handlers must stay obvious enough to audit at a glance.
func htmlEscape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	).Replace(s)
}

// domPage serves a page whose script copies location.hash into the named sink.
func domPage(w http.ResponseWriter, script string) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>dom</title></head>
<body><div id="out"></div><script>
var taint = decodeURIComponent(location.hash.slice(1));
%s
</script></body></html>`, script)
}

func domInnerHTML(w http.ResponseWriter, r *http.Request) {
	domPage(w, `document.getElementById('out').innerHTML = taint;`)
}

func domEval(w http.ResponseWriter, r *http.Request) {
	domPage(w, `try { eval(taint); } catch (e) {}`)
}

func domStorage(w http.ResponseWriter, r *http.Request) {
	domPage(w, `localStorage.setItem('pref', taint);`)
}

func domCookie(w http.ResponseWriter, r *http.Request) {
	domPage(w, `document.cookie = 'pref=' + taint;`)
}

func domRedirect(w http.ResponseWriter, r *http.Request) {
	domPage(w, `if (taint) { location.assign(taint); }`)
}

// The safe twins read the same source and do not pass it to the sink.
func safeDOMInnerHTML(w http.ResponseWriter, r *http.Request) {
	domPage(w, `document.getElementById('out').textContent = taint;`)
}

func safeDOMEval(w http.ResponseWriter, r *http.Request) {
	domPage(w, `document.getElementById('out').textContent = 'would run: ' + taint;`)
}

func safeDOMStorage(w http.ResponseWriter, r *http.Request) {
	domPage(w, `if (/^[a-z]+$/.test(taint)) { localStorage.setItem('pref', taint); }`)
}

// safeDOMCookie writes a fixed value. The taint reaches script but never the cookie, so a
// detector firing on "the page read location.hash" alone is caught here.
func safeDOMCookie(w http.ResponseWriter, r *http.Request) {
	domPage(w, `document.getElementById('out').textContent = taint; document.cookie = 'pref=fixed';`)
}

// safeDOMRedirect navigates only to a same-origin path, rejecting anything that names an
// authority - the DOM counterpart of the safeRedirect rule.
func safeDOMRedirect(w http.ResponseWriter, r *http.Request) {
	domPage(w, `if (/^\/[a-z0-9\/]*$/.test(taint)) { location.assign(taint); }`)
}

// ---------------------------------------------------------------------------
// XML: external entities and entity expansion
// ---------------------------------------------------------------------------

// docText returns the body of the request whichever way it arrived. The XML rows are reached
// through a body point, but the enumerator also offers query points, and an endpoint that only
// honoured one of them would make the other look clean.
func docText(r *http.Request) string {
	if v := r.URL.Query().Get("doc"); v != "" {
		return v
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	return string(b)
}

var xmlEntityDecl = regexp.MustCompile(`<!ENTITY\s+(\w+)\s+(?:SYSTEM\s+"([^"]*)"|"([^"]*)")\s*>`)

// parseXML is a parser configured the wrong way round: it resolves declared entities, including
// SYSTEM ones, and substitutes them into the document it echoes back.
//
// Go's encoding/xml refuses external entities outright, so a genuinely vulnerable endpoint has to
// resolve them itself. That is not a contrivance - it is precisely the misconfiguration the row
// describes, and the resolution here is generic: whatever path the entity names is what gets read,
// with no knowledge of any particular payload or file.
func parseXML(w http.ResponseWriter, r *http.Request) {
	doc := docText(r)
	w.Header().Set("Content-Type", "text/plain")

	values := map[string]string{}
	for _, m := range xmlEntityDecl.FindAllStringSubmatch(doc, -1) {
		name, system, literal := m[1], m[2], m[3]
		if system != "" {
			values[name] = readSystemEntity(system)
			continue
		}
		values[name] = literal
	}

	// Expand references repeatedly so a nested declaration resolves through its parents. The
	// bound is what a real parser without an expansion limit lacks; the cap here only stops the
	// test process itself dying, and is far above the scanner's own bounded payloads.
	body := doc
	for range 24 {
		grew := false
		for name, v := range values {
			ref := "&" + name + ";"
			if strings.Contains(body, ref) {
				body = strings.ReplaceAll(body, ref, v)
				grew = true
			}
		}
		if !grew || len(body) > 1<<22 {
			break
		}
	}
	fmt.Fprintf(w, "parsed document:\n%s\n", body)
}

// readSystemEntity resolves a SYSTEM URI the way an unconfigured parser would.
func readSystemEntity(uri string) string {
	path := strings.TrimPrefix(uri, "file://")
	if strings.HasPrefix(uri, "php://filter") {
		// The wrapper form names its target after "resource=". A PHP parser would return the
		// content base64-encoded; this one returns it plainly, which is strictly more evidence
		// and keeps the endpoint honest about what it read.
		if i := strings.Index(uri, "resource="); i >= 0 {
			path = uri[i+len("resource="):]
		}
	}
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// safeParseXML resolves internal entities only and refuses SYSTEM ones, which is the fixed
// configuration. It still echoes the document, so a detector keying on reflection is caught.
func safeParseXML(w http.ResponseWriter, r *http.Request) {
	doc := docText(r)
	w.Header().Set("Content-Type", "text/plain")
	if strings.Contains(doc, "SYSTEM") {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "refused: external entities are disabled\n")
		return
	}
	fmt.Fprintf(w, "parsed document:\n%s\n", doc)
}

// safeExpandXML caps total expansion, which is the documented fix for entity expansion. The
// document is still echoed, so silence here cannot come from the endpoint ignoring input.
func safeExpandXML(w http.ResponseWriter, r *http.Request) {
	doc := docText(r)
	w.Header().Set("Content-Type", "text/plain")
	if len(doc) > 0 && strings.Count(doc, "&") > 64 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "refused: entity expansion limit exceeded\n")
		return
	}
	fmt.Fprintf(w, "parsed document:\n%s\n", doc)
}

// ---------------------------------------------------------------------------
// XPath, LDAP, server-side templates
// ---------------------------------------------------------------------------

// xpathSearch builds an XPath expression by concatenation and leaks the parser's error, which is
// what makes the flaw detectable. The error text is a real Java XPath one.
func xpathSearch(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/plain")
	// An odd number of quotes leaves the expression unbalanced, exactly as string concatenation
	// into a query language does. The endpoint does not inspect the payload for anything else.
	if (strings.Count(v, "'")+strings.Count(v, `"`))%2 == 1 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "javax.xml.xpath.XPathExpressionException: unable to evaluate //user[name='%s']\n", v)
		return
	}
	fmt.Fprintf(w, "no user matching %s\n", v)
}

func safeXPathSearch(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "no user matching %s\n", v)
}

// directoryEntries is the store the filter runs against.
var directoryEntries = []map[string]string{
	{"uid": "alice", "objectClass": "person", "active": "TRUE"},
	{"uid": "bob", "objectClass": "person", "active": "TRUE"},
	{"uid": "carol", "objectClass": "person", "active": "FALSE"},
}

// ldapLookup concatenates the parameter into a filter and evaluates it for real.
//
// The evaluator below knows nothing about any payload: it parses whatever filter string the
// concatenation produced and applies it. That matters because an endpoint that instead matched
// on the payloads it expected would grade the check against its own guesses - the fixture would
// pass whether or not the detector worked, which is how a corpus stops being evidence.
func ldapLookup(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("uid")
	w.Header().Set("Content-Type", "text/plain")
	writeDirectoryResult(w, "(uid="+v+")")
}

// safeLDAPLookup escapes the filter metacharacters per RFC 4515 before building the filter, so
// every input is one literal assertion. The always-true payload then stops matching the baseline
// too, which is what makes the differential inconclusive rather than a finding.
func safeLDAPLookup(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("uid")
	w.Header().Set("Content-Type", "text/plain")
	esc := strings.NewReplacer(`\`, `\5c`, `*`, `\2a`, `(`, `\28`, `)`, `\29`, "\x00", `\00`).Replace(v)
	writeDirectoryResult(w, "(uid="+esc+")")
}

func writeDirectoryResult(w http.ResponseWriter, filter string) {
	uids, err := evalFilterSequence(filter)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "LDAP: error code 87 - invalid filter %q: %v\n", filter, err)
		return
	}
	if len(uids) == 0 {
		fmt.Fprint(w, "entries: none\n")
		return
	}
	fmt.Fprintf(w, "entries: %s\n", strings.Join(uids, ", "))
}

// evalFilterSequence evaluates one or more adjacent top-level filters, ANDed together. The
// adjacency case is the whole point: closing the app's own filter and appending another is
// exactly what the injection does, and a parser that rejected it outright would not be
// vulnerable in the first place.
func evalFilterSequence(s string) ([]string, error) {
	var out []string
	for _, e := range directoryEntries {
		rest, ok := s, true
		for rest != "" && ok {
			node, tail, err := parseFilter(rest)
			if err != nil {
				return nil, err
			}
			ok = node(e)
			rest = tail
		}
		if ok {
			out = append(out, e["uid"])
		}
	}
	return out, nil
}

// parseFilter parses one parenthesised filter and returns a predicate plus the unconsumed tail.
func parseFilter(s string) (func(map[string]string) bool, string, error) {
	if len(s) == 0 || s[0] != '(' {
		return nil, "", fmt.Errorf("expected '(' at %q", s)
	}
	end := matchingParen(s)
	if end < 0 {
		return nil, "", fmt.Errorf("unbalanced parentheses in %q", s)
	}
	inner, tail := s[1:end], s[end+1:]
	if inner == "" {
		return nil, "", fmt.Errorf("empty filter")
	}

	switch inner[0] {
	case '&', '|', '!':
		op := inner[0]
		var kids []func(map[string]string) bool
		for rest := inner[1:]; rest != ""; {
			kid, t, err := parseFilter(rest)
			if err != nil {
				return nil, "", err
			}
			kids = append(kids, kid)
			rest = t
		}
		if len(kids) == 0 {
			return nil, "", fmt.Errorf("operator %q with no operands", string(op))
		}
		return func(e map[string]string) bool {
			switch op {
			case '&':
				for _, k := range kids {
					if !k(e) {
						return false
					}
				}
				return true
			case '|':
				for _, k := range kids {
					if k(e) {
						return true
					}
				}
				return false
			default:
				return !kids[0](e)
			}
		}, tail, nil
	}

	eq := strings.Index(inner, "=")
	if eq < 0 {
		return nil, "", fmt.Errorf("assertion %q has no '='", inner)
	}
	attr, want := inner[:eq], inner[eq+1:]
	return func(e map[string]string) bool {
		have, present := e[attr]
		switch {
		case want == "*":
			return present
		case strings.HasSuffix(want, "*"):
			return present && strings.HasPrefix(have, strings.TrimSuffix(want, "*"))
		default:
			return present && have == want
		}
	}, tail, nil
}

func matchingParen(s string) int {
	depth := 0
	for i := range len(s) {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// renderTemplate evaluates an arithmetic expression inside template delimiters, which is what a
// server-side template engine handed untrusted input does. It computes the product rather than
// recognising any particular one, so no specific payload is privileged. Operands up to nine digits:
// the scanner draws five-digit operands per probe (j1mk.34), and an engine has no digit limit.
var templateExpr = regexp.MustCompile(`(?:\{\{|\$\{|#\{|<%=)\s*(\d{1,9})\s*\*\s*(\d{1,9})\s*(?:\}\}|\}|%>)`)

func renderTemplate(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("greeting")
	w.Header().Set("Content-Type", "text/plain")
	out := templateExpr.ReplaceAllStringFunc(v, func(m string) string {
		p := templateExpr.FindStringSubmatch(m)
		a, _ := strconv.Atoi(p[1])
		b, _ := strconv.Atoi(p[2])
		return strconv.Itoa(a * b)
	})
	fmt.Fprintf(w, "rendered: %s\n", out)
}

// safeRenderTemplate treats the value as data, never as template source.
func safeRenderTemplate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "rendered: %s\n", r.URL.Query().Get("greeting"))
}

// ---------------------------------------------------------------------------
// Stored (second-order) pair
// ---------------------------------------------------------------------------

// The stored rows need two endpoints and an ordering. A value submitted to one page has to come
// back out of a different one, later - which is why a batch audit can never confirm this without
// going back for a second look. The scanner's re-fetch pass is what supplies the "later".
var (
	guestbookMu      sync.Mutex
	guestbookEntries []string
)

// postComment persists whatever it is given. Storing untrusted input is not itself the defect, so
// this endpoint declares no row of its own.
func postComment(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("comment")
	if v == "" {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if parsed, err := url.ParseQuery(string(b)); err == nil {
			v = parsed.Get("comment")
		}
	}
	if v != "" {
		guestbookMu.Lock()
		// Bounded so a scan cannot grow this without limit; the newest entries are the ones a
		// canary would be in.
		guestbookEntries = append(guestbookEntries, v)
		if len(guestbookEntries) > 200 {
			guestbookEntries = guestbookEntries[len(guestbookEntries)-200:]
		}
		guestbookMu.Unlock()
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "comment received\n")
}

// listComments renders every stored comment without escaping, which is the defect.
func listComments(w http.ResponseWriter, r *http.Request) {
	guestbookMu.Lock()
	entries := append([]string(nil), guestbookEntries...)
	guestbookMu.Unlock()
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>Guestbook</h1>")
	for _, e := range entries {
		fmt.Fprintf(w, "<div class=\"comment\">%s</div>", e)
	}
	fmt.Fprint(w, "</body></html>")
}

// safeListComments renders the same stored values escaped. The canary still appears - so a
// detector that merely greps for its own token fires here - but it appears as text.
func safeListComments(w http.ResponseWriter, r *http.Request) {
	guestbookMu.Lock()
	entries := append([]string(nil), guestbookEntries...)
	guestbookMu.Unlock()
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html><html><body><h1>Guestbook</h1>")
	for _, e := range entries {
		fmt.Fprintf(w, "<div class=\"comment\">%s</div>", htmlEscape(e))
	}
	fmt.Fprint(w, "</body></html>")
}

// ---------------------------------------------------------------------------
// Link manipulation, code injection, SSI
// ---------------------------------------------------------------------------

// profileLink reflects a submitted URL straight into an href, so an attacker chooses where the
// link points without needing a full HTML breakout.
func profileLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html><html><body><a href="%s">your site</a></body></html>`,
		r.URL.Query().Get("website"))
}

// safeProfileLink accepts only a same-origin path, so a submitted absolute URL cannot become the
// target. It still reflects the value as text, so a detector keying on reflection is caught.
func safeProfileLink(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("website")
	w.Header().Set("Content-Type", "text/html")
	target := "/"
	if strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") {
		target = v
	}
	fmt.Fprintf(w, `<!DOCTYPE html><html><body><a href="%s">your site</a><p>%s</p></body></html>`,
		target, htmlEscape(v))
}

// evalNote evaluates an arithmetic expression the way a server-side expression language does. It
// computes whatever product it is given rather than recognising a particular one.
func evalNote(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("note")
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "note: %s\n", templateExpr.ReplaceAllStringFunc(v, func(m string) string {
		p := templateExpr.FindStringSubmatch(m)
		a, _ := strconv.Atoi(p[1])
		b, _ := strconv.Atoi(p[2])
		return strconv.Itoa(a * b)
	}))
}

func safeEvalNote(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "note: %s\n", r.URL.Query().Get("note"))
}

// ssiDirective matches the #if/#else/#endif form a Server-Side Includes processor evaluates.
var ssiDirective = regexp.MustCompile(`(?s)<!--#if expr="([^"]*)" -->(.*?)<!--#else-->(.*?)<!--#endif-->`)

// includePage processes SSI directives in reflected input, which is the defect: the value reaches a
// processor that parses it. The expression is evaluated generically - a literal comparison - rather
// than by looking for any specific payload.
func includePage(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("tpl")
	w.Header().Set("Content-Type", "text/html")
	out := ssiDirective.ReplaceAllStringFunc(v, func(m string) string {
		p := ssiDirective.FindStringSubmatch(m)
		lhs, rhs, ok := strings.Cut(p[1], "=")
		if ok && strings.TrimSpace(lhs) == strings.TrimSpace(rhs) {
			return p[2]
		}
		return p[3]
	})
	fmt.Fprintf(w, "<!DOCTYPE html><html><body>%s</body></html>", out)
}

// safeIncludePage reflects the same value without running it through the processor. The literal
// directive comes back intact, which is what a non-evaluating server does.
func safeIncludePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<!DOCTYPE html><html><body>%s</body></html>", htmlEscape(r.URL.Query().Get("tpl")))
}
