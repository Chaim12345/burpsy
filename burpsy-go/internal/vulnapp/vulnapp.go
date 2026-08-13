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
	"net/http"
	"strings"
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
	// Note explains the mechanism, so a failing assertion can be read without opening the
	// handler.
	Note string
}

// Vulnerabilities returns every endpoint and the catalog row it exposes.
//
// Row names must match internal/scanner's catalog exactly. A typo here would silently exempt an
// endpoint from its own assertion, so the runtime test resolves every Row against the shipped
// catalog before it runs anything.
func Vulnerabilities() []Endpoint {
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

		{Path: "/echo?msg=seed", Row: "HTTP response header injection",
			Note: "reflects msg into a response header, so CRLF splits it"},

		{Path: "/api/data", Row: "Cross-origin resource sharing: arbitrary origin trusted",
			Note: "reflects any Origin and allows credentials"},

		{Path: "/api/debug", Row: "Database connection string disclosed",
			Note: "exposes a mysql:// URI with credentials"},

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
	mux.HandleFunc("/echo", echo)
	mux.HandleFunc("/api/data", cors)

	mux.HandleFunc("/safe/search", safeSearch)
	mux.HandleFunc("/safe/products", safeProducts)
	mux.HandleFunc("/safe/download", safeDownload)
	mux.HandleFunc("/safe/ping", safePing)
	mux.HandleFunc("/safe/redirect", safeRedirect)
	mux.HandleFunc("/safe/echo", safeEcho)
	return mux
}

func home(w http.ResponseWriter, r *http.Request) {
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

// htmlEscape is the minimal escaping the safe endpoints need. html/template is deliberately not
// used: these handlers must stay obvious enough to audit at a glance.
func htmlEscape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	).Replace(s)
}
