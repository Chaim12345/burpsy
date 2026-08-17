package vulnapp

// reflection probes and response-dependence rows.
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
// Corresponding scanner descriptors: ReflectionProbeDescriptors / ResponseDependenceDescriptors.

import (
	"fmt"
	"net/http"
	"strings"
)

// reflectionEndpoints returns this family's manifest entries. All six of the family's rows are
// declared.
//
// The two response-dependence rows were withheld for a while, and the reason is worth keeping: both
// checks took their baseline from responseRaw() — status line, headers AND body of the captured
// response — and compared it against resp.Body, which is body only. The operands were never equal
// for any target, so both rows fired unconditionally and no endpoint could make them quiet.
// Declaring them then would have recorded a green assertion that proved nothing about either
// detector. The checks now compare body against body, and the safe twins below are the evidence
// that they do: before the fix, neither twin could have been silent.
func reflectionEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/rf/greeting?display_name=quokka", Row: "Input returned in response (reflected)",
			Note: "renders display_name verbatim into the page, so the submitted value reappears byte-for-byte in the response"},
		{Path: "/rf/safe/greeting?display_name=quokka", Row: "Input returned in response (reflected)", Safe: true,
			Note: "masks display_name to its first character before rendering, so no submitted value appears verbatim anywhere in the response"},

		{Path: "/rf/backup/notes.txt", Row: "Backup file",
			Note: "an editor backup of this file is still served at notes.txt.bak with different content, while every other neighbour is a definite 404"},
		{Path: "/rf/safe/backup/report.txt", Row: "Backup file", Safe: true,
			Note: "serves the document itself and a definite 404 for every backup-name variant, so no candidate ever returns 200"},

		// Both ASP.NET rows are DispatchScopePerHost and probe a hardcoded absolute path,
		// ignoring the audited exchange's own path, so the endpoint below only has to exist for
		// the host to be audited. See registerReflection for why the routes sit outside /rf/.
		{Path: "/rf/aspnet", Row: "ASP.NET debugging enabled",
			SafeTwinNotApplicable: "the check probes /Default.aspx regardless of which endpoint is " +
				"being audited, so a safe twin is a different path the check never looks at: auditing " +
				"it still reaches the same debugging endpoint and still finds it. A twin could only be " +
				"made quiet by removing the vulnerable route, which removes the row. The exemption is " +
				"the check's host scope, not a detector keying on reflection",
			Note: "answers the ASP.NET remote-debugging Command header at /Default.aspx with the protocol's own refusal message"},
		{Path: "/rf/aspnet/trace", Row: "ASP.NET tracing enabled",
			SafeTwinNotApplicable: "same host scope as ASP.NET debugging enabled: /trace.axd is probed " +
				"whatever endpoint is audited, so no second path on this host can be quiet for this row",
			Note: "serves the ASP.NET application-level trace viewer at /trace.axd, recent requests and all"},

		{Path: "/rf/catalogue", Row: "User agent-dependent response",
			Note: "serves a reduced single-column page to any mobile device-class User-Agent and a full comparison table otherwise"},
		{Path: "/rf/safe/catalogue", Row: "User agent-dependent response", Safe: true,
			Note: "reads the User-Agent and serves one representation to every client, so no header value changes the body"},

		// The baseline capture carries no Referer (seed sets Origin but not Referer), so the
		// baseline gets the full-article branch and the probe's crafted off-site Referer gets the
		// teaser. Stated because the differential inverts if that ordering is ever reversed.
		{Path: "/rf/article", Row: "Referer-dependent response",
			Note: "gates the article body on the Referer's host: an off-site referrer gets a paywall teaser, an absent or same-host one gets the full text"},
		{Path: "/rf/safe/article", Row: "Referer-dependent response", Safe: true,
			Note: "reads the Referer and serves the same article whatever it says, so no referrer changes the body"},
	}
}

// registerReflection serves this family's routes.
//
// # Two routes sit outside the /rf/ prefix, and have to
//
// checkASPDebuggingEnabled and checkASPTracingEnabled (internal/scanner/checks_reflection3.go)
// probe the literal paths "/Default.aspx" and "/trace.axd" recovered from burp.Zihl and burp.Ze3_.
// They never consult the audited exchange's path, so these two rows are unreachable from any
// prefixed path. Moving them under /rf/ would not fail the build - it would leave both rows
// silently undetectable, which looks exactly like a clean target. They are registered as exact
// patterns so they cannot swallow a sibling family's routes.
func registerReflection(mux *http.ServeMux) {
	mux.HandleFunc("/rf/greeting", reflectDisplayName)
	mux.HandleFunc("/rf/safe/greeting", maskDisplayName)

	// Subtree handlers, so every name the backup-file check invents gets a definite 404 rather
	// than falling through to vulnapp.go's root handler. That matters: the check compares each
	// candidate against a control fetched from a deliberately absent neighbour, and a root
	// handler answering 200 for both would make the control and the candidates identical - the
	// vulnerable endpoint would go undetected and the safe one would look correctly quiet for
	// the wrong reason.
	mux.HandleFunc("/rf/backup/", serveNotesWithBackup)
	mux.HandleFunc("/rf/safe/backup/", serveReportWithoutBackup)

	mux.HandleFunc("/rf/aspnet", aspNetLanding)
	mux.HandleFunc("/rf/aspnet/trace", aspNetLanding)
	mux.HandleFunc("/Default.aspx", aspNetDebugTarget)
	mux.HandleFunc("/trace.axd", aspNetTraceViewer)

	// The response-dependence pairs. Each vulnerable route genuinely varies its body on the
	// header the check replaces; each twin reads the same header and ignores it.
	mux.HandleFunc("/rf/catalogue", catalogueByUserAgent)
	mux.HandleFunc("/rf/safe/catalogue", catalogueIgnoringUserAgent)
	mux.HandleFunc("/rf/article", articleByReferer)
	mux.HandleFunc("/rf/safe/article", articleIgnoringReferer)
}

// reflectDisplayName renders the submitted name into the page unchanged, which is all the input
// reflection row is about: the value came back verbatim. It is not itself an escaping bug - the
// row is the prerequisite that makes reflected XSS and open redirection possible.
func reflectDisplayName(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<p>Signed in as %s.</p>", htmlEscape(r.URL.Query().Get("display_name")))
}

// maskDisplayName is the twin: it consumes the same parameter and renders a page derived from it,
// but emits only its first character, so no submitted value survives into the response verbatim.
//
// Escaping alone would NOT do here. The row's evidence is "this value reappears byte-for-byte",
// and an alphanumeric value passes through HTML escaping unchanged - an escaping twin would still
// contain it and would be a correct finding rather than a false positive.
func maskDisplayName(w http.ResponseWriter, r *http.Request) {
	// Sliced by runes, not bytes: name[:1] would cut a multi-byte first character in half and
	// emit a replacement character, which is a different response shape than the masking rule.
	name := []rune(r.URL.Query().Get("display_name"))
	masked := ""
	if len(name) > 0 {
		masked = string(name[0]) + strings.Repeat("*", len(name)-1)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<p>Signed in as %s.</p>", htmlEscape(masked))
}

// notesDocument and notesBackup differ in content, which is what the check keys on: a host that
// answered 200 with identical bytes for every path would not be serving a backup at all, and
// responsesDiffer is what tells those apart.
const (
	notesDocument = "Release notes\n\nPublic changelog for the current version.\n"
	notesBackup   = "Release notes (draft)\n\nInternal: staging DB password rotation still pending.\n"
)

// serveNotesWithBackup models a directory where an editor left its backup behind: the document is
// served, one backup NAME is served, and everything else is a real 404.
//
// The filename comparison is on the backup's own name, not on any list of suffixes the scanner
// might try. An endpoint that answered "any path whose name resembles a backup" would grade the
// check against whatever this file guessed the suffix list to be, and would keep passing if the
// check stopped generating candidates at all.
func serveNotesWithBackup(w http.ResponseWriter, r *http.Request) {
	switch strings.TrimPrefix(r.URL.Path, "/rf/backup/") {
	case "notes.txt":
		servePlain(w, notesDocument)
	case "notes.txt.bak":
		servePlain(w, notesBackup)
	default:
		http.NotFound(w, r)
	}
}

// serveReportWithoutBackup is the fixed deployment: the document is there, nothing else is. Same
// 404-for-neighbours shape, so silence here means no backup was found rather than no probe landed.
func serveReportWithoutBackup(w http.ResponseWriter, r *http.Request) {
	if strings.TrimPrefix(r.URL.Path, "/rf/safe/backup/") == "report.txt" {
		servePlain(w, "Quarterly report\n\nPublished figures.\n")
		return
	}
	http.NotFound(w, r)
}

func servePlain(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, body)
}

// aspNetLanding is an ordinary page. It exists so the manifest has an endpoint to seed for the two
// host-scoped ASP.NET rows; the evidence lives at the absolute paths below.
func aspNetLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<p>Intranet portal.</p>")
}

// aspNetDebugTarget implements the server side of the ASP.NET remote-debugging handshake: a
// DEBUG/Command request is answered from the debugging machinery, and anything else gets the page.
//
// Answering the Command header is the mechanism, not a payload match. A build with debugging
// disabled has no handler for that command and serves the page regardless, which is precisely why
// the check treats even the refusal text as proof the endpoint is there. The refusal branch is
// reached here for a request that provides no debug session, which is what the scanner's probe is.
func aspNetDebugTarget(w http.ResponseWriter, r *http.Request) {
	command := r.Header.Get("Command")
	if command == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<p>Default page.</p>")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Header.Get("DebugSessionID") == "" {
		fmt.Fprint(w, "DebugSessionID corrupted or not provided.")
		return
	}
	fmt.Fprintf(w, "Debug access denied to '%s'.", r.URL.Path)
}

// aspNetTraceViewer serves what trace.axd renders when application-level tracing is left on: the
// request log, in the viewer's own markup. class="tracecontent" is the built-in viewer's real
// class name, and it is the disclosure - the table below it is other users' traffic.
func aspNetTraceViewer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<html><body><span class="tracecontent">`+
		`<h1>Application Trace</h1><table><tr><th>No.</th><th>Time</th><th>File</th><th>Status</th></tr>`+
		`<tr><td>1</td><td>08/17/2026 09:14:02</td><td>/Default.aspx</td><td>200</td></tr>`+
		`<tr><td>2</td><td>08/17/2026 09:14:44</td><td>/Account.aspx?token=8f2c1a</td><td>200</td></tr>`+
		`</table></span></body></html>`)
}

// catalogueByUserAgent genuinely branches on the User-Agent, serving a reduced page to a mobile
// client. It inspects the device-class substrings a real mobile-detection layer looks for, so any
// mobile string reaches the branch - not only the one the check happens to send.
func catalogueByUserAgent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if isMobileAgent(r.Header.Get("User-Agent")) {
		fmt.Fprint(w, "<ul><li>Widget</li></ul>")
		return
	}
	fmt.Fprint(w, "<table><tr><td>Widget</td><td>In stock</td><td>Compare</td></tr></table>")
}

// catalogueIgnoringUserAgent serves one representation to every client, which is the twin: the
// header is read and deliberately not acted on.
func catalogueIgnoringUserAgent(w http.ResponseWriter, r *http.Request) {
	_ = r.Header.Get("User-Agent")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<table><tr><td>Widget</td><td>In stock</td><td>Compare</td></tr></table>")
}

func isMobileAgent(ua string) bool {
	lower := strings.ToLower(ua)
	for _, device := range [...]string{"iphone", "ipad", "android", "mobile", "blackberry", "symbian"} {
		if strings.Contains(lower, device) {
			return true
		}
	}
	return false
}

// articleByReferer varies on where the reader came from: an off-site referrer gets a paywall
// teaser, an on-site or absent one gets the article. It compares the referrer's host against its
// own, which is what a real referrer-gated paywall does.
func articleByReferer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	referer := r.Header.Get("Referer")
	if referer != "" && !strings.Contains(referer, r.Host) {
		fmt.Fprint(w, "<p>Subscribers only. Read the first paragraph.</p>")
		return
	}
	fmt.Fprint(w, "<article><p>Full text of the article.</p></article>")
}

// articleIgnoringReferer reads the header and serves the same article either way.
func articleIgnoringReferer(w http.ResponseWriter, r *http.Request) {
	_ = r.Header.Get("Referer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<article><p>Full text of the article.</p></article>")
}
