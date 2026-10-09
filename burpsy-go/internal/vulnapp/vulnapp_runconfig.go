package vulnapp

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Fixtures for per-run scan-configuration keys (burpsy-react-ui-o2p3), not manifest rows.
//
// They are deliberately absent from Vulnerabilities(). The manifest's contract is that a planted
// defect is found under the runtime suite's ordinary configuration, and these two exist to show a
// configuration key changing the outcome: the redirect pair's XSS is reachable only when a run follows
// redirects (scanner/audit_optimization/follow_redirections), which the ordinary configuration does
// not, and the slow endpoint is not a vulnerability at all — it is a clock the timeout overrides are
// measured against. Declaring either as a row would make the default suite fail for the right reason
// and read as a regression. Their tests live beside the code that reads the keys
// (internal/scanner/audit_project_overrides_test.go).

// registerRunConfigFixtures serves the fixtures. Unlinked from every page, so a crawl of the app does
// not stumble into a deliberately slow endpoint.
func registerRunConfigFixtures(mux *http.ServeMux) {
	mux.HandleFunc("/redirect/xss", redirectToReflectingError)
	mux.HandleFunc("/redirect/xss/landing", reflectingErrorPage)
	mux.HandleFunc("/slow", slowResponse)
}

// redirectToReflectingError answers every request with a 302 to the landing page, carrying q along.
// The 302 itself reflects nothing: the only place q can execute is the page the redirect names, which
// is Burp's own example for "follow redirections where necessary" — cross-site scripting in an error
// message returned only after following a redirect.
func redirectToReflectingError(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	http.Redirect(w, r, "/redirect/xss/landing?q="+url.QueryEscape(q), http.StatusFound)
}

// reflectingErrorPage writes q into an HTML error message unescaped.
func reflectingErrorPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><p class=\"error\">Unknown item: %s</p></body></html>", r.URL.Query().Get("q"))
}

// SlowResponseDelay is how long /slow takes to answer. Fixed rather than a parameter: a delay the
// request could choose would be an insertion point the scanner probes, and a probe that set it to its
// maximum would turn the fixture's clock into the thing under test.
const SlowResponseDelay = 1500 * time.Millisecond

// slowResponse waits SlowResponseDelay before answering, and gives up early when the client goes
// away. It reflects nothing, so the checks run against it can only succeed or time out.
func slowResponse(w http.ResponseWriter, r *http.Request) {
	select {
	case <-time.After(SlowResponseDelay):
	case <-r.Context().Done():
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<html><body><p>a slow answer</p></body></html>")
}
