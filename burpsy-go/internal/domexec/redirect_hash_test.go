package domexec

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// serveRedirect serves "/start", which answers 302 to "/landing", and "/landing", which answers
// landing. It returns the URL of /start.
func serveRedirect(t *testing.T, landing string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/landing", http.StatusFound)
	})
	mux.HandleFunc("/landing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(landing))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + "/start"
}

// A server redirect is not a script-driven navigation. The browser carries the planted fragment
// onto a Location that has none, so the load commits at "/landing#canary" - a URL that differs from
// the one planted and contains the canary, with no script having run at all. Reporting it fired
// "Open redirection (DOM-based)" on every redirecting endpoint, safe ones included.
func TestAServerRedirectCarryingThePlantedFragmentIsNotALocationSinkFlow(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := serveRedirect(t, `<html><body><p>landed</p></body></html>`)
	obs := observe(t, b, url, "burpsyCanaryRedirect1")
	if got := ObservationsForSink(obs, SinkLocationAssign); len(got) != 0 {
		t.Fatalf("an HTTP 302 that the browser followed, carrying the fragment, is the caller's own navigation, not a script flow; got %+v", got)
	}
}

// The positive control for the guard above: the redirect still lands on a page, and a script on that
// page that really navigates from the hash must still be observed. Without it, a guard that dropped
// every navigation after a redirect would pass the test above.
func TestAScriptRedirectOnTheLandingPageOfAServerRedirectIsStillObserved(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := serveRedirect(t, `<html><body><script>
		var t = location.hash.slice(1);
		if (t) { location.href = "/elsewhere?to=" + t; }
	</script></body></html>`)
	obs := observe(t, b, url, "burpsyCanaryRedirect2")
	if len(ObservationsForSink(obs, SinkLocationAssign)) == 0 {
		t.Fatalf("a landing page whose script navigates from location.hash must still be observed; got %+v", obs)
	}
}
