package crawler

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// A follow-up pass whose retries BOTH recover a page (admitting its links to the frontier) AND trip
// the pause policy ends the crawl before those links are visited: the policy just said this target
// is not to be sent to (burpsy-react-ui-credfx).
func TestARetryThatTripsThePauseAlsoStopsTheLinksItAdmitted(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	hit := func(p string) int { mu.Lock(); defer mu.Unlock(); hits[p]++; return hits[p] }
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>" + body + "</body></html>"))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Successes between the slow pages keep the main loop under the consecutive threshold.
		page(w, `<a href="/a1">a1</a><a href="/ok1">ok1</a><a href="/a2">a2</a><a href="/ok2">ok2</a><a href="/a3">a3</a>`)
	})
	mux.HandleFunc("/ok1", func(w http.ResponseWriter, r *http.Request) { page(w, "ok") })
	mux.HandleFunc("/ok2", func(w http.ResponseWriter, r *http.Request) { page(w, "ok") })
	// /a1 times out once, then its retry recovers and admits /late.
	mux.HandleFunc("/a1", func(w http.ResponseWriter, r *http.Request) {
		if hit("/a1") == 1 {
			time.Sleep(time.Second)
			return
		}
		page(w, `<a href="/late">late</a>`)
	})
	// /a2 and /a3 always time out: their retries are the two consecutive timeouts that trip the
	// pause inside the pass, after /a1's retry admitted /late.
	slow := func(w http.ResponseWriter, r *http.Request) { time.Sleep(time.Second) }
	mux.HandleFunc("/a2", slow)
	mux.HandleFunc("/a3", slow)
	mux.HandleFunc("/late", func(w http.ResponseWriter, r *http.Request) { hit("/late"); page(w, "late") })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := fastTimeoutConfig(h, srv.URL+"/")
	cfg.ErrorHandling = ErrorHandling{PauseOnTimeoutCount: intp(2), FollowUpPasses: intp(1)}
	rep := runLikeProduction(t, cfg)

	if !rep.Limits.Hit(StopPausedTimeouts) {
		t.Fatalf("the pause did not trip inside the follow-up pass: stops %v", rep.Limits.Stops)
	}
	mu.Lock()
	recovered, late := hits["/a1"], hits["/late"]
	mu.Unlock()
	if recovered < 2 {
		t.Fatalf("/a1 was not retried (%d request(s)), so the case under test never happened", recovered)
	}
	if late != 0 {
		t.Errorf("/late was fetched %d time(s) after the pause tripped: the links a retry admitted took a visit past the policy", late)
	}
}
