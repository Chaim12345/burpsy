package crawler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Delayed redirects (burpsy-react-ui-q0qr), Burp's DELAYED_REDIRECT edge: a landing page that only
// meta-refreshes into the application, and a response whose Refresh header names the next page. Both
// were one-page crawls before.
func TestACrawlFollowsMetaRefreshAndTheRefreshHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><head><meta http-equiv="Refresh" content="0; URL='/app/'"></head><body>loading</body></html>`))
		case "/app/":
			w.Header().Set("Refresh", "5;url=/app/next")
			w.Write([]byte(`<html><body>app</body></html>`))
		case "/app/next":
			w.Write([]byte(`<html><body>next</body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	h := newHarness()
	rep := run(t, h.config(srv.URL+"/"))
	paths := fetchedPaths(rep)
	if paths["/app/"] == 0 {
		t.Errorf("the meta refresh target was never fetched: %v", paths)
	}
	if paths["/app/next"] == 0 {
		t.Errorf("the Refresh header target was never fetched: %v", paths)
	}
}

func TestRefreshTargetGrammar(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"0; url=/a", "/a", true},
		{"5;URL='/b c'", "/b c", true},
		{`3, url="/q"`, "/q", true},
		{"1; /bare", "/bare", true},
		{"0.5; url = /spaced", "/spaced", true},
		{"10", "", false},     // reload only
		{"url=/x", "", false}, // no delay
		{"0; url=", "", false},
	} {
		got, ok := refreshTarget(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("refreshTarget(%q) = %q,%v; want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}
