package crawler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Subresources (burpsy-react-ui-4ocj): images, stylesheets, icons and media a page loads are fetched,
// so a crawl reports a broken asset and the site map has it; a rel=canonical link is not an asset; an
// asset whose hash changes does not split the page into a new location; NoSubresources turns it off.
func TestACrawlFetchesThePagesSubresources(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<html><head>
				<link rel="stylesheet" href="/app.css"><link rel="icon" href="/favicon.ico">
				<link rel="canonical" href="/canonical-doc">
			</head><body>
				<img src="/logo.png"><video src="/clip.mp4" poster="/poster.jpg"></video>
				<audio src="/sound.mp3"></audio><picture><source src="/alt.webp"></picture>
			</body></html>`))
		case "/broken.png":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.Write([]byte("asset"))
		}
	}))
	t.Cleanup(srv.Close)

	h := newHarness()
	rep := run(t, h.config(srv.URL+"/"))
	paths := fetchedPaths(rep)
	for _, p := range []string{"/app.css", "/favicon.ico", "/logo.png", "/clip.mp4", "/poster.jpg", "/sound.mp3", "/alt.webp"} {
		if paths[p] == 0 {
			t.Errorf("subresource %s was not fetched: %v", p, paths)
		}
	}
	if paths["/canonical-doc"] != 0 {
		t.Errorf("a rel=canonical link was fetched as an asset")
	}
	if rep.EdgeKinds["subresource"] < 7 {
		t.Errorf("edge_kinds[subresource] = %d, want at least 7", rep.EdgeKinds["subresource"])
	}

	cfg := h.config(srv.URL + "/")
	cfg.NoSubresources = true
	if p := fetchedPaths(run(t, cfg)); p["/logo.png"] != 0 || p["/app.css"] != 0 {
		t.Errorf("NoSubresources still fetched assets: %v", p)
	}
}

// Two renderings of one page that differ only in an asset hash are one location.
func TestAnAssetHashDoesNotSplitALocation(t *testing.T) {
	a := parsePage([]byte(`<html><body><img src="/static/app.1a2b.png"><a href="/x">x</a></body></html>`), mustURL(t, "http://h/p"), DefaultLimits(), false)
	b := parsePage([]byte(`<html><body><img src="/static/app.9z8y.png"><a href="/x">x</a></body></html>`), mustURL(t, "http://h/p"), DefaultLimits(), false)
	if a.fingerprint != b.fingerprint {
		t.Error("a changed asset hash made the page a new location")
	}
}

// An image from outside scope is a refused RESOURCE (hgor's distinction), not a refused link.
func TestAnOutOfScopeImageIsARefusedResource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<html><body><img src="http://cdn.elsewhere.test/logo.png"></body></html>`))
	}))
	t.Cleanup(srv.Close)
	h := newHarness()
	h.scope.AddInclude("127.0.0.1")
	rep := run(t, h.config(srv.URL+"/"))
	if rep.Limits.OutOfScopeResources != 1 {
		t.Errorf("out_of_scope_resources = %d, want 1 for the CDN image", rep.Limits.OutOfScopeResources)
	}
}
