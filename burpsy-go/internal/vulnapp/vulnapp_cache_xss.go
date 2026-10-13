package vulnapp

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
)

// Reflected XSS behind a shared cache, answered as a JSON envelope around an HTML fragment.
//
// Each endpoint sits behind a shared cache keyed on the request path alone — the query is not in the
// key, path parameters (";x=y") are, as in a servlet container's request URI — and answers JSON whose
// "content" value is markup the page's script assigns to innerHTML. Two things stand between a
// scanner and the reflection here:
//
//   - The cache: every request to the route after the first is answered with the first one's page,
//     so a probe sent to the route reads its predecessor's value, and is itself stored and served to
//     every other visitor. A probe has to carry a buster the cache keys on to see its own answer.
//   - The envelope: the body opens with '{', so it is not markup, and the fragment is a string value
//     that the page unwraps before inserting it.
//
// The routes are subtrees so a path parameter reaches the same handler, as it does in a servlet
// container. /cx/banner/view reflects the banner parameter into that fragment unescaped. Its twins
// keep the cache, the envelope and the content type: /safe/cx/banner/view escapes the value, and
// /safe/cx/field/view
// returns the value raw but in its own non-markup field (the page writes it with textContent) while
// the markup field never carries it.

func cacheXSSEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/cx/banner/view?banner=hello", Row: "Cross-site scripting (reflected)", DOM: true,
			Note: "route-keyed shared cache; the banner parameter is reflected unescaped into a JSON value the page inserts with innerHTML"},
		{Path: "/safe/cx/banner/view?banner=hello", Row: "Cross-site scripting (reflected)", DOM: true, Safe: true,
			Note: "same cache and envelope, but the banner is HTML-escaped inside the fragment"},
		{Path: "/safe/cx/field/view?banner=hello", Row: "Cross-site scripting (reflected)", DOM: true, Safe: true,
			Note: "same cache and envelope; the banner is returned raw, but in a field of its own that is not markup, and the markup field never carries it"},
		// The consumer page. A support route, crawled rather than audited for a row.
		{Path: "/cx/page"},
	}
}

// One cache per endpoint, so no endpoint can be served another's body.
var (
	cacheXSSStore      vaSharedCache
	cacheXSSSafeStore  vaSharedCache
	cacheXSSFieldStore vaSharedCache
)

// routeKey is the cache key of a cache that ignores the query string.
func routeKey(r *http.Request) string {
	key, _, _ := strings.Cut(r.RequestURI, "?")
	return key
}

func bannerEnvelope(fields map[string]any) string {
	b, _ := json.Marshal(fields)
	return string(b)
}

func registerCacheXSS(mux *http.ServeMux) {
	mux.HandleFunc("/cx/banner/", func(w http.ResponseWriter, r *http.Request) {
		cacheXSSStore.serveAs(w, routeKey(r), "application/json", func() string {
			return bannerEnvelope(map[string]any{"ok": true,
				"content": `<section class="banner"><p>Banner: ` + r.URL.Query().Get("banner") + `</p></section>`})
		})
	})
	mux.HandleFunc("/safe/cx/banner/", func(w http.ResponseWriter, r *http.Request) {
		cacheXSSSafeStore.serveAs(w, routeKey(r), "application/json", func() string {
			return bannerEnvelope(map[string]any{"ok": true,
				"content": `<section class="banner"><p>Banner: ` + html.EscapeString(r.URL.Query().Get("banner")) + `</p></section>`})
		})
	})
	mux.HandleFunc("/safe/cx/field/", func(w http.ResponseWriter, r *http.Request) {
		cacheXSSFieldStore.serveAs(w, routeKey(r), "application/json", func() string {
			return bannerEnvelope(map[string]any{"ok": true, "banner": r.URL.Query().Get("banner"),
				"content": `<section class="banner"><p>Banner of the day</p></section>`})
		})
	})
	mux.HandleFunc("/cx/page", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><body><div id="out"></div><p id="name"></p>
<script>fetch("/cx/banner/view?banner=hello").then(function(r){return r.json()}).then(function(d){document.getElementById("out").innerHTML=d.content})</script>
</body></html>`)
	})
}
