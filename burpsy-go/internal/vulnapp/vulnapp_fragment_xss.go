package vulnapp

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"
)

// Script-fetched HTML fragments (j1mk.42).
//
// Each endpoint answers with an HTML FRAGMENT labelled text/plain, and the page that goes with it
// fetches the endpoint and assigns the answer to innerHTML. Loaded directly the answer is inert —
// which is why the server-side reflected-XSS check, correctly, does not call it a breakout — but the
// page turns it into live markup. The scanner decides these by rendering the answer the way the page
// does (internal/domexec RenderFragment), so the rows are DOM rows: they need a browser.
//
//   - /frag/img reflects into an UNQUOTED attribute after HTML-escaping: quotes and angle brackets
//     are neutralised, a space is not, so an injected error handler runs on the image.
//   - /frag/comments stores the value and answers with every stored value unescaped: stored XSS,
//     proven by a later request that never carried the payload being answered with it.
//
// Their safe twins have the identical shape and content type with the defence that actually works:
// the attribute is quoted AND escaped, and the stored comments are escaped on output. A third twin
// keeps the vulnerable reflection but inside <template>, whose content never renders: markup that
// parses but does not execute. They are the negative controls for the fragment path.

func fragmentXSSEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/frag/img?src=a.png", Row: "Cross-site scripting (reflected)", DOM: true},
		{Path: "/safe/frag/img?src=a.png", Row: "Cross-site scripting (reflected)", DOM: true, Safe: true},
		// The browser's own control: the vulnerable endpoint's exact reflection, inside <template>.
		// The injected handler parses as an attribute (so a parse-level confirmation holds), but
		// template content is inert when inserted and never runs. Only the render can tell.
		{Path: "/safe/frag/img/inert?src=a.png", Row: "Cross-site scripting (reflected)", DOM: true, Safe: true},
		{Path: "/frag/comments?comment=hello", Row: "Cross-site scripting (stored)", DOM: true},
		{Path: "/safe/frag/comments?comment=hello", Row: "Cross-site scripting (stored)", DOM: true, Safe: true},
		// The pages that consume the fragments. Support routes, crawled rather than audited for a row.
		{Path: "/frag/img/page"},
		{Path: "/frag/comments/page"},
	}
}

// fragmentComments is one bounded comment store.
type fragmentComments struct {
	mu  sync.Mutex
	log []string
}

// maxFragmentComments bounds a store, oldest dropped first, so an audit's probes cannot grow it
// without limit across a long test binary.
const maxFragmentComments = 32

func (s *fragmentComments) add(v string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v != "" {
		s.log = append(s.log, v)
		if len(s.log) > maxFragmentComments {
			s.log = s.log[len(s.log)-maxFragmentComments:]
		}
	}
	return append([]string(nil), s.log...)
}

func registerFragmentXSS(mux *http.ServeMux) {
	mux.HandleFunc("/frag/img", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, `<img src=%s width="400" height="300"/>`, html.EscapeString(r.URL.Query().Get("src")))
	})
	mux.HandleFunc("/safe/frag/img", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, `<img src="%s" width="400" height="300"/>`, html.EscapeString(r.URL.Query().Get("src")))
	})

	mux.HandleFunc("/safe/frag/img/inert", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, `<template><img src=%s width="400" height="300"/></template>`, html.EscapeString(r.URL.Query().Get("src")))
	})

	vuln, safe := &fragmentComments{}, &fragmentComments{}
	mux.HandleFunc("/frag/comments", func(w http.ResponseWriter, r *http.Request) {
		writeFragmentComments(w, vuln.add(r.URL.Query().Get("comment")), func(s string) string { return s })
	})
	mux.HandleFunc("/safe/frag/comments", func(w http.ResponseWriter, r *http.Request) {
		writeFragmentComments(w, safe.add(r.URL.Query().Get("comment")), html.EscapeString)
	})

	mux.HandleFunc("/frag/img/page", func(w http.ResponseWriter, _ *http.Request) {
		fragmentPage(w, "/frag/img?src=a.png")
	})
	mux.HandleFunc("/frag/comments/page", func(w http.ResponseWriter, _ *http.Request) {
		fragmentPage(w, "/frag/comments")
	})
}

func writeFragmentComments(w http.ResponseWriter, comments []string, encode func(string) string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	var b strings.Builder
	for _, c := range comments {
		b.WriteString(`<div class="comment">`)
		b.WriteString(encode(c))
		b.WriteString(`</div>`)
	}
	fmt.Fprint(w, b.String())
}

// fragmentPage is the consumer: it fetches the fragment and inserts it with innerHTML.
func fragmentPage(w http.ResponseWriter, src string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><body><div id="out"></div>
<script>fetch(%q).then(function(r){return r.text()}).then(function(t){document.getElementById("out").innerHTML=t})</script>
</body></html>`, src)
}
