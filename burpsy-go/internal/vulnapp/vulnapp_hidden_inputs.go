package vulnapp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"sort"
	"strings"
)

// Fixtures for the hidden-input guesser (burpsy-react-ui-wlz8), not manifest rows.
//
// Deliberately absent from Vulnerabilities(), for the reason vulnapp_runconfig.go's fixtures are: the
// manifest's contract is that the ordinary audit finds each row, and hidden-input guessing is not part
// of an ordinary audit — it is an on-demand action, as Param Miner is in Burp, and its "Secret input"
// issues are extension-generated rows with no catalogue name the runtime suite could resolve. They
// are unlinked from every page: a crawl must not wander into the random page, and the whole point of
// the hidden endpoint is that nothing links to the inputs it reads.
//
// Their tests drive the real route end to end (internal/web/api_hidden_inputs_test.go) and the
// engine directly (internal/scanner/hidden_inputs_test.go).

// The hidden names the guesser must find on /hidden/account. Each is on the built-in wordlist, and
// none sits in the first batch of its kind, so finding them exercises bisection rather than a lucky
// single-name batch. A test in the scanner package asserts both properties against the real list.
const (
	HiddenQueryParam = "preview"
	HiddenHeader     = "X-Api-Version"
	HiddenCookie     = "premium"
	// HiddenReflectedParam is read and echoed into a form field, and changes nothing else: once the
	// guesser strips its own values, only the reflection is left as evidence.
	HiddenReflectedParam = "ref"
)

func registerHiddenInputFixtures(mux *http.ServeMux) {
	mux.HandleFunc("/hidden/account", hiddenAccount)
	mux.HandleFunc("/hidden/random", hiddenRandom)
	mux.HandleFunc("/hidden/echo", hiddenEcho)
}

// hiddenAccount changes its page when a hidden input is present, whatever its value: the shape of a
// real debug or preview switch. Nothing it serves names the inputs.
func hiddenAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var extra []string
	if r.URL.Query().Has(HiddenQueryParam) {
		extra = append(extra, "<p class=\"preview\">Preview mode: unpublished changes are shown.</p>")
	}
	if r.Header.Get(HiddenHeader) != "" {
		extra = append(extra, "<p class=\"api\">Legacy API rendering enabled.</p>")
	}
	if _, err := r.Cookie(HiddenCookie); err == nil {
		extra = append(extra, "<p class=\"premium\">Premium dashboard.</p>")
	}
	fmt.Fprintf(w, "<html><body><h1>Your account</h1><p>Balance: 100</p>%s"+
		"<form><input type=\"hidden\" name=\"r\" value=\"%s\"></form></body></html>",
		strings.Join(extra, ""), html.EscapeString(r.URL.Query().Get(HiddenReflectedParam)))
}

// hiddenRandom answers every request with a different body. Nothing about it is hidden; a guesser
// that reports an input here has read the page's own noise as one, which is what the two-baseline
// stability check exists to refuse.
func hiddenRandom(w http.ResponseWriter, _ *http.Request) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><p>Request id: %s</p></body></html>", hex.EncodeToString(b[:]))
}

// hiddenEcho reads no input at all and echoes everything: the request URI, as a canonical-URL tag
// does, and every header VALUE, as a "your request" diagnostics page does. Every name a guesser adds
// changes this page, and none of them is an input — the real-world false-positive mode.
func hiddenEcho(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	var values []string
	for _, name := range names {
		values = append(values, html.EscapeString(strings.Join(r.Header[name], ",")))
	}
	fmt.Fprintf(w, "<html><head><link rel=\"canonical\" href=\"%s\"></head><body><p>%s</p></body></html>",
		html.EscapeString(r.URL.RequestURI()), strings.Join(values, " | "))
}
