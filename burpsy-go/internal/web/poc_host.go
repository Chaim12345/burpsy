package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// The ephemeral PoC host (burpsy-react-ui-0z10).
//
// Burp's "Test in browser" hands the operator a URL that serves the currently
// displayed PoC: "Copy and paste the unique URL into Burp's browser. The
// browser request is served by Burp with the currently displayed HTML"
// (generate-csrf-poc.html). The property that matters is where that URL
// lives: NEVER under the console's API origin, because the console's origin
// is the one the same-origin gate defends, and a generated PoC is
// attacker-shaped HTML (it embeds bytes captured from a target) that must not
// inherit a single privilege of the console — not its origin, not a cookie
// surface, not a route in its manifest.
//
// So burpsy serves PoCs from a second listener on its own port, which is a
// different origin in every browser's model. The host is deliberately dumb:
// no API routes, no state beyond the one-shot pages, no console cookies or
// authorisation to speak of. A page is served exactly once — the token is
// spent by the first fetch, and every later fetch answers 410 Gone — because
// a URL that keeps serving a replayable attack page after the operator is
// done with it is a URL that outlives its purpose.

// pocHost is the one-shot page server: a listener on its own loopback port
// and the tokens currently unspent.
type pocHost struct {
	mu sync.Mutex
	// pages is the token -> page map. A token leaves the map when it is
	// spent, so "present" and "fetchable" are the same fact and there is no
	// second flag to drift.
	pages map[string]pocPage
	ln    net.Listener
	// baseURL is scheme://host:port once the listener is up, with no trailing
	// slash, so a page URL is baseURL + "/poc/" + token.
	baseURL string
}

// startPocHost starts the PoC host if it is not up and returns its base URL.
// The listener is bound to loopback with an ephemeral port: the console is
// loopback-only by default and the PoC host has even less reason to be
// reachable from anywhere else.
func (s *Server) startPocHost() (string, error) {
	s.pocMu.Lock()
	defer s.pocMu.Unlock()
	if s.poc != nil {
		return s.poc.baseURL, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("binding the PoC host: %w", err)
	}
	host := &pocHost{pages: map[string]pocPage{}, ln: ln, baseURL: "http://" + ln.Addr().String()}
	s.poc = host

	mux := http.NewServeMux()
	mux.HandleFunc("/poc/", func(w http.ResponseWriter, r *http.Request) {
		host.serve(w, r)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(ln) }()

	s.logger.Info("poc host listening", zap.String("addr", host.baseURL), zap.String("reason", "one-shot CSRF PoC pages, off the console origin"))
	return host.baseURL, nil
}

// mintPocURL registers one page and returns the URL that serves it once.
// The token is 32 random bytes in hex — unguessable is the property, and a
// counter would be a guessable URL to an attack page.
func (s *Server) mintPocURL(html string) (string, error) {
	base, err := s.startPocHost()
	if err != nil {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("minting a PoC token: %w", err)
	}
	token := hex.EncodeToString(raw)
	now := time.Now()
	s.poc.mu.Lock()
	defer s.poc.mu.Unlock()
	// Bounded: an unfetched page expires, and past the cap the oldest goes first. Pages are minted
	// on an operator's click, but a page nobody opened must not be held for the life of the process.
	for t, p := range s.poc.pages {
		if now.After(p.expires) {
			delete(s.poc.pages, t)
		}
	}
	for len(s.poc.pages) >= maxPocPages {
		oldest := ""
		for t, p := range s.poc.pages {
			if oldest == "" || p.expires.Before(s.poc.pages[oldest].expires) {
				oldest = t
			}
		}
		delete(s.poc.pages, oldest)
	}
	s.poc.pages[token] = pocPage{html: []byte(html), expires: now.Add(pocPageTTL)}
	return base + "/poc/" + token, nil
}

// pocPage is one minted page and when it stops being served.
type pocPage struct {
	html    []byte
	expires time.Time
}

const (
	// pocPageTTL is how long an unfetched PoC page is kept.
	pocPageTTL = 10 * time.Minute
	// maxPocPages bounds the unfetched pages held at once.
	maxPocPages = 64
)

// serve answers one page fetch: the first gets the HTML, every later one 410.
// 410 rather than 404 so a spent token reads as "this URL did serve something
// and does not any more", not "there was never any such page".
func (h *pocHost) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/poc/")
	h.mu.Lock()
	page, ok := h.pages[token]
	if ok {
		delete(h.pages, token)
	}
	h.mu.Unlock()
	if ok && time.Now().After(page.expires) {
		ok = false
	}
	if !ok {
		http.Error(w, "This PoC URL has already been used or never existed. Generate a fresh one from the console.",
			http.StatusGone)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(page.html)
}
