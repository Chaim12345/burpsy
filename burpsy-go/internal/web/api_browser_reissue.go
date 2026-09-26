package web

// Request-in-browser (burpsy-react-ui-7rk0): re-issue a stored request under two session
// variants and hand the operator a URL that drives each one.
//
// Burp's context menu offers "Request in browser — In original session / In current browser
// session": the first re-sends with the cookie header the original request carried, the second
// with whatever the session jar holds now. Burp implements the browser half as a URL handoff —
// a dialog that says "copy the URL below and paste into a browser" and a listener that serves
// the re-issue when the browser fetches it (repeatRequestInBrowserDialog +
// repeatRequestInBrowserRenderUrlTxtField in the recovered strings).
//
// burpsy takes the same two halves, honestly scoped:
//
//   - The VARIANTS are the server's work: one stored request, two sends, differing only in the
//     Cookie header. Both outcomes are recorded and shown side by side, because "does the same
//     request behave differently under my session" is only answerable with both columns.
//   - The URL is a one-shot token on this console's own web listener, minted by the API and
//     spent by the fetch: opening it in the operator's own browser is the manual step Burp's
//     dialog also asks for, and it is what makes this "in browser" rather than "in Repeater" —
//     the browser supplies its own session context (and the operator watches the real UI, not
//     our rendering of it).
//
// # Why the token is one-shot and short-lived
//
// A URL that re-sends a request is a CSRF token by another name: anything that can induce the
// operator's browser to fetch it re-issues a request against a target. Burp's dialog hands the
// URL to the operator and nothing else; burpsy matches that by minting the token on demand,
// expiring it after five minutes, and spending it on first use — a pasted URL that has already
// fired answers "already used" rather than silently re-sending. The mint endpoint is the same
// surface Burp's right-click is: it needs the operator's hand to reach.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// reissueExpiry bounds how long a minted URL stays live. Long enough to copy and paste; short
// enough that a URL left in a clipboard does not outlive the engagement's interest in it.
const reissueExpiry = 5 * time.Minute

// browserReissue is one minted token: the exchange to re-issue, the variant it drives, and the
// deadline past which it answers "expired" rather than re-sending.
type browserReissue struct {
	exchange core.ExchangeID
	variant  string // "original" | "current" — the two cookie policies Burp names
	expires  time.Time
}

// browserReissueTokens is the mint table. Bounded by expiry sweeps rather than a hard cap: a
// table whose entries die in five minutes cannot grow faster than an operator can click, and
// the sweep on mint is one range over a map that is, in practice, a handful of entries.
type browserReissueTokens struct {
	mu sync.Mutex
	m  map[string]browserReissue
}

// handleRepeaterBrowserReissue serves POST /api/repeater/browser-reissue: the operator's right
// click on a stored exchange. The reply carries both variants' URLs — the dialog shows both,
// because the comparison is the deliverable, and an operator who must mint twice would see
// the first outcome before the second's context existed.
func (s *Server) handleRepeaterBrowserReissue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// A pointer, not a plain uint64: exchange ids are 0-based (position-is-the-id), so 0 is
	// the FIRST exchange and a plain field cannot tell "named the first exchange" from "named
	// nothing". Nil is the absence; 0 is an id like any other.
	var req struct {
		Exchange *uint64 `json:"exchange"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Exchange == nil {
		http.Error(w, "name the exchange to re-issue", http.StatusBadRequest)
		return
	}
	ex, err := s.store.GetExchange(core.ExchangeID(*req.Exchange))
	if err != nil {
		http.Error(w, fmt.Sprintf("no exchange %d to re-issue", *req.Exchange), http.StatusNotFound)
		return
	}
	// Request id 0 is a REAL message id (position-is-the-id, 0-based): the first message the
	// store ever held is id 0, and refusing it would make the very first exchange of every
	// fresh project un-reissuable. GetExchange already answered existence; nothing here needs
	// a zero-check at all.
	// The two scope gates every egress path applies here too: the host the stored request went
	// to, then the raw bytes about to go out. A re-issue is a send; scope set to constrain
	// outbound traffic must not be bypassable by resending what was already sent once.
	if !s.scope.MayContainHost(ex.Host, ex.Port, ex.TLS) {
		http.Error(w, "refused: "+s.scope.Explain(ex.Host, ex.Port, ex.Path, ex.TLS), http.StatusForbidden)
		return
	}
	msg, err := s.store.Get(core.MsgOrZero(ex.Request))
	if err != nil {
		http.Error(w, "the stored request could not be read back", http.StatusInternalServerError)
		return
	}
	if aerr := s.scope.AuthoriseRaw(ex.Host, ex.Port, ex.TLS, msg.Raw()); aerr != nil {
		http.Error(w, "refused: "+aerr.Error(), http.StatusForbidden)
		return
	}

	origURL := s.reissueMint(ex.ID, "original")
	currURL := s.reissueMint(ex.ID, "current")
	if origURL == "" || currURL == "" {
		http.Error(w, "minting the re-issue URLs failed; try again", http.StatusInternalServerError)
		return
	}
	if strings.TrimSpace(s.webBind) == "" {
		// No recorded bind: the console cannot name a URL for the operator's browser if it
		// never learned what address it was started on. Refused with the reason rather than
		// rendered as "http:///reissue/...", which would hand the operator a URL that cannot
		// work and whose failure would look like the feature's.
		http.Error(w, "this console does not know its own web bind address, so it cannot mint a browser URL; "+
			"it was started without the -web flag value being recorded", http.StatusInternalServerError)
		return
	}
	base := "http://" + s.webBind
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusOK, map[string]any{
		"exchange_id":  uint64(ex.ID),
		"original_url": base + "/reissue/" + origURL,
		"current_url":  base + "/reissue/" + currURL,
		"note":         "each URL is one-shot and expires in 5 minutes; open it in the browser whose session you want to test",
	})
}

// handleBrowserReissueFetch serves GET /reissue/{token}: the fetch that drives one variant.
//
// It runs the send synchronously and answers with a small page that names what was sent and
// what came back, because the operator just asked their browser to do this and an answer that
// is only visible back inside the console would be a handoff that handed nothing off. Both
// outcomes are also recorded as exchanges, so the two variants appear in history like any
// other send — the comparison survives the dialog.
func (s *Server) handleBrowserReissueFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/reissue/")
	rec, ok := s.reissueSpend(token)
	if !ok {
		// Expired or already spent: the answer must not be a silent nothing, because the
		// operator's browser just fetched this URL and is waiting for something to be said.
		http.Error(w, "this re-issue URL has already been used or has expired — request a fresh one from the exchange's context menu", http.StatusGone)
		return
	}
	ex, err := s.store.GetExchange(rec.exchange)
	if err != nil {
		http.Error(w, "the exchange this URL was minted for is no longer in the store", http.StatusNotFound)
		return
	}
	msg, err := s.store.Get(core.MsgOrZero(ex.Request))
	if err != nil {
		http.Error(w, "the stored request could not be read back", http.StatusInternalServerError)
		return
	}

	// Build the variant's bytes. Original: the request verbatim, Cookie header exactly as it
	// was captured. Current: the jar's header for this authority and path, substituted in.
	raw := msg.Raw()
	if rec.variant == "current" {
		if jar := s.cookieHeaderFor(ex.Host, ex.Port, ex.TLS, ex.Path); jar != "" {
			raw = replaceCookieHeader(raw, jar)
		}
	}

	// The send: through the sender, so the hostname-resolution table and the upstream proxy
	// policy apply as they do to every send burpsy makes. Scope was checked at mint; the
	// bytes are re-checked here, because the jar may have changed what goes out since.
	if aerr := s.scope.AuthoriseRaw(ex.Host, ex.Port, ex.TLS, raw); aerr != nil {
		http.Error(w, "refused: "+aerr.Error(), http.StatusForbidden)
		return
	}
	started := time.Now()
	respBytes, _, err := s.sender.SendRawOutcome(r.Context(), ex.Host, ex.Port, ex.TLS, raw, sender.ProtocolPreferenceAuto)
	elapsed := time.Since(started)

	// Record both halves like any other send, so history carries the comparison.
	var exchangeID *core.ExchangeID
	if err == nil {
		reqID, perr := s.store.Put(raw, core.DirectionRequest)
		if perr != nil {
			s.logger.Error("browser re-issue: storing the request failed", zap.Error(perr))
		}
		respID, rerr := s.store.Put(respBytes, core.DirectionResponse)
		if rerr != nil {
			s.logger.Error("browser re-issue: storing the response failed", zap.Error(rerr))
		}
		status := parseResponseStatus(respBytes)
		notes := "browser re-issue (" + rec.variant + " session)"
		sent := &core.Exchange{
			Request: core.MsgPtr(reqID), Response: &respID,
			Host: ex.Host, Port: ex.Port, TLS: ex.TLS,
			Method: ex.Method, Path: ex.Path, Status: status,
			Protocol:   core.ProtocolHTTP1,
			UserEdited: true,
			Notes:      &notes,
		}
		s.store.AddExchange(sent)
		exchangeID = &sent.ID
		s.live.notify(changeHistory)
	}
	// The exchange is in history and the page points there by words rather than by id, so the
	// variable's only remaining use is this line: keeping the "recorded" fact visible to the
	// reader as a fact, not a leftover.
	_ = exchangeID

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	variantLabel := "In current session"
	if rec.variant == "original" {
		variantLabel = "In original session"
	}
	// The target is `ex.Host + ex.Path`, which is TARGET-CONTROLLED data: it comes from a request
	// someone recorded, and a request line can carry `<svg/onload=...>` in its path. It is escaped
	// here as well as the error text below, because the error path and the success path both render
	// it and only one of them used to ask (tvdg).
	authority := htmlEscape(ex.Host + ex.Path)
	if err != nil {
		fmt.Fprintf(w, reissuePageShell, htmlEscape(variantLabel), authority,
			"<p class=\"err\">the re-issue did not reach the target: "+htmlEscape(err.Error())+"</p>")
		return
	}
	status := ""
	if st := parseResponseStatus(respBytes); st != nil {
		status = fmt.Sprintf("%d", *st)
	}
	fmt.Fprintf(w, reissuePageShell, htmlEscape(variantLabel), authority,
		"<p>the request was sent and the target answered <strong>"+htmlEscape(status)+"</strong> in "+
			strconv.FormatInt(elapsed.Milliseconds(), 10)+" ms.</p>"+
			"<p class=\"hint\">both this and the other session variant are in HTTP history as their own exchanges.</p>")
}

// reissueMint mints one token for one variant of one exchange. The token is 16 random bytes,
// not a counter: a guessable URL that re-sends a request is a CSRF primitive, and randomness
// is the only property that makes it not one.
func (s *Server) reissueMint(ex core.ExchangeID, variant string) string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand refusing is an environment failure; refusing the mint is the safe
		// direction, and the operator sees it as a 500 on the right-click rather than as a
		// URL that never works.
		return ""
	}
	token := hex.EncodeToString(buf)
	s.reissue.mu.Lock()
	defer s.reissue.mu.Unlock()
	if s.reissue.m == nil {
		s.reissue.m = make(map[string]browserReissue)
	}
	// Sweep on mint: entries live five minutes, so a sweep on every mint keeps the map at
	// the size of an operator's last five minutes of clicking, with no timer to leak.
	now := time.Now()
	for k, v := range s.reissue.m {
		if now.After(v.expires) {
			delete(s.reissue.m, k)
		}
	}
	s.reissue.m[token] = browserReissue{exchange: ex, variant: variant, expires: now.Add(reissueExpiry)}
	return token
}

// reissueSpend consumes one token. One-shot is the point: a URL that re-sends a request N
// times is a request-forgery surface with a five-minute window, and the operator asked for a
// single re-issue anyway.
func (s *Server) reissueSpend(token string) (browserReissue, bool) {
	s.reissue.mu.Lock()
	defer s.reissue.mu.Unlock()
	rec, ok := s.reissue.m[token]
	if !ok || time.Now().After(rec.expires) {
		return browserReissue{}, false
	}
	delete(s.reissue.m, token)
	return rec, true
}

// replaceCookieHeader swaps (or inserts) the Cookie header in a raw request, leaving every
// other byte untouched — the same splice discipline the rest of this package applies, because
// a re-written Content-Length or a lost header order would make the "current session" variant
// differ from the "original" one by more than its cookies.
func replaceCookieHeader(raw []byte, jar string) []byte {
	head, body := splitHead(raw)
	lines := strings.Split(string(head), "\r\n")
	// Find the head's end boundary: the last header line is the empty string before the body.
	insertAt := -1
	for i, l := range lines {
		if i == 0 {
			continue // the request line
		}
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(l, ":", 2)[0]), "cookie") {
			insertAt = i
			break
		}
	}
	if insertAt >= 0 {
		lines[insertAt] = "Cookie: " + jar
	} else {
		// Insert before the trailing empty line that ends the head.
		for i, l := range lines {
			if l == "" {
				insertAt = i
				break
			}
		}
		if insertAt < 0 {
			insertAt = len(lines)
			lines = append(lines, "")
		}
		lines = append(lines[:insertAt], append([]string{"Cookie: " + jar}, lines[insertAt:]...)...)
	}
	out := strings.Join(lines, "\r\n")
	return []byte(out + string(body))
}

// splitHead splits a raw message at the blank line, keeping the separator with the head's
// text so reassembly is a concatenation rather than a reformat.
func splitHead(raw []byte) (head, body []byte) {
	if i := indexDoubleCRLF(raw); i >= 0 {
		return raw[:i+2], raw[i+2:]
	}
	return raw, nil
}

func indexDoubleCRLF(raw []byte) int {
	for i := 0; i+3 < len(raw); i++ {
		if raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n' {
			return i
		}
	}
	return -1
}

// htmlEscape escapes a value for interpolation into the answer page's HTML.
//
// The standard library's escaper, not a hand-written replacer: the previous version here was
// strings.NewReplacer with IDENTITY pairs ("&" -> "&", "<" -> "<"), so htmlEscape(x) == x for
// every input and the two call sites that used it escaped nothing at all (burpsy-react-ui-tvdg).
// A hand-written escape table is one missing entry away from the same silent failure; this one
// cannot be wrong, and a test now says what it must do.
func htmlEscape(s string) string {
	return html.EscapeString(s)
}

// reissuePageShell is the answer page: plain HTML, no script, because its job is to say what
// happened and point at history — and a page that runs nothing cannot be turned into
// anything by the very request it just re-issued.
const reissuePageShell = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>%s</title>
<style>body{font:13px/1.5 system-ui,sans-serif;max-width:40em;margin:4em auto;padding:0 1em;color:#222}
h1{font-size:1.1em}p.err{color:#b00}p.hint{color:#666;font-size:.9em}</style></head>
<body><h1>%s</h1>%s</body></html>`
