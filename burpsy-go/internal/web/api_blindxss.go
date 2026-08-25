package web

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/blindxss"
)

// ---- The blind-XSS callback channel --------------------------------------------------------------
//
// internal/blindxss is a complete capability with no way in: it binds an HTTP listener, serves a
// bounded capture script at a token-carrying path, and records what each execution posts back — and
// nothing outside its own tests ever constructed one. These two routes are the seam.
//
// # What the channel proves, and what it never proves
//
// A blind-XSS payload is rendered somewhere burpsy cannot observe: an admin panel, another user's
// session, a log viewer, an HTML mail client. There is no response body to match a canary against, so
// the only evidence is a callback from that browser. A callback therefore proves the payload executed
// — and no callback proves nothing at all. The rendering browser may be offline for days, may never
// open the page, or may sit behind egress filtering that drops the request.
//
// That asymmetry is the whole reason this surface is shaped the way it is. A minted token with no hits
// is **outstanding**, not clean, and the state this endpoint returns says so in a field and in a
// sentence rather than leaving a reader to infer it from an empty array. The same applies one level
// up: when no listener is wired, GET answers 200 with `configured: false` and the reason — an empty
// hit list on its own would read as "we listened and nothing came back", which is a claim this server
// would not be entitled to make.
//
// # Why the listener is not started from here
//
// The listener is handed in by the process that parsed the operator's flags (see
// Server.WithBlindXSS), for the same reason the external-tool allowlist is: binding a socket the
// public internet is expected to reach is an engagement decision, and a route that could bind one on
// request would make the flag decorative. A bind failure arrives here as the reason string this
// endpoint reports, so "no channel" and "a channel that heard nothing" stay distinguishable —
// internal/blindxss calls that the honest-failure contract and returns a typed *BindError to enforce
// it.

// blindXSSChannel is the server's view of the callback channel: the listener when there is one, the
// reason when there is not, and the tokens this server minted.
//
// The tokens are tracked here because blindxss.Listener answers HitsFor(token) and deliberately does
// not enumerate — a listener that could list every token would let one check read another's callbacks.
// So the minting side keeps the list, which also means this list is exactly "what an operator asked
// this server for", not "every token the listener has ever seen".
type blindXSSChannel struct {
	listener *blindxss.Listener
	// why explains a nil listener. Non-empty exactly when listener is nil.
	why string

	mu     sync.Mutex
	minted []mintedBlindXSSPayload
}

// mintedBlindXSSPayload is one correlation token this server handed out, and the two forms of it an operator
// plants.
type mintedBlindXSSPayload struct {
	Token     string    `json:"token"`
	ScriptURL string    `json:"script_url"`
	ScriptTag string    `json:"script_tag"`
	MintedAt  time.Time `json:"minted_at"`
}

// blindxssPayloadsKept bounds the minted list. Generous — a token is a few hundred bytes and an
// engagement may plant many — but bounded, because this is an in-memory list on a long-lived process
// and the listener has its own cap at 4096 tokens anyway.
const blindxssPayloadsKept = 512

// WithBlindXSS attaches the blind-XSS callback channel.
//
// Both arguments are meaningful. A non-nil listener is a live channel. A nil listener with an error is
// a channel that was asked for and could not be had — a bind failure, typically — and the error's text
// becomes what GET /api/blindxss reports as the reason. A nil listener with a nil error is the state
// this server starts in: nothing was configured, which is also reported rather than rendered as an
// empty result.
//
// The server does not take ownership of the listener's lifetime: whoever bound it closes it. This
// mirrors WithCACertPEM, where the bytes are read by the process that knows where the CA lives.
func (s *Server) WithBlindXSS(listener *blindxss.Listener, unavailable error) *Server {
	switch {
	case listener != nil:
		s.blindxss = &blindXSSChannel{listener: listener}
	case unavailable != nil:
		s.blindxss = &blindXSSChannel{why: unavailable.Error()}
	default:
		s.blindxss = nil
	}
	return s
}

// blindxssPayloadView is one minted payload plus what has come back for it.
type blindxssPayloadView struct {
	mintedBlindXSSPayload
	// Hits is every callback recorded against this token, oldest first.
	Hits []blindxss.Hit `json:"hits"`
	// Outstanding is true while no callback has arrived. Named for what it means rather than derived
	// from len(Hits) by a reader: an outstanding payload is not a clean one, and a UI that renders
	// `hits: []` without that word is one step from writing "no blind XSS found".
	Outstanding bool `json:"outstanding"`
}

// blindxssStateView is the whole channel as one document.
type blindxssStateView struct {
	// Configured is whether this process was given a blind-XSS channel at all.
	Configured bool `json:"configured"`
	// Listening is whether that channel has a live listener behind it.
	Listening bool `json:"listening"`
	// Reason explains a Listening of false, and is empty exactly when Listening is true.
	Reason string `json:"reason,omitempty"`
	// Addr is the address actually bound; BaseURL is the origin planted payloads load from, which is
	// the one an operator has to be able to reach from the victim's network.
	Addr    string `json:"addr,omitempty"`
	BaseURL string `json:"base_url,omitempty"`
	// Payloads is every token this server minted, newest last, each with its callbacks.
	Payloads []blindxssPayloadView `json:"payloads"`
	Counts   blindxssCounts        `json:"counts"`
	// Verdict states in one sentence what this state does and does not license a reader to conclude.
	// It is on the wire rather than left to each surface because every surface would otherwise have to
	// re-derive it, and the one that got it wrong would be the one claiming a clean result.
	Verdict string `json:"verdict"`
}

// blindxssCounts partitions the minted payloads: how many fired, and how many are still outstanding.
type blindxssCounts struct {
	Payloads    int `json:"payloads"`
	Hits        int `json:"hits"`
	Fired       int `json:"fired"`
	Outstanding int `json:"outstanding"`
}

// handleBlindXSS serves GET /api/blindxss: the channel's state, every payload minted through it, and
// every callback recorded against those payloads.
func (s *Server) handleBlindXSS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.blindXSSState())
}

// handleBlindXSSPayload serves POST /api/blindxss/payload: mint one correlation token and return the
// forms of it an operator plants.
//
// A separate route from the state read, and a POST, because minting is a state change: the listener
// will now serve a script for this token and record callbacks against it. A GET that minted would be
// a state change on a safe verb, which is the same defect the sequencer's `GET .../stop` had.
func (s *Server) handleBlindXSSPayload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	channel := s.blindxss
	if channel == nil || channel.listener == nil {
		// 503 with the reason, never a fabricated payload. A token minted against no listener would be
		// planted in a real application and then correlated against a channel that cannot hear it —
		// producing an outstanding finding that can never resolve either way.
		http.Error(w, blindxssUnavailableReason(channel), http.StatusServiceUnavailable)
		return
	}

	payload, err := channel.listener.GeneratePayload()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	minted := mintedBlindXSSPayload{
		Token:     payload.Token,
		ScriptURL: payload.ScriptURL,
		ScriptTag: payload.ScriptTag(),
		MintedAt:  time.Now().UTC(),
	}
	channel.remember(minted)

	writeJSON(w, http.StatusCreated, map[string]any{
		"payload":  minted,
		"base_url": channel.listener.BaseURL(),
		// Said with the payload, where it is impossible to miss, because the operator is about to plant
		// this somewhere and will read the result later expecting an answer.
		"caveat": "A callback proves the payload executed. No callback proves nothing: the rendering " +
			"browser may never open the page, may open it days from now, or may sit behind egress " +
			"filtering. Report an unfired payload as outstanding, never as clean.",
	})
}

// remember records a minted payload, dropping the oldest past the cap.
func (c *blindXSSChannel) remember(p mintedBlindXSSPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.minted = append(c.minted, p)
	if len(c.minted) > blindxssPayloadsKept {
		c.minted = c.minted[len(c.minted)-blindxssPayloadsKept:]
	}
}

// snapshot copies the minted list so hits can be read without holding the lock.
func (c *blindXSSChannel) snapshot() []mintedBlindXSSPayload {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]mintedBlindXSSPayload, len(c.minted))
	copy(out, c.minted)
	return out
}

// blindXSSState assembles the channel's whole story: configuration, listener state, and every minted
// payload with its callbacks.
func (s *Server) blindXSSState() blindxssStateView {
	channel := s.blindxss
	view := blindxssStateView{
		// Non-nil so the field serialises as [] rather than null: a client that distinguishes "no
		// payloads" from "the field was missing" should never have to.
		Payloads: []blindxssPayloadView{},
	}
	if channel == nil {
		view.Reason = blindxssUnavailableReason(nil)
		view.Verdict = "No blind-XSS channel is configured, so nothing has been planted and nothing " +
			"could have been heard. This is not a statement about any target."
		return view
	}
	view.Configured = true
	if channel.listener == nil {
		view.Reason = blindxssUnavailableReason(channel)
		view.Verdict = "A blind-XSS channel was configured and is not listening, so any payload " +
			"already planted is unobservable. This is not a statement about any target."
		return view
	}

	view.Listening = true
	view.Addr = channel.listener.Addr().String()
	view.BaseURL = channel.listener.BaseURL()

	for _, minted := range channel.snapshot() {
		// The error is the listener's room for a future store that can fail; today's in-memory one
		// cannot, and an empty token is the only input it rejects. Treated as "no hits known" rather
		// than dropped, so a payload never disappears from the list it was minted into.
		hits, err := channel.listener.HitsFor(minted.Token)
		if err != nil || hits == nil {
			hits = []blindxss.Hit{}
		}
		view.Payloads = append(view.Payloads, blindxssPayloadView{
			mintedBlindXSSPayload: minted,
			Hits:          hits,
			Outstanding:   len(hits) == 0,
		})
		view.Counts.Payloads++
		view.Counts.Hits += len(hits)
		if len(hits) == 0 {
			view.Counts.Outstanding++
		} else {
			view.Counts.Fired++
		}
	}
	view.Verdict = blindxssVerdict(view.Counts)
	return view
}

// blindxssVerdict states what the counts license a reader to conclude. The outstanding clause is the
// point: it is the sentence that stops "0 hits" from being read as "no blind XSS here".
func blindxssVerdict(c blindxssCounts) string {
	switch {
	case c.Payloads == 0:
		return "The channel is listening and no payload has been minted through it, so nothing has " +
			"been planted. There is nothing here to conclude about any target."
	case c.Outstanding == 0:
		return fmt.Sprintf("%d of %d planted payload(s) have fired, across %d callback(s). A payload "+
			"that has fired is proof; a payload that has not is still only outstanding.",
			c.Fired, c.Payloads, c.Hits)
	default:
		return fmt.Sprintf("%d of %d planted payload(s) have fired (%d callback(s)); %d are "+
			"outstanding. Outstanding is not clean: the rendering browser may never open the page, may "+
			"open it days from now, or may sit behind egress filtering that drops the callback.",
			c.Fired, c.Payloads, c.Hits, c.Outstanding)
	}
}

// blindxssUnavailableReason says why there is no channel to mint against, and what to do about it. A
// nil channel and a channel whose listener failed to bind are different facts — one is a flag nobody
// passed, the other is a socket that would not open — and an operator acts on them differently.
func blindxssUnavailableReason(channel *blindXSSChannel) string {
	if channel == nil {
		return "No blind-XSS callback channel is configured on this process. Start burpsy with " +
			"-blindxss ADDR (and -blindxss-url URL when the rendering browser reaches this host by a " +
			"different address) to bind one. Until then no payload can be planted, and no absence of " +
			"callbacks means anything."
	}
	if channel.why != "" {
		return "The blind-XSS callback channel was requested and is not listening, so no payload can " +
			"be planted and no absence of callbacks means anything: " + channel.why
	}
	return "The blind-XSS callback channel is not listening, and no reason was recorded — treat this " +
		"as no channel at all rather than as a channel that heard nothing."
}
