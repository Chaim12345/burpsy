package web

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/proxy"
)

// The proxy option set's runtime surface: Burp's Proxy → Response modification rules
// and the strip-Accept-Encoding knob, live.
//
// The engine could always apply these rules — Options has existed on the relay path
// since the U12 merge — but nothing could turn a rule on: the option set was built in
// NewProxyConfig with every flag off and no handle on it anywhere. This file and
// WithProxyOptions are the two halves of making the rules reachable: the same pointer
// the relay reads per message is what PUT writes, so a switch here is the switch the
// relay obeys. The counters come with it, for the reason options.go states: a rule
// that fired zero times has to be distinguishable from a rule that was never allowed
// to look.
//
// Every mutation answers with the whole confirmed state — flags and counters — so a
// client never renders a state it has not seen confirmed, the convention the
// passthrough and scanner-config endpoints share.

// proxyOptionsView is one GET's answer: every option by wire name, plus the outcome
// counters. Options is nil-tolerant (a nil set reads as all-off with zero counters),
// but this endpoint refuses nil with 503 instead — an all-off panel on a server with
// no option set attached would look like a working panel nobody has configured, which
// is exactly the reading the counters exist to prevent.
type proxyOptionsView struct {
	Options  map[string]bool   `json:"options"`
	Counters proxy.Counters    `json:"counters"`
	Keys     []proxy.OptionKey `json:"keys"`
}

// handleProxyOptions serves GET/PUT /api/proxy/options.
func (s *Server) handleProxyOptions(w http.ResponseWriter, r *http.Request) {
	// Verb dispatch precedes the option-set guard, matching handleTlsPassthrough: a
	// wrong verb is 405 even when no set is attached; 503 is reserved for "this
	// capability exists and is unavailable".
	switch r.Method {
	case http.MethodGet:
		if s.proxyOptions == nil {
			http.Error(w, "No proxy option set is attached to this server, so there are no response modification rules to manage", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, s.viewProxyOptions())

	case http.MethodPut:
		if s.proxyOptions == nil {
			http.Error(w, "No proxy option set is attached to this server, so there are no response modification rules to manage", http.StatusServiceUnavailable)
			return
		}
		var req map[string]bool
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Body must be a JSON object of option keys to booleans", http.StatusBadRequest)
			return
		}
		if len(req) == 0 {
			http.Error(w, "Body must set at least one option key", http.StatusBadRequest)
			return
		}
		// Validate every key before applying any, so a request with one bad key
		// changes nothing — a half-applied patch would leave the panel describing a
		// state the relay is only partly in.
		for key := range req {
			if !proxy.KnownOption(proxy.OptionKey(key)) {
				http.Error(w, "Unknown proxy option "+key+"; the accepted keys are listed in the GET answer", http.StatusBadRequest)
				return
			}
		}
		for key, on := range req {
			// The error cannot fire after the validation pass, but it is checked
			// rather than discarded because Set owns the "is this key known" rule.
			if err := s.proxyOptions.Set(proxy.OptionKey(key), on); err != nil {
				if errors.Is(err, proxy.ErrUnknownOption) {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		// Mirror the confirmed flag set to the durable store, best-effort like every
		// other persistence sink here: an unavailable mirror costs restart fidelity and
		// must not fail an edit the relay has already applied. Written after the whole
		// batch rather than per key, so the saved document is a state the relay was
		// actually in — a per-key save would persist intermediate states that no
		// request ever produced.
		if s.persist != nil {
			s.persist.SaveProxyOptions(s.proxyOptions.Snapshot())
		}
		writeJSON(w, http.StatusOK, s.viewProxyOptions())

	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// viewProxyOptions assembles the whole confirmed state.
func (s *Server) viewProxyOptions() proxyOptionsView {
	return proxyOptionsView{
		Options:  s.proxyOptions.Snapshot(),
		Counters: s.proxyOptions.Counters(),
		Keys:     proxy.OptionKeys,
	}
}
