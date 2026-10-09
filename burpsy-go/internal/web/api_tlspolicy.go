package web

import (
	"encoding/json"
	"net/http"
	"strings"
)

// The TLS passthrough runtime surface.
//
// The engine could always skip interception for listed hosts — TlsPolicy has held
// the list since the CLI flags landed — but flags are read once at startup, so a
// mistake meant restarting the proxy in the middle of an engagement. This handler
// opens that same list to the UI: Burp's Settings → TLS passthrough is live, and
// now this is too. Every mutation answers with the resulting list, so a client
// never renders a state it has not seen confirmed.

type passthroughView struct {
	Patterns []string `json:"patterns"`
	// Burp's two coupling switches (burpsy-react-ui-n1fi) and the count of hosts auto-add has written,
	// so the panel shows the behaviour rather than a list that silently grows.
	ApplyOutOfScope  bool `json:"apply_out_of_scope"`
	AutoAddOnFailure bool `json:"auto_add_on_failure"`
	AutoAdded        int  `json:"auto_added"`
}

// viewPassthrough renders the policy's current list. Passthrough returns a copy,
// so reading here cannot race a proxy-side match; a nil list renders as empty
// rather than JSON null.
func (s *Server) viewPassthrough() passthroughView {
	patterns := s.tlsPolicy.Passthrough()
	if patterns == nil {
		patterns = []string{}
	}
	return passthroughView{
		Patterns:         patterns,
		ApplyOutOfScope:  s.tlsPolicy.ApplyOutOfScope(),
		AutoAddOnFailure: s.tlsPolicy.AutoAddOnFailure(),
		AutoAdded:        s.tlsPolicy.AutoAddedCount(),
	}
}

// mirrorTlsPassthrough writes the policy's current list through to SQLite when a
// durable store is attached — best-effort like every other persistence sink: an
// unavailable mirror degrades restart fidelity, it must not fail a live edit the
// proxy has already applied.
func (s *Server) mirrorTlsPassthrough() {
	if s.persist != nil {
		s.persist.SaveTlsPassthrough(s.tlsPolicy.Passthrough())
		s.persist.SaveTlsPassthroughMode(s.tlsPolicy.ApplyOutOfScope(), s.tlsPolicy.AutoAddOnFailure())
	}
}

// tlsPassthroughAddReq is the request body handleTlsPassthrough decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type tlsPassthroughAddReq struct {
	Pattern string `json:"pattern"`
}

// tlsPassthroughSwitchesReq is the request body handleTlsPassthrough decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type tlsPassthroughSwitchesReq struct {
	ApplyOutOfScope  *bool `json:"apply_out_of_scope"`
	AutoAddOnFailure *bool `json:"auto_add_on_failure"`
}

// handleTlsPassthrough serves GET/POST/DELETE /api/proxy/passthrough.
func (s *Server) handleTlsPassthrough(w http.ResponseWriter, r *http.Request) {
	// Verb dispatch comes before the policy guard: a server without a policy must
	// still answer 405 to verbs it does not implement at all — 503 means "this
	// capability exists and is unavailable", not "this route does nothing".
	switch r.Method {
	case http.MethodGet:
		if s.tlsPolicy == nil {
			http.Error(w, "No TLS policy is attached to this server, so there is no passthrough list to manage", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.viewPassthrough())

	case http.MethodPost:
		var req tlsPassthroughAddReq
		if err := requestJSON(w, r, nil).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if s.tlsPolicy == nil {
			http.Error(w, "No TLS policy is attached to this server, so there is no passthrough list to manage", http.StatusServiceUnavailable)
			return
		}
		pattern := strings.TrimSpace(req.Pattern)
		if pattern == "" {
			http.Error(w, "A passthrough rule needs a non-empty host pattern", http.StatusBadRequest)
			return
		}
		s.tlsPolicy.AddPassthrough(pattern)
		s.mirrorTlsPassthrough()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.viewPassthrough())

	case http.MethodPut:
		// The two coupling switches. A whole document, so a client sends the state it wants and reads
		// back the confirmed one — the convention every other switch endpoint here follows.
		var req tlsPassthroughSwitchesReq
		if err := requestJSON(w, r, nil).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if s.tlsPolicy == nil {
			http.Error(w, "No TLS policy is attached to this server, so there is no passthrough list to manage", http.StatusServiceUnavailable)
			return
		}
		if req.ApplyOutOfScope != nil {
			s.tlsPolicy.SetApplyOutOfScope(*req.ApplyOutOfScope)
		}
		if req.AutoAddOnFailure != nil {
			s.tlsPolicy.SetAutoAddOnFailure(*req.AutoAddOnFailure)
		}
		s.mirrorTlsPassthrough()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.viewPassthrough())

	case http.MethodDelete:
		if s.tlsPolicy == nil {
			http.Error(w, "No TLS policy is attached to this server, so there is no passthrough list to manage", http.StatusServiceUnavailable)
			return
		}
		pattern := r.URL.Query().Get("pattern")
		if strings.TrimSpace(pattern) == "" {
			http.Error(w, "Usage: DELETE /api/proxy/passthrough?pattern=HOST_PATTERN", http.StatusBadRequest)
			return
		}
		// Removal is exact-match by design (see RemovePassthrough): a pattern that
		// is not in the list must answer 404 rather than quietly report success,
		// or a double-click on remove would look like two rules existed.
		if !s.tlsPolicy.RemovePassthrough(pattern) {
			http.Error(w, "No passthrough rule "+pattern+" is in the list; removal matches the exact pattern only", http.StatusNotFound)
			return
		}
		s.mirrorTlsPassthrough()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.viewPassthrough())

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
