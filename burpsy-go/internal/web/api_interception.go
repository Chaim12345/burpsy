package web

import (
	"net/http"

	"github.com/burpsy-go/burpsy/internal/proxy"
)

// The TLS interception switch, live.
//
// -intercept-tls was read once at startup: a process started without it tunnelled every CONNECT opaque
// until it was restarted, which in the middle of an engagement means losing the proxy's listeners and
// whatever the client had open. The policy already decided per connection whether to intercept (no
// engine means tunnel), so the switch is that engine: on attaches the CA engine (loaded from, or
// generated into, -ca-dir the first time), off detaches it. Off keeps the CA, so /ca.crt, import and
// regenerate go on working and switching back on signs with the same CA the clients already trust.
// Not persisted: like the flag it stands in for, it is this process's choice, and a restart takes the
// flag again.

type interceptionView struct {
	Enabled bool   `json:"enabled"`
	CADir   string `json:"ca_dir"`
	// HasCA says whether a CA is loaded (it stays loaded when interception is switched off).
	HasCA bool `json:"has_ca"`
}

type interceptionReq struct {
	Enabled *bool `json:"enabled"`
}

func (s *Server) viewInterception() interceptionView {
	return interceptionView{Enabled: s.tlsPolicy.Engine() != nil, CADir: s.caDir, HasCA: s.caEngine() != nil}
}

// handleInterception serves GET/PUT /api/proxy/interception.
func (s *Server) handleInterception(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodPut:
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.tlsPolicy == nil {
		http.Error(w, "No TLS policy is attached to this server, so interception cannot be switched", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.viewInterception())
		return
	}
	var req interceptionReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil || req.Enabled == nil {
		http.Error(w, `body must be {"enabled": true|false}`, http.StatusBadRequest)
		return
	}
	if !*req.Enabled {
		s.tlsPolicy.WithEngine(nil)
		writeJSON(w, http.StatusOK, s.viewInterception())
		return
	}
	s.caMu.Lock()
	engine := s.tlsEngine
	if engine == nil {
		loaded, err := proxy.LoadOrGenerateCA(s.caDir)
		if err != nil {
			s.caMu.Unlock()
			http.Error(w, "the CA could not be loaded or generated in "+s.caDir+": "+err.Error(), http.StatusInternalServerError)
			return
		}
		engine = loaded
		s.tlsEngine = loaded
	}
	s.caMu.Unlock()
	s.tlsPolicy.WithEngine(engine)
	writeJSON(w, http.StatusOK, s.viewInterception())
}
