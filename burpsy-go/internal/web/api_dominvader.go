package web

import (
	"io"
	"net"
	"net/http"
	"os"

	"github.com/burpsy-go/burpsy/internal/dominvader"
)

// ---- DOM auditor (burpsy-react-ui-wl94) ----------------------------------------------------------
//
// Burp's DOM Invader, in the shape burpsy ships it: an extension loaded into the operator's browser
// that watches a canary through a page's own sources and sinks while the operator browses. This file
// is the console's side of it — read and set the canary and the switch, read the reported hits — plus
// the endpoint the extension's service worker POSTs each hit to.

// domInvaderReportURL is the absolute URL the extension reports to: burpsy's own web host, with a
// wildcard or empty bind normalised to loopback (the browser runs on this machine). Empty when the
// server was built but never served — tests, which do not launch a browser.
func (s *Server) domInvaderReportURL() string {
	if s.webAddr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(s.webAddr)
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/api/dominvader/hit"
}

// domInvaderBypassHost is the host:port the browser must reach directly for the report POST to skip
// the proxy (see browser.Spec.BypassProxyFor). Same normalisation as the report URL, without the path.
func (s *Server) domInvaderBypassHost() string {
	if s.webAddr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(s.webAddr)
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// materialiseDomAuditor writes the DOM-auditor extension to a fresh temp directory with the current
// config baked in, removing the previous launch's copy so the temp area holds one at a time. Returns
// the directory and the host:port the browser must bypass for the report POST. An empty report URL
// (a server that is not serving) yields an empty dir and no error: there is nowhere to report, so the
// extension is not loaded rather than loaded blind.
func (s *Server) materialiseDomAuditor() (dir, bypass string, err error) {
	report := s.domInvaderReportURL()
	if report == "" {
		return "", "", nil
	}
	if s.domExtDir != "" {
		_ = os.RemoveAll(s.domExtDir)
		s.domExtDir = ""
	}
	dir, err = dominvader.Materialise("", s.domInvader.BeginWorkerLaunch(report))
	if err != nil {
		return "", "", err
	}
	s.domExtDir = dir
	return dir, s.domInvaderBypassHost(), nil
}

type domInvaderView struct {
	Canary  string            `json:"canary"`
	Enabled bool              `json:"enabled"`
	Hits    []*dominvader.Hit `json:"hits"`
	// ReportURL is where the extension reports, shown so the operator can see the loopback endpoint
	// the auditor uses. Empty on a server that is not serving.
	ReportURL string `json:"report_url"`
	// LaunchNote is the one caveat the console states: the canary and switch are baked into the
	// extension at browser launch, so a change needs a relaunch to take effect.
	LaunchNote string `json:"launch_note"`
}

func (s *Server) domInvaderView() domInvaderView {
	hits := s.domInvader.Hits()
	if hits == nil {
		hits = []*dominvader.Hit{}
	}
	return domInvaderView{
		Canary:     s.domInvader.Canary(),
		Enabled:    s.domInvader.Enabled(),
		Hits:       hits,
		ReportURL:  s.domInvaderReportURL(),
		LaunchNote: "The canary and the switch are applied when the browser is launched; change them, then open the browser (or relaunch it) to take effect.",
	}
}

// domInvaderReq is the request body handleDomInvader decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type domInvaderReq struct {
	Canary  *string `json:"canary"`
	Enabled *bool   `json:"enabled"`
}

// handleDomInvader serves GET/PUT /api/dominvader. riskLocal: it reads and writes burpsy's own
// auditor state and sends nothing.
func (s *Server) handleDomInvader(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.domInvaderView())
	case http.MethodPut:
		var body domInvaderReq
		if err := requestJSON(w, r, io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
			http.Error(w, `the body must be {"canary"?:"...","enabled"?:bool}`, http.StatusBadRequest)
			return
		}
		if body.Canary != nil {
			if err := s.domInvader.SetCanary(*body.Canary); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if body.Enabled != nil {
			s.domInvader.SetEnabled(*body.Enabled)
		}
		writeJSON(w, http.StatusOK, s.domInvaderView())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDomInvaderHit serves POST /api/dominvader/hit — the extension's service worker reporting one
// flow. riskLocal: it records a hit burpsy's own browser produced and sends nothing. There is no
// confirmation token: this is the extension burpsy itself loaded, reporting over a loopback host the
// browser reaches directly, and gating it behind a mint the extension cannot perform would only
// silence the auditor.
func (s *Server) handleDomInvaderHit(w http.ResponseWriter, r *http.Request) {
	var h dominvader.Hit
	if err := requestJSON(w, r, io.LimitReader(r.Body, 1<<20)).Decode(&h); err != nil {
		http.Error(w, "the body must be one hit object", http.StatusBadRequest)
		return
	}
	if h.Sink == "" {
		http.Error(w, "a hit needs a sink or source name", http.StatusBadRequest)
		return
	}
	s.domInvader.Add(&h)
	w.WriteHeader(http.StatusNoContent)
}

// handleDomInvaderHits serves DELETE /api/dominvader/hits — clear the list. riskLocal.
func (s *Server) handleDomInvaderHits(w http.ResponseWriter, r *http.Request) {
	s.domInvader.Clear()
	w.WriteHeader(http.StatusNoContent)
}
