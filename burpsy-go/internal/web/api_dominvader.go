package web

import (
	"context"
	"fmt"
	"github.com/burpsy-go/burpsy/internal/core"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

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
	dir, err = dominvader.Materialise("", s.domInvader.Config(report))
	if err != nil {
		return "", "", err
	}
	s.domExtDir = dir
	return dir, s.domInvaderBypassHost(), nil
}

type domInvaderView struct {
	Pollution dominvader.PollutionConfig `json:"pollution"`
	Canary    string                     `json:"canary"`
	Enabled   bool                       `json:"enabled"`
	Hits      []*dominvader.Hit          `json:"hits"`
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
		Pollution:  s.domInvader.Pollution(),
		Enabled:    s.domInvader.Enabled(),
		Hits:       hits,
		ReportURL:  s.domInvaderReportURL(),
		LaunchNote: "The canary and the switch are applied when the browser is launched; change them, then open the browser (or relaunch it) to take effect.",
	}
}

// domInvaderReq is the request body handleDomInvader decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type domInvaderReq struct {
	Pollution *dominvader.PollutionConfig `json:"pollution"`
	Canary    *string                     `json:"canary"`
	Enabled   *bool                       `json:"enabled"`
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
		if body.Pollution != nil {
			if err := body.Pollution.Validate(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if body.Pollution.Enabled {
				u, _ := url.Parse(body.Pollution.Target)
				port := uint64(80)
				if u.Scheme == "https" {
					port = 443
				}
				if u.Port() != "" {
					var err error
					port, err = strconv.ParseUint(u.Port(), 10, 16)
					if err != nil || port == 0 {
						http.Error(w, "invalid target port", http.StatusBadRequest)
						return
					}
				}
				path := u.EscapedPath()
				if path == "" {
					path = "/"
				}
				if s.scope == nil || (s.scope.Empty() && !s.scope.AllowAll()) || !s.scope.Contains(u.Hostname(), uint16(port), path, u.Scheme == "https") {
					http.Error(w, "pollution target is outside current scope; configure matching scope rules or explicitly enable AllowAll", http.StatusForbidden)
					return
				}
			}
		}
		if body.Canary != nil {
			if err := s.domInvader.SetCanary(*body.Canary); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if body.Pollution != nil {
			_ = s.domInvader.SetPollution(*body.Pollution)
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

// domPollutionGate checks the live engagement scope on EVERY URL, including
// redirects. The dedicated probe context is not the operator proxy, which only
// uses scope for recording. Same-origin is an additional restriction, not scope.
type domPollutionGate struct {
	scope  *core.Scope
	origin *url.URL
}

func (g domPollutionGate) AllowURL(u *url.URL) error {
	if u.Scheme != g.origin.Scheme || !strings.EqualFold(u.Host, g.origin.Host) {
		return fmt.Errorf("probe request is outside the selected origin")
	}
	if g.scope == nil || (g.scope.Empty() && !g.scope.AllowAll()) || !g.scope.Contains(u.Hostname(), defaultPort(u), u.EscapedPath(), u.Scheme == "https") {
		return fmt.Errorf("probe request is outside current engagement scope")
	}
	return nil
}
func (g domPollutionGate) AllowAuthority(host string, port uint16, tls bool) error {
	if !strings.EqualFold(host, g.origin.Hostname()) || port != defaultPort(g.origin) || tls != (g.origin.Scheme == "https") {
		return fmt.Errorf("probe tunnel is outside the selected origin")
	}
	if g.scope == nil || !g.scope.MayContainHost(host, port, tls) {
		return fmt.Errorf("probe tunnel is outside current engagement scope")
	}
	return nil
}

// handleDomInvaderScan starts only the finite operator-selected probe plan.
func (s *Server) handleDomInvaderScan(w http.ResponseWriter, r *http.Request) {
	p := s.domInvader.Pollution()
	if !s.domInvader.Enabled() || !p.Enabled {
		http.Error(w, "turn on the DOM auditor and opt into a pollution plan first", http.StatusConflict)
		return
	}
	if err := p.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, _ := url.Parse(p.Target)
	gate := domPollutionGate{s.scope, u}
	if err := gate.AllowURL(u); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if s.wiredScanner() == nil || !s.wiredScanner().DOMCapabilityConfigured() {
		http.Error(w, "no DOM browser is configured", http.StatusServiceUnavailable)
		return
	}
	b, err := s.wiredScanner().BrowserForRender(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	out, err := dominvader.Scan(ctx, b, p, gate)
	if err != nil {
		out.Errors = append(out.Errors, err.Error())
	}
	for _, h := range out.Hits {
		s.domInvader.Add(h)
	}
	writeJSON(w, http.StatusOK, out)
}
