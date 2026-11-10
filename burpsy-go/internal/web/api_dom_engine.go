package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/burpsy-go/burpsy/internal/scanner"
)

// The DOM engine, live (the runtime form of -dom).
//
// -dom was read once at startup, so a process started without it ran every DOM-based check as
// capability-less until a restart, which mid-engagement drops the proxy's listeners. The scanners
// hold one SwitchableBrowsers for their whole life; this route sets, changes or removes its engine.
// The value takes the -dom forms: "" (none), "chrome" (launch and discover), "ws://…"/"wss://…"
// (attach to a CDP server) or a browser binary. The process supplies the builder (cmd/burpsy), so
// the browser leaves through the same egress route as every other send and a bad value is refused
// with the same words as the flag. Setting an engine switches the DOM families on, as the flag did.
// riskExecute: a binary path starts that program. Not persisted: like the flag it stands in for.

// DOMEngineBuilder turns a -dom value into a provider ("" is never passed: it means none).
type DOMEngineBuilder func(value string) (scanner.BrowserProvider, error)

type domEngineView struct {
	// Engine is the -dom value in force, "off" when there is none.
	Engine string `json:"engine"`
	// Configured says whether an engine is set; DOMChecks whether the scanner's DOM families are on.
	Configured bool `json:"configured"`
	DOMChecks  bool `json:"dom_checks"`
}

type domEngineReq struct {
	Engine *string `json:"engine"`
}

// WithDOMSwitch attaches the switch the scanners hold and the builder for its values.
func (s *Server) WithDOMSwitch(sw *scanner.SwitchableBrowsers, build DOMEngineBuilder) *Server {
	s.domSwitch = sw
	s.domBuild = build
	return s
}

// domEngineLabel is the engine in force: the switch's when one is attached, else the -dom value.
// A CDP endpoint is shown as scheme://host:port only: its path carries the browser id, which is
// the capability to drive that browser, and this view is read by every API client.
func (s *Server) domEngineLabel() string {
	label := s.domEngine
	if s.domSwitch != nil {
		label = s.domSwitch.Label()
	}
	if strings.HasPrefix(label, "ws://") || strings.HasPrefix(label, "wss://") {
		// Only a path is withheld: a bare ws://host:port names no browser and is shown as given.
		if u, err := url.Parse(label); err == nil && (len(u.Path) > 1 || u.RawQuery != "") {
			return u.Scheme + "://" + u.Host + "/…"
		}
	}
	return label
}

// domBrowserNames are the program names a runtime PUT may start. The route runs a binary in this
// process's privileges, so it starts browsers and nothing else; any other path needs -dom.
var domBrowserNames = map[string]bool{
	"chrome": true, "google-chrome": true, "google-chrome-stable": true, "chromium": true,
	"chromium-browser": true, "headless_shell": true, "chrome-headless-shell": true,
	"msedge": true, "microsoft-edge": true, "brave": true, "brave-browser": true,
	"obscura": true, "lightpanda": true,
}

// domEngineAllowed says whether a runtime value may be set. The -dom flag is the operator's own
// command line and takes anything; this route is reachable by every API client, so it takes less:
// the value -dom was started with, "chrome", a known browser binary, or a CDP endpoint on this
// machine. A remote endpoint would render in-scope pages (cookies included) on another host.
func (s *Server) domEngineAllowed(value string) error {
	if value == "chrome" || (s.domEngine != "" && value == strings.TrimSpace(s.domEngine)) {
		return nil
	}
	if strings.HasPrefix(value, "ws://") || strings.HasPrefix(value, "wss://") {
		u, err := url.Parse(value)
		if err != nil {
			return fmt.Errorf("unreadable CDP endpoint: %w", err)
		}
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return fmt.Errorf("a CDP endpoint on another host (%s) is refused at runtime: in-scope pages would be rendered there; restart with -dom to use it", host)
	}
	name := strings.TrimSuffix(strings.ToLower(filepath.Base(value)), ".exe")
	if domBrowserNames[name] {
		return nil
	}
	return fmt.Errorf("%q is not a known browser binary; this route starts browsers only - restart with -dom to use another program", filepath.Base(value))
}

func (s *Server) viewDOMEngine() domEngineView {
	v := domEngineView{Engine: "off", Configured: s.domSwitch.Configured()}
	if l := s.domEngineLabel(); l != "" {
		v.Engine = l
	}
	if sc := s.wiredScanner(); sc != nil {
		snap := sc.ConfigSnapshot()
		v.DOMChecks = snap.CheckDOM
	}
	return v
}

// handleDOMEngine serves GET/PUT /api/scanner/dom.
func (s *Server) handleDOMEngine(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodPut:
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The body goes through requestJSON, not a bare json.Decoder, and before the capability guard — the
	// order and the decoder every other body-taking route uses. An agent's unknown field is then
	// refused with a 400 rather than silently dropped (this route can name a binary to execute, so a
	// misspelt "engine" must not quietly mean "no engine"), and the schema sweep reaches the decode.
	var req domEngineReq
	if r.Method == http.MethodPut {
		if err := requestJSON(w, r, http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || req.Engine == nil {
			http.Error(w, `body must be {"engine": ""|"chrome"|"ws://host:port/..."|"/path/to/browser"}`, http.StatusBadRequest)
			return
		}
	}
	if s.domSwitch == nil || s.domBuild == nil {
		http.Error(w, "this process has no switchable DOM engine (it was built without one); restart with -dom", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodPut {
		value := strings.TrimSpace(*req.Engine)
		var p scanner.BrowserProvider
		if value != "" && value != "off" {
			if err := s.domEngineAllowed(value); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			built, err := s.domBuild(value)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			p = built
		} else {
			value = ""
		}
		if err := s.domSwitch.Set(p, value); err != nil && s.logger != nil {
			// the new engine is in force; only the old browser's shutdown complained
			s.logger.Sugar().Warnw("closing the previous DOM engine failed", "error", err)
		}
		if p != nil {
			// a scanner built later from the capability recipe picks the engine up when it is wired
			s.wiredScanner().EnableDOMChecks()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.viewDOMEngine())
}
