package web

import (
	"encoding/json"
	"net/http"
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
func (s *Server) domEngineLabel() string {
	if s.domSwitch != nil {
		return s.domSwitch.Label()
	}
	return s.domEngine
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
	if s.domSwitch == nil || s.domBuild == nil {
		http.Error(w, "this process has no switchable DOM engine (it was built without one); restart with -dom", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodPut {
		var req domEngineReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || req.Engine == nil {
			http.Error(w, `body must be {"engine": ""|"chrome"|"ws://host:port/..."|"/path/to/browser"}`, http.StatusBadRequest)
			return
		}
		value := strings.TrimSpace(*req.Engine)
		var p scanner.BrowserProvider
		if value != "" && value != "off" {
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
	json.NewEncoder(w).Encode(s.viewDOMEngine())
}
