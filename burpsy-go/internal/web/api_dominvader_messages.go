package web

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/burpsy-go/burpsy/internal/dominvader"
)

// All three worker routes fail closed BEFORE parsing page-derived content. The
// capability lives only in worker-config.js, not in MAIN-world config or a view.
const domWorkerHeader = "X-Burpsy-DOM-Worker"

type domMessageWorkerReq struct {
	FrameToken string             `json:"frame_token"`
	Tab        int                `json:"tab"`
	Frame      string             `json:"frame"`
	Message    dominvader.Message `json:"message"`
	HoldID     string             `json:"hold_id,omitempty"`
	Outcome    string             `json:"outcome,omitempty"`
}

func (s *Server) handleDomMessageWorker(w http.ResponseWriter, r *http.Request) {
	if !s.domInvader.WorkerAuthorized(r.Header.Get(domWorkerHeader)) {
		http.Error(w, "worker capability required", http.StatusUnauthorized)
		return
	}
	var body domMessageWorkerReq
	if err := requestJSON(w, r, io.LimitReader(r.Body, dominvader.MaxMessageBody+4096)).Decode(&body); err != nil {
		http.Error(w, "invalid worker report", http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	case "/api/dominvader/messages/register":
		// The worker derives these fields from chrome.runtime sender metadata, NOT
		// from MAIN-world message payloads. A compromised worker defeats this boundary.
		token := s.domMessages.OpenFrame(body.Tab, body.Frame)
		if token == "" {
			http.Error(w, "frame session limit reached", http.StatusTooManyRequests)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"frame_token": token})
	case "/api/dominvader/messages/report":
		// Interception stays OFF until the console/controller is wired. A worker
		// report must never turn it on or smuggle an operator decision.
		m, err := s.domMessages.Record(body.FrameToken, body.Message, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, m)
	case "/api/dominvader/messages/poll":
		writeJSON(w, http.StatusOK, s.domMessages.Poll(body.FrameToken, time.Now()))
	case "/api/dominvader/messages/ack":
		// The worker's own claim that it dispatched a delivered decision to its
		// frame. Frame-bound, single-use, recorded as unverified; never "applied".
		if err := s.domMessages.Acknowledge(body.FrameToken, body.HoldID, body.Outcome, time.Now()); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "recorded-unverified"})
	}
}

type domMessageInterceptReq struct {
	Enabled bool `json:"enabled"`
}
type domMessageDecideReq struct {
	HoldID string `json:"hold_id"`
	Action string `json:"action"`
	Body   string `json:"body"`
	Origin string `json:"origin"`
}

// handleDomMessages serves the CONSOLE-ONLY controller surface (same-origin
// guard; worker capability never unlocks it). Observations listed here are
// untrusted page claims and are labelled so; only an explicit decide call on a
// server-issued hold ID can cause a replay or drop.
func (s *Server) handleDomMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Global GET policy is unguarded; this read carries page-supplied bodies and
	// the hold IDs, so it applies the Host (rebinding) and Origin checks itself.
	if !s.acceptsHost(r.Host) {
		http.Error(w, crossSiteRefusal, http.StatusForbidden)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && !s.originMatchesHost(origin, r.Host) {
		http.Error(w, crossSiteRefusal, http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"untrusted_observations": true,
		"intercept":              s.domMessages.Intercept(),
		"messages":               s.domMessages.Messages(time.Now()),
	})
}

func (s *Server) handleDomMessageIntercept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body domMessageInterceptReq
	if err := requestJSON(w, r, io.LimitReader(r.Body, 1<<10)).Decode(&body); err != nil {
		http.Error(w, `the body must be {"enabled":bool}`, http.StatusBadRequest)
		return
	}
	s.domMessages.SetIntercept(body.Enabled)
	writeJSON(w, http.StatusOK, map[string]bool{"intercept": body.Enabled})
}

func (s *Server) handleDomMessageDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body domMessageDecideReq
	if err := requestJSON(w, r, io.LimitReader(r.Body, dominvader.MaxMessageBody+4096)).Decode(&body); err != nil {
		http.Error(w, "invalid decision", http.StatusBadRequest)
		return
	}
	err := s.domMessages.ControllerDecide(body.HoldID, dominvader.MessageDecision{Action: body.Action, Body: body.Body, Origin: body.Origin}, time.Now())
	if errors.Is(err, dominvader.ErrUnknownHold) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "decided-awaiting-worker-delivery"})
}

// domWorkerRoutes is the ONLY cross-origin worker exception set. The guarded-handler
// exception derives only from this declaration; literal route registrations remain
// visible to the repository route-manifest verifier.
var domWorkerRoutes = map[string]bool{
	"/api/dominvader/messages/register": true,
	"/api/dominvader/messages/report":   true,
	"/api/dominvader/messages/poll":     true,
	"/api/dominvader/messages/ack":      true,
}

func (s *Server) domWorkerException(w http.ResponseWriter, r *http.Request) (bool, bool) {
	if r.Method != http.MethodPost || !domWorkerRoutes[r.URL.Path] {
		if r.Header.Get(domWorkerHeader) != "" {
			http.Error(w, crossSiteRefusal, http.StatusForbidden)
			return true, false
		}
		return false, false
	}
	if !s.acceptsHost(r.Host) {
		http.Error(w, crossSiteRefusal, http.StatusForbidden)
		return true, false
	}
	if !s.domInvader.WorkerAuthorized(r.Header.Get(domWorkerHeader)) {
		http.Error(w, "worker capability required", http.StatusUnauthorized)
		return true, false
	}
	return true, true
}
