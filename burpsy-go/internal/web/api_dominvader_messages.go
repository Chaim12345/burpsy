package web

import (
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
		m, err := s.domMessages.Record(body.FrameToken, body.Message, false, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, m)
	case "/api/dominvader/messages/poll":
		writeJSON(w, http.StatusOK, s.domMessages.Poll(body.FrameToken, time.Now()))
	}
}

// domWorkerRoutes is the ONLY cross-origin worker exception set. The guarded-handler
// exception derives only from this declaration; literal route registrations remain
// visible to the repository route-manifest verifier.
var domWorkerRoutes = map[string]bool{
	"/api/dominvader/messages/register": true,
	"/api/dominvader/messages/report":   true,
	"/api/dominvader/messages/poll":     true,
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
