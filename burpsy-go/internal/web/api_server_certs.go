package web

import (
	"net/http"

	"github.com/burpsy-go/burpsy/internal/servercerts"
)

// handleServerCertificates serves GET/DELETE /api/network/server-certificates — Burp's Settings →
// Network → TLS → "Server TLS certificates" (burpsy-react-ui-t75m). GET lists what target servers
// presented, most recently seen first; DELETE clears it. Attached reports whether a store is wired,
// so an empty list from a server assembled without one does not read as "no server presented
// anything".
func (s *Server) handleServerCertificates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, struct {
			Attached     bool                `json:"attached"`
			Max          int                 `json:"max"`
			Certificates []servercerts.Entry `json:"certificates"`
		}{Attached: s.serverCerts != nil, Max: servercerts.MaxCertificates, Certificates: s.serverCerts.List()})
	case http.MethodDelete:
		s.serverCerts.Clear()
		w.WriteHeader(http.StatusOK)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
