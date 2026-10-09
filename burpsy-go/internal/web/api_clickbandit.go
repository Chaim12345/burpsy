package web

import (
	"net/http"

	"github.com/burpsy-go/burpsy/internal/web/clickbandit"
)

// handleClickbandit serves GET /api/engagement/clickbandit.js — burpsy's Clickbandit script
// (burpsy-react-ui-g67w), for the console's "Copy Clickbandit to clipboard". It is served as text,
// never executed here: it runs in the browser the operator pastes it into.
func (s *Server) handleClickbandit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(clickbandit.Script))
}
