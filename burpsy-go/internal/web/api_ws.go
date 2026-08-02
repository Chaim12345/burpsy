package web

import (
	"encoding/json"
	"net/http"
)

// ---- WebSocket capture surface -----------------------------------------------------------------

// The Go proxy has no WebSocket relay, so these endpoints honestly report an empty capture
// surface rather than fabricating rows. The shapes mirror wshistory.ts so the UI renders its
// "no WebSocket traffic captured yet" empty states.

// wsConnectionView mirrors wshistory.ts's ConnectionView.
type wsConnectionView struct {
	Exchange uint64 `json:"exchange"`
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	Path     string `json:"path"`
	Messages int    `json:"messages"`
}

// wsRowView mirrors wshistory.ts's RowView.
type wsRowView struct {
	ID        uint64 `json:"id"`
	Exchange  uint64 `json:"exchange"`
	Direction string `json:"direction"` // "client_to_server" | "server_to_client"
	Opcode    string `json:"opcode"`
	Len       int    `json:"len"`
	Truncated bool   `json:"truncated"`
	Dropped   int    `json:"dropped"`
	Fragments int    `json:"fragments"`
	AtMs      uint64 `json:"at_ms"`
}

// wsHistoryResp mirrors wshistory.ts's HistoryResp.
type wsHistoryResp struct {
	Rows  []wsRowView `json:"rows"`
	Total int         `json:"total"`
}

// wsMessageResp mirrors wshistory.ts's MessageResp.
type wsMessageResp struct {
	Opcode string       `json:"opcode"`
	Text   *string      `json:"text,omitempty"`
	Hex    *string      `json:"hex,omitempty"`
	Close  *wsCloseInfo `json:"close,omitempty"`
}

type wsCloseInfo struct {
	Code   int    `json:"code"`
	Reason string `json:"reason"`
}

func (s *Server) handleWSConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]wsConnectionView{})
}

func (s *Server) handleWSHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(wsHistoryResp{Rows: []wsRowView{}, Total: 0})
}

func (s *Server) handleWSMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.Error(w, "no WebSocket traffic captured", http.StatusNotFound)
}
