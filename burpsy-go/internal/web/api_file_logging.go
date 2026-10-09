package web

import (
	"io"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/filelog"
)

// handleFileLogging serves GET/PUT /api/project/logging — Burp's Project settings → Logging
// (burpsy-react-ui-nvfl). GET answers the settings with every tool key present, the tool list and
// what the writer has done. PUT replaces the whole document: an unknown key or tool, or a path that is
// not absolute or cannot be opened for appending, is refused by name and nothing changes.
func (s *Server) handleFileLogging(w http.ResponseWriter, r *http.Request) {
	// Verb dispatch first, as every settings route here does: a wrong verb is 405 whatever the server
	// carries.
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if s.fileLog == nil {
			http.Error(w, "No file logger is attached to this server", http.StatusServiceUnavailable)
			return
		}
		s.writeFileLogging(w)
	case http.MethodPut:
		// Decoded before the attachment check, so the body is refused or accepted on its own terms
		// whatever the server carries — and so the schema probe (route_schema.go) reaches the decode.
		// Strict for every caller: an unknown key names the mistake rather than logging nothing.
		var settings filelog.Settings
		dec := requestJSON(w, r, io.LimitReader(r.Body, 1<<20))
		dec.dec.DisallowUnknownFields()
		if err := dec.Decode(&settings); err != nil {
			http.Error(w, "Body must be {\"requests\": {tool: path}, \"responses\": {tool: path}}: "+err.Error(), http.StatusBadRequest)
			return
		}
		if s.fileLog == nil {
			http.Error(w, "No file logger is attached to this server", http.StatusServiceUnavailable)
			return
		}
		if err := s.fileLog.Apply(settings); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if s.persist != nil {
			s.persist.SaveFileLogging(s.fileLog.Settings())
		}
		s.writeFileLogging(w)
	}
}

func (s *Server) writeFileLogging(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, struct {
		filelog.Settings
		Tools []string      `json:"tools"`
		Stats filelog.Stats `json:"stats"`
	}{Settings: s.fileLog.Settings(), Tools: filelog.Tools, Stats: s.fileLog.Stats()})
}
