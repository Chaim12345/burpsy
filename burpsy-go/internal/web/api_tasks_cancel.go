package web

import (
	"net/http"
	"strconv"
	"strings"
)

// ---- Task cancellation -------------------------------------------------------------------------
//
// POST /api/tasks/{id}/cancel asks the shared task registry to stop one running task. The
// registry's own contract does the honesty work: an id that names nothing running returns false,
// and this route reports that as 404 so a stale dashboard row's button says "gone" instead of
// pretending a cancellation happened.

func (s *Server) handleTaskCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.tasks == nil {
		http.Error(w, "No task registry is configured in this process", http.StatusServiceUnavailable)
		return
	}
	idStr := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/tasks/"), "/cancel")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid task id", http.StatusNotFound)
		return
	}
	if !s.tasks.Cancel(id) {
		http.Error(w, "No running task with that id", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": id})
}
