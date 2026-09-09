package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/dash"
)

// ---- Task row actions ----------------------------------------------------------------------------
//
// The /api/tasks/ subtree carries every per-task action the dashboard row offers
// (burpsy-react-ui-r6q):
//
//	POST /api/tasks/{id}/cancel   — stop one running task (as before)
//	POST /api/tasks/{id}/again    — scan again: start the same kind of work at the same target
//	DELETE /api/tasks/{id}        — remove one finished task from the list
//
// The registry's own contracts do the honesty work: cancel of nothing-running answers false and
// this route reports 404, so a stale dashboard row's button says "gone" instead of pretending;
// delete of a RUNNING task is refused with 409, because a list entry that vanishes while its work
// keeps going is a lie about what is happening now.

func (s *Server) handleTaskCancel(w http.ResponseWriter, r *http.Request) {
	s.taskAction(w, r, "cancel")
}

// handleTaskAgain re-runs a task: scan again. Only crawl-kind tasks re-run today, because a crawl
// is the only kind whose Start call needs nothing the old task did not already carry — an audit
// needs its exchange ids and an attack its payload set, neither of which the row holds. Saying so
// in a 409 is honest; silently starting something narrower than the operator asked for is not.
// The re-run goes through the same startCrawl the New scan dialog uses, so a scan-again crawl
// validates, registers and accounts exactly like a hand-typed one.
func (s *Server) handleTaskAgain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, ok := s.taskIDOf(w, r)
	if !ok {
		return
	}
	task := s.taskByID(id)
	if task == nil {
		http.Error(w, "No task with that id", http.StatusNotFound)
		return
	}
	if task.Kind != dash.KindCrawl {
		http.Error(w, "Only crawl tasks can be re-run from the dashboard; an audit or an attack needs its original inputs", http.StatusConflict)
		return
	}
	if _, _, err := s.startCrawl(crawlStartReq{Seeds: []string{task.Target}}); err != nil {
		http.Error(w, err.Error(), crawlStartStatus(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"started": id, "target": task.Target})
}

// handleTaskDelete removes one finished task from the list. The registry refuses a running task;
// this surfaces that refusal as 409 with the reason, rather than as a bare failure.
func (s *Server) handleTaskDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.tasks == nil {
		http.Error(w, "No task registry is configured in this process", http.StatusServiceUnavailable)
		return
	}
	id, ok := s.taskIDOf(w, r)
	if !ok {
		return
	}
	if !s.tasks.Delete(id) {
		task := s.taskByID(id)
		if task == nil {
			http.Error(w, "No task with that id", http.StatusNotFound)
		} else {
			http.Error(w, "Task is still running — cancel it before deleting its row", http.StatusConflict)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// taskAction dispatches the subtree by suffix, the way the single /cancel route used to. A path
// that is just the id (DELETE) or carries no known action verb is routed by verb here.
func (s *Server) taskAction(w http.ResponseWriter, r *http.Request, _ string) {
	if s.tasks == nil {
		http.Error(w, "No task registry is configured in this process", http.StatusServiceUnavailable)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	switch {
	case strings.HasSuffix(rest, "/cancel"):
		idStr := strings.TrimSuffix(rest, "/cancel")
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
	case strings.HasSuffix(rest, "/again"):
		s.handleTaskAgain(w, r)
	default:
		s.handleTaskDelete(w, r)
	}
}

// taskIDOf parses the task id from a path of the form /api/tasks/{id}[|/suffix]. Failing is a
// written 404, so callers return immediately on false.
func (s *Server) taskIDOf(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	for _, suffix := range []string{"/cancel", "/again"} {
		rest = strings.TrimSuffix(rest, suffix)
	}
	id, err := strconv.ParseUint(strings.Trim(rest, "/"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid task id", http.StatusNotFound)
		return 0, false
	}
	return id, true
}

// taskByID snapshots one task by id, or nil when there is no such row.
func (s *Server) taskByID(id uint64) *dash.Task {
	if s.tasks == nil {
		return nil
	}
	for _, t := range s.tasks.Snapshot() {
		if t.ID == id {
			return &t
		}
	}
	return nil
}
