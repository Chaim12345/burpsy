package web

import (
	"net/http"
	"strconv"

	"github.com/burpsy-go/burpsy/internal/dash"
)

// ---- Task row actions ----------------------------------------------------------------------------
//
// The /api/tasks family is one pattern per action (burpsy-react-ui-fxxm, batch 2), so the manifest
// says what each route is and the mux owns every 405:
//
//	GET    /api/tasks/{id}          — one task's row and an async task's finished body
//	DELETE /api/tasks/{id}          — remove one finished task from the list
//	POST   /api/tasks/{id}/cancel   — stop one running task
//	POST   /api/tasks/{id}/again    — scan again: start the same kind of work at the same target
//	POST   /api/tasks/{id}/pause    — hold one task at its next gate
//	POST   /api/tasks/{id}/resume   — release one task's hold
//	POST   /api/tasks/pause         — hold EVERY running task (suite-wide)
//	POST   /api/tasks/resume        — release the suite-wide hold
//
// Until batch 2 one subtree handler switched on the path tail, and the verb guards lived inside
// whichever branch ran — the drift class behind burpsy-react-ui-0gg5, where GET /api/tasks/pause
// answered 200 and set the suite-wide gate. The method patterns make that shape unwritable: a
// wrong verb never reaches a handler.
//
// The registry's own contracts do the honesty work: cancel of nothing-running answers false and
// this route reports 404, so a stale dashboard row's button says "gone" instead of pretending;
// delete of a RUNNING task is refused with 409, because a list entry that vanishes while its work
// keeps going is a lie about what is happening now.

// taskID parses the {id} wildcard as a task id. Failing is a written 404, so callers return
// immediately on false.
func taskID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid task id", http.StatusNotFound)
		return 0, false
	}
	return id, true
}

func (s *Server) noTaskRegistry(w http.ResponseWriter) bool {
	if s.tasks != nil {
		return false
	}
	http.Error(w, "No task registry is configured in this process", http.StatusServiceUnavailable)
	return true
}

// handleTaskByID serves the row's own verbs. The mux admitted only GET and DELETE; the switch
// names them rather than trusting that silently.
func (s *Server) handleTaskByID(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleTaskGet(w, r)
	case http.MethodDelete:
		s.handleTaskDelete(w, r)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTaskCancel asks one running task to stop.
func (s *Server) handleTaskCancel(w http.ResponseWriter, r *http.Request) {
	if s.noTaskRegistry(w) {
		return
	}
	id, ok := taskID(w, r)
	if !ok {
		return
	}
	if !s.tasks.Cancel(id) {
		http.Error(w, "No running task with that id", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": id})
}

// handleTaskPause and handleTaskResume are Burp's per-task Pause / Resume (burpsy-react-ui-g0ba),
// beside the suite-wide pair below.
func (s *Server) handleTaskPause(w http.ResponseWriter, r *http.Request) { s.setTaskPaused(w, r, true) }
func (s *Server) handleTaskResume(w http.ResponseWriter, r *http.Request) {
	s.setTaskPaused(w, r, false)
}

func (s *Server) setTaskPaused(w http.ResponseWriter, r *http.Request, pause bool) {
	if s.noTaskRegistry(w) {
		return
	}
	id, ok := taskID(w, r)
	if !ok {
		return
	}
	switch err := s.tasks.SetTaskPaused(id, pause); err {
	case nil:
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "paused": pause})
	case dash.ErrNoSuchTask:
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		http.Error(w, err.Error(), http.StatusConflict)
	}
}

// handleTasksPauseAll and handleTasksResumeAll are the suite-wide gate (burpsy-react-ui-8gw):
// Burp's dashboardPauseAllTasksButton and dashboardResumeAllTasksButton. Distinct routes, not task
// ids — the gate is registry state, so they answer for every running task at once. The count in
// the answer says whether anything was actually holding; pausing an empty dashboard is fine, but
// "paused 0 tasks" is the honest version of that reply.
func (s *Server) handleTasksPauseAll(w http.ResponseWriter, r *http.Request) { s.setAllPaused(w, true) }
func (s *Server) handleTasksResumeAll(w http.ResponseWriter, r *http.Request) {
	s.setAllPaused(w, false)
}

func (s *Server) setAllPaused(w http.ResponseWriter, pause bool) {
	if s.noTaskRegistry(w) {
		return
	}
	var n int
	if pause {
		n = s.tasks.PauseAll()
	} else {
		n = s.tasks.ResumeAll()
	}
	writeJSON(w, http.StatusOK, map[string]any{"paused": s.tasks.Paused(), "running": n})
}

// handleTaskAgain re-runs a task: scan again. Only crawl-kind tasks re-run today, because a crawl
// is the only kind whose Start call needs nothing the old task did not already carry — an audit
// needs its exchange ids and an attack its payload set, neither of which the row holds. Saying so
// in a 409 is honest; silently starting something narrower than the operator asked for is not.
// The re-run goes through the same startCrawl the New scan dialog uses, so a scan-again crawl
// validates, registers and accounts exactly like a hand-typed one.
func (s *Server) handleTaskAgain(w http.ResponseWriter, r *http.Request) {
	if s.noTaskRegistry(w) {
		return
	}
	id, ok := taskID(w, r)
	if !ok {
		return
	}
	task := s.taskByID(id)
	if task == nil {
		http.Error(w, "No task with that id", http.StatusNotFound)
		return
	}
	if task.Kind != dash.KindCrawl {
		// Two refusals, said apart, because they are different facts and only one of them is obvious.
		// An audit or an attack needs inputs this process never held. An API scan's inputs are a
		// document it *did* read and deliberately did not keep: the run record carries what the scan
		// sent — every resolved method, path and template — and not the file, so re-running from this
		// row would mean re-sending the endpoints with bodies and header values this build would have
		// to invent. That is a different scan wearing the same target, and the difference is exactly
		// what the definition's own examples were there to prevent.
		reason := "Only crawl tasks can be re-run from the dashboard; an audit or an attack needs its original inputs"
		if task.Kind == dash.KindAPIScan {
			reason = "An API scan cannot be re-run from here: the definition it read is not retained, only the endpoints it sent, so a re-run would be a different scan. Start a new one from the document."
		}
		http.Error(w, reason, http.StatusConflict)
		return
	}
	if _, _, _, _, err := s.startCrawl(crawlStartReq{Seeds: []string{task.Target}}); err != nil {
		http.Error(w, err.Error(), crawlStartStatus(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"started": id, "target": task.Target})
}

// handleTaskDelete removes one finished task from the list. The registry refuses a running task;
// this surfaces that refusal as 409 with the reason, rather than as a bare failure.
func (s *Server) handleTaskDelete(w http.ResponseWriter, r *http.Request) {
	if s.noTaskRegistry(w) {
		return
	}
	id, ok := taskID(w, r)
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
