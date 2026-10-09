package web

import (
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/dash"
)

// Finished bodies of asynchronous work, read through GET /api/tasks/{id} (burpsy-react-ui-wdza).
//
// The dashboard registry keeps a task's progress and breakdown; an async audit's full answer — the
// outcome, dispositions and summary the synchronous call returns — has nowhere to live once its
// goroutine ends. This keeps the last maxTaskResults of them, keyed by task id. Bounded because a
// long engagement starts many tasks, and the newest answers are the ones an agent is waiting on.

const maxTaskResults = 64

type taskResultStore struct {
	mu    sync.Mutex
	order []uint64
	m     map[uint64]any
}

func (t *taskResultStore) put(id uint64, body any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[uint64]any{}
	}
	if _, ok := t.m[id]; !ok {
		t.order = append(t.order, id)
	}
	t.m[id] = body
	for len(t.order) > maxTaskResults {
		delete(t.m, t.order[0])
		t.order = t.order[1:]
	}
}

func (t *taskResultStore) get(id uint64) (any, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[id]
	return v, ok
}

// taskResults is this server's store; its zero value is ready, so a Server built directly needs no wiring.
func (s *Server) taskResults() *taskResultStore { return &s.finished }

// taskReadView is GET /api/tasks/{id}.
type taskReadView struct {
	Task dash.Task `json:"task"`
	// Result is the finished body of async work that keeps one (an async audit), and null otherwise —
	// null while it runs, and null for a kind that answers through its own route.
	Result any `json:"result"`
	// Done is true once the task is no longer running.
	Done bool `json:"done"`
}

// handleTaskGet serves GET /api/tasks/{id}: the task row, and the finished body when there is one.
func (s *Server) handleTaskGet(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/tasks/"), "/")
	id, err := strconv.ParseUint(rest, 10, 64)
	if err != nil {
		http.Error(w, "GET /api/tasks/{id} takes a numeric task id", http.StatusNotFound)
		return
	}
	task := s.taskByID(id)
	if task == nil {
		http.Error(w, "No task with that id", http.StatusNotFound)
		return
	}
	view := taskReadView{Task: *task, Done: !task.Running()}
	if body, ok := s.taskResults().get(id); ok {
		view.Result = body
	}
	writeJSON(w, http.StatusOK, view)
}
