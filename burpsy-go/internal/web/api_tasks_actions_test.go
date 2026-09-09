package web

// Per-task actions beyond cancel (burpsy-react-ui-r6q). These drive the HTTP surface, so what is
// pinned is what a dashboard row can rely on: scan-again re-runs a crawl through the same start
// path the New scan dialog uses, refuses to silently re-run a kind whose inputs the row does not
// hold, and delete removes a finished row but refuses a running one — a list entry that vanishes
// while its work keeps going is a lie about what is happening now.

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/burpsy-go/burpsy/internal/dash"
)

// taskPost issues a POST against the tasks subtree the way the dashboard does.
func taskPost(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// taskDelete issues a DELETE against the tasks subtree.
func taskDelete(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func TestTaskScanAgainReRunsACrawlAndRefusesOtherKinds(t *testing.T) {
	s := newTestServer()
	// A finished crawl task, registered the way the crawl runner does.
	done := s.tasks.Start(dash.KindCrawl, "https://demo.local/", 3)
	done.Finish(dash.Breakdown{})

	rec := taskPost(t, s, "/api/tasks/"+strconv.FormatUint(done.ID(), 10)+"/again")
	if rec.Code != http.StatusOK {
		t.Fatalf("scan-again on a finished crawl: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	// The re-run is a real crawl task, not a synthetic row: one more task now exists, running.
	if s.tasks.Running() != 1 {
		t.Fatalf("after scan-again %d tasks are running, want 1 — the re-run did not start", s.tasks.Running())
	}

	// An audit task cannot be re-run from the row: the row does not carry the exchange id an audit
	// acts on, and starting something narrower than the operator asked for is the failure this
	// refusal exists to avoid.
	audit := s.tasks.Start(dash.KindAudit, "https://demo.local/x", 1)
	audit.Finish(dash.Breakdown{})
	rec = taskPost(t, s, "/api/tasks/"+strconv.FormatUint(audit.ID(), 10)+"/again")
	if rec.Code != http.StatusConflict {
		t.Fatalf("scan-again on an audit task: status = %d, want 409 naming the refusal", rec.Code)
	}
}

func TestTaskDeleteRemovesFinishedRowsAndRefusesRunningOnes(t *testing.T) {
	s := newTestServer()
	done := s.tasks.Start(dash.KindCrawl, "https://demo.local/", 1)
	done.Finish(dash.Breakdown{})

	if rec := taskDelete(t, s, "/api/tasks/"+strconv.FormatUint(done.ID(), 10)); rec.Code != http.StatusOK {
		t.Fatalf("delete of a finished task: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	for _, task := range s.tasks.Snapshot() {
		if task.ID == done.ID() {
			t.Fatalf("task %d is still listed after its row was deleted", done.ID())
		}
	}

	// A running task's row cannot go: the work is real and the list is the only place that shows it.
	running := s.tasks.Start(dash.KindCrawl, "https://demo.local/", 5)
	if rec := taskDelete(t, s, "/api/tasks/"+strconv.FormatUint(running.ID(), 10)); rec.Code != http.StatusConflict {
		t.Fatalf("delete of a running task: status = %d, want 409 telling the operator to cancel first", rec.Code)
	}
	if s.tasks.Running() != 1 {
		t.Fatalf("running task count = %d after a refused delete, want 1 — the refusal must not have stopped it", s.tasks.Running())
	}
	// An unknown id is "not found", not "deleted".
	if rec := taskDelete(t, s, "/api/tasks/99999"); rec.Code != http.StatusNotFound {
		t.Fatalf("delete of an unknown task: status = %d, want 404", rec.Code)
	}
}
