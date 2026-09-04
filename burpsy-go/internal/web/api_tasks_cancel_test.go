package web

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/dash"
)

// ---- Task cancellation --------------------------------------------------------------------------
//
// The dashboard lists cancellable tasks; cancelling one from the UI needs a route. Cancel is
// idempotent by registry contract: an already-finished or unknown id answers 404 so a stale row's
// button reports "gone" rather than pretending something was cancelled.

func taskCancelPath(id uint64) string {
	return "/api/tasks/" + strconv.FormatUint(id, 10) + "/cancel"
}

func TestTaskCancelStopsARunningTask(t *testing.T) {
	s := newTestServer()
	handle := s.tasks.Start("crawl", "https://demo.local", 10)
	if handle == nil {
		t.Fatal("task start returned no handle; nothing to cancel")
	}
	// Play the worker a real producer builds: WithCancel registers the task as cancellable, and the
	// goroutine watching the context performs the Stop when it fires — the route itself only asks.
	ctx, _ := handle.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		handle.Stop(dash.Breakdown{}, "cancelled by operator")
		close(stopped)
	}()

	rec := postJSON(t, s, taskCancelPath(handle.ID()), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST cancel = %d; body %s", rec.Code, rec.Body.String())
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel answered success but the task's context never fired")
	}
	if got := s.tasks.Snapshot()[0].State; got != dash.TaskStopped {
		t.Fatalf("task state = %v after cancel; the route answered success but the task did not stop", got)
	}
}

func TestTaskCancelRefusesAnUnknownOrFinishedId(t *testing.T) {
	s := newTestServer()
	for name, path := range map[string]string{
		"unknown id":  "/api/tasks/999/cancel",
		"non-numeric": "/api/tasks/soon/cancel",
	} {
		if rec := postJSON(t, s, path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s: POST cancel = %d, want 404", name, rec.Code)
		}
	}
}
