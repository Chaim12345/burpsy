package web

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/dash"
)

// The suite-wide pause (burpsy-react-ui-8gw): one registry gate every running task honours
// between units of work, with Burp's two dashboard buttons behind it.

// startPauseableTask registers a task the registry can see (and cancel, so the test can
// always clean up), the way every real task author does.
func startPauseableTask(t *testing.T, s *Server, target string) (*dash.Handle, context.CancelFunc) {
	t.Helper()
	h := s.tasks.Start(dash.KindCrawl, target, 10)
	ctx, cancel := h.WithCancel(context.Background())
	_ = ctx
	return h, cancel
}

func postPause(t *testing.T, s *Server, verb string) (bool, int) {
	t.Helper()
	rec := postJSON(t, s, "/api/tasks/"+verb, map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("%s answered %d (%s)", verb, rec.Code, rec.Body.String())
	}
	return decodePause(t, rec.Body.Bytes())
}

func decodePause(t *testing.T, body []byte) (bool, int) {
	t.Helper()
	var out struct {
		Paused  bool `json:"paused"`
		Running int  `json:"running"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out.Paused, out.Running
}

// The round trip: pause reports the gate and how many tasks are behind it; a task started
// after the pause is still behind it (the gate is state, not an event); resume clears both.
func TestTheSuiteWidePauseRoundTripsThroughTheAPI(t *testing.T) {
	s := newTestServer()

	if s.tasks.Paused() {
		t.Fatal("fresh state paused=true — a preference nobody wrote must not pause anything")
	}

	h1, cancel1 := startPauseableTask(t, s, "http://one.test/")
	h2, cancel2 := startPauseableTask(t, s, "http://two.test/")
	defer cancel1()
	defer cancel2()
	defer h1.Finish(dash.Breakdown{})
	defer h2.Finish(dash.Breakdown{})

	paused, running := postPause(t, s, "pause")
	if !paused || running != 2 {
		t.Fatalf("pause answered paused=%v running=%d, want true/2 — the count is the honest part of the reply", paused, running)
	}
	if !s.tasks.Paused() {
		t.Fatal("the registry gate did not take")
	}

	// Pause is idempotent: pausing twice is one pause, and the count is still true.
	if paused, _ := postPause(t, s, "pause"); !paused {
		t.Fatal("a second pause turned the gate off")
	}

	// The gate survives a task finishing: it is the dashboard's switch, not any task's.
	h1.Finish(dash.Breakdown{})
	if !s.tasks.Paused() {
		t.Fatal("the gate cleared when one task finished; it is suite-wide state")
	}

	paused, _ = postPause(t, s, "resume")
	if paused {
		t.Fatal("resume left the gate set")
	}
}

// Pausing with nothing running still works and says so: "paused, 0 running" is the honest
// version of the reply, not an error.
func TestPausingWithNothingRunningReportsZero(t *testing.T) {
	s := newTestServer()
	paused, running := postPause(t, s, "pause")
	if !paused || running != 0 {
		t.Fatalf("pause answered paused=%v running=%d, want true/0", paused, running)
	}
	postPause(t, s, "resume")
}

// The gate does not eat cancellation: a task loop blocked in GateCheck still answers its
// context, so pause+cancel stops instead of ordering the two.
func TestGateCheckYieldsToCancellation(t *testing.T) {
	r := &dash.Registry{}
	r.PauseAll()

	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		r.GateCheck(ctx)
		close(done)
	}()
	cancel()

	select {
	case <-done:
		// The select inside GateCheck returned on ctx.Done, not on the flag clearing.
	case <-time.After(2 * time.Second):
		t.Fatal("GateCheck ignored cancellation while paused; pause+cancel would hang every task")
	}
}
