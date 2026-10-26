package web

// The control routes, and the dashboard's stop button.
//
// Before this, /api/intruder/points and /api/intruder/run were the only Intruder routes, and /run
// registered its dashboard task without calling dash.Handle.WithCancel — so Task.Cancellable() was
// false for every attack and the dashboard rendered no stop button for the one kind of task that can
// send 200,000 requests.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
)

// slowOrigin answers every request after `delay`, and counts them. A long enough attack against it
// gives a test time to find the task and stop it.
func slowOrigin(t *testing.T, delay time.Duration) (addr string, served *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var count atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(30 * time.Second))
				buf := make([]byte, 4096)
				if _, err := c.Read(buf); err != nil {
					return
				}
				count.Add(1)
				time.Sleep(delay)
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()
	return ln.Addr().String(), &count
}

// awaitIntruderTask polls the dashboard task registry for a running intruder task.
func awaitIntruderTask(t *testing.T, srv *Server) dash.Task {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, task := range srv.tasks.Snapshot() {
			if task.Kind == dash.KindIntruder && task.Running() {
				return task
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no running intruder task appeared in the registry")
	return dash.Task{}
}

// launchAttack starts an attack in the background and returns a channel carrying its report body.
func launchAttack(t *testing.T, srv *Server, msgID uint64, addr string, points []int, payloads []string) <-chan map[string]any {
	t.Helper()
	out := make(chan map[string]any, 1)
	go func() {
		var view map[string]any
		postJSONInto(t, srv, "/api/intruder/run", map[string]any{
			"msg_id":        msgID,
			"target":        "http://" + addr,
			"mode":          "sniper",
			"points":        points,
			"payload_sets":  [][]string{payloads},
			"max_requests":  5000,
			"rps":           1000,
			"max_in_flight": 1,
		}, &view)
		out <- view
	}()
	return out
}

func manyPayloads(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("p%04d", i)
	}
	return out
}

func TestARunningAttackIsCancellableFromTheDashboard(t *testing.T) {
	addr, served := slowOrigin(t, 40*time.Millisecond)
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /a?q=x HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	qIndex := pointIndex(t, srv, id, "url_param_value", "q")

	done := launchAttack(t, srv, id, addr, []int{qIndex}, manyPayloads(400))
	task := awaitIntruderTask(t, srv)

	if !task.Cancellable() {
		t.Fatal("the intruder task is not cancellable, so the dashboard renders no stop button for " +
			"a task that can send 200,000 requests")
	}

	// Through the route an operator's stop button actually calls.
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/tasks/%d/cancel", task.ID), nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel status = %d (%s), want 200", rec.Code, rec.Body.String())
	}

	select {
	case view := <-done:
		report, _ := view["report"].(map[string]any)
		if report == nil {
			t.Fatalf("no report in %v", view)
		}
		if report["status"] != "stopped" {
			t.Errorf("report status = %v, want stopped", report["status"])
		}
		if n := served.Load(); n > 350 {
			t.Errorf("%d of 400 requests reached the origin after the cancel: the loop kept going",
				n)
		}
		// The task must record that it was stopped, not that it finished: a stopped run reported as
		// done presents a prefix of the payload set as a complete answer.
		var found bool
		for _, task2 := range srv.tasks.Snapshot() {
			if task2.ID == task.ID {
				found = true
				if task2.State != dash.TaskStopped {
					t.Errorf("task state = %v, want stopped", task2.State)
				}
				if task2.Complete() {
					t.Error("a stopped attack's task reports itself complete")
				}
			}
		}
		if !found {
			t.Error("the task vanished from the registry")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the attack did not return after the dashboard cancelled its task")
	}
}

func TestIntruderAttacksListsARunningAttackAndStopEndsIt(t *testing.T) {
	addr, _ := slowOrigin(t, 40*time.Millisecond)
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /a?q=x HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	qIndex := pointIndex(t, srv, id, "url_param_value", "q")

	done := launchAttack(t, srv, id, addr, []int{qIndex}, manyPayloads(400))
	task := awaitIntruderTask(t, srv)

	var list intruderAttacksResp
	req := httptest.NewRequest(http.MethodGet, "/api/intruder/attacks", nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Attacks) != 1 {
		t.Fatalf("attacks = %+v, want one running attack", list.Attacks)
	}
	got := list.Attacks[0]
	if got.TaskID != task.ID {
		t.Errorf("task_id = %d, want the dashboard task id %d", got.TaskID, task.ID)
	}
	if got.Status != "running" || got.Kind != "sniper" || got.Planned != 400 {
		t.Errorf("attack view = %+v", got)
	}

	// The live counts move while the attack runs — the whole point of carrying them on the list.
	// The origin answers in 40ms, so sends settle continuously; a view stuck at zero would make
	// "is it doing anything" unanswerable.
	var progressed intruderAttacksResp
	deadline := time.Now().Add(10 * time.Second)
	for {
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/intruder/attacks", nil))
		if err := json.Unmarshal(rec.Body.Bytes(), &progressed); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		if len(progressed.Attacks) == 1 && progressed.Attacks[0].Sent+progressed.Attacks[0].Failed > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("live counts never moved: attacks = %+v", progressed.Attacks)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Pause, then stop while paused. A pause that could not be stopped would leave the driver in its
	// wait forever.
	if code, _ := attackAction(t, srv, task.ID, "pause"); code != http.StatusOK {
		t.Fatalf("pause status = %d, want 200", code)
	}
	if code, body := attackAction(t, srv, task.ID, "stop"); code != http.StatusOK {
		t.Fatalf("stop status = %d (%v), want 200", code, body)
	}

	select {
	case view := <-done:
		report, _ := view["report"].(map[string]any)
		if report["status"] != "stopped" {
			t.Errorf("report status = %v, want stopped", report["status"])
		}
		if !strings.Contains(fmt.Sprint(report["stop_reason"]), "operator") {
			t.Errorf("stop_reason = %v, want the operator's stop named", report["stop_reason"])
		}
	case <-time.After(30 * time.Second):
		t.Fatal("stopping a paused attack did not release it")
	}

	// Once the attack is gone the routes say so rather than reporting a success on nothing.
	if code, _ := attackAction(t, srv, task.ID, "stop"); code != http.StatusNotFound {
		t.Errorf("stopping a finished attack = %d, want 404", code)
	}
}

func TestIntruderAttackActionRefusals(t *testing.T) {
	srv := newTestServer()
	cases := []struct {
		path string
		code int
		why  string
	}{
		{"/api/intruder/attacks/9999/stop", http.StatusNotFound, "an unknown task id"},
		{"/api/intruder/attacks/notanumber/stop", http.StatusNotFound, "a non-numeric id"},
		{"/api/intruder/attacks/1", http.StatusNotFound, "no action segment"},
		{"/api/intruder/attacks/1/frobnicate", http.StatusNotFound, "an unknown action"},
		{"/api/intruder/attacks/1/stop/extra", http.StatusNotFound, "a segment after the action"},
		{"/api/intruder/attacks/1/stop/", http.StatusNotFound, "a trailing slash after the action"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, tc.path, nil)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Errorf("%s: %s = %d, want %d", tc.why, tc.path, rec.Code, tc.code)
		}
	}
	// An empty list is an empty array, not null: a client must not be able to read a missing field as
	// "there are none".
	req := httptest.NewRequest(http.MethodGet, "/api/intruder/attacks", nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if body := strings.TrimSpace(rec.Body.String()); body != `{"attacks":[]}` {
		t.Errorf("empty list body = %s", body)
	}
}

func attackAction(t *testing.T, srv *Server, taskID uint64, action string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/intruder/attacks/%d/%s", taskID, action), nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}
