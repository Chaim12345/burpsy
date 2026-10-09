package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-wdza: an audit started with {"async":true} answers 202 with a task id at once;
// GET /api/tasks/{id} reads it; POST /api/tasks/{id}/cancel stops it.

func getTask(t *testing.T, s *Server, id uint64) (map[string]any, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/tasks/%d", id), nil))
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	return v, rec.Code
}

func waitTaskDone(t *testing.T, s *Server, id uint64, within time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		v, code := getTask(t, s, id)
		if code != http.StatusOK {
			t.Fatalf("GET task %d answered %d", id, code)
		}
		if v["done"] == true {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("task %d still running after %v", id, within)
	return nil
}

func TestAnAsyncAuditAnswers202AndItsResultIsReadByTask(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/audit/424242", map[string]any{"async": true})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("async audit answered %d: %s", rec.Code, rec.Body.String())
	}
	var started struct {
		TaskID uint64 `json:"task_id"`
		Poll   string `json:"poll"`
	}
	json.Unmarshal(rec.Body.Bytes(), &started)
	if started.TaskID == 0 || started.Poll != fmt.Sprintf("/api/tasks/%d", started.TaskID) {
		t.Fatalf("no task handle: %s", rec.Body.String())
	}
	v := waitTaskDone(t, s, started.TaskID, 10*time.Second)
	result, _ := v["result"].(map[string]any)
	if result == nil || result["outcome"] == nil || result["exchange_id"] == nil {
		t.Fatalf("the finished task carries no audit body: %v", v)
	}
	task := v["task"].(map[string]any)
	if task["kind"] != "audit" || task["id"].(float64) != float64(started.TaskID) {
		t.Fatalf("task row: %v", task)
	}
	// A task with no kept body answers result null, marshalled.
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/tasks/99999", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown task answered %d", rec.Code)
	}
	// GET on the action paths is still refused (the 0gg5 guard).
	for _, p := range []string{"/api/tasks/pause", "/api/tasks/resume", fmt.Sprintf("/api/tasks/%d/cancel", started.TaskID)} {
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s answered %d", p, rec.Code)
		}
	}
}

func TestCancellingAnAsyncAuditStopsIt(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(150 * time.Millisecond):
		case <-r.Context().Done():
		}
		w.Write([]byte("<html>ok</html>"))
	}))
	defer slow.Close()
	host, port := hostPort(t, slow)
	s := newTestServer()
	raw := fmt.Sprintf("GET /search?q=x&id=1 HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	reqID, _ := s.store.Put([]byte(raw), core.DirectionRequest)
	respID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>ok</html>"), core.DirectionResponse)
	status := uint16(200)
	s.store.AddExchange(&core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: uint16(port), Method: "GET", Path: "/search?q=x&id=1", Status: &status, Source: core.SourceProxy})
	exID := s.store.Exchanges()[0].ID

	// Pause the suite first so the audit is provably still running when the cancel lands: the audit
	// loop waits at the dashboard's gate, which honours the task's context.
	if rec := postJSON(t, s, "/api/tasks/pause", nil); rec.Code != http.StatusOK {
		t.Fatalf("pause answered %d", rec.Code)
	}
	defer postJSON(t, s, "/api/tasks/resume", nil)
	rec := postJSON(t, s, fmt.Sprintf("/api/audit/%d", exID), map[string]any{"async": true})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("async audit answered %d: %s", rec.Code, rec.Body.String())
	}
	var started struct {
		TaskID uint64 `json:"task_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &started)
	time.Sleep(300 * time.Millisecond)
	if v, _ := getTask(t, s, started.TaskID); v["done"] == true {
		t.Fatalf("the audit finished before it could be cancelled; the slow target is not slow enough: %v", v)
	}
	rec = postJSON(t, s, fmt.Sprintf("/api/tasks/%d/cancel", started.TaskID), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel answered %d: %s", rec.Code, rec.Body.String())
	}
	v := waitTaskDone(t, s, started.TaskID, 15*time.Second)
	task := v["task"].(map[string]any)
	if task["state"] != "stopped" || !strings.HasPrefix(fmt.Sprint(task["note"]), "cancelled") {
		t.Fatalf("a cancelled audit is not reported stopped: %v", task)
	}
}
