package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/web"
)

// burpsy-react-ui-wdza over the real stdio transport against a real gated console: task handles past
// the sync window, ping answered while a call is pending, progress only with a token, completion
// pushed as notifications/message, and notifications/cancelled stopping the console task.

// liveSession is a stdio session the test writes to and reads from while it runs.
type liveSession struct {
	t    *testing.T
	in   *io.PipeWriter
	msgs chan map[string]any
	done chan error
}

func startSession(t *testing.T, opts Options) *liveSession {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	opts.In, opts.Out = inR, outW
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ls := &liveSession{t: t, in: inW, msgs: make(chan map[string]any, 256), done: make(chan error, 1)}
	go func() {
		ls.done <- srv.Serve(context.Background())
		outW.Close()
	}()
	go func() {
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				t.Errorf("stdout is not one JSON-RPC message per line: %q", sc.Text())
				continue
			}
			ls.msgs <- m
		}
		close(ls.msgs)
	}()
	t.Cleanup(func() {
		inW.Close()
		select {
		case <-ls.done:
		case <-time.After(20 * time.Second):
			t.Error("Serve did not return after the input closed")
		}
	})
	return ls
}

func (ls *liveSession) write(v any) {
	ls.t.Helper()
	b, _ := json.Marshal(v)
	if _, err := ls.in.Write(append(b, '\n')); err != nil {
		ls.t.Fatal(err)
	}
}

// next returns the next message matching pred within d, collecting every message seen on the way.
func (ls *liveSession) next(d time.Duration, pred func(map[string]any) bool) (map[string]any, []map[string]any) {
	ls.t.Helper()
	var seen []map[string]any
	deadline := time.After(d)
	for {
		select {
		case m, ok := <-ls.msgs:
			if !ok {
				ls.t.Fatalf("the session closed; saw %v", seen)
			}
			seen = append(seen, m)
			if pred(m) {
				return m, seen
			}
		case <-deadline:
			return nil, seen
		}
	}
}

func reply(id int) func(map[string]any) bool {
	return func(m map[string]any) bool { return m["method"] == nil && fmt.Sprint(m["id"]) == strconv.Itoa(id) }
}

func method(name string) func(map[string]any) bool {
	return func(m map[string]any) bool { return m["method"] == name }
}

func resultText(t *testing.T, m map[string]any) string {
	t.Helper()
	res, _ := m["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content: %v", m)
	}
	return content[0].(map[string]any)["text"].(string)
}

// auditConsole is a real console holding one exchange to an origin that answers quickly, with the
// suite paused so an audit started against it waits at the dashboard gate until the test resumes it.
func auditConsole(t *testing.T) (base string, exID core.ExchangeID) {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>ok</html>")) }))
	t.Cleanup(origin.Close)
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	store := core.NewTrafficStore()
	raw := fmt.Sprintf("GET /?q=1 HTTP/1.1\r\nHost: %s\r\n\r\n", strings.TrimPrefix(origin.URL, "http://"))
	reqID, _ := store.Put([]byte(raw), core.DirectionRequest)
	respID, _ := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>ok</html>"), core.DirectionResponse)
	status := uint16(200)
	store.AddExchange(&core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: uint16(port), Method: "GET", Path: "/?q=1", Status: &status, Source: core.SourceProxy})
	srv := web.NewServer(store, core.NewScope())
	ts := httptest.NewServer(srv.MCPGuarded())
	t.Cleanup(ts.Close)
	tasks(t, ts.URL, "pause")
	return ts.URL, store.Exchanges()[0].ID
}

func tasks(t *testing.T, base, action string) {
	t.Helper()
	resp, err := http.Post(base+"/api/tasks/"+action, "application/json", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("tasks %s: %v %v", action, err, resp)
	}
	resp.Body.Close()
}

// mintAudit mints the audit confirmation through the console.
func mintAudit(t *testing.T, base string) string {
	t.Helper()
	resp, err := http.Post(base+web.MCPConfirmEndpoint("/api/audit/"), "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tok struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&tok)
	return tok.Token
}

func auditCall(id int, base string, t *testing.T, exID core.ExchangeID, meta map[string]any) map[string]any {
	params := map[string]any{"name": "scan", "arguments": map[string]any{
		"op": "POST /api/audit/", "id": fmt.Sprint(exID), "confirm": mintAudit(t, base),
	}}
	if meta != nil {
		params["_meta"] = meta
	}
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params}
}

func TestAnAuditPastTheSyncWindowAnswersAHandleWhilePingStillAnswers(t *testing.T) {
	base, exID := auditConsole(t)
	ls := startSession(t, Options{BaseURL: base, SyncWindow: 1500 * time.Millisecond})
	ls.write(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-06-18"}})
	if m, _ := ls.next(5*time.Second, reply(1)); m == nil || !strings.Contains(fmt.Sprint(m["result"]), "logging") {
		t.Fatalf("initialize does not advertise logging: %v", m)
	}
	ls.write(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	start := time.Now()
	ls.write(auditCall(2, base, t, exID, nil))
	ls.write(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "ping"})
	pong, seen := ls.next(5*time.Second, reply(3))
	if pong == nil || time.Since(start) > time.Second {
		t.Fatalf("ping was not answered while the audit call was pending (%v): %v", time.Since(start), seen)
	}
	for _, m := range seen {
		if fmt.Sprint(m["id"]) == "2" {
			t.Fatal("the audit call answered before the ping; it was not pending")
		}
	}
	handleMsg, _ := ls.next(10*time.Second, reply(2))
	if handleMsg == nil {
		t.Fatal("no answer to the audit call")
	}
	text := resultText(t, handleMsg)
	if !strings.HasPrefix(text, "HTTP 202 task handle") || !strings.Contains(text, `"status":"running"`) || !strings.Contains(text, taskStatusToolName) {
		t.Fatalf("past the window the call did not answer a handle:\n%s", text)
	}
	var handle struct {
		TaskID uint64 `json:"task_id"`
	}
	json.Unmarshal([]byte(strings.SplitN(text, "\n", 3)[1]), &handle)
	if handle.TaskID == 0 || time.Since(start) < 1400*time.Millisecond {
		t.Fatalf("handle %+v after %v", handle, time.Since(start))
	}

	// Resume: the audit finishes, and its completion is pushed with the task id, unasked.
	tasks(t, base, "resume")
	note, seen := ls.next(30*time.Second, func(m map[string]any) bool {
		if m["method"] != "notifications/message" {
			return false
		}
		data, _ := m["params"].(map[string]any)["data"].(map[string]any)
		return data["event"] == "task.finished" && data["task_id"] == float64(handle.TaskID)
	})
	if note == nil {
		t.Fatalf("no task.finished notification for task %d; saw %v", handle.TaskID, seen)
	}
	if lvl := note["params"].(map[string]any)["level"]; lvl != "info" {
		t.Fatalf("completion level %v", lvl)
	}

	// The handle reads the finished result through burpsy_task_status.
	ls.write(map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{
		"name": taskStatusToolName, "arguments": map[string]any{"task_id": handle.TaskID, "wait_seconds": 10}}})
	st, _ := ls.next(15*time.Second, reply(4))
	if st == nil || !strings.Contains(resultText(t, st), "(finished)") || !strings.Contains(resultText(t, st), `"outcome"`) {
		t.Fatalf("task status: %v", st)
	}
}

func TestProgressIsSentOnlyToACallWithAToken(t *testing.T) {
	old := taskPollInterval
	taskPollInterval = 50 * time.Millisecond
	t.Cleanup(func() { taskPollInterval = old })
	base, exID := auditConsole(t)
	ls := startSession(t, Options{BaseURL: base, SyncWindow: 700 * time.Millisecond, NoNotifications: true})

	ls.write(auditCall(1, base, t, exID, nil))
	_, seen := ls.next(10*time.Second, reply(1))
	for _, m := range seen {
		if m["method"] == "notifications/progress" {
			t.Fatalf("progress sent to a call without a token: %v", m)
		}
	}
	ls.write(auditCall(2, base, t, exID, map[string]any{"progressToken": "tok-7"}))
	_, seen = ls.next(10*time.Second, reply(2))
	progressed := false
	for _, m := range seen {
		if m["method"] == "notifications/progress" {
			p := m["params"].(map[string]any)
			if p["progressToken"] != "tok-7" {
				t.Fatalf("progress carries token %v", p["progressToken"])
			}
			progressed = true
		}
	}
	if !progressed {
		t.Fatalf("a call with a progress token got no progress: %v", seen)
	}
	tasks(t, base, "resume")
}

func TestNotificationsCancelledStopsTheConsoleTask(t *testing.T) {
	base, exID := auditConsole(t)
	ls := startSession(t, Options{BaseURL: base, SyncWindow: 20 * time.Second, NoNotifications: true})
	ls.write(auditCall(9, base, t, exID, nil))
	time.Sleep(500 * time.Millisecond)
	ls.write(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 9, "reason": "test"}})
	// The cancelled request gets no answer; the console task is stopped.
	ls.write(map[string]any{"jsonrpc": "2.0", "id": 10, "method": "ping"})
	_, seen := ls.next(3*time.Second, reply(10))
	tasks(t, base, "resume")
	var task struct {
		Tasks []struct {
			ID    uint64 `json:"id"`
			State string `json:"state"`
			Note  string `json:"note"`
		} `json:"tasks"`
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/api/dashboard")
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(resp.Body).Decode(&task)
		resp.Body.Close()
		if len(task.Tasks) > 0 && task.Tasks[0].State != "running" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(task.Tasks) == 0 || task.Tasks[0].State != "stopped" {
		t.Fatalf("the console task was not stopped: %+v", task.Tasks)
	}
	more, _ := ls.next(500*time.Millisecond, reply(9))
	for _, m := range append(seen, more) {
		if m != nil && fmt.Sprint(m["id"]) == "9" {
			t.Fatalf("a cancelled request was answered: %v", m)
		}
	}
}

var _ = sync.Mutex{}

func TestAHighIssueIsPushedAndALowOneIsNot(t *testing.T) {
	store := core.NewTrafficStore()
	base := consoleOver(t, store)
	exID := putExchange(t, store, "shop.test", "/x")
	ls := startSession(t, Options{BaseURL: base})
	ls.write(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{}})
	ls.next(5*time.Second, reply(1))
	ls.write(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	time.Sleep(300 * time.Millisecond) // the watcher's baseline and stream subscription
	record := func(sev, name string) {
		b, _ := json.Marshal(map[string]any{"name": name, "severity": sev, "confidence": "firm", "exchange_id": exID, "description": "d"})
		resp, err := http.Post(base+"/api/issues/record", "application/json", strings.NewReader(string(b)))
		if err != nil || resp.StatusCode/100 != 2 {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("record %s: %v %s", sev, err, body)
		}
		resp.Body.Close()
	}
	record("low", "Low thing")
	record("high", "SQL injection (manual)")
	note, seen := ls.next(10*time.Second, func(m map[string]any) bool {
		if m["method"] != "notifications/message" {
			return false
		}
		data, _ := m["params"].(map[string]any)["data"].(map[string]any)
		return data["event"] == "issue.found"
	})
	if note == nil {
		t.Fatalf("no issue notification; saw %v", seen)
	}
	data := note["params"].(map[string]any)["data"].(map[string]any)
	if !strings.EqualFold(fmt.Sprint(data["severity"]), "high") || note["params"].(map[string]any)["level"] != "warning" {
		t.Fatalf("the pushed issue is not the High one: %v", note)
	}
	more, _ := ls.next(700*time.Millisecond, func(m map[string]any) bool {
		data, _ := m["params"].(map[string]any)["data"].(map[string]any)
		return m["method"] == "notifications/message" && data["event"] == "issue.found"
	})
	if more != nil {
		t.Fatalf("a Low issue was pushed: %v", more)
	}
}
