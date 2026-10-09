package mcp

// Task handles, progress and completion push (burpsy-react-ui-wdza).
//
// Burp's agent tools run long operations behind a sync window: a call waits up to 15 s, answers with
// the result if the work finished, and otherwise answers with a task handle the agent polls
// (task/SyncWindow.java, TaskHandle.java); progress rides MCP progress notifications, and finished
// tasks and High-severity issues are "reported back automatically". burpsy's audit ran inline on
// POST /api/audit/{id}, so an MCP session was blocked for the whole audit, and nothing was ever
// pushed.
//
// The pieces here, all transport-side over console routes:
//
//   - asyncOps: an audit called through the transport is started with {"async": true}, so the console
//     answers 202 with a task id at once. Any 202 carrying a task_id — the audit, a crawl, an API scan,
//     an audit of a selection — is then awaited for the sync window: the call answers with the task's
//     finished view (and, for an audit, the same body a blocking call returns) or, past the window,
//     with a handle. The handle lives in the console's task registry, so it outlives this process.
//   - burpsy_task_status reads a handle, optionally long-polling up to 60 s for it to finish.
//   - A call carrying _meta.progressToken gets notifications/progress while it waits on its task; a
//     call without one gets none, as the spec requires.
//   - notifications/cancelled on a call that is waiting on its task cancels the task through POST
//     /api/tasks/{id}/cancel — the registry's own cancel primitive.
//   - After notifications/initialized, a watcher holds the console's SSE stream open and, on each
//     dashboard or issues change, pushes notifications/message for every task that finished and every
//     High or Critical issue that appeared since the session began.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/web"
)

const taskStatusToolName = "burpsy_task_status"

// maxTaskWait bounds burpsy_task_status's long-poll, below every client timeout on the path.
const maxTaskWait = 60

// taskPollInterval is how often a wait re-reads its task.
var taskPollInterval = 250 * time.Millisecond

// asyncOps are the operations the transport starts asynchronously.
var asyncOps = map[string]bool{"POST /api/audit/": true}

// callState is what a tools/call carries beyond its arguments.
type callState struct {
	progressToken json.RawMessage
}

// withAsync sets "async": true in a JSON object body unless the caller set async itself.
func withAsync(body json.RawMessage) json.RawMessage {
	m := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &m); err != nil {
			return body // not an object: leave it for the console to refuse
		}
	}
	if _, set := m["async"]; set {
		return body
	}
	m["async"] = json.RawMessage("true")
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// taskIDOf reads a top-level numeric task_id from a console answer.
func taskIDOf(payload []byte) (uint64, bool) {
	var v struct {
		TaskID *uint64 `json:"task_id"`
	}
	if json.Unmarshal(payload, &v) != nil || v.TaskID == nil || *v.TaskID == 0 {
		return 0, false
	}
	return *v.TaskID, true
}

// taskRead is GET /api/tasks/{id} as the transport reads it.
type taskRead struct {
	Task struct {
		ID       uint64 `json:"id"`
		Kind     string `json:"kind"`
		Target   string `json:"target"`
		State    string `json:"state"`
		Done     uint64 `json:"done"`
		Total    uint64 `json:"total"`
		Progress string `json:"progress"`
		Note     string `json:"note"`
	} `json:"task"`
	Done bool `json:"done"`
}

// readTask fetches one task view; raw is the console's body verbatim.
func (s *Server) readTask(ctx context.Context, id uint64) (taskRead, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/tasks/%d", s.baseURL, id), nil)
	if err != nil {
		return taskRead{}, nil, err
	}
	req.Header.Set(web.MCPAgentHeaderName, "burpsy-mcp")
	resp, err := s.http.Do(req)
	if err != nil {
		return taskRead{}, nil, err
	}
	defer resp.Body.Close()
	raw, truncated, err := readCapped(resp.Body, maxResultBytes)
	if err != nil {
		return taskRead{}, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return taskRead{}, raw, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if truncated {
		return taskRead{}, raw, fmt.Errorf("the task view is larger than %d bytes", maxResultBytes)
	}
	var tr taskRead
	if err := json.Unmarshal(raw, &tr); err != nil {
		return taskRead{}, raw, err
	}
	return tr, raw, nil
}

// progress sends notifications/progress for a call that asked for it.
func (s *Server) progress(call callState, tr taskRead) {
	if len(call.progressToken) == 0 {
		return
	}
	params := map[string]any{
		"progressToken": call.progressToken,
		"progress":      tr.Task.Done,
		"message":       fmt.Sprintf("task %d (%s %s): %s", tr.Task.ID, tr.Task.Kind, tr.Task.State, tr.Task.Progress),
	}
	if tr.Task.Total > 0 {
		params["total"] = tr.Task.Total
	}
	_ = s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": params})
}

// waitTask polls a task until it finishes, the deadline passes, or ctx ends. It reports progress
// changes to a call that asked for them.
func (s *Server) waitTask(ctx context.Context, id uint64, deadline time.Time, call callState) (taskRead, []byte, error) {
	last := ""
	for {
		tr, raw, err := s.readTask(ctx, id)
		if err != nil {
			return tr, raw, err
		}
		if key := fmt.Sprintf("%d/%d/%s", tr.Task.Done, tr.Task.Total, tr.Task.State); key != last {
			last = key
			s.progress(call, tr)
		}
		if tr.Done || !time.Now().Before(deadline) {
			return tr, raw, nil
		}
		wait := taskPollInterval
		if left := time.Until(deadline); left < wait {
			wait = left
		}
		select {
		case <-ctx.Done():
			return tr, raw, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// awaitTask is the sync window: the call that started task id waits up to syncWindow for it.
func (s *Server) awaitTask(ctx context.Context, id uint64, started string, call callState) callResult {
	tr, raw, err := s.waitTask(ctx, id, time.Now().Add(s.syncWindow), call)
	if ctx.Err() != nil {
		// notifications/cancelled (or the session ending): the work this call started is stopped
		// too, through the registry's own cancel. A fresh context, because this one is done.
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(cctx, http.MethodPost, fmt.Sprintf("%s/api/tasks/%d/cancel", s.baseURL, id), nil)
		req.Header.Set(web.MCPAgentHeaderName, "burpsy-mcp")
		if resp, cerr := s.http.Do(req); cerr == nil {
			resp.Body.Close()
		}
		return errResult(fmt.Sprintf("cancelled: task %d was asked to stop", id))
	}
	if err != nil {
		return errResult(fmt.Sprintf("%s\nthe console started task %d, and reading it failed: %v", started, id, err))
	}
	if tr.Done {
		// The status line keeps the call that was made; the body is the finished task view, whose
		// "result" is what a blocking call would have answered.
		first, _, _ := strings.Cut(started, "\n")
		return callResult{Content: []contentBlock{{Type: "text", Text: fmt.Sprintf(
			"%s -> task %d finished within the %s sync window (GET /api/tasks/%d)\n%s", first, id, s.syncWindow, id, raw)}}}
	}
	handle := map[string]any{
		"task_id":          id,
		"status":           "running",
		"kind":             tr.Task.Kind,
		"target":           tr.Task.Target,
		"progress":         tr.Task.Progress,
		"poll_interval_ms": 1000,
		"next": fmt.Sprintf("the task is still running after the %s sync window. Call %s with {\"task_id\":%d} "+
			"(optionally \"wait_seconds\" up to %d) to read it; the result arrives in the task view when it finishes. "+
			"Cancel it with the tasks tool: POST /api/tasks/%d/cancel.", s.syncWindow, taskStatusToolName, id, maxTaskWait, id),
	}
	b, _ := json.Marshal(handle)
	return callResult{Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("HTTP 202 task handle\n%s\n(the console answered: %s)", b, strings.TrimSpace(started))}}}
}

// taskStatus is the burpsy_task_status tool.
func (s *Server) taskStatus(ctx context.Context, rawArgs json.RawMessage, call callState) callResult {
	var args struct {
		TaskID      uint64 `json:"task_id"`
		WaitSeconds int    `json:"wait_seconds"`
	}
	if len(rawArgs) > 0 {
		dec := json.NewDecoder(bytes.NewReader(rawArgs))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&args); err != nil {
			return errResult("arguments: " + err.Error())
		}
	}
	if args.TaskID == 0 {
		return errResult("task_id is required")
	}
	if args.WaitSeconds < 0 || args.WaitSeconds > maxTaskWait {
		return errResult(fmt.Sprintf("wait_seconds must be 0..%d", maxTaskWait))
	}
	tr, raw, err := s.waitTask(ctx, args.TaskID, time.Now().Add(time.Duration(args.WaitSeconds)*time.Second), call)
	if err != nil {
		return errResult(fmt.Sprintf("reading task %d: %v", args.TaskID, err))
	}
	state := "running"
	if tr.Done {
		state = "finished"
	}
	return callResult{Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("HTTP 200 GET /api/tasks/%d (%s)\n%s", args.TaskID, state, raw)}}}
}

// taskStatusDescriptor describes burpsy_task_status.
func taskStatusDescriptor() tool {
	return tool{
		Name: taskStatusToolName,
		Description: "Reads a task handle: the state, progress and — once it has finished — the result of work a call started " +
			"(an audit, a crawl, an API scan). A call that outlives its " + "15 s sync window answers with a handle instead of a result; " +
			"pass its task_id here, with wait_seconds (0-60) to long-poll until it finishes. Reading a task changes nothing.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"task_id":      map[string]any{"type": "integer", "minimum": 1, "description": "the task_id from a handle"},
				"wait_seconds": map[string]any{"type": "integer", "minimum": 0, "maximum": maxTaskWait, "description": "long-poll up to this many seconds for the task to finish"},
			},
			"required":             []string{"task_id"},
			"additionalProperties": false,
		},
		Annotations: map[string]any{
			"readOnlyHint": true, "idempotentHint": true, "destructiveHint": false, "openWorldHint": false,
			"riskClass": "read", "requiresConfirmation": false, "group": groupDatasets,
			"shortDescription": "Reads a task handle's state, progress and finished result.",
		},
	}
}

// ---- logging and the console watcher ---------------------------------------------------------------

var levelRank = map[string]int{"debug": 0, "info": 1, "notice": 2, "warning": 3, "error": 4, "critical": 5, "alert": 6, "emergency": 7}

func (s *Server) capabilities() capabilities {
	c := capabilities{Tools: toolsCapability{ListChanged: false}}
	if s.notify {
		c.Logging = &struct{}{}
	}
	return c
}

func (s *Server) setLevel(req request) response {
	var p struct {
		Level string `json:"level"`
	}
	if r := s.parseParams(req, &p); r != nil {
		return *r
	}
	if _, ok := levelRank[p.Level]; !ok {
		return s.fail(req, codeInvalidParams, "unknown logging level %q", p.Level)
	}
	s.levelMu.Lock()
	s.level = p.Level
	s.levelMu.Unlock()
	return s.ok(req, map[string]any{})
}

// message pushes one notifications/message when level is at or above the session's.
func (s *Server) message(level string, data any) {
	s.levelMu.Lock()
	min := s.level
	s.levelMu.Unlock()
	if levelRank[level] < levelRank[min] {
		return
	}
	_ = s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/message",
		"params": map[string]any{"level": level, "logger": "burpsy", "data": data}})
}

// watchState is what the watcher has already announced or seen.
type watchState struct {
	finished map[uint64]bool
	issues   map[uint64]bool
}

func (s *Server) getJSON(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set(web.MCPAgentHeaderName, "burpsy-mcp")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

type dashTasks struct {
	Tasks []struct {
		ID       uint64          `json:"id"`
		Kind     string          `json:"kind"`
		Target   string          `json:"target"`
		State    string          `json:"state"`
		Note     string          `json:"note"`
		Progress string          `json:"progress"`
		Result   json.RawMessage `json:"result"`
	} `json:"tasks"`
}

type issueList struct {
	Findings []struct {
		ID         uint64  `json:"id"`
		CheckName  string  `json:"check_name"`
		IssueName  *string `json:"issue_name"`
		Severity   string  `json:"severity"`
		Confidence string  `json:"confidence"`
		Host       string  `json:"host"`
	} `json:"findings"`
}

func highSeverity(sev string) bool {
	switch strings.ToLower(sev) {
	case "high", "critical":
		return true
	}
	return false
}

// scan diffs the dashboard and the issue list against what was already seen; announce false takes the
// baseline silently.
func (s *Server) scan(ctx context.Context, st *watchState, tasks, issues, announce bool) {
	if tasks {
		var d dashTasks
		if s.getJSON(ctx, "/api/dashboard", &d) == nil {
			for _, t := range d.Tasks {
				if t.State == "running" || st.finished[t.ID] {
					continue
				}
				st.finished[t.ID] = true
				if announce {
					s.message("info", map[string]any{
						"event": "task.finished", "task_id": t.ID, "kind": t.Kind, "target": t.Target,
						"state": t.State, "note": t.Note, "progress": t.Progress, "result": t.Result,
						"read": fmt.Sprintf("%s {\"task_id\":%d}", taskStatusToolName, t.ID),
					})
				}
			}
		}
	}
	if issues {
		var l issueList
		if s.getJSON(ctx, "/api/issues", &l) == nil {
			for _, f := range l.Findings {
				if st.issues[f.ID] {
					continue
				}
				st.issues[f.ID] = true
				if announce && highSeverity(f.Severity) {
					name := f.CheckName
					if f.IssueName != nil && *f.IssueName != "" {
						name = *f.IssueName
					}
					s.message("warning", map[string]any{
						"event": "issue.found", "issue_id": f.ID, "name": name, "severity": f.Severity,
						"confidence": f.Confidence, "host": f.Host,
					})
				}
			}
		}
	}
}

// startWatcher starts the console watcher once per session.
func (s *Server) startWatcher() {
	if !s.notify || s.session == nil {
		return
	}
	s.watchOnce.Do(func() {
		ctx := s.session
		st := &watchState{finished: map[uint64]bool{}, issues: map[uint64]bool{}}
		s.scan(ctx, st, true, true, false)
		s.watchers.Add(1)
		go func() {
			defer s.watchers.Done()
			for ctx.Err() == nil {
				s.follow(ctx, st)
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
				}
			}
		}()
	})
}

// follow reads the SSE stream until it ends, rescanning on the kinds that can carry news. A rescan
// also runs on (re)connect, so a change that landed while the stream was down is not lost.
func (s *Server) follow(ctx context.Context, st *watchState) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/api/events", nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := s.events.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	s.scan(ctx, st, true, true, true)
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var f struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &f) != nil {
			continue
		}
		switch f.Kind {
		case "dashboard":
			s.scan(ctx, st, true, false, true)
		case "issues":
			s.scan(ctx, st, false, true, true)
		}
	}
}
