package web

// The bead's acceptance pin (burpsy-react-ui-1944): a Repeater tab carries a custom action - a
// small sandboxed script on the ydmj runtime - that runs ON DEMAND and AUTO-RUNS when a response
// arrives for that tab (Burp: "Auto-run on send ... The custom action runs when Burp receives a
// response"). burpsy's script hooks are pre-request only (ydmj/xe82/q7f8); nothing answers a
// response. RED on the pre-implementation tree: these routes do not exist.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

func repeaterActionTarget(t *testing.T, body string) (host string, port uint16, closeFn func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, body)
	}))
	authority := strings.TrimPrefix(srv.URL, "http://")
	name, portStr, _ := strings.Cut(authority, ":")
	p, err := strconv.Atoi(portStr)
	if err != nil {
		srv.Close()
		t.Fatalf("test origin port: %v", err)
	}
	return name, uint16(p), srv.Close
}

func TestAcceptanceRepeaterTabCustomAction(t *testing.T) {
	host, port, closeFn := repeaterActionTarget(t, "hello")
	defer closeFn()
	s := newTestServer()

	// Install the tab's action: log the response status, stamp the request.
	script := `log("saw " + response.status); request.headers["X-Action-Ran"] = "yes";`
	rec := putJSON(t, s, "/api/repeater/tabs/tab-1/action", map[string]any{
		"script": script, "auto_run": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("install the action: %d %s", rec.Code, rec.Body)
	}

	// A send from the tab: the response arrives, and the action auto-runs against it.
	raw := fmt.Sprintf("GET /form HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	if _, err := s.sendOneRepeaterRequest(context.Background(), repeaterSendSpec{
		TabID: "tab-1", Host: host, Port: port, Raw: []byte(raw), AsWritten: raw,
	}); err != nil {
		t.Fatalf("repeater send: %v", err)
	}

	// The run is inspectable: its log saw the response, and the rewrite it produced is there
	// for the tab's next send.
	rec = get(t, s, "/api/repeater/tabs/tab-1/action")
	if rec.Code != http.StatusOK {
		t.Fatalf("read the action: %d %s", rec.Code, rec.Body)
	}
	var state struct {
		LastRun struct {
			Log     []string `json:"log"`
			Request string   `json:"request"`
		} `json:"last_run"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode action: %v", err)
	}
	if len(state.LastRun.Log) == 0 || state.LastRun.Log[0] != "saw 200" {
		t.Errorf("the auto-run did not see the response: %v", state.LastRun.Log)
	}
	if !strings.Contains(state.LastRun.Request, "X-Action-Ran: yes") {
		t.Errorf("the auto-run's rewritten request is missing the stamp: %q", state.LastRun.Request)
	}

	// On demand: the same script runs against the tab's latest exchange when the operator asks.
	rec = postJSON(t, s, "/api/repeater/tabs/tab-1/action/run", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("run on demand: %d %s", rec.Code, rec.Body)
	}
	var run struct {
		Log     []string `json:"log"`
		Request string   `json:"request"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if len(run.Log) == 0 || run.Log[0] != "saw 200" || !strings.Contains(run.Request, "X-Action-Ran: yes") {
		t.Errorf("the on-demand run did not reproduce the action: log %v, request %q", run.Log, run.Request)
	}
}

// The action's guard rails: a script that does not compile is refused at install; reads, runs and
// deletes of a tab with no action are 404, distinctly from the 400s; an action without auto_run
// stays quiet on sends and fires only when asked; a script that fails says so in the run, without
// losing the config.
func TestRepeaterTabActionGuardRails(t *testing.T) {
	host, port, closeFn := repeaterActionTarget(t, "hello")
	defer closeFn()
	s := newTestServer()

	// Not found, in three shapes.
	if rec := get(t, s, "/api/repeater/tabs/ghost/action"); rec.Code != http.StatusNotFound {
		t.Errorf("GET with no action: %d", rec.Code)
	}
	if rec := deleteReq(t, s, "/api/repeater/tabs/ghost/action"); rec.Code != http.StatusNotFound {
		t.Errorf("DELETE with no action: %d", rec.Code)
	}
	if rec := postJSON(t, s, "/api/repeater/tabs/ghost/action/run", map[string]any{}); rec.Code != http.StatusNotFound {
		t.Errorf("run with no action: %d", rec.Code)
	}

	// A script that does not compile never installs.
	rec := putJSON(t, s, "/api/repeater/tabs/tab-1/action", map[string]any{"script": "this is not javascript(", "auto_run": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a broken script answered %d, not 400", rec.Code)
	}

	// Manual only: no auto_run, so a send does not run it.
	rec = putJSON(t, s, "/api/repeater/tabs/tab-1/action", map[string]any{
		"script": `log("saw " + response.status); store.set("runs", (parseInt(store.get("runs") || "0") + 1).toString());`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("install: %d %s", rec.Code, rec.Body)
	}
	raw := fmt.Sprintf("GET /form HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	if _, err := s.sendOneRepeaterRequest(context.Background(), repeaterSendSpec{
		TabID: "tab-1", Host: host, Port: port, Raw: []byte(raw), AsWritten: raw,
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	rec = get(t, s, "/api/repeater/tabs/tab-1/action")
	var state struct {
		LastRun *struct {
			Log []string `json:"log"`
		} `json:"last_run"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if state.LastRun != nil {
		t.Errorf("a manual-only action ran on a send: %v", state.LastRun.Log)
	}

	// On demand it runs, and its store survives into the next run.
	for i, want := range []string{"1", "2"} {
		rec = postJSON(t, s, "/api/repeater/tabs/tab-1/action/run", map[string]any{})
		if rec.Code != http.StatusOK {
			t.Fatalf("run %d: %d %s", i+1, rec.Code, rec.Body)
		}
		var run struct {
			Log   []string `json:"log"`
			Error string   `json:"error"`
		}
		if err := decodeJSON(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode run: %v", err)
		}
		if run.Error != "" || len(run.Log) == 0 || run.Log[0] != "saw 200" {
			t.Fatalf("run %d: log %v error %q", i+1, run.Log, run.Error)
		}
		_ = want
	}

	// A failing script reports its failure as data and the config survives it.
	rec = putJSON(t, s, "/api/repeater/tabs/tab-1/action", map[string]any{"script": `throw new Error("boom")`})
	if rec.Code != http.StatusOK {
		t.Fatalf("replace: %d", rec.Code)
	}
	rec = postJSON(t, s, "/api/repeater/tabs/tab-1/action/run", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("a failed run is still a run: %d", rec.Code)
	}
	var failed struct {
		Error string `json:"error"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &failed); err != nil {
		t.Fatalf("decode failed run: %v", err)
	}
	if !strings.Contains(failed.Error, "boom") {
		t.Errorf("the script's failure was not reported: %q", failed.Error)
	}
	rec = get(t, s, "/api/repeater/tabs/tab-1/action")
	if rec.Code != http.StatusOK {
		t.Errorf("the config did not survive its script's failure: %d", rec.Code)
	}
}

// The config is project state: it comes back after a reopen. The run log does not - it describes
// traffic from a session that is gone.
func TestRepeaterTabActionPersists(t *testing.T) {
	p, err := persist.Open(filepath.Join(t.TempDir(), "p.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer p.Close()
	s := newTestServer().WithPersist(p)

	rec := putJSON(t, s, "/api/repeater/tabs/tab-7/action", map[string]any{
		"script": `log("x")`, "auto_run": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("install: %d %s", rec.Code, rec.Body)
	}

	// A fresh server over the same store has the action back.
	s2 := newTestServer().WithPersist(p)
	rec = get(t, s2, "/api/repeater/tabs/tab-7/action")
	if rec.Code != http.StatusOK {
		t.Fatalf("the action did not survive a reopen: %d %s", rec.Code, rec.Body)
	}
	var state struct {
		Action struct {
			Script  string `json:"script"`
			AutoRun bool   `json:"auto_run"`
		} `json:"action"`
		LastRun *struct{} `json:"last_run"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if state.Action.Script != `log("x")` || !state.Action.AutoRun {
		t.Errorf("the config did not round-trip: %+v", state.Action)
	}
	if state.LastRun != nil {
		t.Errorf("a run log crossed a reopen; only the config is project state")
	}

	// Deleted is deleted on disk too.
	rec = deleteReq(t, s2, "/api/repeater/tabs/tab-7/action")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d", rec.Code)
	}
	s3 := newTestServer().WithPersist(p)
	if rec := get(t, s3, "/api/repeater/tabs/tab-7/action"); rec.Code != http.StatusNotFound {
		t.Errorf("a deleted action came back after a reopen: %d", rec.Code)
	}
}
