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
	"strconv"
	"strings"
	"testing"
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
