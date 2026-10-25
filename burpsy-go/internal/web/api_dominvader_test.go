package web

import (
	"encoding/json"
	"fmt"
	"github.com/burpsy-go/burpsy/internal/dominvader"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// burpsy-react-ui-wl94: the auditor is off with a fresh canary by default; the operator sets the
// canary and the switch; the extension's reports arrive and the console reads them; a repeat
// collapses onto its row.
func TestDomInvaderSetReportAndRead(t *testing.T) {
	s := newTestServer()

	g := get(t, s, "/api/dominvader")
	if !strings.Contains(g.Body.String(), `"enabled":false`) || !strings.Contains(g.Body.String(), "burpsyDI") {
		t.Fatalf("default view = %s", g.Body.String())
	}

	if rec := putJSON(t, s, "/api/dominvader", map[string]any{"canary": "myMark", "enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if !s.domInvader.Enabled() || s.domInvader.Canary() != "myMark" {
		t.Errorf("state not applied: enabled %v canary %q", s.domInvader.Enabled(), s.domInvader.Canary())
	}
	if rec := putJSON(t, s, "/api/dominvader", map[string]any{"canary": "  "}); rec.Code != http.StatusBadRequest {
		t.Errorf("an empty canary = %d, want 400", rec.Code)
	}

	// The extension reports two hits, the second a repeat of the first.
	hit := map[string]any{"kind": "sink", "sink": "innerHTML", "sources": []string{"location.hash"}, "excerpt": "<img src=x onerror=myMark>", "dedupe": "d1"}
	for i := 0; i < 2; i++ {
		if rec := postJSON(t, s, "/api/dominvader/hit", hit); rec.Code != http.StatusNoContent {
			t.Fatalf("POST hit = %d: %s", rec.Code, rec.Body.String())
		}
	}
	if rec := postJSON(t, s, "/api/dominvader/hit", map[string]any{"kind": "source", "sink": "postMessage", "dedupe": "d2"}); rec.Code != http.StatusNoContent {
		t.Fatalf("POST source hit = %d", rec.Code)
	}
	if rec := postJSON(t, s, "/api/dominvader/hit", map[string]any{"kind": "sink"}); rec.Code != http.StatusBadRequest {
		t.Errorf("a hit without a sink name = %d, want 400", rec.Code)
	}

	g = get(t, s, "/api/dominvader")
	var view domInvaderView
	if err := json.Unmarshal(g.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Hits) != 2 {
		t.Fatalf("hits = %d, want 2 (the repeat collapsed)", len(view.Hits))
	}
	if view.Hits[0].Sink != "innerHTML" || view.Hits[0].Sources[0] != "location.hash" {
		t.Errorf("first hit = %+v", view.Hits[0])
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/dominvader/hits", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, del)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE hits = %d", rec.Code)
	}
	if g := get(t, s, "/api/dominvader"); !strings.Contains(g.Body.String(), `"hits":[]`) {
		t.Errorf("hits not cleared: %s", g.Body.String())
	}
}

func TestDomMessageWorkerRoutesRefuseMissingStaleAndWrongCapabilities(t *testing.T) {
	s := newTestServer()
	launch := s.domInvader.BeginWorkerLaunch("http://localhost/hit")
	s.domInvader.BeginWorkerLaunch("http://localhost/hit")
	for _, path := range []string{"/api/dominvader/messages/register", "/api/dominvader/messages/report", "/api/dominvader/messages/poll", "/api/dominvader/messages/ack"} {
		for _, capability := range []string{"", "wrong", launch.WorkerCapability} {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			req.Header.Set("X-Burpsy-DOM-Worker", capability)
			rec := httptest.NewRecorder()
			s.mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("worker route %s accepted invalid capability: %d", path, rec.Code)
			}
		}
	}
}

func TestDomMessageWorkerRegistrationRequiresCapabilityAndDoesNotExposeItToConsole(t *testing.T) {
	s := newTestServer()
	launch := s.domInvader.BeginWorkerLaunch("http://localhost/hit")
	req := httptest.NewRequest(http.MethodPost, "/api/dominvader/messages/register", strings.NewReader(`{"tab":4,"frame":"0"}`))
	req.Header.Set("X-Burpsy-DOM-Worker", launch.WorkerCapability)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized worker refused %d %s", rec.Code, rec.Body.String())
	}
	var frame struct {
		Token string `json:"frame_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &frame); err != nil {
		t.Fatal(err)
	}
	if frame.Token == "" {
		t.Fatal("worker received empty frame session")
	}
	view := get(t, s, "/api/dominvader")
	if strings.Contains(view.Body.String(), launch.WorkerCapability) || strings.Contains(view.Body.String(), frame.Token) {
		t.Fatal("private capability leaked into console view")
	}
	for _, path := range []string{"/worker-config.js", "/api/dominvader/worker-config.js"} {
		rec := get(t, s, path)
		if strings.Contains(rec.Body.String(), launch.WorkerCapability) {
			t.Fatalf("worker capability served to page at %s", path)
		}
	}
}

func TestDomWorkerExceptionThroughGuardedHandlerIsExactAndCapabilityBound(t *testing.T) {
	s := newTestServer()
	old := s.domInvader.BeginWorkerLaunch("http://localhost/hit")
	current := s.domInvader.BeginWorkerLaunch("http://localhost/hit")
	for _, tc := range []struct {
		path, capability string
		want             int
	}{
		{"/api/dominvader/messages/register", current.WorkerCapability, 200},
		{"/api/dominvader/messages/register", old.WorkerCapability, 401},
		{"/api/dominvader/messages/register", "", 401},
		{"/api/dominvader/messages/register", "wrong", 401},
		{"/api/dominvader/messages/fourth", current.WorkerCapability, 403},
		{"/api/dominvader", current.WorkerCapability, 403},
	} {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081"+tc.path, strings.NewReader(`{"tab":4,"frame":"0"}`))
		req.Header.Set("Origin", "chrome-extension://test-extension")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		if tc.capability != "" {
			req.Header.Set(domWorkerHeader, tc.capability)
		}
		rec := httptest.NewRecorder()
		s.guarded.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s guarded status %d want %d", tc.path, rec.Code, tc.want)
		}
	}
}

func TestDomWorkerExceptionSetHasExactlyFourNonControllerRoutes(t *testing.T) {
	// Four: register, report, poll, and the frame-specific ack (added with the
	// controller slice; the decide/intercept/list controller routes are NOT in it).
	if len(domWorkerRoutes) != 4 {
		t.Fatal("worker exception set changed; a new route requires a new security decision")
	}
	for _, path := range []string{"/api/dominvader/messages/register", "/api/dominvader/messages/report", "/api/dominvader/messages/poll", "/api/dominvader/messages/ack"} {
		if !domWorkerRoutes[path] {
			t.Fatalf("required worker route missing: %s", path)
		}
	}
	s := newTestServer()
	capability := s.domInvader.BeginWorkerLaunch("http://localhost/hit").WorkerCapability
	req := httptest.NewRequest(http.MethodPost, "http://evil.example/api/dominvader/messages/register", strings.NewReader(`{}`))
	req.Header.Set(domWorkerHeader, capability)
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("worker capability bypassed Host validation: %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPut, "http://127.0.0.1:8081/api/dominvader", strings.NewReader(`{"enabled":true}`))
	req.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("cross-site controller was accepted: %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPut, "http://127.0.0.1:8081/api/dominvader", strings.NewReader(`{"enabled":true}`))
	req.Header.Set(domWorkerHeader, capability)
	rec = httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("worker capability was worth something on controller: %d", rec.Code)
	}
}

func registerFrame(t *testing.T, s *Server, capability string, tab int, frame string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081/api/dominvader/messages/register", strings.NewReader(fmt.Sprintf(`{"tab":%d,"frame":%q}`, tab, frame)))
	req.Header.Set(domWorkerHeader, capability)
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	var out struct {
		Token string `json:"frame_token"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Token == "" {
		t.Fatalf("register %d %s", rec.Code, rec.Body.String())
	}
	return out.Token
}

func workerPost(s *Server, capability, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081"+path, strings.NewReader(body))
	req.Header.Set("Origin", "chrome-extension://test-extension")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set(domWorkerHeader, capability)
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	return rec
}

func consoleDo(s *Server, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://127.0.0.1:8081"+path, strings.NewReader(body))
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	return rec
}

func TestControllerRoutesRefuseWorkersCrossSiteAndForgedHolds(t *testing.T) {
	s := newTestServer()
	cap := s.domInvader.BeginWorkerLaunch("http://localhost/hit").WorkerCapability
	for _, tc := range []struct{ method, path, body string }{
		{"PUT", "/api/dominvader/messages/intercept", `{"enabled":true}`},
		{"POST", "/api/dominvader/messages/decide", `{"hold_id":"x","action":"drop"}`},
		{"GET", "/api/dominvader/messages", ``},
	} {
		// worker capability must not unlock a controller route
		req := httptest.NewRequest(tc.method, "http://127.0.0.1:8081"+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Origin", "chrome-extension://test-extension")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set(domWorkerHeader, cap)
		rec := httptest.NewRecorder()
		s.guarded.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("%s %s with worker capability = %d", tc.method, tc.path, rec.Code)
		}
		// cross-site page without header is refused too
		req = httptest.NewRequest(tc.method, "http://127.0.0.1:8081"+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Origin", "https://evil.example")
		rec = httptest.NewRecorder()
		s.guarded.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("%s %s cross-site = %d", tc.method, tc.path, rec.Code)
		}
	}
	if s.domMessages.Intercept() {
		t.Fatal("interception toggled by a refused request")
	}
	if rec := consoleDo(s, "POST", "/api/dominvader/messages/decide", `{"hold_id":"forged","action":"drop"}`); rec.Code != 404 {
		t.Fatalf("forged hold id = %d", rec.Code)
	}
}

func TestWorkerReportNeverBecomesAControllerDecisionAndFullHoldFlowIsFrameBound(t *testing.T) {
	s := newTestServer()
	cap := s.domInvader.BeginWorkerLaunch("http://localhost/hit").WorkerCapability
	top := registerFrame(t, s, cap, 4, "0")
	child := registerFrame(t, s, cap, 4, "7")
	rep := func(tok string) *httptest.ResponseRecorder {
		return workerPost(s, cap, "/api/dominvader/messages/report", fmt.Sprintf(`{"frame_token":%q,"message":{"body":"{\"x\":1}","origin":"https://t.example","state":"held","hold_id":"forged"}}`, tok))
	}
	// interception off: observation only, even though the report claims held
	var m struct {
		State  string `json:"state"`
		HoldID string `json:"hold_id"`
	}
	rec := rep(top)
	json.Unmarshal(rec.Body.Bytes(), &m)
	if rec.Code != 200 || m.State != "observed" || m.HoldID != "" {
		t.Fatalf("report self-selected hold: %d %s", rec.Code, rec.Body.String())
	}
	if rec := consoleDo(s, "PUT", "/api/dominvader/messages/intercept", `{"enabled":true}`); rec.Code != 200 || !s.domMessages.Intercept() {
		t.Fatalf("controller could not enable interception: %d", rec.Code)
	}
	rec = rep(top)
	json.Unmarshal(rec.Body.Bytes(), &m)
	if m.State != "held" || m.HoldID == "" || m.HoldID == "forged" {
		t.Fatalf("not held with server hold id: %s", rec.Body.String())
	}
	hold := m.HoldID
	// the worker cannot decide: no decide on worker routes, and a worker-authenticated poll shows nothing yet
	if rec := workerPost(s, cap, "/api/dominvader/messages/decide", fmt.Sprintf(`{"hold_id":%q,"action":"forward","body":"1"}`, hold)); rec.Code != 403 {
		t.Fatalf("worker reached decide: %d", rec.Code)
	}
	if rec := consoleDo(s, "POST", "/api/dominvader/messages/decide", fmt.Sprintf(`{"hold_id":%q,"action":"forward","body":"{\"edited\":true}"}`, hold)); rec.Code != 200 {
		t.Fatalf("controller decide %d %s", rec.Code, rec.Body.String())
	}
	if rec := workerPost(s, cap, "/api/dominvader/messages/poll", fmt.Sprintf(`{"frame_token":%q}`, child)); strings.Contains(rec.Body.String(), hold) {
		t.Fatal("decision crossed to sibling frame")
	}
	if rec := workerPost(s, cap, "/api/dominvader/messages/ack", fmt.Sprintf(`{"frame_token":%q,"hold_id":%q,"outcome":"dispatched"}`, top, hold)); rec.Code == 200 {
		t.Fatal("ack accepted before delivery")
	}
	if rec := workerPost(s, cap, "/api/dominvader/messages/poll", fmt.Sprintf(`{"frame_token":%q}`, top)); !strings.Contains(rec.Body.String(), hold) {
		t.Fatalf("own frame poll missed decision: %s", rec.Body.String())
	}
	if rec := workerPost(s, cap, "/api/dominvader/messages/ack", fmt.Sprintf(`{"frame_token":%q,"hold_id":%q,"outcome":"dispatched"}`, child, hold)); rec.Code == 200 {
		t.Fatal("sibling frame acked")
	}
	if rec := workerPost(s, cap, "/api/dominvader/messages/ack", fmt.Sprintf(`{"frame_token":%q,"hold_id":%q,"outcome":"dispatched"}`, top, hold)); rec.Code != 200 {
		t.Fatalf("own ack refused %d %s", rec.Code, rec.Body.String())
	}
	list := consoleDo(s, "GET", "/api/dominvader/messages", ``).Body.String()
	if !strings.Contains(list, "worker-reported-dispatched-unverified") || strings.Contains(list, cap) || strings.Contains(list, top) {
		t.Fatalf("list wrong or leaks secrets: %s", list)
	}
}

// Drives the real extension sw.js under Node (mocked chrome API, real fetch) against a real server.
// PROTOCOL + sender-binding evidence only: this is not a browser test.
func TestExtensionWorkerAgainstRealServerBindsFrameFromSenderAndFollowsControllerDecision(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH: worker protocol test not run")
	}
	s := newTestServer()
	ts := httptest.NewServer(s.guarded)
	defer ts.Close()
	cfg := s.domInvader.BeginWorkerLaunch(ts.URL + "/api/dominvader/hit")
	cfg.Enabled = true
	cfg.Canary = "burpsyDItest"
	dir, err := dominvader.Materialise(t.TempDir(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.domMessages.SetIntercept(true)
	cmd := exec.Command(node, "testdata/sw_harness.js")
	cmd.Env = append(os.Environ(), "BURPSY_EXT_DIR="+dir)
	var out, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// operator side: wait for the held message, then decide through the console route
	var hold string
	for i := 0; i < 100 && hold == ""; i++ {
		time.Sleep(100 * time.Millisecond)
		for _, m := range s.domMessages.Messages(time.Now()) {
			if m.State == "held" {
				hold = m.HoldID
			}
		}
	}
	if hold == "" {
		cmd.Process.Kill()
		t.Fatalf("worker never produced a held message; stderr=%s", stderr.String())
	}
	if rec := consoleDo(s, "POST", "/api/dominvader/messages/decide", fmt.Sprintf(`{"hold_id":%q,"action":"forward","body":"{\"edited\":1}"}`, hold)); rec.Code != 200 {
		t.Fatalf("decide %d %s", rec.Code, rec.Body.String())
	}
	if err := <-done; err != nil {
		t.Fatalf("harness: %v %s", err, stderr.String())
	}
	var res struct {
		Deliveries []struct {
			Tab      int `json:"tab"`
			FrameID  int `json:"frameId"`
			Decision struct {
				HoldID    string `json:"hold_id"`
				Synthetic bool   `json:"synthetic"`
			} `json:"decision"`
		} `json:"deliveries"`
		Cap string `json:"capabilityOnPageGlobals"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &res); err != nil {
		t.Fatalf("harness output %q: %v", out.String(), err)
	}
	if len(res.Deliveries) != 1 || res.Deliveries[0].Tab != 4 || res.Deliveries[0].FrameID != 7 || res.Deliveries[0].Decision.HoldID != hold || !res.Deliveries[0].Decision.Synthetic {
		t.Fatalf("decision not delivered to the sender-bound frame: %+v", res)
	}
	rows := s.domMessages.Messages(time.Now())
	if len(rows) != 1 {
		t.Fatalf("forged senders produced observations: %+v", rows)
	}
	if rows[0].Tab != 4 || rows[0].Frame != "7" || rows[0].Body != `"payload-claims-frame"` || rows[0].State != "forward-worker-reported-dispatched-unverified" {
		t.Fatalf("binding/ack wrong: %+v", rows[0])
	}
}
