package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// hiddenFixture is vulnapp behind a hit counter, and a server whose scanner can reach it.
type hiddenFixture struct {
	srv  *httptest.Server
	host string
	port uint16
	hits atomic.Int64
	s    *Server
}

func newHiddenFixture(t *testing.T, include string) *hiddenFixture {
	return newHiddenFixtureDelayed(t, include, 0)
}

// newHiddenFixtureDelayed slows every origin response by delay, so a run lasts long enough to stop.
func newHiddenFixtureDelayed(t *testing.T, include string, delay time.Duration) *hiddenFixture {
	t.Helper()
	hf := &hiddenFixture{}
	inner := vulnapp.Handler()
	hf.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hf.hits.Add(1)
		time.Sleep(delay)
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(hf.srv.Close)
	h, p, _ := strings.Cut(strings.TrimPrefix(hf.srv.URL, "http://"), ":")
	n, _ := strconv.Atoi(p)
	hf.host, hf.port = h, uint16(n)
	if include == "" {
		include = hf.host
	}
	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.AddInclude(include)
	active := scanner.NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithScope(scope)
	hf.s = NewServer(store, scope).WithScanner(active)
	return hf
}

// seed stores a capture of path without contacting the origin, so the hit counter only counts guesses.
func (hf *hiddenFixture) seed(t *testing.T, path string) core.ExchangeID {
	t.Helper()
	raw := "GET " + path + " HTTP/1.1\r\nHost: " + hf.host + ":" + strconv.Itoa(int(hf.port)) + "\r\nAccept: */*\r\n\r\n"
	reqID, _ := hf.s.store.Put([]byte(raw), core.DirectionRequest)
	respID, _ := hf.s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), core.DirectionResponse)
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: hf.host, Port: hf.port, Method: "GET", Path: path}
	hf.s.store.AddExchange(ex)
	return ex.ID
}

// run starts a guess through the real route and waits (bounded) for its run record to finish,
// returning the run's marshalled JSON as the console would read it.
func (hf *hiddenFixture) run(t *testing.T, id core.ExchangeID, kinds []string) (map[string]any, string) {
	t.Helper()
	rec := postJSON(t, hf.s, "/api/hidden-inputs", map[string]any{"exchange_id": id, "kinds": kinds})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	var started struct {
		TaskID uint64 `json:"task_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &started)
	for i := 0; i < 400; i++ {
		g := get(t, hf.s, "/api/hidden-inputs?task="+strconv.FormatUint(started.TaskID, 10))
		var run map[string]any
		_ = json.Unmarshal(g.Body.Bytes(), &run)
		if run["state"] != "running" {
			return run, g.Body.String()
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("the run never finished")
	return nil, ""
}

func issueNames(t *testing.T, s *Server) []string {
	t.Helper()
	var body struct {
		Findings []struct {
			CheckName  string `json:"check_name"`
			Param      string `json:"param"`
			Confidence string `json:"confidence"`
			Severity   string `json:"severity"`
			Evidence   string `json:"evidence"`
			Advisory   *struct {
				Name string `json:"name"`
			} `json:"advisory"`
			Occurrences []struct {
				ExchangeID uint64 `json:"exchange_id"`
			} `json:"occurrences"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(get(t, s, "/api/issues").Body.Bytes(), &body); err != nil {
		t.Fatalf("decode issues: %v", err)
	}
	out := []string{}
	for _, f := range body.Findings {
		if f.Severity != "Informational" || f.Evidence == "" || len(f.Occurrences) == 0 ||
			f.Advisory == nil || f.Advisory.Name != "Extension generated issue" {
			t.Errorf("finding %s/%s: want Informational severity, an evidence line, the exchange as its one "+
				"occurrence and the extension-generated advisory; got %+v", f.CheckName, f.Param, f)
		}
		out = append(out, f.CheckName+"="+f.Param+"/"+f.Confidence)
	}
	sort.Strings(out)
	return out
}

// The whole path: route, background task, engine, scope gate, findings, run record, dashboard row.
func TestHiddenInputsRouteFindsAndFilesTheFixtureInputs(t *testing.T) {
	hf := newHiddenFixture(t, "")
	id := hf.seed(t, "/hidden/account")
	run, raw := hf.run(t, id, []string{"query", "cookie", "header"})
	if run["state"] != "done" {
		t.Fatalf("state %v: %s", run["state"], raw)
	}
	want := []string{
		"Secret input: cookie=" + vulnapp.HiddenCookie + "/Firm",
		"Secret input: header=" + vulnapp.HiddenHeader + "/Firm",
		"Secret input: query parameter=" + vulnapp.HiddenQueryParam + "/Firm",
		"Secret input: query parameter=" + vulnapp.HiddenReflectedParam + "/Firm",
	}
	if got := issueNames(t, hf.s); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("issues = %v\nwant %v\nrun: %s", got, want, raw)
	}
	if ids, _ := run["finding_ids"].([]any); len(ids) != 4 {
		t.Errorf("finding_ids = %v, want four", run["finding_ids"])
	}
	var task map[string]any
	for _, tk := range hf.s.tasks.Snapshot() {
		if string(tk.Kind) == "hidden-inputs" {
			b, _ := json.Marshal(tk)
			_ = json.Unmarshal(b, &task)
		}
	}
	if task == nil {
		t.Fatalf("no hidden-inputs task on the dashboard")
	}
	if !strings.Contains(raw, `"requests_sent":`) || int64(run["result"].(map[string]any)["requests_sent"].(float64)) != hf.hits.Load() {
		t.Errorf("requests_sent must equal what the origin saw (%d): %s", hf.hits.Load(), raw)
	}
	// A second run of the same exchange merges into the same four findings, not eight.
	hf.run(t, id, []string{"query", "cookie", "header"})
	if got := issueNames(t, hf.s); len(got) != 4 {
		t.Errorf("a re-run filed %d findings, want the same 4 merged: %v", len(got), got)
	}
}

// The random page: no finding, the reason on the wire, and empty lists as [] rather than null.
func TestHiddenInputsRouteReportsAnUnstablePageAndFilesNothing(t *testing.T) {
	hf := newHiddenFixture(t, "")
	run, raw := hf.run(t, hf.seed(t, "/hidden/random"), []string{"query", "header"})
	if run["state"] != "unstable" || !strings.Contains(raw, "varies on its own") {
		t.Fatalf("state %v: %s", run["state"], raw)
	}
	for _, frag := range []string{`"finding_ids":[]`, `"inputs":[]`, `"found":[]`, `"unconfirmed":[]`} {
		if !strings.Contains(raw, frag) {
			t.Errorf("run JSON lacks %s: %s", frag, raw)
		}
	}
	if got := issueNames(t, hf.s); len(got) != 0 {
		t.Errorf("an unstable page filed findings: %v", got)
	}
	if hf.hits.Load() != 2 {
		t.Errorf("an unstable page costs the two baselines; the origin saw %d", hf.hits.Load())
	}
}

func TestHiddenInputsRouteFilesNothingForAPageThatEchoesItsRequest(t *testing.T) {
	hf := newHiddenFixture(t, "")
	run, raw := hf.run(t, hf.seed(t, "/hidden/echo"), []string{"query", "cookie", "header"})
	if run["state"] != "done" || !strings.Contains(raw, `"inputs":[]`) {
		t.Fatalf("state %v: %s", run["state"], raw)
	}
	if got := issueNames(t, hf.s); len(got) != 0 {
		t.Errorf("an echo page filed findings: %v", got)
	}
}

// Out of scope: refused before a task exists, and nothing reaches the origin.
func TestHiddenInputsRouteRefusesAnOutOfScopeExchangeBeforeSending(t *testing.T) {
	hf := newHiddenFixture(t, "other.invalid")
	id := hf.seed(t, "/hidden/account")
	rec := postJSON(t, hf.s, "/api/hidden-inputs", map[string]any{"exchange_id": id, "kinds": []string{"query"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if hf.hits.Load() != 0 || len(hf.s.tasks.Snapshot()) != 0 {
		t.Fatalf("origin saw %d requests and %d tasks were registered; want none", hf.hits.Load(), len(hf.s.tasks.Snapshot()))
	}
}

func TestHiddenInputsRouteRefusesMalformedRequests(t *testing.T) {
	hf := newHiddenFixture(t, "")
	first := hf.seed(t, "/hidden/echo")
	if first != 0 {
		t.Fatalf("the first seeded exchange is %d; this test relies on id 0 being a real exchange", first)
	}
	for name, tc := range map[string]struct {
		body map[string]any
		code int
	}{
		"no kinds":         {map[string]any{"exchange_id": 0, "kinds": []string{}}, http.StatusBadRequest},
		"unknown kind":     {map[string]any{"exchange_id": 0, "kinds": []string{"body"}}, http.StatusBadRequest},
		"no exchange":      {map[string]any{"kinds": []string{"query"}}, http.StatusBadRequest},
		"missing exchange": {map[string]any{"exchange_id": 999, "kinds": []string{"query"}}, http.StatusNotFound},
		"budget too large": {map[string]any{"exchange_id": 0, "kinds": []string{"query"}, "max_requests": 999999}, http.StatusBadRequest},
	} {
		if rec := postJSON(t, hf.s, "/api/hidden-inputs", tc.body); rec.Code != tc.code {
			t.Errorf("%s: POST = %d, want %d: %s", name, rec.Code, tc.code, rec.Body.String())
		}
	}
	if hf.hits.Load() != 0 {
		t.Errorf("a refused request sent %d guesses", hf.hits.Load())
	}
	// Exchange 0 is a real id, not a missing field.
	if run, raw := hf.run(t, 0, []string{"query"}); run["state"] == "running" || !strings.Contains(raw, `"exchange_id":0`) {
		t.Errorf("exchange 0 did not run: %s", raw)
	}
}

// The route sends traffic, so an unattended caller must confirm it — the reason it is not nested
// under the riskLocal /api/exchange/ subtree.
func TestHiddenInputsRouteIsBehindTheConfirmationGate(t *testing.T) {
	hf := newHiddenFixture(t, "")
	id := hf.seed(t, "/hidden/account")
	body := `{"exchange_id":` + strconv.FormatUint(uint64(id), 10) + `,"kinds":["query"]}`
	if rec := guarded(t, hf.s, http.MethodPost, "/api/hidden-inputs", body); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("an unconfirmed POST = %d, want %d", rec.Code, http.StatusPreconditionRequired)
	}
	if hf.hits.Load() != 0 {
		t.Fatalf("an unconfirmed POST sent %d guesses", hf.hits.Load())
	}
	if rec := guarded(t, hf.s, http.MethodGet, "/api/hidden-inputs", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"runs":[]`) {
		t.Errorf("GET = %d %s; want 200 with runs: []", rec.Code, rec.Body.String())
	}
}

// The dashboard's Stop reaches the run: cancelling the task ends it within a request or two, the
// run record and the task both say stopped, and most of the wordlist is reported as never sent.
func TestHiddenInputsRouteStopsWhenTheTaskIsCancelled(t *testing.T) {
	hf := newHiddenFixtureDelayed(t, "", 40*time.Millisecond)
	id := hf.seed(t, "/hidden/account")
	rec := postJSON(t, hf.s, "/api/hidden-inputs", map[string]any{"exchange_id": id, "kinds": []string{"query", "cookie", "header"}})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	var started struct {
		TaskID uint64 `json:"task_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &started)
	for i := 0; i < 200 && hf.hits.Load() < 3; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !hf.s.tasks.Cancel(started.TaskID) {
		t.Fatalf("the task was not cancellable")
	}
	var run map[string]any
	var raw string
	for i := 0; i < 400; i++ {
		g := get(t, hf.s, "/api/hidden-inputs?task="+strconv.FormatUint(started.TaskID, 10))
		raw = g.Body.String()
		_ = json.Unmarshal(g.Body.Bytes(), &run)
		if run["state"] != "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if run["state"] != "stopped" {
		t.Fatalf("run state %v after cancel: %s", run["state"], raw)
	}
	if hits := hf.hits.Load(); hits > 10 {
		t.Errorf("the origin saw %d requests after a cancel at 3; a full run is 61", hits)
	}
	for _, tk := range hf.s.tasks.Snapshot() {
		if tk.ID == started.TaskID && tk.State != dash.TaskStopped {
			t.Errorf("task state = %v, want stopped", tk.State)
		}
	}
}
