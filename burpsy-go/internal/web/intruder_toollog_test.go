package web

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// runUI2IntruderAttack drives the full two-step ui2 launch (confirm, then a run POST rebuilt
// from the confirm fragment's own fields) against a loopback victim and answers the finished
// attack's task id, parsed from the results link the run page hands back.
func runUI2IntruderAttack(t *testing.T, s *Server, victim *httptest.Server) uint64 {
	t.Helper()
	vhost := strings.TrimPrefix(victim.URL, "http://")
	s.scope.AddInclude("127.0.0.1")
	msgID := seedUI2ExchangeMsgID(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: "+vhost+"\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nvictim-ok")

	form := "msg_id=" + strconv.FormatUint(msgID, 10) + "&payloads=admin%0Aroot&all_points=on"
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/confirm", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d", rec.Code)
	}
	frag := rec.Body.String()
	runForm := "token=" + extractHiddenInput(t, frag, "token") + "&msg_id=" + extractHiddenInput(t, frag, "msg_id") +
		"&target=" + extractHiddenInput(t, frag, "target") +
		"&payload_placement=" + extractHiddenInput(t, frag, "payload_placement")
	for _, pt := range extractHiddenInputs(frag, "point") {
		runForm += "&point=" + pt
	}
	for _, ap := range extractHiddenInputs(frag, "all_points") {
		runForm += "&all_points=" + ap
	}
	runForm += "&payloads=" + urlQueryEscape(extractTextarea(t, frag, "payloads"))
	req2 := httptest.NewRequest(http.MethodPost, "/ui2/intruder/run", strings.NewReader(runForm))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("run = %d", rec2.Code)
	}
	body := rec2.Body.String()
	i := strings.Index(body, `href="/ui2/intruder/`)
	if i < 0 {
		t.Fatalf("run page links no results: %s", body[:ui2Min(300, len(body))])
	}
	rest := body[i+len(`href="/ui2/intruder/`):]
	task, err := strconv.ParseUint(rest[:strings.Index(rest, `/`)], 10, 64)
	if err != nil {
		t.Fatalf("results link carries no task id: %s", rest[:ui2Min(80, len(rest))])
	}
	return task
}

func intruderStoreExchanges(s *Server, task uint64) map[core.ExchangeID]*core.Exchange {
	out := map[core.ExchangeID]*core.Exchange{}
	for _, ex := range s.store.Exchanges() {
		if ex.Source == core.SourceIntruder && ex.TaskID == task {
			out[ex.ID] = ex
		}
	}
	return out
}

// TestUI2IntruderAttackRowsReachLogger is the Logger half of the "tools in Logger, out of
// History" contract for Intruder: every exchange an attack stores must also be a Logger row
// linked back to that exchange, and HTTP history must still not list the attack's sends.
func TestUI2IntruderAttackRowsReachLogger(t *testing.T) {
	s := newTestServer()
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("victim-ok"))
	}))
	t.Cleanup(victim.Close)
	task := runUI2IntruderAttack(t, s, victim)

	stored := intruderStoreExchanges(s, task)
	if len(stored) == 0 {
		t.Fatal("attack stored no exchanges; the Logger assertion would be vacuous")
	}
	var entries []*toollog.Entry
	for _, e := range s.toolLog.All() {
		if e.Tool == toollog.ToolIntruder {
			entries = append(entries, e)
		}
	}
	if len(entries) != len(stored) {
		t.Fatalf("Logger holds %d Intruder rows, store holds %d attack exchanges", len(entries), len(stored))
	}
	for _, e := range entries {
		if e.Exchange == nil {
			t.Fatalf("Intruder Logger row %d (%s %s) is not linked to an exchange", e.ID, e.Method, e.Path)
		}
		ex, ok := stored[*e.Exchange]
		if !ok {
			t.Fatalf("Intruder Logger row %d links exchange %d, which is not one of this attack's stored exchanges", e.ID, *e.Exchange)
		}
		if e.Method != ex.Method || e.Path != ex.Path {
			t.Errorf("Logger row %d = %s %s, exchange %d = %s %s", e.ID, e.Method, e.Path, ex.ID, ex.Method, ex.Path)
		}
		if ex.Status != nil && e.Status != int(*ex.Status) {
			t.Errorf("Logger row %d status %d, exchange %d status %d", e.ID, e.Status, ex.ID, *ex.Status)
		}
	}

	// The other half of the contract: History's exclusion of tool-originated exchanges stands.
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/history", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/history = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "a=admin") || strings.Contains(rec.Body.String(), "a=root") {
		t.Errorf("HTTP history lists the attack's sends; the tool-originated exclusion regressed")
	}
}

// TestUI2IntruderLoggerRowsRespectCaptureGate: an operator who unchecked Intruder on Logger's
// capture axis gets no attack rows, and the loss is counted on Uncaptured rather than hidden.
func TestUI2IntruderLoggerRowsRespectCaptureGate(t *testing.T) {
	s := newTestServer()
	s.toolLog.SetCapturing(toollog.ToolIntruder, false)
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("victim-ok"))
	}))
	t.Cleanup(victim.Close)
	task := runUI2IntruderAttack(t, s, victim)

	stored := intruderStoreExchanges(s, task)
	if len(stored) == 0 {
		t.Fatal("attack stored no exchanges; the gate assertion would be vacuous")
	}
	for _, e := range s.toolLog.All() {
		if e.Tool == toollog.ToolIntruder {
			t.Fatalf("capture gate off for Intruder, yet Logger recorded row %d", e.ID)
		}
	}
	if got := s.toolLog.Uncaptured(toollog.ToolIntruder); got != uint64(len(stored)) {
		t.Fatalf("Uncaptured(Intruder) = %d, want %d (one per stored attack exchange)", got, len(stored))
	}
}

// TestUI2IntruderLoggerRowsRespectCaptureFilter: a capture filter that refuses the attack's
// response class drops the rows and counts the loss on Filtered.
func TestUI2IntruderLoggerRowsRespectCaptureFilter(t *testing.T) {
	s := newTestServer()
	if err := s.toolLog.SetFilter(toollog.CaptureFilter{Status: []int{5}}); err != nil {
		t.Fatalf("SetFilter: %v", err)
	}
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("victim-ok"))
	}))
	t.Cleanup(victim.Close)
	task := runUI2IntruderAttack(t, s, victim)

	stored := intruderStoreExchanges(s, task)
	if len(stored) == 0 {
		t.Fatal("attack stored no exchanges; the filter assertion would be vacuous")
	}
	for _, e := range s.toolLog.All() {
		if e.Tool == toollog.ToolIntruder {
			t.Fatalf("capture filter accepts only 5xx, yet Logger recorded the victim's 200 as row %d", e.ID)
		}
	}
	if got := s.toolLog.Filtered(); got != uint64(len(stored)) {
		t.Fatalf("Filtered() = %d, want %d (one per stored attack exchange)", got, len(stored))
	}
}
