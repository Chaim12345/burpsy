package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// An unwired server (no WithScanner) must still dispatch the loaded corpus's active checks:
// runAudit builds its scanner lazily, and the fallback has to pass the same ActiveChecks() the
// explicit wiring in main.go does — otherwise the two construction paths would drift and the
// corpus would silently stop running for an operator whose server took the fallback.
//
// The check is `given host` with no send, so it needs no network: a bare response audit. It
// reports when the status is 200, so a passing run is observable as a dispatched check rather
// than as an empty "no findings" that could equally mean the check never ran.
func Test_an_unwired_server_dispatching_audits_still_runs_corpus_active_checks(t *testing.T) {
	dir := t.TempDir()
	src := `metadata:
  language: v2-beta
  name: "web-fallback-corpus"
given host then
  if {response.status_code} is "200" then
    report issue:
      severity: low
      confidence: certain
  end if
`
	if err := os.WriteFile(filepath.Join(dir, "fallback.bcheck"), []byte(src), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	s := newTestServer()
	store := s.store
	reqID, err := store.Put([]byte("GET / HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\n\r\n<html>hello</html>"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	// The audit route rejects id 0 (the first capture of a session) as invalid, so the exchange
	// under test is the second one — same shape as the existing audit endpoint tests.
	store.AddExchange(&core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: "h.test", Port: 80, Method: "GET", Path: "/first"})
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: "h.test", Port: 80, Method: "GET", Path: "/"}
	store.AddExchange(ex)

	ps, err := scanner.LoadDir(dir, store, s.scope, zap.NewNop())
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if got := ps.ActiveLoaded(); got != 1 {
		t.Fatalf("loaded active checks = %d, want 1", got)
	}
	s.WithPassiveScanner(ps)
	// Deliberately no WithScanner: the lazy fallback in runAudit is what is under test.

	rec := postJSON(t, s, "/api/audit/"+strconv.FormatUint(uint64(ex.ID), 10), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/audit/%d: %d", ex.ID, rec.Code)
	}

	var body struct {
		ActiveChecks int `json:"active_checks"`
		Outcome      struct {
			Ran int `json:"ran"`
		} `json:"outcome"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode audit response %q: %v", rec.Body.String(), err)
	}
	// The corpus check is in the dispatched set (only the corpus's check is enabled — the fallback
	// scanner has the default ScanConfig, whose SSRF switch is on but unimplemented and is counted
	// as skipped, never as ran).
	if body.ActiveChecks == 0 {
		t.Error("active_checks = 0, want the corpus check in the set")
	}
	if body.Outcome.Ran == 0 {
		t.Error("outcome.ran = 0, want the corpus `given host` check to have dispatched")
	}
}
