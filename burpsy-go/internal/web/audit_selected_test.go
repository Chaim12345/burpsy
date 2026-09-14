package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
)

// ---- Auditing a selection (Burp's "Audit selected items") ---------------------------------------
//
// The feature is a launch surface, so these pin the launch and not the engine: the engine's own
// behaviour is scanner.AuditSession's, already covered over there and by the crawl-and-audit phase.
// What is new and therefore worth pinning is that a *selection* reaches the engine as the work, that a
// launch with no selection is refused rather than started, and that the reply says what was run —
// because every one of those is a way a scan can report success while auditing something other than
// what the operator ticked.

// auditSelection posts a selection to the launch and returns the decoded reply.
//
// A refusal is plain text (http.Error) and an acceptance is JSON, so the decode is conditional on the
// content type rather than on the status: decoding a refusal would fail with a parse error and hide
// the message the test is actually asserting on.
func auditSelection(t *testing.T, s *Server, ids []int) (int, map[string]any) {
	t.Helper()
	rec := postJSON(t, s, "/api/audit/selected", map[string]any{"exchange_ids": ids})
	body := map[string]any{"raw": rec.Body.String()}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode reply %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, body
}

// The core claim: the audit runs over the exchanges that were selected, and the work is the selection
// rather than the store. Three rows are in the capture and one is selected; a launch that audited
// "everything captured" would pass a smoke test and be the defect this door exists to avoid.
func TestASelectionAuditCoversExactlyTheSelectedExchanges(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("h.test")
	recordCompleteExchange(t, s, "h.test", "/one")
	recordCompleteExchange(t, s, "h.test", "/two")
	recordCompleteExchange(t, s, "h.test", "/not-selected")

	code, body := auditSelection(t, s, []int{0, 1})
	if code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (%v) — a selection has no bound on its size, so the launch "+
			"cannot answer with the outcome", code, body)
	}
	if got := body["count"]; got != float64(2) {
		t.Errorf("count = %v, want 2 — the reply must state the work it took on, not the size of the capture", got)
	}
	if got := body["kind"]; got != "audit-session" {
		t.Errorf("kind = %v, want audit-session; the row the operator will look for is the audit-session one", got)
	}

	task := waitForAuditTask(t, s)
	if task.Total != 2 {
		t.Errorf("audit total = %d, want 2 — the task's total is the second place this can go wrong, and "+
			"a total of the whole capture would make the progress fraction meaningless", task.Total)
	}
	if task.Done != task.Total {
		t.Errorf("done/total = %d/%d; a finished selection audit that did not advance through every "+
			"selected exchange is a run that stopped looking", task.Done, task.Total)
	}
	if task.Target == "" {
		t.Error("the task row has no target; a row naming no run is a row an operator cannot act on")
	}
}

// An empty selection is refused, and refused *by name*, before anything is registered. Accepting it
// would put a task on the dashboard that read as a scan and meant "the click did nothing".
func TestASelectionAuditRefusesAnEmptySelection(t *testing.T) {
	s := newTestServer()

	code, body := auditSelection(t, s, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%v)", code, body)
	}
	message, _ := body["raw"].(string)
	for _, want := range []string{"at least one exchange id", "/api/audit/{id}"} {
		if !strings.Contains(message, want) {
			t.Errorf("refusal %q does not mention %q; the operator needs to know what to do next, and "+
				"the single-exchange door is the thing they are looking for", message, want)
		}
	}
	if _, ok := auditTaskFor(t, s); ok {
		t.Error("a refused selection registered an audit task; it must not appear as work at all")
	}
}

// Deduplication is honest: the work is smaller than the list, and the reply says by how much rather
// than quietly auditing less than the caller counted.
func TestASelectionAuditDropsDuplicatesAndSaysSo(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("h.test")
	recordCompleteExchange(t, s, "h.test", "/one")
	recordCompleteExchange(t, s, "h.test", "/two")

	code, body := auditSelection(t, s, []int{1, 0, 1})
	if code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (%v)", code, body)
	}
	if got := body["count"]; got != float64(2) {
		t.Errorf("count = %v, want 2", got)
	}
	if got := body["duplicates_dropped"]; got != float64(1) {
		t.Errorf("duplicates_dropped = %v, want 1 — a caller whose list was three long and whose scan "+
			"was two big cannot tell a dedupe from a dropped item unless this is reported", got)
	}
	// Order is the operator's order, not sorted: the first id named is the one they ticked first, and
	// the task row is built from it.
	if target, _ := body["target"].(string); target == "" || target[:1] != "2" {
		t.Errorf("target = %q, want it to lead with the count of selected items", target)
	}
	task := waitForAuditTask(t, s)
	if task.Total != 2 {
		t.Errorf("audit total = %d, want 2", task.Total)
	}
}

// A run that was cancelled says so. The dashboard row means two different things depending on this —
// "the scan looked at all of it" and "someone stopped it" — and only one of them is a result, so a
// cancelled run that reported itself done would be the honest-counting defect in miniature.
//
// Driven through the context rather than by racing a live scan against a cancel: the race is what makes
// a cancellation test flaky, and the claim here is about what the run reports, not about how quickly
// an operator can click.
func TestACancelledBulkAuditReportsItselfStoppedRatherThanDone(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("h.test")
	recordCompleteExchange(t, s, "h.test", "/one")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	task := s.tasks.Start(dash.KindAuditSession, "a cancelled selection", 1)
	s.runBulkAudit(ctx, task, "a cancelled selection", []core.ExchangeID{0}, s.activeScanner().AuditConfig(), "")

	row, ok := taskByID(t, s, task.ID())
	if !ok {
		t.Fatal("the task vanished from the registry")
	}
	if row.State != dash.TaskStopped {
		t.Errorf("state = %s, want %s — a cancelled audit reported as done tells an operator the whole "+
			"selection was looked at", row.State, dash.TaskStopped)
	}
	if !strings.Contains(row.Note, "stopped") {
		t.Errorf("note = %q, want it to say the run was stopped", row.Note)
	}
}

// taskByID reads one row out of the registry, so an assertion can be about the task it started rather
// than about whichever audit row happens to be first.
func taskByID(t *testing.T, s *Server, id uint64) (dash.Task, bool) {
	t.Helper()
	for _, task := range s.tasks.Snapshot() {
		if task.ID == id {
			return task, true
		}
	}
	return dash.Task{}, false
}

// The single-exchange door still works. /api/audit/selected is registered as a literal under the
// /api/audit/ subtree, and the whole point of doing it that way is that a numeric id still routes to
// the subtree handler — a literal pattern that shadowed the subtree would have replaced one feature
// with another.
func TestTheSingleExchangeAuditStillRoutes(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("h.test")
	recordCompleteExchange(t, s, "h.test", "/one")

	rec := postJSON(t, s, "/api/audit/0", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/audit/0: status = %d, want 200 (%s) — the selection door must not shadow "+
			"the per-exchange one", rec.Code, rec.Body.String())
	}
	var body struct {
		ExchangeID int `json:"exchange_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body.ExchangeID != 0 {
		t.Errorf("exchange_id = %d, want 0 — exchange ids are a dense counter from zero and 0 is a real "+
			"row, not a sentinel", body.ExchangeID)
	}
}

// A named configuration is honoured and echoed, and an unknown name is refused with the known ones.
// The first half is SCAN-03's whole risk (an endpoint accepting a name and running something else);
// the second is the same rule every other audit door follows.
func TestASelectionAuditHonoursANamedConfiguration(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("h.test")
	recordCompleteExchange(t, s, "h.test", "/one")

	rec := postJSON(t, s, "/api/audit/selected", map[string]any{
		"exchange_ids": []int{0},
		"config":       "Never stop audit due to application errors",
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		ConfigName string   `json:"config_name"`
		Unapplied  []string `json:"unapplied"`
	}
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body.ConfigName == "" {
		t.Error("config_name is empty in the reply; the caller cannot then tell a preset that was " +
			"applied from one that was ignored")
	}

	unknown := postJSON(t, s, "/api/audit/selected", map[string]any{
		"exchange_ids": []int{0},
		"config":       "no such preset",
	})
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown config: status = %d, want 400 (%s)", unknown.Code, unknown.Body.String())
	}
	if !strings.Contains(unknown.Body.String(), "Never stop audit due to application errors") {
		t.Errorf("the refusal for an unknown configuration does not name a known one: %s", unknown.Body.String())
	}
}

// An unknown pool is 404, matching the other two audit doors: the request is well formed and the world
// is not what the caller thought, and the fix is to reload rather than to retype.
func TestASelectionAuditRefusesAnUnknownPool(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("h.test")
	recordCompleteExchange(t, s, "h.test", "/one")

	rec := postJSON(t, s, "/api/audit/selected", map[string]any{
		"exchange_ids": []int{0},
		"pool":         "no such pool",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (%s)", rec.Code, rec.Body.String())
	}
	if _, ok := auditTaskFor(t, s); ok {
		t.Error("a refused pool registered an audit task; a launch that fails validation must not " +
			"appear on the dashboard as work")
	}
}
