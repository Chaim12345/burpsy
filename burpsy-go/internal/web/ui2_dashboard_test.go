package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/dash"
)

func ui2DashTaskOf(t *testing.T, s *Server, id uint64) dash.Task {
	t.Helper()
	for _, task := range s.Tasks().Snapshot() {
		if task.ID == id {
			return task
		}
	}
	t.Fatalf("task %d is not in the registry", id)
	return dash.Task{}
}

// The detail page renders every tab against real registry state, and the event-log filter narrows
// by severity and search on the server.
func TestUI2DashboardTaskPageTabs(t *testing.T) {
	s := newTestServer()
	h := s.Tasks().Start(dash.KindCrawl, "https://shop.test/", 10)
	h.Advance(4)
	id := h.ID()
	s.events.RecordFor(id, "probe.warned", dash.SeverityWarn, "warn-detail-marker")
	s.events.Record("probe.info", dash.SeverityInfo, "info-detail-marker")
	base := "/ui2/dashboard/task/" + strconv.FormatUint(id, 10)

	for tab, want := range map[string]string{
		"summary":  "Task configuration",
		"issues":   "This task recorded no issues",
		"events":   "warn-detail-marker",
		"activity": "No tool traffic",
	} {
		rec := getUI2(t, s, base+"?tab="+tab)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) || !strings.Contains(rec.Body.String(), "<!doctype html") {
			t.Errorf("tab %s = %d, missing %q", tab, rec.Code, want)
		}
	}
	body := getUI2(t, s, base+"?tab=events&severity=warn&search=marker").Body.String()
	if !strings.Contains(body, "warn-detail-marker") || strings.Contains(body, "info-detail-marker") {
		t.Errorf("severity filter did not narrow the event log")
	}
	body = getUI2(t, s, base+"?tab=events&source=task").Body.String()
	if strings.Contains(body, "info-detail-marker") {
		t.Errorf("source=task kept an event about no task")
	}
	if rec := getUI2(t, s, "/ui2/dashboard/task/x"); rec.Code != http.StatusBadRequest {
		t.Errorf("non-numeric task id = %d, want 400", rec.Code)
	}
	if body := getUI2(t, s, "/ui2/dashboard/task/999").Body.String(); !strings.Contains(body, "is not in the task list") {
		t.Errorf("an unknown task did not say so")
	}
}

// The dashboard lists tasks behind the text filter and carries the dock (issue count, event log).
func TestUI2DashboardTaskFilterAndDock(t *testing.T) {
	s := newTestServer()
	s.Tasks().Start(dash.KindCrawl, "https://alpha.test/", 0)
	s.Tasks().Start(dash.KindCrawl, "https://beta.test/", 0)
	s.events.Record("probe.dock", dash.SeverityInfo, "dock-event-marker")
	body := getUI2(t, s, "/ui2/dashboard?filter=beta").Body.String()
	list := body[strings.Index(body, `class="dash-tasks"`):]
	list = list[:strings.Index(list, "</table>")]
	if !strings.Contains(list, "beta.test") || strings.Contains(list, "alpha.test") {
		t.Errorf("task filter did not narrow the list")
	}
	if !strings.Contains(body, "All issues") || !strings.Contains(body, "dock-event-marker") {
		t.Errorf("dock is missing the issue count or the event log")
	}
}

// Pause, resume and cancel drive the registry through the riskLocal API routes, one click each.
func TestUI2DashboardTaskActions(t *testing.T) {
	s := newTestServer()
	h := s.Tasks().Start(dash.KindAudit, "https://shop.test/", 0)
	ctx, cancel := h.WithCancel(context.Background())
	defer cancel()
	h.Pausable(ctx)
	id := h.ID()
	path := "/ui2/dashboard/task/" + strconv.FormatUint(id, 10) + "/"
	back := url.Values{"back": {strconv.FormatUint(id, 10)}}

	if rec := postUI2Form(t, s, path+"pause", back); !strings.Contains(rec.Body.String(), "paused at its next step") || !ui2DashTaskOf(t, s, id).Paused {
		t.Fatalf("pause did not land: %d %s", rec.Code, rec.Body.String())
	}
	if postUI2Form(t, s, path+"resume", back); ui2DashTaskOf(t, s, id).Paused {
		t.Fatalf("resume did not land")
	}
	postUI2Form(t, s, path+"cancel", url.Values{})
	select {
	case <-ctx.Done():
	default:
		t.Fatalf("cancel did not reach the task's context")
	}
	h.Stop(dash.Breakdown{}, "cancelled")
	if rec := postUI2Form(t, s, path+"delete", url.Values{}); !strings.Contains(rec.Body.String(), "removed from the list") {
		t.Fatalf("delete did not land: %s", rec.Body.String())
	}

	postUI2Form(t, s, "/ui2/dashboard/tasks/pause", url.Values{})
	if !s.Tasks().Paused() {
		t.Fatalf("pause all did not set the suite-wide gate")
	}
	postUI2Form(t, s, "/ui2/dashboard/tasks/resume", url.Values{})
	if s.Tasks().Paused() {
		t.Fatalf("resume all did not clear the suite-wide gate")
	}
}

// Refusals: a task kind that never reaches a gate cannot be paused, a smuggled field is refused,
// and an unknown action is a 400 — none of them change the task.
func TestUI2DashboardTaskActionRefusals(t *testing.T) {
	s := newTestServer()
	h := s.Tasks().Start(dash.KindCrawl, "https://shop.test/", 0)
	path := "/ui2/dashboard/task/" + strconv.FormatUint(h.ID(), 10) + "/"
	if rec := postUI2Form(t, s, path+"pause", url.Values{}); !strings.Contains(rec.Body.String(), "refused") || ui2DashTaskOf(t, s, h.ID()).Paused {
		t.Errorf("pausing a non-pausable task was not refused: %s", rec.Body.String())
	}
	if rec := postUI2Form(t, s, path+"delete", url.Values{"evil": {"1"}}); !strings.Contains(rec.Body.String(), "Not applied") {
		t.Errorf("a smuggled field was not refused")
	}
	if rec := postUI2Form(t, s, path+"bogus", url.Values{}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown action = %d, want 400", rec.Code)
	}
	if !ui2DashTaskOf(t, s, h.ID()).Running() {
		t.Errorf("a refused action changed the task")
	}
}

// The live switch goes through the gate review: the sheet shows the full bound body, the run
// spends the token, and an edited field is refused by the token's digest.
func TestUI2DashboardLiveReview(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	form := url.Values{"mode": {"task"}, "query": {`host == "demo.local"`}, "config": {""}, "pool": {""}}
	sheet := postUI2Form(t, s, "/ui2/dashboard/live/confirm", form).Body.String()
	if !strings.Contains(sheet, "data-review") || !strings.Contains(sheet, "disabled data-arm-on-load") ||
		!strings.Contains(sheet, `{&#34;config&#34;:&#34;&#34;,&#34;enabled&#34;:true,&#34;pool&#34;:&#34;&#34;,&#34;query&#34;:&#34;host == \&#34;demo.local\&#34;&#34;}`) {
		t.Fatalf("review sheet does not show the bound body: %s", sheet)
	}
	if s.liveAudit.IsEnabled() {
		t.Fatalf("the confirm step changed the live sweep")
	}
	run := url.Values{"token": {extractHiddenInput(t, sheet, "token")}}
	for k, v := range form {
		run[k] = v
	}
	if body := postUI2Form(t, s, "/ui2/dashboard/live/run", run).Body.String(); !strings.Contains(body, "Live audit is ON") || !s.liveAudit.IsEnabled() {
		t.Fatalf("the reviewed run did not enable the live sweep: %s", body)
	}
}

func TestUI2DashboardLiveReviewRefusesAnEditedBody(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	sheet := postUI2Form(t, s, "/ui2/dashboard/live/confirm", url.Values{"mode": {"toggle"}, "enabled": {"off"}}).Body.String()
	run := url.Values{"token": {extractHiddenInput(t, sheet, "token")}, "mode": {"toggle"}, "enabled": {"on"}}
	if body := postUI2Form(t, s, "/ui2/dashboard/live/run", run).Body.String(); !strings.Contains(body, "Not applied") || s.liveAudit.IsEnabled() {
		t.Fatalf("an edited body ran under a token minted for another: %s", body)
	}
}

// Clear event log: reviewed DELETE clears the log; a forged token clears nothing.
func TestUI2DashboardClearEventLog(t *testing.T) {
	s := newTestServer()
	s.events.Record("probe.kept", dash.SeverityInfo, "kept")
	if body := postUI2Form(t, s, "/ui2/dashboard/events/run", url.Values{"token": {"forged"}}).Body.String(); !strings.Contains(body, "Not applied") || s.events.Count() == 0 {
		t.Fatalf("a forged token cleared the event log: %s", body)
	}
	sheet := postUI2Form(t, s, "/ui2/dashboard/events/confirm", url.Values{}).Body.String()
	if !strings.Contains(sheet, "DELETE /api/dashboard/events") {
		t.Fatalf("review sheet does not name the call: %s", sheet)
	}
	if s.events.Count() == 0 {
		t.Fatalf("the confirm step cleared the event log")
	}
	body := postUI2Form(t, s, "/ui2/dashboard/events/run", url.Values{"token": {extractHiddenInput(t, sheet, "token")}}).Body.String()
	if !strings.Contains(body, "Event log cleared") || s.events.Count() != 0 {
		t.Fatalf("the reviewed clear did not land: %s", body)
	}
}
