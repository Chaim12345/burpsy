package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

// ---- decoding helpers ---------------------------------------------------------------------------

// breakdownView is the wire shape of dash.Breakdown, decoded field by field rather than by reusing
// the Go type. The point of several of these tests is that the *wire* carries all four buckets, and
// decoding through the type that produces it would hide a missing key behind a Go zero value.
type breakdownView struct {
	Found       uint64 `json:"found"`
	Skipped     uint64 `json:"skipped"`
	Errored     uint64 `json:"errored"`
	Gated       uint64 `json:"gated"`
	Unaccounted uint64 `json:"unaccounted"`
	Complete    bool   `json:"complete"`
	Summary     string `json:"summary"`
}

type summaryView struct {
	Label     string        `json:"label"`
	Unit      string        `json:"unit"`
	WorkUnit  string        `json:"work_unit"`
	Breakdown breakdownView `json:"breakdown"`
	Reasons   []struct {
		Bucket string `json:"bucket"`
		Detail string `json:"detail"`
		Count  uint64 `json:"count"`
	} `json:"reasons"`
}

type taskView struct {
	ID            uint64        `json:"id"`
	Kind          string        `json:"kind"`
	Target        string        `json:"target"`
	State         string        `json:"state"`
	Done          uint64        `json:"done"`
	Total         uint64        `json:"total"`
	StartedMs     uint64        `json:"started_ms"`
	EndedMs       uint64        `json:"ended_ms"`
	Note          string        `json:"note"`
	Result        breakdownView `json:"result"`
	ElapsedMs     uint64        `json:"elapsed_ms"`
	Fraction      float64       `json:"fraction"`
	FractionKnown bool          `json:"fraction_known"`
	Progress      string        `json:"progress"`
	Complete      bool          `json:"complete"`
}

type dashboardView struct {
	Summaries       []summaryView  `json:"summaries"`
	Tasks           []taskView     `json:"tasks"`
	TasksRunning    int            `json:"tasks_running"`
	TasksDropped    uint64         `json:"tasks_dropped"`
	Activity        []toolLogEntry `json:"activity"`
	ActivityShown   int            `json:"activity_shown"`
	ActivityTotal   int            `json:"activity_total"`
	ActivityDropped uint64         `json:"activity_dropped"`
	Exchanges       int            `json:"exchanges"`
}

func dashboardGet(t *testing.T, s *Server) dashboardView {
	t.Helper()
	rec := get(t, s, "/api/dashboard")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/dashboard: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var v dashboardView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode dashboard response %q: %v", rec.Body.String(), err)
	}
	return v
}

// dashboardSummary picks one named summary out of the dashboard, failing if it is absent — a summary
// that quietly disappeared is a count that stopped being reported.
func dashboardSummary(t *testing.T, s *Server, label string) summaryView {
	t.Helper()
	for _, sum := range dashboardGet(t, s).Summaries {
		if sum.Label == label {
			return sum
		}
	}
	t.Fatalf("no summary labelled %q on the dashboard", label)
	return summaryView{}
}

// ---- DASH-01: running tasks and their progress --------------------------------------------------

// A task registered while it is still running appears on the dashboard with its progress, not only
// once it finishes.
func TestDashboardReportsRunningTasksAndTheirProgress(t *testing.T) {
	s := newTestServer()

	running := s.Tasks().Start(dash.KindCrawl, "https://shop.test/", 10)
	running.Advance(4)
	finished := s.Tasks().Start(dash.KindAudit, "GET shop.test/cart", 3)
	finished.Advance(3)
	finished.Finish(dash.Breakdown{Found: 2})

	v := dashboardGet(t, s)
	if v.TasksRunning != 1 {
		t.Errorf("tasks_running = %d, want 1", v.TasksRunning)
	}
	if len(v.Tasks) != 2 {
		t.Fatalf("tasks = %d, want 2", len(v.Tasks))
	}
	// Newest first: the audit was registered second.
	if v.Tasks[0].Kind != string(dash.KindAudit) {
		t.Errorf("first task kind = %q, want the most recently started (%q)", v.Tasks[0].Kind, dash.KindAudit)
	}

	var crawl taskView
	for _, task := range v.Tasks {
		if task.Kind == string(dash.KindCrawl) {
			crawl = task
		}
	}
	if crawl.State != "running" {
		t.Errorf("crawl state = %q, want running", crawl.State)
	}
	if crawl.Done != 4 || crawl.Total != 10 {
		t.Errorf("crawl progress = %d/%d, want 4/10", crawl.Done, crawl.Total)
	}
	if !crawl.FractionKnown || crawl.Fraction < 0.39 || crawl.Fraction > 0.41 {
		t.Errorf("crawl fraction = %v (known %v), want ~0.4", crawl.Fraction, crawl.FractionKnown)
	}
	if crawl.EndedMs != 0 {
		t.Errorf("crawl ended_ms = %d, want 0 while it is still running", crawl.EndedMs)
	}
	if crawl.Progress == "" {
		t.Error("crawl progress label is empty; the UI renders this string")
	}
}

// A crawl frontier grows as it is walked, so a task can start without knowing its total. That must
// read as an unknown fraction rather than as zero progress — a progress bar at 0% and a task whose
// end is not yet known are different facts.
func TestDashboardTaskWithNoKnownTotalReportsAnUnknownFraction(t *testing.T) {
	s := newTestServer()
	h := s.Tasks().Start(dash.KindCrawl, "https://shop.test/", 0)
	h.Advance(7)

	task := dashboardGet(t, s).Tasks[0]
	if task.FractionKnown {
		t.Errorf("fraction_known = true with total 0; want the unknown total reported as unknown")
	}
	if task.Done != 7 {
		t.Errorf("done = %d, want 7", task.Done)
	}
	if task.Progress == "" || task.Progress == "0/0 (0%)" {
		t.Errorf("progress = %q, want it to say the total is not yet known", task.Progress)
	}
}

// ---- DASH-02: an event log of what the tool did -------------------------------------------------

// The dashboard's activity log carries a timestamp per row and comes back newest-first. Both were
// broken: the wire shape had no started_ms at all (so the UI's relative time rendered "NaNs ago"),
// and the log came back in append order, so the newest rows were last.
func TestDashboardEventLogCarriesTimestampsNewestFirst(t *testing.T) {
	s := newTestServer()
	before := uint64(time.Now().UnixMilli())
	s.toolLog.Record(toollog.ToolRepeater, "first.test", 80, false, "GET", "/one", 200, toollog.Bytes(21), 5, "")
	s.toolLog.Record(toollog.ToolIntruder, "second.test", 443, true, "POST", "/two", 500, nil, 9, "boom")

	v := dashboardGet(t, s)
	if len(v.Activity) != 2 {
		t.Fatalf("activity = %d rows, want 2", len(v.Activity))
	}
	if v.Activity[0].Host != "second.test" {
		t.Errorf("first activity row host = %q, want the newest entry (second.test)", v.Activity[0].Host)
	}
	for _, e := range v.Activity {
		if e.StartedMs < before {
			t.Errorf("entry %d started_ms = %d, want a real timestamp at or after %d", e.ID, e.StartedMs, before)
		}
	}
	if v.ActivityShown != 2 || v.ActivityTotal != 2 {
		t.Errorf("activity_shown/total = %d/%d, want 2/2", v.ActivityShown, v.ActivityTotal)
	}
}

// The tool log's limit used to be accepted and ignored, so the dashboard's ?limit=20 rendered the
// whole log. A limit now returns the newest N and says how many matched.
func TestToolLogHonoursItsLimitAndReturnsTheNewestRows(t *testing.T) {
	s := newTestServer()
	for i := 0; i < 25; i++ {
		s.toolLog.Record(toollog.ToolRepeater, fmt.Sprintf("h%02d.test", i), 80, false, "GET", "/", 200, toollog.Bytes(7), 1, "")
	}

	rec := get(t, s, "/api/tools/log?limit=5")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tools/log?limit=5: status = %d", rec.Code)
	}
	var body struct {
		Total   int            `json:"total"`
		Shown   int            `json:"shown"`
		Counts  map[string]int `json:"counts"`
		Entries []toolLogEntry `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode tool log: %v", err)
	}
	if len(body.Entries) != 5 || body.Shown != 5 {
		t.Errorf("returned %d entries (shown %d), want 5 — limit was ignored", len(body.Entries), body.Shown)
	}
	if body.Total != 25 {
		t.Errorf("total = %d, want 25: the window must not be reported as the whole log", body.Total)
	}
	if body.Entries[0].Host != "h24.test" {
		t.Errorf("first entry host = %q, want the newest (h24.test)", body.Entries[0].Host)
	}
	// Counts are over every match, not over the five returned rows.
	if body.Counts["repeater"] != 25 {
		t.Errorf("counts[repeater] = %d, want 25 (the histogram is of the log, not of the window)", body.Counts["repeater"])
	}
}

// The tool log's filter reads the "filter" and "search" parameters. The Logger tab sent "tool" and
// "q", which nothing looked at, so both controls silently returned the unfiltered log.
func TestToolLogFilterAndSearchActuallyFilter(t *testing.T) {
	s := newTestServer()
	s.toolLog.Record(toollog.ToolRepeater, "alpha.test", 80, false, "GET", "/a", 200, toollog.Bytes(7), 1, "")
	s.toolLog.Record(toollog.ToolIntruder, "beta.test", 80, false, "GET", "/b", 200, toollog.Bytes(9), 1, "")

	for _, tc := range []struct {
		query string
		want  int
	}{
		{"filter=intruder", 1},
		{"search=alpha", 1},
		{"filter=intruder&search=alpha", 0},
		{"", 2},
	} {
		rec := get(t, s, "/api/tools/log?"+tc.query)
		var body struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode tool log for %q: %v", tc.query, err)
		}
		if body.Total != tc.want {
			t.Errorf("/api/tools/log?%s total = %d, want %d", tc.query, body.Total, tc.want)
		}
	}
}

// A crawler needs a tool-log identity to appear in the event log at all. Pinned here because the
// ordinal is what the durable mirror persists, so the variant's position is part of the wire format.
func TestToolLogNamesTheCrawler(t *testing.T) {
	s := newTestServer()
	s.toolLog.Record(toollog.ToolCrawler, "shop.test", 80, false, "GET", "/products", 200, toollog.Bytes(310), 12, "")

	v := dashboardGet(t, s)
	if len(v.Activity) != 1 || v.Activity[0].Tool != "crawler" {
		t.Fatalf("activity = %+v, want one row from the crawler", v.Activity)
	}
}

// ---- DASH-03: every summary count shows its disposition breakdown -------------------------------

// The requirement, at the wire: no count on the dashboard can be read without its breakdown. Walked
// generically over the decoded JSON rather than through the Go types, because the guarantee being
// tested is a property of the bytes the UI receives.
func TestDashboardEverySummaryCountCarriesItsBreakdown(t *testing.T) {
	s := newTestServer()
	s.findings.Add(core.NewFinding{Name: "something", Severity: core.ParseSeverity("high")})

	rec := get(t, s, "/api/dashboard")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/dashboard: status = %d", rec.Code)
	}
	var raw struct {
		Summaries []map[string]json.RawMessage `json:"summaries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	if len(raw.Summaries) == 0 {
		t.Fatal("no summaries on the dashboard")
	}
	for i, sum := range raw.Summaries {
		blob, ok := sum["breakdown"]
		if !ok {
			t.Errorf("summary %d has no breakdown; a count must never be reported alone", i)
			continue
		}
		var buckets map[string]json.RawMessage
		if err := json.Unmarshal(blob, &buckets); err != nil {
			t.Errorf("summary %d breakdown is not an object: %v", i, err)
			continue
		}
		// All four, unconditionally — including the ones that are zero. A caveat that vanishes from
		// the wire when it happens to be zero is a caveat the UI can accidentally stop rendering.
		for _, key := range []string{"found", "skipped", "errored", "gated", "unaccounted", "complete", "summary"} {
			if _, ok := buckets[key]; !ok {
				t.Errorf("summary %d breakdown is missing %q; got keys %v", i, key, bucketKeys(buckets))
			}
		}
	}
}

func bucketKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A count that is not complete must always say why. An unexplained caveat is a number an operator
// cannot act on, which is only marginally better than no caveat at all.
func TestDashboardIncompleteSummaryAlwaysNamesAReason(t *testing.T) {
	s := newTestServer()

	v := dashboardGet(t, s)
	sawIncomplete := false
	for _, sum := range v.Summaries {
		if sum.Breakdown.Complete {
			continue
		}
		sawIncomplete = true
		if len(sum.Reasons) == 0 {
			t.Errorf("summary %q is incomplete (%+v) with no reason given", sum.Label, sum.Breakdown)
		}
		var named uint64
		for _, r := range sum.Reasons {
			named += r.Count
		}
		if named == 0 {
			t.Errorf("summary %q names reasons that account for nothing", sum.Label)
		}
	}
	// A bare server has no check set loaded, so at least one summary must be reporting a gate. If
	// none is, the dashboard is claiming a complete picture of a process that is scanning nothing.
	if !sawIncomplete {
		t.Error("every summary on a server with no check set reports a complete count; a process that is not scanning cannot have a complete finding list")
	}
}

// The issues count is the one DASH-03 was written about. On a process with no passive check set it
// must not read as complete, whatever the finding total happens to be.
func TestDashboardIssuesCountIsAFloorWhenNothingIsScanning(t *testing.T) {
	s := newTestServer()
	s.findings.Add(core.NewFinding{Name: "one", Severity: core.ParseSeverity("high")})
	s.findings.Add(core.NewFinding{Name: "two", Severity: core.ParseSeverity("low")})

	sum := dashboardSummary(t, s, "Issues")
	if sum.Breakdown.Found != 2 {
		t.Errorf("found = %d, want 2", sum.Breakdown.Found)
	}
	if sum.Breakdown.Complete {
		t.Error(`"2 issues" reports as complete with no check set loaded; that is exactly the "that's all there is" reading DASH-03 forbids`)
	}
	if sum.Breakdown.Gated == 0 {
		t.Errorf("gated = 0 with no check set loaded, want the missing check set counted as a gate (%+v)", sum.Breakdown)
	}
	if len(sum.Reasons) == 0 {
		t.Error("no reason given for the gated issues count")
	}
}

// A task's result carries the same four buckets, so a finished run cannot report a count on the
// dashboard without reporting what it did not look at.
func TestDashboardTaskResultCarriesItsBreakdown(t *testing.T) {
	s := newTestServer()
	h := s.Tasks().Start(dash.KindAuditSession, "shop.test (200 exchange(s))", 200)
	h.Advance(200)
	h.FinishWithNote(dash.Breakdown{Found: 3, Gated: 600}, "the time budget was spent")

	task := dashboardGet(t, s).Tasks[0]
	if task.Result.Found != 3 || task.Result.Gated != 600 {
		t.Errorf("result = %+v, want found 3 gated 600", task.Result)
	}
	if task.Complete {
		t.Error("a task that finished with 600 gated checks reports complete; a bound is not a clean result")
	}
	if task.Result.Summary == "" {
		t.Error("result summary is empty; the UI renders this line beside the count")
	}
	if task.Note == "" {
		t.Error("note is empty; a bounded run must say what stopped it")
	}
}

// GET is the only method. Pinned so a stray POST does not silently succeed and appear to have
// changed something.
func TestDashboardRejectsNonGet(t *testing.T) {
	s := newTestServer()
	if rec := postJSON(t, s, "/api/dashboard", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/dashboard: status = %d, want 405", rec.Code)
	}
}

// ---- DASH-02, half two: the event log -----------------------------------------------------------

type eventView struct {
	ID       uint64 `json:"id"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	TaskID   uint64 `json:"task_id"`
	AtMs     uint64 `json:"at_ms"`
}

func dashboardEvents(t *testing.T, s *Server) []eventView {
	t.Helper()
	rec := get(t, s, "/api/dashboard")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/dashboard: status = %d", rec.Code)
	}
	var body struct {
		Events        []eventView `json:"events"`
		EventsShown   int         `json:"events_shown"`
		EventsTotal   int         `json:"events_total"`
		EventsDropped uint64      `json:"events_dropped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode dashboard events: %v", err)
	}
	if body.EventsShown != len(body.Events) {
		t.Errorf("events_shown = %d but %d events returned", body.EventsShown, len(body.Events))
	}
	return body.Events
}

// The dashboard carries the event log as its own list, newest first, with a real timestamp and a
// severity name per row.
func TestDashboardCarriesTheEventLogSeparatelyFromTheRequestLog(t *testing.T) {
	s := newTestServer()
	before := uint64(time.Now().UnixMilli())
	s.toolLog.Record(toollog.ToolRepeater, "sent.test", 80, false, "GET", "/a-request", 200, toollog.Bytes(15), 3, "")
	s.events.Record(dash.EventScopeChanged, dash.SeverityInfo, "an event, not a request")

	v := dashboardGet(t, s)
	if len(v.Activity) != 1 {
		t.Errorf("activity = %d rows, want the one sent request", len(v.Activity))
	}
	events := dashboardEvents(t, s)
	if len(events) != 1 {
		t.Fatalf("events = %d rows, want the one event", len(events))
	}
	// The two lists are disjoint: the request did not become an event and the event did not become a
	// request row with an invented method and path.
	if events[0].Detail != "an event, not a request" {
		t.Errorf("event detail = %q", events[0].Detail)
	}
	if events[0].Severity != "info" {
		t.Errorf("severity = %q, want the name not an ordinal", events[0].Severity)
	}
	if events[0].AtMs < before {
		t.Errorf("at_ms = %d, want a real timestamp at or after %d", events[0].AtMs, before)
	}
}

// A task registered anywhere in the process produces started and finished events on the dashboard,
// which is what makes DASH-02 cover a crawl without the crawler knowing the event log exists.
func TestDashboardTaskLifecycleAppearsInTheEventLog(t *testing.T) {
	s := newTestServer()
	h := s.Tasks().Start(dash.KindCrawl, "https://shop.test/", 4)
	h.Advance(4)
	h.Finish(dash.Breakdown{Found: 4})

	kinds := map[string]eventView{}
	for _, e := range dashboardEvents(t, s) {
		kinds[e.Kind] = e
	}
	for _, want := range []string{dash.EventTaskStarted, dash.EventTaskFinished} {
		e, ok := kinds[want]
		if !ok {
			t.Errorf("no %q event on the dashboard; kinds were %v", want, kinds)
			continue
		}
		if e.TaskID != h.ID() {
			t.Errorf("%q event carries task id %d, want %d", want, e.TaskID, h.ID())
		}
	}
}

// The live sweep used to record its own completion into the *request* log, as
// Record(ToolScanner, host, port, tls, "LIVE", "/audit", ...) — a request row for something that is not
// a request. Pinned gone: an event that is not a request must not appear in the request log.
func TestSweepCompletionIsNotFakedAsARequestRow(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	for i := 0; i < 3; i++ {
		completeExchange(t, s, "shop.test", "/p")
	}
	// A scanner with no sender: it audits without reaching a network, which is enough to finish a sweep.
	s.WithScanner(scanner.NewActiveScanner(s.store, zap.NewNop()).WithScope(s.scope))

	run := liveAuditRun{}
	s.liveAuditTick(context.Background(), &run)
	if s.liveAudit.Swept() == 0 {
		t.Fatal("the sweep audited nothing, so there is no completion to check")
	}

	for _, e := range s.toolLog.All() {
		if e.Method == "LIVE" || e.Path == "/audit" {
			t.Errorf("the request log still carries a faked sweep row: %s %s", e.Method, e.Path)
		}
	}
	found := false
	for _, e := range s.events.Recent(0) {
		if e.Kind == dash.EventLiveAuditBounded {
			found = true
			if e.Detail == "" {
				t.Error("the sweep's completion event carries no detail")
			}
		}
	}
	if !found {
		t.Error("the sweep completed without recording an event; DASH-02 lost the row that used to be faked")
	}
}

// Switching the live audit on and off through the operator's own surface is an event, because "what did
// the tool do" includes "the operator turned the thing that sends traffic on".
func TestLiveAuditToggleIsRecordedAsAnEvent(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())

	if rec := postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("enable: status = %d", rec.Code)
	}
	if rec := postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("disable: status = %d", rec.Code)
	}
	// Twice with the same value is one state change, so it is one event: a UI polling its own toggle
	// must not fill the log.
	if rec := postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("disable again: status = %d", rec.Code)
	}

	on, off := 0, 0
	for _, e := range dashboardEvents(t, s) {
		switch e.Kind {
		case dash.EventLiveAuditEnabled:
			on++
		case dash.EventLiveAuditDisabled:
			off++
		}
	}
	if on != 1 || off != 1 {
		t.Errorf("enabled/disabled events = %d/%d, want 1/1 for two real state changes and one no-op", on, off)
	}
}

// ---- DASH-03 with core.Exchange.Source ---------------------------------------------------------

// The count Source was added for: which surface the captured traffic came from. An exchange whose
// producer said nothing is reported as unattributed, never folded into proxy — which is the whole point
// of Source's zero value not being SourceProxy.
func TestDashboardCaptureSummaryDoesNotAssumeUnattributedIsProxy(t *testing.T) {
	s := newTestServer()
	proxied := completeExchange(t, s, "shop.test", "/proxied")
	proxied.Source = core.SourceProxy
	crawled := completeExchange(t, s, "shop.test", "/crawled")
	crawled.Source = core.SourceCrawl
	completeExchange(t, s, "shop.test", "/who-knows") // deliberately unset

	sum := dashboardSummary(t, s, "Captured traffic")
	if sum.Breakdown.Found != 2 {
		t.Errorf("found = %d, want the 2 attributed exchanges", sum.Breakdown.Found)
	}
	if sum.Breakdown.Skipped != 1 {
		t.Errorf("skipped = %d, want the 1 unattributed exchange (%+v)", sum.Breakdown.Skipped, sum.Breakdown)
	}
	if sum.Breakdown.Complete {
		t.Error("a capture with an unattributed exchange reports a complete attribution")
	}
	named := false
	for _, r := range sum.Reasons {
		if strings.Contains(r.Detail, "NOT assumed to be proxy") {
			named = true
		}
	}
	if !named {
		t.Errorf("no reason says unattributed traffic is not assumed to be proxy; reasons = %+v", sum.Reasons)
	}

	// The per-source histogram keys every known source even at zero, so a pane cannot lose one by it
	// not having appeared yet.
	rec := get(t, s, "/api/dashboard")
	var body struct {
		Sources map[string]int `json:"sources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode sources: %v", err)
	}
	for _, want := range []string{"unattributed", "proxy", "crawl", "repeater", "intruder", "scanner"} {
		if _, ok := body.Sources[want]; !ok {
			t.Errorf("sources has no key %q; got %v", want, body.Sources)
		}
	}
	if body.Sources["proxy"] != 1 || body.Sources["crawl"] != 1 || body.Sources["unattributed"] != 1 {
		t.Errorf("sources = %v, want one each of proxy, crawl and unattributed", body.Sources)
	}
}
