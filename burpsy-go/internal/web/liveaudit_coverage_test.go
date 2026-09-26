package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
)

// ---- the sweep cursor: it must not be possible to wedge it permanently -------------------------
//
// The sweep walks exchange ids in order and stops at one whose response has not landed. That wait is
// correct — ids are handed out when a request is captured and a later id can complete first, so
// auditing past a gap would skip the request still in flight — but "wait" and "wait forever" are
// different behaviours and only the first was implemented.
//
// No producer used to mint a nil-Response exchange, so nothing exercised it. scanner/capture.go does
// (a transport failure stores the request and no response), and the crawler is its first caller. One
// failed request would have parked the cursor at that id for the life of the process while
// LiveAuditState.Swept() went on reporting the number it had reached: CRAWL-06 silently dead, with the
// dashboard reporting a steady state.

// stalledExchange records a request with no response — the shape a transport failure produces.
func stalledExchange(t *testing.T, s *Server, host, path string) *core.Exchange {
	t.Helper()
	reqID, err := s.store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Host: host, Port: 80, Method: "GET", Path: path}
	s.store.AddExchange(ex)
	return ex
}

// proxiedCompleteExchange is completeExchange attributed the way the capture seam
// attributes proxy traffic (zk35): the live sweep's source gate refuses unattributed
// captures under the default, so a test that means "the operator's own capture" says so.
func proxiedCompleteExchange(t *testing.T, s *Server, host, path string) *core.Exchange {
	t.Helper()
	ex := completeExchange(t, s, host, path)
	ex.Source = core.SourceProxy
	return ex
}

// completeExchange records a request and a response, the ordinary case.
func completeExchange(t *testing.T, s *Server, host, path string) *core.Exchange {
	t.Helper()
	reqID, err := s.store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hi</html>"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	status := uint16(200)
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: 80, Method: "GET", Path: path, Status: &status}
	s.store.AddExchange(ex)
	return ex
}

// An exchange whose response never lands must not end coverage. The cursor waits a bounded number of
// ticks, then steps over it and counts it — never as swept, and never silently.
func TestLiveAuditCursorCannotBeWedgedByAResponseThatNeverLands(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	// No scanner wired: this test is about the cursor, and nothing here should reach a network.
	stalledExchange(t, s, "stuck.test", "/never-answered")
	completeExchange(t, s, "after.test", "/reachable")

	run := liveAuditRun{}
	ctx := context.Background()

	// liveAuditStallTicks ticks of waiting, and the last of them is the one that gives up — the counter
	// reaches the threshold inside that tick. So every tick before it must still be waiting.
	for i := 0; i < liveAuditStallTicks-1; i++ {
		s.liveAuditTick(ctx, &run)
		if run.cursor.at != 0 {
			t.Fatalf("tick %d moved the cursor to %d; it must wait at the stalled exchange", i, run.cursor.at)
		}
		if id, waiting := s.liveAudit.StalledAt(); !waiting || id != 0 {
			t.Fatalf("tick %d: stalled at (%d, %v), want waiting on exchange 0", i, id, waiting)
		}
		if s.liveAudit.Skipped() != 0 {
			t.Fatalf("tick %d gave up early: skipped = %d", i, s.liveAudit.Skipped())
		}
	}

	// The tick that reaches the threshold steps over it.
	s.liveAuditTick(ctx, &run)
	if s.liveAudit.Skipped() != 1 {
		t.Errorf("skipped = %d after %d stalled ticks, want 1", s.liveAudit.Skipped(), liveAuditStallTicks)
	}
	if run.cursor.at == 0 {
		t.Fatal("the cursor is still parked on the stalled exchange; live audit coverage is permanently lost")
	}

	// And the exchange behind it is reachable again, which is the whole point.
	s.liveAuditTick(ctx, &run)
	if run.cursor.at < 2 {
		t.Errorf("cursor at %d, want it past both exchanges so the one behind the stall was reached", run.cursor.at)
	}
	if s.liveAudit.Swept() != 0 {
		// No scanner is wired, so nothing was handed off — but the cursor still had to get here.
		t.Logf("swept = %d (no scanner wired, so this is expected to be 0)", s.liveAudit.Swept())
	}
	if s.liveAudit.Skipped() != 1 {
		t.Errorf("skipped = %d, want exactly 1: only the stalled exchange was given up on", s.liveAudit.Skipped())
	}
}

// Giving up must be visible in the event log, not only in a counter. An operator who was not watching
// the number when it moved still needs to be able to find out that coverage was lost.
func TestLiveAuditRecordsAnEventWhenItGivesUpOnAnExchange(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	stalledExchange(t, s, "stuck.test", "/never-answered")

	run := liveAuditRun{}
	for i := 0; i <= liveAuditStallTicks; i++ {
		s.liveAuditTick(context.Background(), &run)
	}

	var gaveUp, stalled *dash.Event
	for _, e := range s.events.Recent(0) {
		switch e.Kind {
		case dash.EventLiveAuditSkipped:
			gaveUp = &e
		case dash.EventLiveAuditStalled:
			stalled = &e
		}
	}
	if gaveUp == nil {
		t.Fatal("no event recorded when the sweep gave up on an exchange")
	}
	if gaveUp.Severity != dash.SeverityWarn {
		t.Errorf("giving up recorded at severity %v, want warn", gaveUp.Severity)
	}
	if !strings.Contains(gaveUp.Detail, "unaudited") {
		t.Errorf("detail %q does not say the exchange went unaudited", gaveUp.Detail)
	}
	if stalled == nil {
		t.Error("no event recorded when the wait began")
	}
	// Once, on the tick the wait began — not once per tick, or a normal stall would flood the log.
	stalls := 0
	for _, e := range s.events.Recent(0) {
		if e.Kind == dash.EventLiveAuditStalled {
			stalls++
		}
	}
	if stalls != 1 {
		t.Errorf("stall events = %d, want exactly 1 for one continuous wait", stalls)
	}
}

// ---- the backlog: a sweep behind a crawl must say so -------------------------------------------

// The sweep's admission is not a constant: it scales to the backlog it faces, bounded by
// liveAuditCatchUpBatchMax (burpsy-react-ui-iosv). Swept alone would still be a number with nothing
// saying how much was left, so the backlog is reported beside it — and a backlog larger than one
// catch-up burst is the case that proves those are two different numbers rather than one.
func TestLiveAuditReportsItsBacklogNotJustWhatItSwept(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	// Past the cap, so one tick cannot clear it however it scales.
	recorded := liveAuditCatchUpBatchMax + 25
	for i := 0; i < recorded; i++ {
		proxiedCompleteExchange(t, s, "shop.test", "/p")
	}

	run := liveAuditRun{}
	s.liveAuditTick(context.Background(), &run)

	if got := s.liveAudit.BatchLimit(); got != liveAuditCatchUpBatchMax {
		t.Errorf("batch limit = %d, want the catch-up cap %d — a backlog past the cap admits the cap, not the backlog",
			got, liveAuditCatchUpBatchMax)
	}
	if behind := s.liveAudit.Behind(); behind != 25 {
		t.Errorf("behind = %d, want 25 (%d recorded, %d admitted in one tick)",
			behind, recorded, liveAuditCatchUpBatchMax)
	}
	// And it reaches zero once the sweep catches up, so "caught up" is a state the pane can show.
	s.liveAuditTick(context.Background(), &run)
	if behind := s.liveAudit.Behind(); behind != 0 {
		t.Errorf("behind = %d after catching up, want 0", behind)
	}
}

// A backlog the sweep is allowed to take in one tick must actually be taken, not merely counted. This
// is the difference between the pane reporting a backlog and the sweep working it off: a batch that
// stayed at the baseline would leave 25 of these behind, which is what this file used to assert.
func TestLiveAuditClearsABacklogOneBurstCanHold(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	recorded := liveAuditBatchSize + 25
	for i := 0; i < recorded; i++ {
		proxiedCompleteExchange(t, s, "shop.test", "/p")
	}

	run := liveAuditRun{}
	s.liveAuditTick(context.Background(), &run)

	if got := s.liveAudit.BatchLimit(); got != uint64(recorded) {
		t.Errorf("batch limit = %d, want %d — the batch must scale to the backlog it faces", got, recorded)
	}
	if behind := s.liveAudit.Behind(); behind != 0 {
		t.Errorf("behind = %d after one tick facing %d, want 0 — the backlog was counted but not worked off",
			behind, recorded)
	}
}

// The batch bound is a function of the backlog and nothing else, so it is pinned here rather than
// inferred from a tick. Below the baseline it is the baseline, between the two it is the backlog
// itself, and past the cap it is the cap — a backlog cannot be admitted in one tick however large it
// grows, because the engine bounds the run the batch becomes.
func TestLiveAuditTickBatchScalesWithTheBacklogAndStopsAtTheCap(t *testing.T) {
	for _, tc := range []struct {
		behind uint64
		want   int
	}{
		{0, liveAuditBatchSize},
		{1, liveAuditBatchSize},
		{liveAuditBatchSize, liveAuditBatchSize},
		{liveAuditBatchSize + 1, liveAuditBatchSize + 1},
		{liveAuditCatchUpBatchMax - 1, liveAuditCatchUpBatchMax - 1},
		{liveAuditCatchUpBatchMax, liveAuditCatchUpBatchMax},
		{liveAuditCatchUpBatchMax + 1, liveAuditCatchUpBatchMax},
		{1 << 40, liveAuditCatchUpBatchMax},
	} {
		if got := liveAuditTickBatch(tc.behind); got != tc.want {
			t.Errorf("liveAuditTickBatch(%d) = %d, want %d", tc.behind, got, tc.want)
		}
	}
}

// Behind() says how much is left; BehindFor() says how long it has been left, which is the part that
// separates a sweep keeping up with a busy moment from one that has stopped keeping up with anything.
// Zero is the third state — caught up — and it is a duration of zero rather than an absent answer.
func TestLiveAuditBacklogAgeSeparatesBehindFromIdle(t *testing.T) {
	la := NewLiveAuditState()

	if got := la.BehindFor(); got != 0 {
		t.Errorf("behind-for = %s before any tick, want 0 — nothing has been recorded yet, so nothing is behind", got)
	}

	// Caught up: the cursor has reached everything recorded.
	la.recordPosition(10, 10)
	if got := la.BehindFor(); got != 0 {
		t.Errorf("behind-for = %s while caught up, want 0", got)
	}

	// A backlog appears: the age starts, and stays anchored to that first tick rather than being
	// restarted by every tick that finds it still there.
	la.recordPosition(10, 40)
	first := la.BehindFor()
	if first <= 0 {
		t.Fatalf("behind-for = %s with 30 exchanges unreached, want a positive age", first)
	}
	time.Sleep(2 * time.Millisecond)
	la.recordPosition(11, 40)
	if second := la.BehindFor(); second < first {
		t.Errorf("behind-for went from %s to %s across a tick that left the backlog in place; "+
			"the age must date the backlog, not the last tick", first, second)
	}

	// Caught up again: the age clears, so "idle" is distinguishable from "behind by a little".
	la.recordPosition(40, 40)
	if got := la.BehindFor(); got != 0 {
		t.Errorf("behind-for = %s after catching up, want 0", got)
	}
}

// The pane reads the age and the bound off the wire, so both have to be on it — and neither may be
// omitempty: a zero age is "caught up" and must be distinguishable from a field that is missing.
func TestLiveAuditStatusCarriesTheBacklogAgeAndBatchLimit(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	s.liveAudit.Record(0, 0)
	s.liveAudit.recordPosition(10, 40)
	s.liveAudit.recordBatchLimit(liveAuditCatchUpBatchMax)
	// The wire carries the age in whole milliseconds, so assert after it has had one to accumulate:
	// an age read in the same millisecond it was stamped truncates to 0, which is a rounding artefact
	// of the wire unit and not the answer the getter holds.
	time.Sleep(5 * time.Millisecond)

	v := liveAuditGet(t, s)
	if v.BehindForMs <= 0 {
		t.Errorf("behind_for_ms = %d with a backlog in place, want a positive age", v.BehindForMs)
	}
	if v.BatchLimit != liveAuditCatchUpBatchMax {
		t.Errorf("batch_limit = %d, want %d", v.BatchLimit, liveAuditCatchUpBatchMax)
	}
}

// The backlog must be current even on a tick that did no work — a sweep parked behind a stalled
// exchange while a crawl races ahead is exactly when the operator needs the number.
func TestLiveAuditBacklogIsCurrentEvenWhileStalled(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	stalledExchange(t, s, "stuck.test", "/never-answered")
	for i := 0; i < 5; i++ {
		completeExchange(t, s, "shop.test", "/behind-the-stall")
	}

	run := liveAuditRun{}
	s.liveAuditTick(context.Background(), &run)
	if behind := s.liveAudit.Behind(); behind != 6 {
		t.Errorf("behind = %d while stalled at exchange 0, want 6 (all of them are unreached)", behind)
	}
}

// The dashboard's Live audit summary must carry the backlog as a caveat, so the finding count reads as
// a floor while the sweep is behind.
func TestDashboardLiveAuditSummaryCarriesTheBacklog(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	s.liveAudit.SetEnabled(true)
	// Past the catch-up cap, so the sweep is still behind after one tick and the summary has a
	// backlog to carry.
	for i := 0; i < liveAuditCatchUpBatchMax+7; i++ {
		proxiedCompleteExchange(t, s, "shop.test", "/p")
	}
	run := liveAuditRun{}
	s.liveAuditTick(context.Background(), &run)

	sum := dashboardSummary(t, s, "Live audit")
	if sum.Breakdown.Complete {
		t.Error("a sweep 7 exchanges behind reports a complete count")
	}
	if sum.Breakdown.Skipped < 7 {
		t.Errorf("skipped = %d, want at least the 7-exchange backlog (%+v)", sum.Breakdown.Skipped, sum.Breakdown)
	}
	named := false
	for _, r := range sum.Reasons {
		if strings.Contains(r.Detail, "not reached yet") {
			named = true
		}
	}
	if !named {
		t.Errorf("no reason names the backlog; reasons = %+v", sum.Reasons)
	}
}

// ---- DSL-03: live-audit scoping ----------------------------------------------------------------
//
// DSL-03's wording is "crawler/live-audit scoping" and the sweep filtered on scope alone. Live audit
// runs *after* the response is stored, so unlike the crawler's pre-fetch gate it takes the full
// grammar: status, mime and body are real answers here, not unobtainable ones.

func TestLiveAuditQueryFiltersWhichExchangesAreAdmitted(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	html := proxiedCompleteExchange(t, s, "shop.test", "/page")
	other := stalledExchange(t, s, "shop.test", "/no-response")

	// Every field the grammar has, including the three the crawler's gate must refuse.
	for _, tc := range []struct {
		query string
		admit bool
	}{
		{`host = "shop.test"`, true},
		{`host = "other.test"`, false},
		{`method = "GET"`, true},
		{`status = 200`, true},
		{`status = 404`, false},
		{`mime = "text/html"`, true},
		{`mime = "application/json"`, false},
		{`body ~ "hi"`, true},
		{`body ~ "absent-marker"`, false},
		{`host = "shop.test" and status = 200`, true},
		{`host = "shop.test" and status = 500`, false},
		{`not status = 200`, false},
	} {
		if err := s.liveAudit.SetQuery(tc.query); err != nil {
			t.Fatalf("SetQuery(%q): %v", tc.query, err)
		}
		if got := s.liveAuditAdmits(html); got != tc.admit {
			t.Errorf("query %q admitted the text/html 200 exchange = %v, want %v", tc.query, got, tc.admit)
		}
	}

	// An exchange with no response is refused whatever the query says, and the negated case is why that
	// refusal has to happen before the query rather than being left to one caller's walk order.
	//
	// The query package's absent-field rule makes `mime = "text/html"` correctly false for a response
	// that does not exist — and therefore makes `not mime = "text/html"` *true*, which would admit
	// precisely the exchanges that cannot be audited at all. internal/query/fields.go documents this as
	// the reason the crawler's pre-fetch gate refuses those fields outright; live audit can accept them
	// only because it never evaluates them against a missing response.
	for _, q := range []string{`mime = "text/html"`, `not mime = "text/html"`, `body ~ "hi"`, `not body ~ "hi"`} {
		if err := s.liveAudit.SetQuery(q); err != nil {
			t.Fatalf("SetQuery(%q): %v", q, err)
		}
		if s.liveAuditAdmits(other) {
			t.Errorf("query %q admitted an exchange with no response; it cannot be audited at all", q)
		}
	}
	// Pinned separately so the reason above is not mistaken for a claim about the query package: the
	// negation really does evaluate to true, and it is liveAuditAdmits that refuses.
	expr, _ := s.liveAudit.Query()
	if !expr.Match(&auditedExchangeQuery{store: s.store, ex: other}) {
		t.Error("`not body ~ \"hi\"` did not match a response-less exchange; if the query package ever starts refusing these, liveAuditAdmits' response check can be reconsidered")
	}
}

// Scope wins over the query: a filter narrows what the operator wants audited and can never widen it
// past the engagement.
func TestLiveAuditQueryCannotWidenPastTheEngagementScope(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	ex := completeExchange(t, s, "out.test", "/page")
	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "include", "pattern": "only.test"}); rec.Code != http.StatusOK {
		t.Fatalf("include: status = %d", rec.Code)
	}

	if err := s.liveAudit.SetQuery(`host = "out.test"`); err != nil {
		t.Fatalf("SetQuery: %v", err)
	}
	if s.liveAuditAdmits(ex) {
		t.Error("a query naming an out-of-scope host admitted it; the query must never widen the engagement")
	}
}

// An unparseable query is refused and nothing changes. A filter the operator believed they set,
// followed by a sweep running against the whole scope because the parse failed quietly, is the one
// outcome this must never produce.
func TestLiveAuditRejectsABadQueryAndKeepsThePreviousOne(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	if rec := postJSON(t, s, "/api/scanner/live", map[string]interface{}{"enabled": true, "query": `host = "shop.test"`}); rec.Code != http.StatusOK {
		t.Fatalf("install good query: status = %d (%s)", rec.Code, rec.Body.String())
	}

	rec := postJSON(t, s, "/api/scanner/live", map[string]interface{}{"enabled": true, "query": `hostt ~~ (`})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad query: status = %d, want 400", rec.Code)
	}
	if _, src := s.liveAudit.Query(); src != `host = "shop.test"` {
		t.Errorf("installed query = %q, want the previous one kept after a parse failure", src)
	}

	// An explicit empty string is the way to clear it; an absent field leaves it alone.
	if rec := postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("toggle without a query: status = %d", rec.Code)
	}
	if _, src := s.liveAudit.Query(); src != `host = "shop.test"` {
		t.Errorf("query = %q after a toggle that named none, want it untouched", src)
	}
	if rec := postJSON(t, s, "/api/scanner/live", map[string]interface{}{"enabled": false, "query": ""}); rec.Code != http.StatusOK {
		t.Fatalf("clear query: status = %d", rec.Code)
	}
	if expr, src := s.liveAudit.Query(); expr != nil || src != "" {
		t.Errorf("query = %q after an explicit clear, want none", src)
	}
}

// A filtered sweep's finding count is not a statement about the whole scope, so the filter is itself a
// gate on the summary.
func TestDashboardReportsALiveAuditQueryAsAGate(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	s.liveAudit.SetEnabled(true)
	if err := s.liveAudit.SetQuery(`mime = "text/html"`); err != nil {
		t.Fatalf("SetQuery: %v", err)
	}

	sum := dashboardSummary(t, s, "Live audit")
	if sum.Breakdown.Complete {
		t.Error("a filtered live audit reports a complete count")
	}
	named := false
	for _, r := range sum.Reasons {
		if strings.Contains(r.Detail, `mime = "text/html"`) {
			named = true
		}
	}
	if !named {
		t.Errorf("no reason quotes the query that is excluding traffic; reasons = %+v", sum.Reasons)
	}

	// And the view carries it, so the pane can show what it is filtered to.
	var v struct {
		Query string `json:"query"`
	}
	rec := get(t, s, "/api/scanner/live")
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode live audit view: %v", err)
	}
	if v.Query != `mime = "text/html"` {
		t.Errorf("view query = %q, want the installed filter", v.Query)
	}
}

// ---- the shared admission ledger ----------------------------------------------------------------

// The ledger must be the same object across ticks, or every host-scoped and path-scoped check
// re-dispatches every liveAuditSweepInterval for the life of the process.
func TestLiveAuditSweepKeepsOneLedgerAcrossTicks(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	run := liveAuditRun{}

	first := run.auditLedger(s.liveAudit, s.events, s.logger)
	if first == nil {
		t.Fatal("no ledger built")
	}
	if second := run.auditLedger(s.liveAudit, s.events, s.logger); second != first {
		t.Error("a second tick got a different ledger; scope collapse would reset every tick")
	}
	if s.liveAudit.LedgerResets() != 0 {
		t.Errorf("ledger resets = %d before the cap was reached, want 0", s.liveAudit.LedgerResets())
	}
}

// Past its unit cap the ledger is rebuilt rather than grown without limit — and the reset is counted
// and recorded, because the checks it had collapsed will each dispatch once more.
func TestLiveAuditLedgerResetAtItsUnitCapIsCountedAndRecorded(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	run := liveAuditRun{}
	ledger := run.auditLedger(s.liveAudit, s.events, s.logger)
	for i := 0; i <= liveAuditLedgerUnitCap; i++ {
		ledger.Admit("path:"+strconv.Itoa(i), 0)
	}

	rebuilt := run.auditLedger(s.liveAudit, s.events, s.logger)
	if rebuilt == ledger {
		t.Fatal("the ledger was not rebuilt past its unit cap; it would grow without bound")
	}
	if s.liveAudit.LedgerResets() != 1 {
		t.Errorf("ledger resets = %d, want 1", s.liveAudit.LedgerResets())
	}
	found := false
	for _, e := range s.events.Recent(0) {
		if e.Kind == dash.EventLedgerReset {
			found = true
			if e.Severity != dash.SeverityWarn {
				t.Errorf("ledger reset recorded at severity %v, want warn", e.Severity)
			}
			if !strings.Contains(e.Detail, "dispatch once more") {
				t.Errorf("detail %q does not say what the reset costs", e.Detail)
			}
		}
	}
	if !found {
		t.Error("no event recorded for a ledger reset; a silent cap is the failure this reports")
	}
}
