// GET /api/dashboard — the one place an operator sees what is running, what the tool has done, and
// what every count on screen does not account for.
//
// # The three requirements this serves, and why they are one endpoint
//
//   - DASH-01, running tasks and their progress: the task registry's snapshot.
//   - DASH-02, an event log of what the tool did: two lists — the existing tool log for requests
//     sent, and a separate event log for everything that is not a request. See below for why two.
//   - DASH-03, every summary count with its disposition breakdown: the summaries list, where each
//     entry is a dash.Summary and therefore cannot carry a number without carrying its four buckets.
//
// One endpoint because the three are one screen and one poll. The dashboard previously made four
// requests (/api/stats, /api/scope, /api/issues, /api/tools/log) and stitched together numbers that
// each arrived without their caveats; the stitching was where the caveats got lost.
//
// # Why DASH-02 is two lists and not one
//
// `activity` is internal/toollog: one row per request burpsy's own tools *sent*, with a host, a
// method, a path and a status. `events` is internal/dash's EventLog: one row per thing the tool
// *did* — a task started, the scope was edited, a crawl stopped at its bound, live audit was
// switched on, the admission ledger was reset. Those have no host, no path and no status, and the
// proof that they do not fit toollog's shape was already in the tree: the live sweep used to record
// its own completion as a request row with the invented method "LIVE" and the invented path
// "/audit". That row is gone.
//
// So: two logs, each honest about its unit, neither able to disagree with the other about the same
// fact, and joined on the surface rather than in a schema that fits one of them badly. It is the same
// argument Breakdown makes about never summing found and skipped.
//
// toollog also needed fixing before it could serve the request half at all: the UI rendered
// `relTime(e.started_ms)` against a wire shape that never carried started_ms, so every row read
// "NaNs ago", and the pane's `?limit=20` was ignored by a handler that returned the whole log
// oldest-first — the newest activity last, below however many thousand rows preceded it. Fixed in
// the log's own handler rather than worked around here.
package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// dashboardActivityLimit bounds how many log rows the dashboard carries.
//
// A named limit rather than a silent truncation: dashboardResp.ActivityShown and ActivityTotal are
// both reported, so a pane showing 50 of 4000 rows can say so.
const dashboardActivityLimit = 50

// dashboardResp is what GET /api/dashboard answers. Mirrors dashboard.ts's DashboardResp.
type dashboardResp struct {
	// Summaries is every count on the dashboard, each with its breakdown. A list rather than named
	// fields so a pane renders whatever it is given: a summary added here appears on screen without
	// a matching UI change, and — more to the point — cannot be added *without* a breakdown.
	Summaries []dash.Summary `json:"summaries"`
	// Tasks is the registry snapshot, newest first (DASH-01).
	Tasks []dash.Task `json:"tasks"`
	// TasksRunning and TasksDropped describe the task list as a window rather than as everything
	// that ever ran.
	TasksRunning int    `json:"tasks_running"`
	TasksDropped uint64 `json:"tasks_dropped"`
	// Activity is the tool log's newest rows: requests the tool sent (DASH-02, half one).
	Activity []toolLogEntry `json:"activity"`
	// ActivityShown, ActivityTotal and ActivityDropped make the window explicit.
	ActivityShown   int    `json:"activity_shown"`
	ActivityTotal   int    `json:"activity_total"`
	ActivityDropped uint64 `json:"activity_dropped"`
	// Events is the event log's newest rows: things the tool did (DASH-02, half two). A separate list
	// from Activity because they count different things — see the package docs.
	Events        []dash.Event `json:"events"`
	EventsShown   int          `json:"events_shown"`
	EventsTotal   int          `json:"events_total"`
	EventsDropped uint64       `json:"events_dropped"`
	// Counts is the raw capture state the header already showed, kept so the pane needs one poll.
	Exchanges   int   `json:"exchanges"`
	Messages    int   `json:"messages"`
	StoredBytes int64 `json:"stored_bytes"`
	// Sources is the per-source exchange histogram behind the Captured traffic summary. Every known
	// source is a key even at zero, including "unattributed", so a pane cannot lose a source by it
	// happening not to have appeared yet.
	Sources map[string]int `json:"sources"`
	// Paused is the suite-wide task gate (burpsy-react-ui-8gw): the dashboard's pause button
	// reads the state it toggles from the same poll as everything else, so a flip is visible on
	// the next refresh without a second endpoint.
	Paused bool `json:"paused"`
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	messages, exchanges := s.store.Count()
	entries := s.toolLog.All()
	activity := make([]toolLogEntry, 0, dashboardActivityLimit)
	for i := len(entries) - 1; i >= 0 && len(activity) < dashboardActivityLimit; i-- {
		activity = append(activity, toolLogEntryView(entries[i]))
	}

	events := s.events.Recent(dashboardActivityLimit)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboardResp{
		Summaries:       s.dashboardSummaries(),
		Tasks:           s.tasks.Snapshot(),
		TasksRunning:    s.tasks.Running(),
		TasksDropped:    s.tasks.Dropped(),
		Activity:        activity,
		ActivityShown:   len(activity),
		ActivityTotal:   len(entries),
		ActivityDropped: s.toolLog.Dropped(),
		Events:          events,
		EventsShown:     len(events),
		EventsTotal:     s.events.Count(),
		EventsDropped:   s.events.Dropped(),
		Exchanges:       exchanges,
		Messages:        messages,
		StoredBytes:     s.store.Bytes(),
		Sources:         s.sourceCounts(),
		Paused:          s.tasks.Paused(),
	})
}

// handleDashboardEvents serves DELETE /api/dashboard/events: the "Clear event log" action (Burp's
// burp.Zbuz). It clears the EventLog the dashboard reads — the source, not a client-side view — so
// the feed is genuinely empty afterwards and the next thing the tool does is its first row again.
//
// A separate route from /api/dashboard (which stays GET-only) rather than a DELETE verb on it: the
// dashboard aggregates tasks, activity, coverage and the event log, and a DELETE there would name
// the whole aggregate when only one list is being discarded. It is not filed under /api/events
// either — that prefix is the SSE change stream, a different resource — so this names the EventLog
// the dashboard reads and nothing else. DELETE only; anything else is a 405 the route manifest's
// verb test checks for.
func (s *Server) handleDashboardEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.events.Clear()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"cleared": true})
}

// dashboardSummaries builds every count the dashboard shows, each through dash.NewSummary so a
// caveat can never travel without a reason naming it.
//
// They are deliberately in different units, and each says so: an issue is not a check and a task is
// not a request. That is why dash.Breakdown has no total — see its package docs.
func (s *Server) dashboardSummaries() []dash.Summary {
	return []dash.Summary{
		s.issuesSummary(),
		s.passiveSummary(),
		s.liveAuditSummary(),
		s.captureSummary(),
		s.tasksSummary(),
	}
}

// issuesSummary is the count DASH-03 was written about: "12 issues" must not read as "that's all
// there is".
//
// Found is the issues in the store. The caveats come from the passive check set's runtime coverage,
// because that is the work that produces issues on the live proxy path — a check that never
// dispatched is an issue that was never going to be found. A process with no check set loaded is one
// gate covering everything, which is the honest reading of a findings list that cannot grow.
func (s *Server) issuesSummary() dash.Summary {
	found := uint64(s.findings.Count())
	if s.passiveScanner == nil || s.passiveScanner.Loaded() == 0 {
		return dash.NewSummary("Issues", "issues", "passive check sets",
			dash.Breakdown{Found: found, Gated: 1},
			dash.Reason{
				Bucket: dash.BucketGated,
				Detail: "no passive check set is loaded, so proxied traffic is not being scanned; start with --bchecks DIR",
				Count:  1,
			})
	}
	coverage := s.passiveScanner.Coverage()
	b := coverage.Breakdown()
	// The coverage report's own Found counts findings the *passive set* produced; the store's count
	// is every issue from every source (audits, the live sweep, native checks). The store is the
	// authority for what is on screen, so its number wins and the projection contributes caveats only.
	b.Found = found
	return dash.NewSummary("Issues", "issues", "passive scanning work", b, coverage.BreakdownReasons()...)
}

// passiveSummary is the check set's own coverage, in checks: how many of the loaded checks actually
// got to look at something.
func (s *Server) passiveSummary() dash.Summary {
	if s.passiveScanner == nil {
		return dash.NewSummary("Passive checks", "findings", "passive check sets",
			dash.Breakdown{Gated: 1},
			dash.Reason{
				Bucket: dash.BucketGated,
				Detail: "passive BCheck scanning is not enabled; start with --bchecks DIR",
				Count:  1,
			})
	}
	coverage := s.passiveScanner.Coverage()
	return dash.NewSummary("Passive checks", "findings", "passive scanning work",
		coverage.Breakdown(), coverage.BreakdownReasons()...)
}

// liveAuditSummary reports the live sweep. An audit that is switched off is gated, not clean: the
// whole point of CRAWL-06's opt-in is that nothing is audited until an operator asks, and a
// dashboard that showed "0 findings" without saying "because it is off" would turn that opt-in into
// a false negative.
//
// The backlog is the other half, and the reason this summary needed rewriting. The sweep admits
// liveAuditBatchSize exchanges per tick, which a crawl outpaces easily, so the honest report of a
// sweep mid-crawl is "3 findings, and 9,000 exchanges I have not looked at yet". Reporting the
// findings alone would make the pane whose job is to demonstrate DASH-03 the one violating it.
func (s *Server) liveAuditSummary() dash.Summary {
	if s.liveAudit == nil {
		return dash.NewSummary("Live audit", "findings", "exchanges",
			dash.Breakdown{Gated: 1},
			dash.Reason{
				Bucket: dash.BucketGated,
				Detail: "live active audit is not wired in this process; it needs a loaded check set",
				Count:  1,
			})
	}
	b := dash.Breakdown{Found: s.liveAudit.FindingCount()}
	var reasons []dash.Reason
	if !s.liveAudit.IsEnabled() {
		b.Gated++
		reasons = append(reasons, dash.Reason{
			Bucket: dash.BucketGated,
			Detail: "live active audit is off; no active check is sent at proxied traffic until the operator turns it on",
			Count:  1,
		})
	}
	if behind := s.liveAudit.Behind(); behind > 0 {
		b.Skipped += behind
		reasons = append(reasons, dash.Reason{
			Bucket: dash.BucketSkipped,
			Detail: fmt.Sprintf("captured exchanges the sweep has not reached yet; it admits %d every %s", liveAuditBatchSize, liveAuditSweepInterval),
			Count:  behind,
		})
	}
	if skipped := s.liveAudit.Skipped(); skipped > 0 {
		b.Gated += skipped
		reasons = append(reasons, dash.Reason{
			Bucket: dash.BucketGated,
			Detail: "exchanges the sweep advanced past unaudited because their response never landed",
			Count:  skipped,
		})
	}
	if _, waiting := s.liveAudit.StalledAt(); waiting {
		b.Skipped++
		reasons = append(reasons, dash.Reason{
			Bucket: dash.BucketSkipped,
			Detail: "the sweep is waiting on an exchange whose response has not landed; everything after it waits with it",
			Count:  1,
		})
	}
	if _, src := s.liveAudit.Query(); src != "" {
		// A filter is a gate the operator chose, and it is still a gate: an exchange the query excluded
		// was not audited, so a filtered sweep's finding count is not a statement about the whole scope.
		b.Gated++
		reasons = append(reasons, dash.Reason{
			Bucket: dash.BucketGated,
			Detail: "the live audit is filtered by the operator's query, so exchanges it excludes are never audited: " + src,
			Count:  1,
		})
	}
	return dash.NewSummary("Live audit", "findings", "exchanges", b, reasons...)
}

// captureSummary is what DASH-03 could not say before core.Exchange.Source existed: which surface the
// captured traffic came from.
//
// Found is attributed exchanges. Unattributed ones are Skipped rather than quietly counted as proxy —
// that is the whole point of Source's zero value being SourceUnattributed, and folding them into any
// named source here would undo it at the surface. A producer someone adds without setting Source shows
// up on the dashboard as an unattributed count, which is visible and fixable.
func (s *Server) captureSummary() dash.Summary {
	perSource := map[core.Source]uint64{}
	var attributed, unattributed uint64
	for _, ex := range s.store.Exchanges() {
		perSource[ex.Source]++
		if ex.Source.Attributed() {
			attributed++
		} else {
			unattributed++
		}
	}
	reasons := make([]dash.Reason, 0, len(perSource))
	if unattributed > 0 {
		reasons = append(reasons, dash.Reason{
			Bucket: dash.BucketSkipped,
			Detail: "exchanges whose producer did not say what surface they came from; they are NOT assumed to be proxy traffic",
			Count:  unattributed,
		})
	}
	return dash.NewSummary("Captured traffic", "attributed exchanges", "exchanges",
		dash.Breakdown{Found: attributed, Skipped: unattributed}, reasons...)
}

// sourceCounts is the per-source histogram the capture summary headlines, reported separately because
// it is a partition of one number rather than a count with caveats — Breakdown is the wrong shape for
// it, and bending it into one would mean inventing a fifth bucket per source.
func (s *Server) sourceCounts() map[string]int {
	out := map[string]int{}
	for _, src := range []core.Source{
		core.SourceUnattributed, core.SourceProxy, core.SourceCrawl, core.SourceIsolatedScan,
		core.SourceRepeater, core.SourceIntruder, core.SourceScanner,
	} {
		out[src.String()] = 0
	}
	for _, ex := range s.store.Exchanges() {
		out[ex.Source.String()]++
	}
	return out
}

// tasksSummary is the registry counting itself, in tasks: how much of the long-running work that
// started actually finished the work it was given.
func (s *Server) tasksSummary() dash.Summary {
	return dash.NewSummary("Tasks", "completed tasks", "tasks",
		s.tasks.Breakdown(), s.tasks.Reasons()...)
}

// ---- shared tool-log projection -----------------------------------------------------------------

// toolLogEntryView is the one place a toollog.Entry becomes wire shape, shared by /api/tools/log and
// /api/dashboard. Two projections of one row would eventually differ in which fields they carried,
// which is how started_ms came to be missing from one of them in the first place.
func toolLogEntryView(e *toollog.Entry) toolLogEntry {
	var status *int
	if e.Status > 0 {
		st := e.Status
		status = &st
	}
	view := toolLogEntry{
		ID:   e.ID,
		Tool: e.Tool.String(),
		Host: e.Host,
		Port: e.Port,
		// The flag the record has always held. See toolLogEntry.TLS for what dropping it cost.
		TLS:    e.TLS,
		Method: e.Method,
		Path:   e.Path,
		Status: status,
		// Passed through, not synthesised. This used to be a literal 0 on every row of both routes,
		// because toollog.Entry had no length on it to pass through: the projection could only invent a
		// number, and the number it invented said every response was empty. The entry now carries the
		// measurement, or nil where there was nothing to measure, and both travel as they are.
		ResponseLen: e.ResponseLen,
		StartedMs:   e.StartedMs,
		DurationMs:  e.DurationMs,
		Error:       strPtrIf(e.Note != "", e.Note),
		Comment:     e.Comment,
		Highlight:   e.Highlight,
	}
	if e.Exchange != nil {
		id := uint64(*e.Exchange)
		view.Exchange = &id
	}
	return view
}

// toolLogMatches is the log's filter, shared for the same reason as the projection.
func toolLogMatches(e *toollog.Entry, filter, search string) bool {
	if filter != "" && e.Tool.String() != filter {
		return false
	}
	if search != "" && !strings.Contains(strings.ToLower(e.Host+e.Path+e.Method), strings.ToLower(search)) {
		return false
	}
	return true
}
