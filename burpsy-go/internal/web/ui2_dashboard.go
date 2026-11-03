package web

// ui2 Dashboard (unit 8): the task list, the live-audit task and one task's detail page.
//
// Every read is the JSON API's own answer (GET /api/dashboard, /api/scanner/live, /api/issues,
// /api/crawl, /api/crawl/live) decoded in process, so the page and the React console cannot
// disagree about a task. Writes follow each API route's risk class:
//
//   - /api/tasks/* (riskLocal): one-click POSTs to /ui2/dashboard/task/{id}/{action} and
//     /ui2/dashboard/tasks/{action}. The class is re-checked at dispatch with needsConfirmation, so
//     a route that is ever reclassified into the gated set stops being one-click here.
//   - POST /api/scanner/live (riskAttack) and DELETE /api/dashboard/events (riskDestructive): the
//     gate review. confirm mints a one-time confirmation for the exact call and renders the full
//     bound body; run rebuilds the body from the sheet's hidden fields through the SAME builder and
//     spends the token, so an edited field fails the token's digest instead of running.

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- wire shapes (decoded from the JSON API) --------------------------------------------------

type ui2DashBreakdown struct {
	Found       uint64 `json:"found"`
	Skipped     uint64 `json:"skipped"`
	Errored     uint64 `json:"errored"`
	Gated       uint64 `json:"gated"`
	Unaccounted uint64 `json:"unaccounted"`
	Complete    bool   `json:"complete"`
	Summary     string `json:"summary"`
}

type ui2DashSummary struct {
	Label     string           `json:"label"`
	Unit      string           `json:"unit"`
	WorkUnit  string           `json:"work_unit"`
	Breakdown ui2DashBreakdown `json:"breakdown"`
	Reasons   []struct {
		Bucket string `json:"bucket"`
		Detail string `json:"detail"`
		Count  uint64 `json:"count"`
	} `json:"reasons"`
}

type ui2DashTask struct {
	ID          uint64           `json:"id"`
	Kind        string           `json:"kind"`
	Target      string           `json:"target"`
	State       string           `json:"state"`
	Done        uint64           `json:"done"`
	Total       uint64           `json:"total"`
	Note        string           `json:"note"`
	Result      ui2DashBreakdown `json:"result"`
	Pausable    bool             `json:"pausable"`
	Paused      bool             `json:"paused"`
	ElapsedMs   uint64           `json:"elapsed_ms"`
	Progress    string           `json:"progress"`
	Cancellable bool             `json:"cancellable"`
}

// Running, CanPause etc. are what the action buttons read: a button renders only where the API
// would act on it, never as a control that answers 409.
func (t ui2DashTask) Running() bool  { return t.State == "running" }
func (t ui2DashTask) CanPause() bool { return t.Running() && t.Pausable }
func (t ui2DashTask) CanCancel() bool {
	return t.Running() && t.Cancellable
}
func (t ui2DashTask) CanAgain() bool { return !t.Running() && t.Kind == "crawl" }
func (t ui2DashTask) Title() string {
	if t.Kind == "live-audit" {
		return "Live audit from Proxy (" + t.Target + ")"
	}
	return t.Kind + " (" + t.Target + ")"
}

type ui2DashActivity struct {
	Tool      string `json:"tool"`
	Host      string `json:"host"`
	Port      uint16 `json:"port"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    *int   `json:"status"`
	StartedMs uint64 `json:"started_ms"`
}

func (a ui2DashActivity) At() string { return ui2DashClock(a.StartedMs) }

type ui2DashEvent struct {
	ID       uint64 `json:"id"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	TaskID   uint64 `json:"task_id"`
	AtMs     uint64 `json:"at_ms"`
}

type ui2DashWire struct {
	Summaries     []ui2DashSummary  `json:"summaries"`
	Tasks         []ui2DashTask     `json:"tasks"`
	TasksRunning  int               `json:"tasks_running"`
	TasksDropped  uint64            `json:"tasks_dropped"`
	Activity      []ui2DashActivity `json:"activity"`
	ActivityShown int               `json:"activity_shown"`
	ActivityTotal int               `json:"activity_total"`
	Events        []ui2DashEvent    `json:"events"`
	EventsShown   int               `json:"events_shown"`
	EventsTotal   int               `json:"events_total"`
	EventsDropped uint64            `json:"events_dropped"`
	Exchanges     int               `json:"exchanges"`
	Messages      int               `json:"messages"`
	StoredBytes   int64             `json:"stored_bytes"`
	Sources       map[string]int    `json:"sources"`
	Paused        bool              `json:"paused"`
}

type ui2DashLive struct {
	Wired    bool   `json:"wired"`
	Enabled  bool   `json:"enabled"`
	Hint     string `json:"hint"`
	Swept    uint64 `json:"swept"`
	Findings uint64 `json:"findings"`
	Behind   uint64 `json:"behind"`
	Query    string `json:"query"`
	Config   string `json:"config"`
	Pool     string `json:"pool"`
}

// ui2DashGet decodes one in-process GET into v and reports a non-200 as text.
func (s *Server) ui2DashGet(path string, v any) string {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
	if rec.Code != http.StatusOK {
		return ui2APIErrorText(strings.TrimSpace(rec.Body.String()))
	}
	if err := ui2DecodeJSON(rec.Body.Bytes(), v); err != nil {
		return "unreadable response: " + err.Error()
	}
	return ""
}

// ---- view helpers -----------------------------------------------------------------------------

type ui2DashEventRow struct {
	ui2DashEvent
	Source string
	At     string
}

type ui2DashKV struct {
	Name  string
	Count int
}

func ui2DashDuration(ms uint64) string {
	d := time.Duration(ms) * time.Millisecond
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", ms)
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

func ui2DashClock(ms uint64) string {
	if ms == 0 {
		return ""
	}
	return time.UnixMilli(int64(ms)).Format("2006-01-02 15:04:05")
}

// ui2DashEventSource names what an event is about: the task, by the name the list shows, or no
// task. A deleted task still names its id rather than reading as sourceless.
func ui2DashEventSource(ev ui2DashEvent, tasks []ui2DashTask) string {
	if ev.TaskID == 0 {
		return "not a task"
	}
	for _, t := range tasks {
		if t.ID == ev.TaskID {
			return fmt.Sprintf("Task %d · %s (%s)", t.ID, t.Kind, t.Target)
		}
	}
	return fmt.Sprintf("Task %d", ev.TaskID)
}

// ui2DashEventRows filters the event log the way the console's event-log filter does: severity,
// source (0 = every source) and a case-insensitive search over kind, detail and the source label.
func ui2DashEventRows(events []ui2DashEvent, tasks []ui2DashTask, severity string, source uint64, search string) []ui2DashEventRow {
	needle := strings.ToLower(strings.TrimSpace(search))
	out := make([]ui2DashEventRow, 0, len(events))
	for _, ev := range events {
		if severity != "" && severity != "all" && ev.Severity != severity {
			continue
		}
		if source != 0 && ev.TaskID != source {
			continue
		}
		src := ui2DashEventSource(ev, tasks)
		if needle != "" && !strings.Contains(strings.ToLower(ev.Kind+"\n"+ev.Detail+"\n"+src), needle) {
			continue
		}
		out = append(out, ui2DashEventRow{ui2DashEvent: ev, Source: src, At: ui2DashClock(ev.AtMs)})
	}
	return out
}

func ui2DashSources(m map[string]int) []ui2DashKV {
	out := make([]ui2DashKV, 0, len(m))
	for k, v := range m {
		out = append(out, ui2DashKV{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// ui2DashHistoryHref is the "Show in HTTP history" link: the task target's host as a history
// filter, the same query the console builds.
func ui2DashHistoryHref(target string) string {
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	host = strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(host)
	return "/ui2/history?q=" + url.QueryEscape(`host ~ "`+host+`"`)
}

// ---- Dashboard page ---------------------------------------------------------------------------

type ui2DashModel struct {
	ui2DashWire
	Filter       string
	Shown        []ui2DashTask
	Live         ui2DashLive
	LiveErr      string
	LiveStanding bool
	Configs      []string
	Pools        []string
	Issues       int
	IssueCounts  map[string]int
	IssueFP      int
	DockEvents   []ui2DashEventRow
	Error        string
	Note         string
	Done         string
	// LiveGated says the live switch and the New live task form go through the review step.
	LiveGated bool
	// LiveURL is what app.js re-fetches on a dashboard frame; Back is 0 (the dashboard itself).
	LiveURL string
	Back    uint64
}

// ui2DashboardModel builds the dashboard page model: the task list (filtered), the live task,
// the coverage table and the dock (issue count + newest events).
func (s *Server) ui2DashboardModel(filter, note, done string) ui2DashModel {
	m := ui2DashModel{Filter: strings.TrimSpace(filter), Note: note, Done: done}
	if errText := s.ui2DashGet("/api/dashboard", &m.ui2DashWire); errText != "" {
		m.Error = "dashboard unavailable: " + errText
	}
	needle := strings.ToLower(m.Filter)
	for _, t := range m.Tasks {
		if needle == "" || strings.Contains(strings.ToLower(t.Kind+" "+t.Target), needle) {
			m.Shown = append(m.Shown, t)
		}
	}
	m.LiveErr = s.ui2DashGet("/api/scanner/live", &m.Live)
	batchRunning := false
	for _, t := range m.Tasks {
		if t.Kind == "live-audit" && t.Running() {
			batchRunning = true
		}
	}
	// The standing live entry: the registry records a row per bounded sweep batch, so between
	// batches an enabled live audit is shown from /api/scanner/live state, never as a fake row.
	m.LiveStanding = m.Live.Enabled && !batchRunning &&
		(needle == "" || strings.Contains("live-audit proxied traffic", needle))
	m.Configs, m.Pools = s.ui2DashNames()
	var issues struct {
		Counted        int            `json:"counted"`
		Counts         map[string]int `json:"counts"`
		FalsePositives int            `json:"false_positives"`
	}
	_ = s.ui2DashGet("/api/issues?count=1", &issues)
	m.Issues, m.IssueCounts, m.IssueFP = issues.Counted, issues.Counts, issues.FalsePositives
	rows := ui2DashEventRows(m.Events, m.Tasks, "", 0, "")
	if len(rows) > 20 {
		rows = rows[:20]
	}
	m.DockEvents = rows
	_, risk, _ := routeRiskFor("/api/scanner/live")
	m.LiveGated = needsConfirmation(risk)
	m.LiveURL = "/ui2/dashboard"
	if m.Filter != "" {
		m.LiveURL += "?filter=" + url.QueryEscape(m.Filter)
	}
	return m
}

// ui2DashNames lists the scan configuration and resource pool names the New live task form offers.
func (s *Server) ui2DashNames() (configs, pools []string) {
	var c struct {
		Configs []struct {
			Name string `json:"name"`
		} `json:"configs"`
	}
	_ = s.ui2DashGet("/api/scanner/configs", &c)
	for _, v := range c.Configs {
		configs = append(configs, v.Name)
	}
	var p struct {
		Pools []struct {
			Name string `json:"name"`
		} `json:"pools"`
	}
	_ = s.ui2DashGet("/api/pools", &p)
	for _, v := range p.Pools {
		pools = append(pools, v.Name)
	}
	return configs, pools
}

// handleUI2Dashboard serves GET /ui2/dashboard[?filter=]: the shell, or the #rows fragment for htmx.
func (s *Server) handleUI2Dashboard(w http.ResponseWriter, r *http.Request) {
	s.ui2DashWritePage(w, r, 0, "", r.URL.Query().Get("filter"), "", "")
}

// ui2DashWritePage renders the dashboard (task 0) or one task's page, with an outcome line.
func (s *Server) ui2DashWritePage(w http.ResponseWriter, r *http.Request, task uint64, tab, filter, note, done string) {
	if task != 0 {
		m := s.ui2DashTaskModel(task, tab, url.Values{}, note, done)
		ui2Fragment(w, r, "burpsy /ui2/ — Task "+strconv.FormatUint(task, 10), "dashboard", ui2Exec("dashboard_task.html", m))
		return
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Dashboard", "dashboard", ui2Exec("dashboard.html", s.ui2DashboardModel(filter, note, done)))
}

// ---- Task detail page -------------------------------------------------------------------------

type ui2DashTab struct {
	Key, Label string
	Active     bool
}

type ui2DashFinding struct {
	ID        uint64 `json:"id"`
	TaskID    uint64 `json:"task_id"`
	Severity  string `json:"severity"`
	IssueName string `json:"issue_name"`
	CheckName string `json:"check_name"`
	Host      string `json:"host"`
	TimesSeen int    `json:"times_seen"`
	Isolated  bool   `json:"isolated"`
}

type ui2DashCrawlLogin struct {
	Label               string   `json:"label"`
	Authenticated       bool     `json:"authenticated"`
	Verified            bool     `json:"verified"`
	Attempts            int      `json:"attempts"`
	Succeeded           int      `json:"succeeded"`
	Failed              int      `json:"failed"`
	Relogins            int      `json:"relogins"`
	LastFailure         string   `json:"last_failure"`
	FinalURL            string   `json:"final_url"`
	CookieNames         []string `json:"cookie_names"`
	Blocked             []string `json:"blocked"`
	RequestsWithSession int      `json:"requests_with_session"`
	PagesAfterLogin     int      `json:"pages_found_after_login"`
	RenderBlocked       []string `json:"render_blocked"`
}

type ui2DashCrawlRun struct {
	TaskID uint64 `json:"task_id"`
	State  string `json:"state"`
	Kind   string `json:"kind"`
	Error  string `json:"error"`
	Report *struct {
		Login  *ui2DashCrawlLogin `json:"login"`
		Limits *struct {
			Stops []string `json:"stops"`
		} `json:"limits"`
	} `json:"report"`
}

// ui2DashCrawlStopLabels are the console's labels for the crawl engine's stop names.
var ui2DashCrawlStopLabels = map[string]string{
	"request-budget":            "Request budget spent with URLs still queued",
	"duration":                  "Time budget spent with URLs still queued",
	"location-budget":           "Location budget spent",
	"depth":                     "Links past the depth limit were not followed",
	"frontier-capacity":         "Frontier full — links were dropped",
	"speculative-links":         "Speculative-link cap spent",
	"links-per-page":            "A page had more links than the per-page bound",
	"parse-bytes":               "A body's tail was not examined for links",
	"cancelled":                 "Cancelled before the frontier emptied",
	"template-quota":            "A URL template was sampled to its quota",
	"capture-bytes":             "A response was too large to store or scan",
	"fingerprint-budget":        "Request-identity table full — unseen URLs refused",
	"relogin-budget":            "Re-login budget spent — the rest was crawled logged out",
	"paused-timeouts":           "Paused by policy: too many requests timed out in a row",
	"paused-timeout-percentage": "Paused by policy: too large a share of requests timed out",
	"paused-auth-failures":      "Paused by policy: re-logins kept failing",
	"follow-up-budget":          "Failed requests not retried — the request budget was spent",
	"follow-up-cancelled":       "Cancelled during the follow-up pass — some failures not retried",
	"login-failed":              "The recorded login failed — the whole crawl ran logged out",
}

type ui2DashTaskModel struct {
	ID        uint64
	Back      uint64
	Found     bool
	Task      ui2DashTask
	Tab       string
	Tabs      []ui2DashTab
	LiveURL   string
	IsLive    bool
	Live      ui2DashLive
	LiveGated bool
	Paused    bool
	Findings  uint64
	Elapsed   string
	Rate      string
	History   string
	// Crawl run (summary card, login card, stops) and the live crawl tab.
	Run       *ui2DashCrawlRun
	Outcome   string
	Stops     []string
	Policy    bool
	HasCrawl  bool
	CrawlLive map[string]any
	CrawlErr  string
	// Project-wide panes.
	Summaries []ui2DashSummary
	Sources   []ui2DashKV
	Recent    []ui2DashActivity
	Activity  []ui2DashActivity
	// Issue activity tab.
	Issues        []ui2DashFinding
	IssuesHidden  int
	IssuesErr     string
	IssuesEnabled bool
	// Event log tab.
	Events      []ui2DashEventRow
	EventsAll   int
	EventsDrop  uint64
	Severity    string
	Source      string
	Search      string
	SevCounts   map[string]int
	Filtered    bool
	Error, Note string
	Done        string
}

var ui2DashTabOrder = []ui2DashTab{
	{Key: "summary", Label: "Summary"},
	{Key: "issues", Label: "Issue activity"},
	{Key: "events", Label: "Event log"},
	{Key: "activity", Label: "Activity"},
	{Key: "crawl", Label: "Live crawl view"},
}

// ui2DashTaskModel builds one task's detail page. Reads that only one tab needs (the issue list,
// the live crawl view) run only for that tab.
func (s *Server) ui2DashTaskModel(id uint64, tab string, q url.Values, note, done string) ui2DashTaskModel {
	m := ui2DashTaskModel{ID: id, Back: id, Tab: tab, Note: note, Done: done}
	var wire ui2DashWire
	if errText := s.ui2DashGet("/api/dashboard", &wire); errText != "" {
		m.Error = "dashboard unavailable: " + errText
		return m
	}
	for _, t := range wire.Tasks {
		if t.ID == id {
			m.Task, m.Found = t, true
		}
	}
	if !m.Found {
		return m
	}
	m.Paused = wire.Paused
	m.IsLive = m.Task.Kind == "live-audit"
	_ = s.ui2DashGet("/api/scanner/live", &m.Live)
	_, risk, _ := routeRiskFor("/api/scanner/live")
	m.LiveGated = needsConfirmation(risk)
	if m.IsLive {
		m.Findings = m.Live.Findings
	} else {
		m.Findings = m.Task.Result.Found
	}
	m.Elapsed = ui2DashDuration(m.Task.ElapsedMs)
	m.Rate = "—"
	if m.Task.ElapsedMs > 0 {
		m.Rate = fmt.Sprintf("%.1f req/s", float64(m.Task.Done)/(float64(m.Task.ElapsedMs)/1000))
	}
	m.History = ui2DashHistoryHref(m.Task.Target)
	var run ui2DashCrawlRun
	if s.ui2DashGet("/api/crawl?task="+strconv.FormatUint(id, 10), &run) == "" {
		m.Run = &run
		if run.Report != nil && run.Report.Limits != nil {
			for _, stop := range run.Report.Limits.Stops {
				label, ok := ui2DashCrawlStopLabels[stop]
				if !ok {
					label = "Stopped: " + stop
				}
				m.Stops = append(m.Stops, label)
				m.Policy = m.Policy || strings.HasPrefix(stop, "paused-")
			}
		}
		switch {
		case run.State == "failed" || run.State == "running":
			m.Outcome = run.State
		case m.Policy:
			m.Outcome = "paused by policy"
		case len(m.Stops) > 0:
			m.Outcome = "incomplete"
		default:
			m.Outcome = "done"
		}
		m.HasCrawl = run.Kind != "api-scan"
	}
	tabs := make([]ui2DashTab, 0, len(ui2DashTabOrder))
	valid := false
	for _, t := range ui2DashTabOrder {
		if t.Key == "crawl" && !m.HasCrawl {
			continue
		}
		valid = valid || t.Key == m.Tab
		tabs = append(tabs, t)
	}
	if !valid {
		m.Tab = "summary"
	}
	for i := range tabs {
		tabs[i].Active = tabs[i].Key == m.Tab
	}
	m.Tabs = tabs
	m.Summaries = wire.Summaries
	m.Sources = ui2DashSources(wire.Sources)
	m.Activity = wire.Activity
	if len(m.Activity) > 20 {
		m.Activity = m.Activity[:20]
	}
	m.Recent = m.Activity
	if len(m.Recent) > 5 {
		m.Recent = m.Recent[:5]
	}
	live := url.Values{"tab": {m.Tab}}
	switch m.Tab {
	case "issues":
		var doc struct {
			Enabled  bool             `json:"enabled"`
			Findings []ui2DashFinding `json:"findings"`
		}
		m.IssuesErr = s.ui2DashGet("/api/issues?include_isolated=1&summary=1", &doc)
		m.IssuesEnabled = doc.Enabled
		// Scoped BEFORE the cap: a busy neighbouring task must not push this task's findings out.
		for _, f := range doc.Findings {
			if f.TaskID == id {
				m.Issues = append(m.Issues, f)
			}
		}
		sort.Slice(m.Issues, func(i, j int) bool { return m.Issues[i].ID > m.Issues[j].ID })
		if len(m.Issues) > 20 {
			m.IssuesHidden = len(m.Issues) - 20
			m.Issues = m.Issues[:20]
		}
	case "events":
		m.Severity = q.Get("severity")
		switch m.Severity {
		case "error", "warn", "info":
		default:
			m.Severity = "all"
		}
		m.Source = "all"
		var source uint64
		if q.Get("source") == "task" {
			m.Source, source = "task", id
		}
		m.Search = strings.TrimSpace(q.Get("search"))
		m.Events = ui2DashEventRows(wire.Events, wire.Tasks, m.Severity, source, m.Search)
		m.EventsAll = len(wire.Events)
		m.EventsDrop = wire.EventsDropped
		m.SevCounts = map[string]int{}
		for _, ev := range wire.Events {
			m.SevCounts[ev.Severity]++
		}
		m.Filtered = m.Severity != "all" || m.Source != "all" || m.Search != ""
		live.Set("severity", m.Severity)
		live.Set("source", m.Source)
		live.Set("search", m.Search)
	case "crawl":
		rec := newRecorder()
		s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/crawl/live?task="+strconv.FormatUint(id, 10)))
		if rec.Code != http.StatusOK {
			m.CrawlErr = ui2APIErrorText(strings.TrimSpace(rec.Body.String()))
		} else if err := ui2DecodeJSON(rec.Body.Bytes(), &m.CrawlLive); err != nil {
			m.CrawlErr = "unreadable live crawl view: " + err.Error()
		}
	}
	m.LiveURL = "/ui2/dashboard/task/" + strconv.FormatUint(id, 10) + "?" + live.Encode()
	return m
}

// handleUI2DashboardTask serves GET /ui2/dashboard/task/{id}?tab=…: one task's detail page.
func (s *Server) handleUI2DashboardTask(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		http.Error(w, "Invalid task id", http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	m := s.ui2DashTaskModel(id, q.Get("tab"), q, "", "")
	ui2Fragment(w, r, "burpsy /ui2/ — Task "+strconv.FormatUint(id, 10), "dashboard", ui2Exec("dashboard_task.html", m))
}

// ---- form discipline --------------------------------------------------------------------------

// ui2DashForm parses a POST form under a strict contract: no query fields, every field at most
// once and from the allowed set, and every required field present.
func ui2DashForm(r *http.Request, required []string, optional ...string) error {
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("invalid form")
	}
	if len(r.URL.Query()) != 0 {
		return fmt.Errorf("query fields are not permitted here")
	}
	allowed := map[string]bool{}
	for _, k := range optional {
		allowed[k] = true
	}
	for _, k := range required {
		allowed[k] = true
		if len(r.PostForm[k]) != 1 {
			return fmt.Errorf("%s is required exactly once", k)
		}
	}
	for k, v := range r.PostForm {
		if !allowed[k] || len(v) != 1 {
			return fmt.Errorf("%s is not a single permitted field", k)
		}
	}
	return nil
}

// ui2DashBack reads the optional "back" field: the task page to re-render, or 0 for the dashboard.
func ui2DashBack(r *http.Request) (uint64, error) {
	raw := r.PostFormValue("back")
	if raw == "" {
		return 0, nil
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("back must be a task id")
	}
	return id, nil
}

// ---- one-click task actions (riskLocal) -------------------------------------------------------

// ui2DashOneClick dispatches one riskLocal task call. It re-derives the class from the manifest
// so a route moved into the gated set is refused here rather than run without a review.
func (s *Server) ui2DashOneClick(method, path string) (any, string) {
	_, risk, ok := routeRiskFor(path)
	if !ok || needsConfirmation(risk) {
		return nil, path + " needs a reviewed confirmation; it cannot run from a one-click button"
	}
	return s.ui2APIResult(method, path, nil)
}

// handleUI2DashboardTaskAction serves POST /ui2/dashboard/task/{id}/{action} for pause, resume,
// cancel, again and delete. Fields: back (re-render that task's page) and filter (the dashboard's).
func (s *Server) handleUI2DashboardTaskAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		http.Error(w, "Invalid task id", http.StatusBadRequest)
		return
	}
	action := r.PathValue("action")
	method, path := http.MethodPost, "/api/tasks/"+strconv.FormatUint(id, 10)+"/"+action
	switch action {
	case "pause", "resume", "cancel", "again":
	case "delete":
		method, path = http.MethodDelete, "/api/tasks/"+strconv.FormatUint(id, 10)
	default:
		http.Error(w, "unknown task action", http.StatusBadRequest)
		return
	}
	if err := ui2DashForm(r, nil, "back", "filter"); err != nil {
		s.ui2DashWritePage(w, r, 0, "", "", "Not applied: "+err.Error(), "")
		return
	}
	back, err := ui2DashBack(r)
	if err != nil {
		s.ui2DashWritePage(w, r, 0, "", "", "Not applied: "+err.Error(), "")
		return
	}
	filter := r.PostFormValue("filter")
	note, done := "", ""
	if _, errText := s.ui2DashOneClick(method, path); errText != "" {
		note = fmt.Sprintf("Task %d: %s refused — %s", id, action, ui2APIErrorText(errText))
	} else {
		done = map[string]string{
			"pause":  fmt.Sprintf("Task %d paused at its next step.", id),
			"resume": fmt.Sprintf("Task %d resumed.", id),
			"cancel": fmt.Sprintf("Task %d asked to stop.", id),
			"again":  fmt.Sprintf("Task %d started again at its target (a new crawl task).", id),
			"delete": fmt.Sprintf("Task %d removed from the list; its findings and traffic remain.", id),
		}[action]
		if action == "delete" {
			back = 0
		}
	}
	s.ui2DashWritePage(w, r, back, "summary", filter, note, done)
}

// handleUI2DashboardTasksAll serves POST /ui2/dashboard/tasks/{action}: the suite-wide pause and
// resume (riskLocal, one click).
func (s *Server) handleUI2DashboardTasksAll(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	var path string
	switch action {
	case "pause":
		path = "/api/tasks/pause"
	case "resume":
		path = "/api/tasks/resume"
	default:
		http.Error(w, "unknown tasks action", http.StatusBadRequest)
		return
	}
	if err := ui2DashForm(r, nil, "filter"); err != nil {
		s.ui2DashWritePage(w, r, 0, "", "", "Not applied: "+err.Error(), "")
		return
	}
	note, done := "", ""
	result, errText := s.ui2DashOneClick(http.MethodPost, path)
	if errText != "" {
		note = "Not applied: " + ui2APIErrorText(errText)
	} else {
		running := 0.0
		if m, ok := result.(map[string]any); ok {
			running, _ = m["running"].(float64)
		}
		if action == "pause" {
			done = fmt.Sprintf("Task execution paused (%d running task(s) will hold at their next step).", int(running))
		} else {
			done = "Task execution resumed."
		}
	}
	s.ui2DashWritePage(w, r, 0, "", r.PostFormValue("filter"), note, done)
}

// ---- live audit (riskAttack: gate review) -----------------------------------------------------

// ui2DashLivePayload builds the exact POST /api/scanner/live body from the form. Both the confirm
// and the run step call it, so the body the run sends is the body the sheet showed.
//
// mode=toggle carries only enabled (on|off) — omitting query keeps an installed filter, exactly as
// the console's switch does. mode=task is the New live task form: enabled true, the query only when
// one was typed, and the configuration and pool as chosen ("" is the default).
func ui2DashLivePayload(r *http.Request) (map[string]any, string) {
	switch r.PostFormValue("mode") {
	case "toggle":
		if _, ok := r.PostForm["query"]; ok {
			return nil, "a capturing toggle carries no query"
		}
		if _, ok := r.PostForm["config"]; ok {
			return nil, "a capturing toggle carries no configuration"
		}
		if _, ok := r.PostForm["pool"]; ok {
			return nil, "a capturing toggle carries no pool"
		}
		switch r.PostFormValue("enabled") {
		case "on":
			return map[string]any{"enabled": true}, ""
		case "off":
			return map[string]any{"enabled": false}, ""
		}
		return nil, "enabled must be on or off"
	case "task":
		if _, ok := r.PostForm["enabled"]; ok {
			return nil, "a new live task always enables capturing"
		}
		payload := map[string]any{
			"enabled": true,
			"config":  r.PostFormValue("config"),
			"pool":    r.PostFormValue("pool"),
		}
		if q := strings.TrimSpace(r.PostFormValue("query")); q != "" {
			payload["query"] = q
		}
		return payload, ""
	}
	return nil, "mode must be toggle or task"
}

var ui2DashLiveFields = []string{"mode", "enabled", "query", "config", "pool", "back"}

// handleUI2DashboardLive serves POST /ui2/dashboard/live/{action}: confirm renders the review
// sheet, run spends the reviewed call. The first click never changes the live sweep.
func (s *Server) handleUI2DashboardLive(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("action") {
	case "confirm":
		s.ui2DashLiveConfirm(w, r)
	case "run":
		s.ui2DashLiveRun(w, r)
	default:
		http.Error(w, "unknown live action", http.StatusBadRequest)
	}
}

func (s *Server) ui2DashSheet(w http.ResponseWriter, model map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("dashboard_confirm.html", model)))
}

func (s *Server) ui2DashLiveConfirm(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string, back uint64) {
		s.ui2DashSheet(w, map[string]any{"error": msg, "back": back})
	}
	if err := ui2DashForm(r, []string{"mode"}, ui2DashLiveFields...); err != nil {
		fail(err.Error(), 0)
		return
	}
	back, err := ui2DashBack(r)
	if err != nil {
		fail(err.Error(), 0)
		return
	}
	payload, errText := ui2DashLivePayload(r)
	if errText != "" {
		fail(errText, back)
		return
	}
	// Names are checked against the live lists here so the operator reviews a call that can run;
	// the API checks them again at dispatch.
	configs, pools := s.ui2DashNames()
	if name, _ := payload["config"].(string); name != "" {
		if !ui2DashListed(configs, name) {
			fail(fmt.Sprintf("no scan configuration is named %q", name), back)
			return
		}
	}
	if name, _ := payload["pool"].(string); name != "" {
		if !ui2DashListed(pools, name) {
			fail(fmt.Sprintf("no resource pool is named %q", name), back)
			return
		}
	}
	body, _ := ui2Marshal(payload)
	token, preview, mintErr := s.ui2MintConfirm("/api/scanner/live", http.MethodPost, "/api/scanner/live", body)
	fields := []ui2DashHidden{{"mode", r.PostFormValue("mode")}}
	for _, k := range []string{"enabled", "query", "config", "pool"} {
		if _, ok := r.PostForm[k]; ok {
			fields = append(fields, ui2DashHidden{k, r.PostFormValue(k)})
		}
	}
	if back != 0 {
		fields = append(fields, ui2DashHidden{"back", strconv.FormatUint(back, 10)})
	}
	enabled, _ := payload["enabled"].(bool)
	s.ui2DashSheet(w, map[string]any{
		"kind":    "live",
		"title":   map[bool]string{true: "switch the live audit ON", false: "switch the live audit OFF"}[enabled],
		"enabled": enabled,
		"body":    string(body),
		"preview": preview,
		"token":   token,
		"error":   mintErr,
		"fields":  fields,
		"action":  "/ui2/dashboard/live/run",
		"back":    back,
	})
}

type ui2DashHidden struct{ Name, Value string }

func ui2DashListed(list []string, name string) bool {
	for _, v := range list {
		if v == name {
			return true
		}
	}
	return false
}

func (s *Server) ui2DashLiveRun(w http.ResponseWriter, r *http.Request) {
	if err := ui2DashForm(r, []string{"token", "mode"}, append([]string{"token"}, ui2DashLiveFields...)...); err != nil {
		s.ui2DashWritePage(w, r, 0, "", "", "Not applied: "+err.Error(), "")
		return
	}
	back, err := ui2DashBack(r)
	if err != nil {
		s.ui2DashWritePage(w, r, 0, "", "", "Not applied: "+err.Error(), "")
		return
	}
	note, done := "", ""
	payload, errText := ui2DashLivePayload(r)
	if errText == "" {
		_, errText = s.ui2DispatchConfirmed(http.MethodPost, "/api/scanner/live", payload, r.PostFormValue("token"))
	}
	if errText != "" {
		note = "Not applied: " + ui2APIErrorText(errText)
	} else if payload["enabled"] == true {
		done = "Live audit is ON: active checks will be sent at newly captured in-scope traffic."
	} else {
		done = "Live audit is OFF."
	}
	s.ui2DashWritePage(w, r, back, "summary", "", note, done)
}

// ---- clear event log (riskDestructive: gate review) -------------------------------------------

// handleUI2DashboardEvents serves POST /ui2/dashboard/events/{action}: confirm renders the review
// for DELETE /api/dashboard/events, run spends it.
func (s *Server) handleUI2DashboardEvents(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("action") {
	case "confirm":
		if err := ui2DashForm(r, nil, "back"); err != nil {
			s.ui2DashSheet(w, map[string]any{"error": err.Error()})
			return
		}
		back, err := ui2DashBack(r)
		if err != nil {
			s.ui2DashSheet(w, map[string]any{"error": err.Error()})
			return
		}
		token, preview, mintErr := s.ui2MintConfirm("/api/dashboard/events", http.MethodDelete, "/api/dashboard/events", nil)
		var fields []ui2DashHidden
		if back != 0 {
			fields = append(fields, ui2DashHidden{"back", strconv.FormatUint(back, 10)})
		}
		s.ui2DashSheet(w, map[string]any{
			"kind":    "events",
			"title":   "clear the dashboard event log",
			"count":   s.events.Count(),
			"preview": preview,
			"token":   token,
			"error":   mintErr,
			"fields":  fields,
			"action":  "/ui2/dashboard/events/run",
			"back":    back,
		})
	case "run":
		if err := ui2DashForm(r, []string{"token"}, "back"); err != nil {
			s.ui2DashWritePage(w, r, 0, "", "", "Not applied: "+err.Error(), "")
			return
		}
		back, err := ui2DashBack(r)
		if err != nil {
			s.ui2DashWritePage(w, r, 0, "", "", "Not applied: "+err.Error(), "")
			return
		}
		note, done := "", ""
		if _, errText := s.ui2DispatchConfirmed(http.MethodDelete, "/api/dashboard/events", nil, r.PostFormValue("token")); errText != "" {
			note = "Not applied: " + ui2APIErrorText(errText)
		} else {
			done = "Event log cleared for every viewer."
		}
		s.ui2DashWritePage(w, r, back, "events", "", note, done)
	default:
		http.Error(w, "unknown event-log action", http.StatusBadRequest)
	}
}
