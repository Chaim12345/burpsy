package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/crawler"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/pool"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// ---- Crawl ---------------------------------------------------------------------------------------
//
// The crawl engine in internal/crawler was complete, tested and unreachable: nothing outside its own
// tests imported it, so no CLI flag and no route could start one. This file is the missing seam. It
// deliberately adds no crawling logic of its own — every bound, every refusal category and the whole
// coverage report come from the engine, and this only supplies the collaborators the Server already
// holds and turns the Report into JSON.
//
// The scope gate is not re-implemented here either. crawler.Config.Scope takes the engagement scope
// straight through, and the engine wraps every send in a sender.AuthorisedSender bound to the target
// origin, which is what makes the check unavoidable rather than customary. A crawl started from this
// endpoint is therefore no more privileged than any other burpsy tool.

// crawlRunsKept bounds retained crawl reports. A report holds the whole coverage story for one crawl
// — fetches, refusals, skip samples — so a handful is a browsable history and an unbounded list is a
// leak that grows with every crawl an operator starts and forgets.
const crawlRunsKept = 20

// crawlRuns holds finished (and in-flight) crawl reports, keyed by the task id that produced them,
// so the dashboard's task row and the crawl report are the same identity rather than two numbers an
// operator has to correlate by hand.
type crawlRuns struct {
	mu    sync.RWMutex
	byID  map[uint64]*crawlRun
	order []uint64
}

// crawlRun is one crawl: its request, its state, and its report once there is one.
type crawlRun struct {
	TaskID uint64   `json:"task_id"`
	Seeds  []string `json:"seeds"`
	// Kind is which scan kind this run is: crawlKindCrawl or crawlKindAudit. Carried on the retained
	// run rather than only in the request, so GET /api/crawl?task=N answers "what kind of scan was
	// that" for a run an operator started this morning, and so the 202 reply echoes the kind the
	// server took rather than the kind the caller hoped it sent.
	Kind     string          `json:"kind"`
	State    string          `json:"state"`
	Started  time.Time       `json:"started"`
	Finished *time.Time      `json:"finished,omitempty"`
	Error    string          `json:"error,omitempty"`
	Report   *crawler.Report `json:"report,omitempty"`
}

func newCrawlRuns() *crawlRuns {
	return &crawlRuns{byID: map[uint64]*crawlRun{}}
}

func (c *crawlRuns) start(taskID uint64, seeds []string, kind string) *crawlRun {
	c.mu.Lock()
	defer c.mu.Unlock()
	run := &crawlRun{TaskID: taskID, Seeds: seeds, Kind: kind, State: "running", Started: time.Now()}
	c.byID[taskID] = run
	c.order = append(c.order, taskID)
	for len(c.order) > crawlRunsKept {
		delete(c.byID, c.order[0])
		c.order = c.order[1:]
	}
	return run
}

// finish records a crawl's outcome. It looks the run up again rather than mutating the pointer start
// returned, because a long crawl can outlive its own retention window: by the time it ends, its entry
// may already have been evicted by newer crawls, and writing through a stale pointer would resurrect
// a report the eviction had removed.
func (c *crawlRuns) finish(taskID uint64, rep *crawler.Report, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	run := c.byID[taskID]
	if run == nil {
		return
	}
	now := time.Now()
	run.Finished = &now
	run.Report = rep
	if err != nil {
		run.State = "failed"
		run.Error = err.Error()
		return
	}
	run.State = "done"
}

func (c *crawlRuns) get(taskID uint64) (*crawlRun, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	run, ok := c.byID[taskID]
	return run, ok
}

// list returns the retained runs, newest first.
func (c *crawlRuns) list() []*crawlRun {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*crawlRun, 0, len(c.order))
	for _, id := range c.order {
		if run := c.byID[id]; run != nil {
			out = append(out, run)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TaskID > out[j].TaskID })
	return out
}

// The two scan kinds POST /api/crawl can start, Burp's New-scan dialog's first page reduced to the
// two burpsy can run.
//
// Burp has four — "Crawl and audit", "Crawl", "Audit selected items" and "API-only scan" (Zhw0 in
// the 2026.7.1 teardown, the dialog's four radio buttons) — and the difference that matters here is
// whether the crawl is followed by an audit of what it found. Naming them as constants rather than
// leaving a bare string in the request means an unknown kind is refused by name, and the two UI
// cards, the request and this handler cannot drift apart silently.
const (
	// crawlKindCrawl maps the attack surface and stops there. The default, and the behaviour every
	// caller predating this field gets.
	crawlKindCrawl = "crawl"
	// crawlKindAudit maps the attack surface and then audits the exchanges the crawl itself produced.
	crawlKindAudit = "crawl-audit"
)

// crawlStartReq is the POST body. Every bound is optional and falls back to the engine's own
// documented default rather than to a value invented here, so "what bounds a crawl" has one answer.
type crawlStartReq struct {
	Seeds []string `json:"seeds"`
	// Kind is which scan kind to run: crawlKindCrawl (the default, empty) or crawlKindAudit. An
	// unrecognised value is refused rather than treated as the default — see startCrawl. A typo'd
	// kind that silently ran a plain crawl would leave an operator waiting for findings that the
	// audit half was never going to produce, and nothing on screen would say why.
	Kind string `json:"kind,omitempty"`
	// Query gates each URL before it is fetched, so it may only name host and method. The engine
	// refuses one naming post-fetch fields rather than evaluating it against absent values.
	Query string `json:"query"`
	// RetentionQuery runs after the fetch and decides whether a response's links are followed. It may
	// name every field the grammar has.
	RetentionQuery string `json:"retention_query"`
	// SubmitForms defaults off, and that is a requirement rather than a default: a crawl that submits
	// forms writes to the application.
	SubmitForms     bool `json:"submit_forms"`
	MaxRequests     int  `json:"max_requests"`
	MaxDepth        int  `json:"max_depth"`
	MaxDurationSecs int  `json:"max_duration_secs"`
	// Pool names a saved resource pool to run under. Empty leaves the crawl on this package's own
	// documented defaults, which is what every caller predating pools sends.
	//
	// It is checked against the saved set and an unknown name is a 400 — never a fallback to the
	// defaults. A crawl that ran at five requests a second because its pool had been renamed, while
	// the operator believed a two-a-second pool was in force, is precisely the failure a named pool
	// exists to prevent.
	Pool string `json:"pool"`
	// RequestsPerSecond is the inline form, kept working: a pool is a resolution step, not a
	// replacement. Naming both is refused rather than silently resolved one way — see handleCrawlStart.
	RequestsPerSecond float64           `json:"requests_per_second"`
	UserAgent         string            `json:"user_agent"`
	Headers           map[string]string `json:"headers"`
}

// handleCrawl serves POST /api/crawl (start) and GET /api/crawl (list, or one by ?task=).
func (s *Server) handleCrawl(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleCrawlGet(w, r)
	case http.MethodPost:
		s.handleCrawlStart(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCrawlGet(w http.ResponseWriter, r *http.Request) {
	if raw := r.URL.Query().Get("task"); raw != "" {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			http.Error(w, "task must be a whole number", http.StatusBadRequest)
			return
		}
		run, ok := s.crawls.get(id)
		if !ok {
			http.Error(w, fmt.Sprintf("No crawl %d is retained", id), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, run)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"crawls": s.crawls.list()})
}

func (s *Server) handleCrawlStart(w http.ResponseWriter, r *http.Request) {
	var req crawlStartReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	taskID, seeds, err := s.startCrawl(req)
	if err != nil {
		http.Error(w, err.Error(), crawlStartStatus(err))
		return
	}
	run, _ := s.crawls.get(taskID)
	state, kind := "", crawlKindCrawl
	if run != nil {
		state = run.State
		kind = run.Kind
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"task_id": taskID,
		"seeds":   seeds,
		"state":   state,
		// Echoed for the same reason /api/scanner/audit echoes config_name: a reply that looked the
		// same whether or not the audit half was accepted could not be told apart from one that
		// accepted the kind and ran a plain crawl.
		"kind": kind,
	})
}

// crawlStartStatus maps a start failure to its status. A pool the operator named and that is not
// saved is 404 — the request is well formed and the world is not what they thought — while a
// malformed configuration is 400. Told apart because the fix differs: reload versus retype.
func crawlStartStatus(err error) int {
	if errors.Is(err, pool.ErrNoSuchPool) {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// startCrawl validates a crawl request, registers the task and starts the crawl, returning the task
// id and the seeds it actually took.
//
// Split out of the handler so a *scheduled* crawl is the same crawl: the schedule runner hands its
// saved params here rather than re-implementing seed trimming, limit defaults and pool resolution.
// Two code paths that both "start a crawl" would drift, and the one that drifted would be the
// unattended one nobody watches.
// scanKind normalises the requested scan kind, refusing anything it does not recognise.
//
// Empty means the plain crawl, because that is what every caller predating the field asked for by
// omission. Anything else non-empty must name one of the two constants: an unknown kind is refused
// with the accepted set in the message, never quietly downgraded to a crawl.
func scanKind(requested string) (string, error) {
	switch requested {
	case "", crawlKindCrawl:
		return crawlKindCrawl, nil
	case crawlKindAudit:
		return crawlKindAudit, nil
	}
	return "", fmt.Errorf(
		"unknown scan kind %q; this build runs %q and %q", requested, crawlKindCrawl, crawlKindAudit)
}

func (s *Server) startCrawl(req crawlStartReq) (uint64, []string, error) {
	kind, kerr := scanKind(req.Kind)
	if kerr != nil {
		return 0, nil, kerr
	}
	seeds := make([]string, 0, len(req.Seeds))
	for _, seed := range req.Seeds {
		if t := strings.TrimSpace(seed); t != "" {
			seeds = append(seeds, t)
		}
	}
	if len(seeds) == 0 {
		return 0, nil, errors.New("At least one seed URL is required")
	}

	// A named pool and an inline rate are refused together rather than resolved in some order. Both
	// are the operator stating the crawl's rate, and picking one would mean the number they typed in
	// the box was ignored — with no way for them to tell, since a crawl reports the rate it ran at
	// and not the rate it was told twice.
	if req.Pool != "" && req.RequestsPerSecond > 0 {
		return 0, nil, fmt.Errorf(
			"this crawl names both the pool %q and requests_per_second %v; the pool already states a "+
				"rate, so send one or the other", req.Pool, req.RequestsPerSecond)
	}
	var poolLimit *intruder.RateLimit
	if req.Pool != "" {
		limit, err := s.pools.Limit(req.Pool)
		if err != nil {
			return 0, nil, fmt.Errorf("%w (saved pools: %s)", err, availablePools(s.pools))
		}
		poolLimit = &limit
	}

	limits := crawler.DefaultLimits()
	if req.MaxRequests > 0 {
		limits.MaxRequests = req.MaxRequests
	}
	if req.MaxDepth > 0 {
		limits.MaxDepth = req.MaxDepth
	}
	if req.MaxDurationSecs > 0 {
		limits.MaxDuration = time.Duration(req.MaxDurationSecs) * time.Second
	}

	// Built before the task is registered so a configuration mistake is a 400 the operator can fix,
	// not a task that appears in the dashboard only to fail immediately.
	c, err := crawler.New(crawler.Config{
		Seeds:  seeds,
		Scope:  s.scope,
		Sender: s.sender,
		Capture: scanner.Capture{
			Store:    s.store,
			Scanner:  s.passiveScanner,
			Findings: s.findings,
			Logger:   s.logger,
			Source:   core.SourceCrawl,
		},
		Query:             req.Query,
		RetentionQuery:    req.RetentionQuery,
		SubmitForms:       req.SubmitForms,
		Limits:            limits,
		RequestsPerSecond: req.RequestsPerSecond,
		Pool:              poolLimit,
		UserAgent:         req.UserAgent,
		Headers:           req.Headers,
		Logger:            s.logger,
	})
	if err != nil {
		return 0, nil, err
	}
	// The dashboard's Pause all tasks reaches the crawl loop (burpsy-react-ui-cijs). GateCheck is
	// nil-receiver safe, so a process with no task registry attaches a gate that never holds.
	c.WithSuiteGate(s.tasks.GateCheck)

	task := s.tasks.Start(dash.KindCrawl, strings.Join(seeds, ", "), uint64(limits.MaxRequests))
	s.crawls.start(task.ID(), seeds, kind)

	// Detached from the request context on purpose: a crawl outlives the HTTP call that started it,
	// and binding it to r.Context() would cancel the whole crawl the moment the operator's browser
	// navigated away. The bound that actually stops it is Limits.MaxDuration, which the engine
	// enforces, plus the request budget — both reported in the Report either way.
	// The one thing the capture handle could not be given at construction time: the task id does not
	// exist until the task is registered, and the config above is built before it on purpose (a
	// mistyped bound must be a 400, not a task that appears only to fail). Handing the crawler the id
	// afterwards is what makes "show me the traffic this scan produced" answerable at all.
	c.WithTaskID(task.ID())

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		rep := c.Run(ctx)
		s.crawls.finish(task.ID(), &rep, nil)
		task.SetNote(fmt.Sprintf("%d fetched, %d refused, %d failed", rep.Fetched, rep.Refused, rep.Failed))
		task.Advance(uint64(rep.Fetched))
		if kind == crawlKindAudit {
			// Before Finish, because the audit phase's own task id is handed to the findings it
			// produces and the crawl task stays open while it runs — the two rows then read as one
			// scan's two halves, which is what the operator launched.
			s.auditCrawledExchanges(ctx, &rep)
		}
		task.Finish(dash.Breakdown{})
		// changeHistory covers the site map and every traffic-derived count; changeIssues covers the
		// findings the capture path produced along the way. Both, because a crawl is the one tool that
		// routinely moves both at once.
		s.live.notify(changeHistory)
		s.live.notify(changeIssues)
		s.live.notify(changeDashboard)
	}()

	return task.ID(), seeds, nil
}

// auditCrawledExchanges runs the audit half of a crawl-and-audit scan over the exchanges the crawl
// itself produced.
//
// # Where the list comes from
//
// The crawl's own report, not the store. Report.Fetches carries one entry per request that reached
// the target, each with the exchange id the capture path wrote — so the audit is over exactly what
// this crawl fetched, and a second crawl running beside it cannot contribute a single row. A scan of
// "everything recorded since the crawl started" would audit the operator's own browsing, and the
// task row would count it as the scan's work.
//
// # Why it is a second task rather than a phase of the first
//
// The crawl's progress is counted in requests fetched against a request budget, and the audit's work
// is counted in exchanges audited against an exchange count. Folding them into one row would need
// one total in two units, and a fraction computed from that number is a number that means nothing.
// Registering the audit as its own task is the same call the live sweep makes for its own ticks
// (see liveAuditTick), and it is what lets the audit report the engine's own outcome — including the
// checks its budget did not admit — against a total an operator can check.
//
// # What it refuses to leave unsaid
//
// The task is registered even when there is nothing to audit, because "the crawl found no exchanges
// to audit" and "the audit half did not run" are different facts and only one of them is a problem,
// and a row that says the former is the only way to tell them apart on screen.
func (s *Server) auditCrawledExchanges(ctx context.Context, rep *crawler.Report) {
	ids := make([]core.ExchangeID, 0, len(rep.Fetches))
	for _, f := range rep.Fetches {
		ids = append(ids, f.ExchangeID)
	}
	target := fmt.Sprintf("crawl of %s (%d exchange(s))", crawlAuditHost(rep), len(ids))
	task := s.tasks.Start(dash.KindAuditSession, target, uint64(len(ids)))
	// The config comes off the active scanner rather than from a preset name, because a crawl-and-audit
	// is not launched with a configuration — the crawl's card names bounds, not a check set. The engine
	// half is shared with the selection-driven launch (api_scanner_audit.go): two places that both
	// "audit these exchanges" is how a launched scan comes to audit less than a crawl's own phase
	// without anything on screen saying so.
	cfg := s.activeScanner().AuditConfig()
	s.runBulkAudit(ctx, task, target, ids, cfg, "the crawl produced no exchanges to audit")
}

// crawlAuditHost names a crawl for the audit's task row: the first seed's host, or the seed itself
// when it has no parseable host, so the row is never blank.
func crawlAuditHost(rep *crawler.Report) string {
	if len(rep.Seeds) == 0 {
		return "no seeds"
	}
	if u, err := url.Parse(rep.Seeds[0]); err == nil && u.Host != "" {
		return u.Host
	}
	return rep.Seeds[0]
}

// availablePools names the saved pools for an error message, so a refusal says what *is* there.
// "none are saved" rather than an empty list: the two readings of a blank space are "there are none"
// and "the message is broken", and only one of them is true.
func availablePools(reg *pool.Registry) string {
	names := reg.Names()
	if len(names) == 0 {
		return "none are saved"
	}
	return strings.Join(names, ", ")
}
