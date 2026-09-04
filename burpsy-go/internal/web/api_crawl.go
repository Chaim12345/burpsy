package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	TaskID   uint64          `json:"task_id"`
	Seeds    []string        `json:"seeds"`
	State    string          `json:"state"`
	Started  time.Time       `json:"started"`
	Finished *time.Time      `json:"finished,omitempty"`
	Error    string          `json:"error,omitempty"`
	Report   *crawler.Report `json:"report,omitempty"`
}

func newCrawlRuns() *crawlRuns {
	return &crawlRuns{byID: map[uint64]*crawlRun{}}
}

func (c *crawlRuns) start(taskID uint64, seeds []string) *crawlRun {
	c.mu.Lock()
	defer c.mu.Unlock()
	run := &crawlRun{TaskID: taskID, Seeds: seeds, State: "running", Started: time.Now()}
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

// crawlStartReq is the POST body. Every bound is optional and falls back to the engine's own
// documented default rather than to a value invented here, so "what bounds a crawl" has one answer.
type crawlStartReq struct {
	Seeds []string `json:"seeds"`
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
	state := ""
	if run != nil {
		state = run.State
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"task_id": taskID,
		"seeds":   seeds,
		"state":   state,
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
func (s *Server) startCrawl(req crawlStartReq) (uint64, []string, error) {
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

	task := s.tasks.Start(dash.KindCrawl, strings.Join(seeds, ", "), uint64(limits.MaxRequests))
	s.crawls.start(task.ID(), seeds)

	// Detached from the request context on purpose: a crawl outlives the HTTP call that started it,
	// and binding it to r.Context() would cancel the whole crawl the moment the operator's browser
	// navigated away. The bound that actually stops it is Limits.MaxDuration, which the engine
	// enforces, plus the request budget — both reported in the Report either way.
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		rep := c.Run(ctx)
		s.crawls.finish(task.ID(), &rep, nil)
		task.SetNote(fmt.Sprintf("%d fetched, %d refused, %d failed", rep.Fetched, rep.Refused, rep.Failed))
		task.Advance(uint64(rep.Fetched))
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
