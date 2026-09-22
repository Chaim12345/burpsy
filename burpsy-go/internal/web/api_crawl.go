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
	"go.uber.org/zap"
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
	// Kind is which scan kind this run is: crawlKindCrawl, crawlKindAudit or runKindAPIScan. Carried
	// on the retained run rather than only in the request, so GET /api/crawl?task=N answers "what kind
	// of scan was that" for a run an operator started this morning, and so the 202 reply echoes the
	// kind the server took rather than the kind the caller hoped it sent.
	Kind string `json:"kind"`
	// Definition is the API-scan half: the document a seeds-only run was built from, what it had to
	// invent, and the endpoints it sent. Nil for the two crawl kinds, which were given URLs and have no
	// definition to describe.
	//
	// Carried on the run rather than returned once from the launch, because "which endpoints did this
	// scan send, and where did those values come from" is a question asked after the scan, when the
	// launch reply is long gone.
	Definition *apiScanSummary `json:"definition,omitempty"`
	State      string          `json:"state"`
	Started    time.Time       `json:"started"`
	Finished   *time.Time      `json:"finished,omitempty"`
	Error      string          `json:"error,omitempty"`
	Report     *crawler.Report `json:"report,omitempty"`
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

// setDefinition attaches an API scan's definition summary to the run the task id names. A no-op when
// the run has already been evicted, which is the same race finish tolerates: retention is bounded by
// run count, and a slow scan can outlive its own entry.
func (c *crawlRuns) setDefinition(taskID uint64, summary *apiScanSummary) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if run := c.byID[taskID]; run != nil {
		run.Definition = summary
	}
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
	// IncludeLiveSeen seeds the crawl from the live sweep's captured-URL set (tqug): every
	// distinct in-scope URL the live audit admitted, wire-observed. Union with Seeds, so a
	// request may name its own origins as well. Taking the set consumes it — a second crawl
	// finds nothing held and says so, rather than silently re-walking the same harvest.
	// With nothing held and no Seeds, the request is refused: a crawl with no origins is
	// not a smaller crawl, it is none.
	IncludeLiveSeen bool `json:"include_live_seen,omitempty"`
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
	taskID, seeds, liveTaken, err := s.startCrawl(req)
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
		// The live-seen count the seeds include (tqug): an operator who asked for live capture
		// needs to know how much of the seed list came from the wire rather than their typing.
		"live_seen_used": liveTaken,
		"state":          state,
		// Echoed for the same reason /api/scanner/audit echoes config_name: a reply that looked the
		// same whether or not the audit half was accepted could not be told apart from one that
		// accepted the kind and ran a plain crawl.
		"kind": kind,
	})
}

// crawlStartStatus maps a start failure from any scan launch to its status. A pool the operator named
// and that is not saved is 404 — the request is well formed and the world is not what they thought —
// while a malformed configuration is 400. Told apart because the fix differs: reload versus retype.
func crawlStartStatus(err error) int {
	if errors.Is(err, pool.ErrNoSuchPool) {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// resolveRunRate turns the two ways a caller can state a scan's rate — a saved pool's name, or an
// inline requests-per-second — into the resolved limit a run gets, or nil for this package's defaults.
//
// Shared by every launch surface rather than repeated in each, because the two rules it encodes are
// the same two for all of them: naming both is a refusal rather than an order of precedence (a scan
// that ran at a rate the operator typed in a box they were told was ignored has no way to find out),
// and a named pool that is not saved is an error rather than a silent fall back to the defaults.
func (s *Server) resolveRunRate(poolName string, requestsPerSecond float64) (*intruder.RateLimit, error) {
	if poolName == "" {
		return nil, nil
	}
	if requestsPerSecond > 0 {
		return nil, fmt.Errorf(
			"this scan names both the pool %q and requests_per_second %v; the pool already states a "+
				"rate, so send one or the other", poolName, requestsPerSecond)
	}
	limit, err := s.pools.Limit(poolName)
	if err != nil {
		return nil, fmt.Errorf("%w (saved pools: %s)", err, availablePools(s.pools))
	}
	return &limit, nil
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

func (s *Server) startCrawl(req crawlStartReq) (taskID uint64, seeds []string, liveTaken int, err error) {
	kind, kerr := scanKind(req.Kind)
	if kerr != nil {
		return 0, nil, 0, kerr
	}
	seeds = make([]string, 0, len(req.Seeds))
	for _, seed := range req.Seeds {
		if t := strings.TrimSpace(seed); t != "" {
			seeds = append(seeds, t)
		}
	}
	// The live passive crawl's seed set (tqug): the sweep's captured URLs, taken (consumed) so
	// a second crawl cannot silently re-walk the same harvest. Union with the named seeds; the
	// honest count rides the reply.
	if req.IncludeLiveSeen && s.liveAudit != nil {
		live, n := s.liveAudit.TakeLiveSeenURLs()
		liveTaken = n
		seeds = append(seeds, live...)
	}
	if len(seeds) == 0 {
		if req.IncludeLiveSeen {
			return 0, nil, 0, errors.New("no seed URLs and no live-captured URLs held: the live audit has not admitted any in-scope traffic to seed from yet")
		}
		return 0, nil, 0, errors.New("At least one seed URL is required")
	}

	poolLimit, err := s.resolveRunRate(req.Pool, req.RequestsPerSecond)
	if err != nil {
		return 0, nil, 0, err
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

	// The audit half's producer, built before the crawler because it is one of the crawler's
	// collaborators now rather than something applied to the report afterwards. It registers nothing
	// and starts nothing yet: a configuration mistake below must still be a 400 with no task row, so
	// the feed only becomes visible once the crawl goroutine starts it.
	var feed *crawlAuditFeed
	var onFetch func(crawler.Fetch)
	if kind == crawlKindAudit {
		feed = newCrawlAuditFeed(s, "crawl of "+seedAuditHost(seeds))
		onFetch = feed.offer
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
		OnFetch:           onFetch,
		Logger:            s.logger,
	})
	if err != nil {
		return 0, nil, 0, err
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
		// Started before Run, not after it: from here on every completed fetch is audited while the
		// crawl is still fetching. Ordering is why this line is where it is — the consumer reads a
		// field the crawl goroutine wrote, and starting it in this goroutine before Run puts the two
		// in a happens-before relation rather than relying on the crawl's own timing.
		if feed != nil {
			feed.start(ctx)
		}
		rep := c.Run(ctx)
		s.crawls.finish(task.ID(), &rep, nil)
		task.SetNote(fmt.Sprintf("%d fetched, %d refused, %d failed", rep.Fetched, rep.Refused, rep.Failed))
		task.Advance(uint64(rep.Fetched))
		if feed != nil {
			// Before Finish and before this goroutine's deferred cancel, because the audit phase's
			// own task id is handed to the findings it produces and the crawl task stays open while
			// it runs — the two rows then read as one scan's two halves, which is what the operator
			// launched. Most of the audit is already done by now; seal waits out the tail of it.
			feed.seal()
		}
		task.Finish(dash.Breakdown{})
		// changeHistory covers the site map and every traffic-derived count; changeIssues covers the
		// findings the capture path produced along the way. Both, because a crawl is the one tool that
		// routinely moves both at once.
		s.live.notify(changeHistory)
		s.live.notify(changeIssues)
		s.live.notify(changeDashboard)
	}()

	return task.ID(), seeds, liveTaken, nil
}

// crawlAuditBatchLimit is how many exchanges one incremental audit batch covers.
//
// Small on purpose. The batch is the unit of latency between a page being fetched and its findings
// being on screen, and the whole point of auditing during the crawl is that the number is small; a
// batch of two hundred would be the end-of-crawl batch again with extra steps. It is not a coverage
// bound — nothing is dropped for exceeding it, the queue simply hands over the next batch — so the
// only thing a larger value buys is fewer task-row updates, and the only thing it costs is the
// latency this exists to remove.
const crawlAuditBatchLimit = 16

// crawlAuditFeed is the audit half of a crawl-and-audit, running beside the crawl instead of after it.
//
// # The gap this closes
//
// Burp's crawl→audit bridge is per-URL and event-driven: a newly-reached URL is published to the
// audit bus as it is reached, so audit work starts mid-crawl. burpsy handed the finished
// Report.Fetches to the audit engine once c.Run had returned, which made "crawl and audit" a crawl
// *then* an audit. On a twenty-minute crawl the first finding could not appear until minute twenty,
// and a crawl the operator stopped at minute nineteen produced no findings at all despite having
// fetched hundreds of auditable exchanges. The crawl already knew about each fetch the instant it
// completed; the information was there and was being thrown away until the end.
//
// # Where the list comes from
//
// The crawl's own fetches, announced by the crawl, never the store. Every id audited here came from
// a request this crawl made, so a second crawl running beside it cannot contribute a single row and
// neither can the operator's own browser. A scan of "everything recorded since the crawl started"
// would audit traffic the operator did not launch a scan for, and the task row would count it as
// this scan's work. That property survived the move off the finished Report.Fetches because the
// source is still the same crawl — it is now announcing each fetch instead of handing over a list.
//
// # Why a crawl-side callback, and not a channel into the live sweep
//
// The obvious-looking shape is to push each ExchangeID into a queue the always-on live sweep
// consumes. It was rejected. The sweep walks store ids *in order* precisely because an id is handed
// out at capture time and a later id can complete before an earlier one, so auditing past a gap
// would skip a request still in flight; liveAuditStallTicks, Skipped, StalledAt and RetryStalled all
// exist to manage exactly that. An event-driven push has no gap to wait at, so it would retire the
// four of them and silently drop the coverage accounting they produce. The sweep's job is "audit
// everything that has been captured, in order, missing nothing"; this one's is "audit what this scan
// just fetched, as it fetches it". Two different jobs, and folding the second into the first costs
// the first its honesty.
//
// # One task row, not one per batch
//
// The row is registered when the crawl starts and its total grows as fetches arrive (dash.Handle
// has SetTotal for exactly this). A row per batch would make a crawl-and-audit produce dozens of
// KindAuditSession rows an operator would have to add up to answer "did the audit cover what the
// crawl fetched", which is the one question the row exists to answer. The trade is that the total is
// provisional while the crawl runs — it is the fetches so far, not a prediction — and done/total is
// therefore a rate rather than a fraction of a known whole until the crawl finishes.
//
// # What is genuinely different from the end-of-crawl batch
//
// Two things, both deliberate. The AuditLedger is created once here and handed to every batch, so
// the scope collapse that makes 500 captures of one URL dispatch once still happens across batch
// boundaries — without it, incremental auditing would do strictly more work than the batch it
// replaces. The time and request budgets cannot be shared that way (AuditSession starts a fresh
// auditRun per call), so they bound each batch rather than the scan. That is the same bargain the
// live sweep already makes for its own per-tick sessions, and it is stated here rather than left to
// be discovered from a request count.
type crawlAuditFeed struct {
	s      *Server
	target string
	// cfg is snapshotted once, when the scan is launched, so every batch of one run audits under the
	// configuration the run was started with. Re-reading the active scanner per batch would let a
	// mid-crawl settings change split one scan into two different scans with one row.
	cfg scanner.AuditConfig

	// mu guards the queue and the counters, which the crawl goroutine writes (offer) and the
	// consumer goroutine reads (take).
	mu      sync.Mutex
	pending []core.ExchangeID
	queued  uint64
	sealed  bool

	// wake is a capacity-1 signal, never a queue: offer does a non-blocking send, so a crawl that
	// outruns the audit is never *slowed* by it, and a full channel means "the consumer already has
	// work to find" rather than a lost fetch. The ids themselves live in pending, which is unbounded
	// for the reason a bounded one would be wrong — dropping an id on a full buffer is coverage loss
	// that nothing on screen would report.
	wake chan struct{}
	done chan struct{}

	// task and outcome are touched only by the consumer goroutine after start, so they need no lock.
	task    *dash.Handle
	outcome scanner.SessionOutcome
}

// newCrawlAuditFeed prepares the audit half of a crawl-and-audit without registering or starting
// anything: the crawler it is handed to may still fail to build, and a scan that was refused with a
// 400 must leave no task row behind. start does the visible half.
func newCrawlAuditFeed(s *Server, target string) *crawlAuditFeed {
	// The config comes off the active scanner rather than from a preset name, because a
	// crawl-and-audit is not launched with a configuration — the crawl's card names bounds, not a
	// check set. Same call auditFetchedExchanges makes, so the two launch surfaces cannot disagree
	// about what a crawl's audit runs.
	cfg := s.activeScanner().AuditConfig()
	cfg.Ledger = scanner.NewAuditLedger()
	return &crawlAuditFeed{
		s:      s,
		target: target,
		cfg:    cfg,
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
}

// start registers the audit's task row and starts the consumer. It must be called before the crawl
// runs and from the same goroutine that runs it, which is what orders the write of task against the
// reads offer makes from the crawl's own goroutine.
//
// The row is registered even for a crawl that turns out to fetch nothing, because "the crawl found
// no exchanges to audit" and "the audit half did not run" are different facts, only one of them is a
// problem, and a row that says the former is the only way to tell them apart on screen.
func (f *crawlAuditFeed) start(ctx context.Context) {
	f.task = f.s.tasks.Start(dash.KindAuditSession, f.target+" (audited during the crawl)", 0)
	go f.run(ctx)
}

// offer is the crawler's OnFetch callback: one completed fetch, announced from the crawl goroutine.
//
// It does an append and a non-blocking signal and returns, because it runs synchronously inside the
// crawl loop — anything slower here would turn audit latency into crawl latency, which is the
// failure mode that makes an event-driven bridge worse than the batch it replaces.
func (f *crawlAuditFeed) offer(fetch crawler.Fetch) {
	f.mu.Lock()
	f.pending = append(f.pending, fetch.ExchangeID)
	f.queued++
	queued := f.queued
	f.mu.Unlock()
	// The total is the fetches so far, restated on every arrival. It is honest rather than
	// predictive: a crawl's final fetch count is not knowable while it is running, and a row showing
	// the request *budget* as the audit's total would report a fraction of a number the audit was
	// never going to reach.
	f.task.SetTotal(queued)
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// take pops up to n queued ids, and reports whether the crawl has finished announcing.
func (f *crawlAuditFeed) take(n int) (batch []core.ExchangeID, sealed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pending) == 0 {
		return nil, f.sealed
	}
	if n > len(f.pending) {
		n = len(f.pending)
	}
	// Full three-index slice: the batch keeps its own cap, so a later append to pending cannot reach
	// the ids a running audit is holding.
	batch = f.pending[0:n:n]
	f.pending = f.pending[n:]
	return batch, false
}

// seal tells the consumer the crawl is done announcing and waits for it to drain the queue and close
// out the task row. Called from the crawl goroutine once Run has returned, before the crawl's own
// task is finished and before its context is cancelled.
func (f *crawlAuditFeed) seal() {
	f.mu.Lock()
	f.sealed = true
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
	<-f.done
}

// run is the consumer: batch, audit, repeat, until the crawl is sealed or the run is cancelled.
func (f *crawlAuditFeed) run(ctx context.Context) {
	defer close(f.done)
	for ctx.Err() == nil {
		batch, sealed := f.take(crawlAuditBatchLimit)
		if len(batch) > 0 {
			f.audit(ctx, batch)
			continue
		}
		if sealed {
			break
		}
		select {
		case <-f.wake:
		case <-ctx.Done():
		}
	}
	f.finish(ctx)
}

// audit runs one batch and lands its findings immediately.
//
// Immediately, rather than accumulated and added at the end, is the whole deliverable: a finding
// from the first page is on screen while the crawl is still walking the twentieth, and a scan the
// operator stops early keeps everything it had already found.
func (f *crawlAuditFeed) audit(ctx context.Context, ids []core.ExchangeID) {
	cfg := f.cfg
	// The queue, for the same reason the live sweep and the bulk paths attach it: an audit split into
	// batches is exactly the caller that makes "which of these did the budget bound" answerable.
	cfg.Items = f.s.auditItems
	outcome, findings := f.s.activeScanner().AuditSession(ctx, ids, cfg)
	f.task.Advance(uint64(len(ids)))
	f.merge(outcome)
	for _, finding := range findings {
		f.s.findings.Add(f.s.activeFinding(finding, f.task.ID()))
	}
	f.task.SetNote(f.outcome.Summary())
	f.s.live.notify(changeIssues)
	f.s.live.notify(changeDashboard)
}

// merge folds one batch's outcome into the run's. Consumer-goroutine only, so it takes no lock.
//
// Everything SessionOutcome derives — Completed, NotAdmitted, AlreadyCovered, Summary, Breakdown —
// folds over Items plus the scalars, so appending and summing gives the same answer one session over
// the same ids would have given. DispatchUnits is the exception and is *replaced*, not added: it is
// read off the ledger as a running total of the units that ledger has seen, and this run shares one
// ledger across every batch, so summing it would count the first batch's units again in the second.
func (f *crawlAuditFeed) merge(o *scanner.SessionOutcome) {
	if o == nil {
		return
	}
	f.outcome.Items = append(f.outcome.Items, o.Items...)
	f.outcome.Findings += o.Findings
	f.outcome.RequestsSent += o.RequestsSent
	f.outcome.FailedItems += o.FailedItems
	f.outcome.DispatchUnits = o.DispatchUnits
	f.outcome.Paused = f.outcome.Paused || o.Paused
	f.outcome.TimedOut = f.outcome.TimedOut || o.TimedOut
}

// finish closes the audit row out: the deferred second look, then the run's merged outcome.
func (f *crawlAuditFeed) finish(ctx context.Context) {
	f.mu.Lock()
	queued, unaudited := f.queued, len(f.pending)
	f.mu.Unlock()

	if queued == 0 {
		f.task.FinishWithNote(dash.Breakdown{}, "the crawl produced no exchanges to audit")
		return
	}
	// The deferred half (gxbk), same guard and same reasoning as runBulkAudit's tail: settle only
	// when a claim was actually registered, and before the task's finish call, because a finished
	// task must not be cancellable and Handle.finish clears the cancel the re-fetch pass needs.
	active := f.s.activeScanner()
	if active.PendingCount() > 0 {
		deferred, completion := active.FinishScan(ctx)
		f.s.events.RecordFor(f.task.ID(), dash.EventAuditBounded, dash.SeverityInfo, fmt.Sprintf(
			"deferred phase of %s: %s (outstanding: %d)", f.target, completion.Pending, len(completion.Outstanding)))
		for _, finding := range deferred {
			f.s.findings.Add(f.s.activeFinding(finding, f.task.ID()))
		}
	}
	// A cancelled run is reported as stopped, not done, and says how many announced fetches it never
	// reached. Those two rows mean different things to the operator reading them — "the audit looked
	// at all of it" and "someone stopped the scan with forty still queued" — and only one of them is
	// a result.
	if ctx.Err() != nil {
		f.task.Stop(f.outcome.Breakdown(), fmt.Sprintf(
			"stopped: %s; %d fetched exchange(s) never reached the audit", f.outcome.Summary(), unaudited))
	} else {
		f.task.FinishWithNote(f.outcome.Breakdown(), f.outcome.Summary())
	}
	f.s.events.RecordFor(f.task.ID(), dash.EventAuditBounded, auditOutcomeSeverity(&f.outcome), fmt.Sprintf(
		"audit of %s: %s", f.target, f.outcome.Summary()))
	f.s.logger.Debug("crawl audit",
		zap.Uint64("exchanges", queued),
		zap.Int("unaudited", unaudited),
		zap.String("engine", f.outcome.Summary()))
	if f.outcome.Paused || f.outcome.TimedOut {
		f.s.logger.Warn("a crawl's audit was bounded before it finished",
			zap.Uint64("exchanges", queued),
			zap.Int("checks_not_admitted", f.outcome.NotAdmitted()),
			zap.Bool("paused", f.outcome.Paused),
			zap.Bool("timed_out", f.outcome.TimedOut))
	}
	f.s.live.notify(changeIssues)
	f.s.live.notify(changeDashboard)
}

// auditFetchedExchanges runs the audit half of a scan whose fetches are all known before the audit
// starts. One caller now: the API-only sweep.
//
// # Why the API scan stays a batch when the crawl no longer is
//
// A crawl discovers its attack surface as it walks, so its fetch list does not exist until it
// finishes — which is what made auditing from the finished report a twenty-minute wait, and why the
// crawl's half is now fed per fetch by crawlAuditFeed. An API-only scan's surface is the definition
// it was handed: every request it will send is known before the first one goes out, and the run is a
// fixed list walked once. There is nothing to overlap that is not already overlapping, so the extra
// machinery would buy latency back from a run that never had it to lose.
//
// subject names the run for the task row. Kept as a parameter rather than inlined because this body
// was shared before the crawl left it and is worth keeping shareable: two places that both "audit
// these exchanges" is how one launched scan comes to audit less than another with nothing on screen
// saying which.
func (s *Server) auditFetchedExchanges(ctx context.Context, rep *crawler.Report, subject string) *scanner.SessionOutcome {
	ids := make([]core.ExchangeID, 0, len(rep.Fetches))
	for _, f := range rep.Fetches {
		ids = append(ids, f.ExchangeID)
	}
	target := fmt.Sprintf("%s (%d exchange(s))", subject, len(ids))
	task := s.tasks.Start(dash.KindAuditSession, target, uint64(len(ids)))
	// The config comes off the active scanner rather than from a preset name, because a crawl-and-audit
	// is not launched with a configuration — the crawl's card names bounds, not a check set. The engine
	// half is shared with the selection-driven launch (api_scanner_audit.go): two places that both
	// "audit these exchanges" is how a launched scan comes to audit less than a crawl's own phase
	// without anything on screen saying so.
	cfg := s.activeScanner().AuditConfig()
	return s.runBulkAudit(ctx, task, target, ids, cfg, "the run produced no exchanges to audit")
}

// seedAuditHost names a crawl for the audit's task row: the first seed's host, or the seed itself
// when it has no parseable host, so the row is never blank.
//
// It takes the seed list rather than the finished Report because the audit row now exists before the
// report does — the row is registered as the crawl starts, not written from its outcome.
func seedAuditHost(seeds []string) string {
	if len(seeds) == 0 {
		return "no seeds"
	}
	if u, err := url.Parse(seeds[0]); err == nil && u.Host != "" {
		return u.Host
	}
	return seeds[0]
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
