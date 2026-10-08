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
	"github.com/burpsy-go/burpsy/internal/domexec"
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
	// Limits is the effective bound set this run was launched with, after defaults were filled in
	// and any named configuration overlaid (burpsy-react-ui-qzzy).
	//
	// Carried on the run rather than only inside the finished Report, because a crawl that is still
	// running — or one that found nothing and reported no report — is exactly the case where an
	// operator asks "what was this bounded by" and the answer has to exist. A bound that fires with
	// no control behind it is indistinguishable from a bug, and the eight bounds that had no wire
	// field at all were all in that position.
	//
	// Marshalled through crawlLimitsView rather than as crawler.Limits directly, because the Go struct
	// has no json tags and would publish as "MaxLocations" while every other bound on this endpoint
	// is snake_case (max_requests, max_depth). One endpoint with two conventions is an endpoint a
	// console has to special-case, and the run record is the wrong place to discover that.
	Limits *crawlLimitsView `json:"limits,omitempty"`
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

// snapshot returns a copy of the run safe to read without the lock.
//
// The pointer start() returned used to be handed straight back out by get() and list(), which is a
// data race the moment the run is still in flight: finish() and setDefinition() write State, Report,
// Finished and Definition under c.mu, while every caller read those same fields after get() had
// already released it. The mutex guarded the map, not the struct it handed over - so the fields a
// report is made of were never protected at all, and `go test -race` flagged every stored run.
//
// Copying under the lock is the fix rather than locking at each call site: the readers are a JSON
// encode, a dashboard list, and a launch reply, and none of them should have to know a run can be
// written while it is being read. Report and Finished are pointers, but their pointees are written
// once and never mutated afterwards, so sharing them in the copy is safe; Seeds is copied because
// it is the one slice a caller could plausibly retain.
func (r *crawlRun) snapshot() crawlRun {
	out := *r
	out.Seeds = append([]string(nil), r.Seeds...)
	return out
}

func newCrawlRuns() *crawlRuns {
	return &crawlRuns{byID: map[uint64]*crawlRun{}}
}

// CrawlDefaults is the engine's own default bound set, published on GET /api/crawl so a console can
// mark "which bounds are not the default" without keeping a second table.
//
// Added because the console's first version carried its own copy and got MaxRelogins wrong (10 in the
// table, 5 in the engine) — verified by reading a live run, which showed a bound the operator never
// set presented as one they had. A duplicate source of truth for eleven numbers is a defect waiting
// for the first default to change, and there is no way to test a hard-coded table against the thing
// it is supposed to describe.
var CrawlDefaults = newCrawlLimitsView(crawler.DefaultLimits())

func (c *crawlRuns) start(taskID uint64, seeds []string, kind string, limits crawler.Limits) *crawlRun {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Aliased, not copied. Checked rather than assumed: startCrawl applies every field and then makes
	// no further write to `limits` before calling this, and the caller does not outlive the call, so
	// a defensive copy would be provably a no-op — and an untestable one, since a mutation that
	// removed it changes nothing (verified: M3 in the mutation log).
	run := &crawlRun{
		TaskID: taskID, Seeds: seeds, Kind: kind, State: "running", Started: time.Now(),
		Limits: newCrawlLimitsView(limits),
	}
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

func (c *crawlRuns) get(taskID uint64) (crawlRun, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	run, ok := c.byID[taskID]
	if !ok {
		return crawlRun{}, false
	}
	return *run, true
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
func (c *crawlRuns) list() []crawlRun {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]crawlRun, 0, len(c.order))
	for _, id := range c.order {
		if run := c.byID[id]; run != nil {
			out = append(out, run.snapshot())
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
	// SeedFromSiteMap pre-marks every request the site map already holds for the seeds' origins as
	// already made (burpsy-react-ui-z8qf), so a second crawl of a site does not repeat the first
	// crawl's discovery cost. Burp pre-seeds its crawl dedup the same way (Zrbx.java:91-93).
	//
	// Opt-in, and the reason is coverage: a request the site map holds is NOT fetched, so its links are
	// not extracted. That is free when the map came from an earlier crawl — that crawl followed those
	// links and they are in the map too — but a page the operator only BROWSED through the proxy may
	// link to pages nothing has visited, and seeding it would hide them. The crawl's own seeds are never
	// pre-marked, scope is honoured on the way in, and the count rides the report (sitemap_seeded).
	SeedFromSiteMap bool `json:"seed_from_site_map,omitempty"`
	// RequestWellKnown requests the standard .well-known documents once per seed authority
	// (burpsy-react-ui-bc2x) — security.txt, OpenID/OAuth metadata, app-link associations, a CSAF
	// index. Opt-in: it adds seven requests per authority.
	RequestWellKnown bool `json:"request_well_known,omitempty"`
	// Config is a scan configuration by name, applied to the CRAWL half of it (burpsy-react-ui-3ok6).
	//
	// A Burp configuration carries a `scanner` object and a `crawler` object, and importing one is a
	// first-class migration path. Until now only the scanner half arrived: the crawler object present
	// in 9 of Burp's 29 shipped configurations, ten keys across them, was parsed into nothing, so a
	// third of a shipped configuration silently did not.
	//
	// Empty is the default and is not an error, exactly as on the audit path. The reply names the
	// keys the configuration set that this engine did not apply, so the loss is visible rather than
	// inferred from a crawl that behaved like the defaults.
	Config string `json:"config,omitempty"`
	// LoginPagePattern is a regex matched against a response body to recognise the application's
	// own login page (burpsy-react-ui-nc9s). It is the SECOND signal for a lost session, beside
	// the 200→non-200 status flip the crawler detects on its own: a login page served with a 200 is
	// the case the flip cannot see, and it is the common one behind an SPA that returns its shell for
	// every route.
	//
	// Empty disables this signal and keeps the status flip, so the field is optional rather than
	// required. A malformed pattern is refused as a 400 by crawler.New, before any task row exists —
	// the same rule the rest of this request follows, so a configuration mistake is something the
	// operator fixes rather than a crawl that appears in the dashboard and then fails.
	LoginPagePattern string `json:"login_page_pattern,omitempty"`
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
	SubmitForms bool `json:"submit_forms"`
	// RequestSpeculative turns on the speculative-hidden-link phase (burpsy-react-ui-t5m0):
	// mining HTML comments and script bodies for hidden links. Off by default here — the
	// operator's explicit request is the switch, and a named Burp configuration can set it
	// (crawler/customization/request_speculative lands through the config overlay below).
	RequestSpeculative bool `json:"request_speculative"`
	// MaxSpeculativeLinks caps how many mined candidates the crawl admits, when the
	// phase is on. A POINTER so an explicit 0 (admit none) is distinguishable from unset
	// (take the default of 1000, Burp's own shipped default).
	MaxSpeculativeLinks *int `json:"max_speculative_links,omitempty"`
	// The three bounds that predate the rest, kept as plain ints, and the eight that joined them as
	// POINTERS. The difference is load-bearing and it is the iueb shape the scanner keys already
	// refused (burpsy-react-ui-qzzy).
	//
	// Every bound is a COUNT or a LENGTH, so 0 is a real value: zero locations is a crawl that
	// fetched one page and admitted nothing, and zero max-links-per-page is a crawl that follows no
	// link at all. `if n > 0` reads 0 as "unset" and silently runs the DEFAULT instead, so an operator
	// who asked for a bounded-nothing crawl gets five hundred requests and a report saying the
	// default stopped it — a confident wrong answer, and the exact defect the limits module exists to
	// avoid. A pointer separates "not set" from "set to zero" the way OptUint32 does on the audit
	// path, and a caller who sends nothing keeps the default.
	//
	// The three below are left as ints for compatibility with every caller predating this change,
	// and they carry the same 0-means-default rule. That asymmetry is deliberate and visible rather
	// than silently wrong: converting them is a wire break for a field the UI has always sent.
	MaxRequests     int `json:"max_requests"`
	MaxDepth        int `json:"max_depth"`
	MaxDurationSecs int `json:"max_duration_secs"`
	// MaxLocations caps distinct content fingerprints. The bound that stops an application whose
	// URLs are unbounded but whose pages are not — a calendar generating a URL per month.
	MaxLocations *int `json:"max_locations,omitempty"`
	// MaxFrontier caps queued-but-unfetched URLs. Bounds the queue's memory; links arriving at a
	// full frontier are dropped and counted rather than silently discarded.
	MaxFrontier *int `json:"max_frontier,omitempty"`
	// MaxLinksPerPage caps links and forms taken from one response. A generated index page can carry
	// a hundred thousand links, and admitting them all fills the frontier from one document.
	MaxLinksPerPage *int `json:"max_links_per_page,omitempty"`
	// MaxParseBytes caps the bytes of a response body examined for links. The body is still stored
	// and scanned in full; the tail is only never examined for links.
	MaxParseBytes *int `json:"max_parse_bytes,omitempty"`
	// MaxTemplateVisits caps fetches of one URL template. The honest cutoff for the infinite-
	// application shape: twenty samples of one shape is enough to see whether it behaves consistently.
	MaxTemplateVisits *int `json:"max_template_visits,omitempty"`
	// MaxCaptureBytes caps the size of a response that is stored and scanned at all. Past it the
	// response is neither stored nor scanned, which is why it has its own stop and is not folded
	// into the parse bound.
	MaxCaptureBytes *int `json:"max_capture_bytes,omitempty"`
	// MaxFingerprints caps each of the two request-identity tables. Reached, further unseen URLs are
	// refused admission rather than remembered, and the crawl says so via StopFingerprintBudget.
	MaxFingerprints *int `json:"max_fingerprints,omitempty"`
	// MaxRelogins caps session-recovery attempts. Each costs a full login round trip, so a target
	// whose session keeps expiring spends the crawl on logins rather than on pages.
	MaxRelogins *int `json:"max_relogins,omitempty"`
	// Burp's crawler.error_handling family (burpsy-react-ui-o0c5), under Burp's own key names. Every
	// one is a POINTER because 0 is a real answer: Burp's shipped "Never stop crawl due to application
	// errors" sets all three pause thresholds to 0, and an int read as "0 means unset" would turn that
	// into a crawl that pauses where the operator explicitly said never. Absent means the named
	// configuration's value, or Burp's default when there is none; present overrides both.
	PauseOnTimeoutCount   *int `json:"pause_task_requests_timed_out_count,omitempty"`
	PauseOnTimeoutPercent *int `json:"pause_task_requests_timed_out_percentage,omitempty"`
	PauseOnAuthFailures   *int `json:"consecutive_authentication_failures_before_pausing_task,omitempty"`
	FollowUpPasses        *int `json:"number_of_follow_up_passes,omitempty"`
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

// validateCrawlBounds refuses a bound that is not a bound.
//
// REFUSED rather than clamped, and the distinction is the point. A negative limit is not "no limit"
// and not "the default" — it is a request that cannot be honoured, and the three answers available
// to the engine (treat it as the default, treat it as zero, treat it as unlimited) each produce a
// crawl that reports a result nobody asked for. Clamping to the default would be the worst of the
// three: the crawl runs, fills its frontier, stops on the default, and the report names a stop the
// operator never chose.
//
// Zero is ACCEPTED, which is why the eight fields are pointers. Zero is a real answer for every
// bound in this set — zero locations, zero links per page, zero re-logins — and the only way to tell
// it from "not set" is the pointer. This is the iueb shape the audit path's OptUint32 already
// refuses to flatten, applied to the crawler.
func validateCrawlBounds(req crawlStartReq) error {
	// name/value pairs, in the order the request declares them, so a request naming several bad
	// bounds is answered with all of them rather than one per attempt.
	bad := make([]string, 0, 4)
	for _, b := range []struct {
		name  string
		value *int
	}{
		{"max_requests", intPtr(req.MaxRequests)}, {"max_depth", intPtr(req.MaxDepth)},
		{"max_locations", req.MaxLocations}, {"max_frontier", req.MaxFrontier},
		{"max_links_per_page", req.MaxLinksPerPage}, {"max_parse_bytes", req.MaxParseBytes},
		{"max_template_visits", req.MaxTemplateVisits}, {"max_capture_bytes", req.MaxCaptureBytes},
		{"max_fingerprints", req.MaxFingerprints}, {"max_relogins", req.MaxRelogins},
	} {
		if b.value != nil && *b.value < 0 {
			bad = append(bad, fmt.Sprintf("%s: %d is negative; a bound is a count of what may happen "+
				"and a negative one cannot be honoured — send 0 for none, or omit it for the default", b.name, *b.value))
		}
	}
	if req.MaxDurationSecs < 0 {
		bad = append(bad, fmt.Sprintf("max_duration_secs: %d is negative; a negative duration is not "+
			"a shorter crawl", req.MaxDurationSecs))
	}
	if len(bad) == 0 {
		return nil
	}
	return errors.New(strings.Join(bad, "; "))
}

// intPtr lifts a plain int field to the pointer shape the eight optional bounds use, so one loop
// validates both. Nil for the three legacy fields when they are zero, which is exactly their
// "unset" reading and keeps them out of the negative check.
func intPtr(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}

// crawlLimitsView is the effective bound set as the wire spells it: snake_case, seconds for the
// duration, and every field present.
//
// Present rather than omitempty, so a run record names every bound that bounded it instead of the
// console having to know which ones it may assume. MaxDuration is seconds because that is what the
// launch request takes (max_duration_secs) and what an operator reads; the engine's time.Duration is
// nanoseconds, and publishing those would be a number nobody asked for.
type crawlLimitsView struct {
	MaxRequests       int `json:"max_requests"`
	MaxDepth          int `json:"max_depth"`
	MaxDurationSecs   int `json:"max_duration_secs"`
	MaxLocations      int `json:"max_locations"`
	MaxFrontier       int `json:"max_frontier"`
	MaxLinksPerPage   int `json:"max_links_per_page"`
	MaxParseBytes     int `json:"max_parse_bytes"`
	MaxTemplateVisits int `json:"max_template_visits"`
	MaxCaptureBytes   int `json:"max_capture_bytes"`
	MaxFingerprints   int `json:"max_fingerprints"`
	MaxRelogins       int `json:"max_relogins"`
}

func newCrawlLimitsView(l crawler.Limits) *crawlLimitsView {
	return &crawlLimitsView{
		MaxRequests:       l.MaxRequests,
		MaxDepth:          l.MaxDepth,
		MaxDurationSecs:   int(l.MaxDuration / time.Second),
		MaxLocations:      l.MaxLocations,
		MaxFrontier:       l.MaxFrontier,
		MaxLinksPerPage:   l.MaxLinksPerPage,
		MaxParseBytes:     l.MaxParseBytes,
		MaxTemplateVisits: l.MaxTemplateVisits,
		MaxCaptureBytes:   l.MaxCaptureBytes,
		MaxFingerprints:   l.MaxFingerprints,
		MaxRelogins:       l.MaxRelogins,
	}
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
	writeJSON(w, http.StatusOK, map[string]any{"crawls": s.crawls.list(), "default_limits": CrawlDefaults})
}

func (s *Server) handleCrawlStart(w http.ResponseWriter, r *http.Request) {
	var req crawlStartReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	taskID, seeds, liveTaken, unapplied, err := s.startCrawl(req)
	if err != nil {
		http.Error(w, err.Error(), crawlStartStatus(err))
		return
	}
	run, ok := s.crawls.get(taskID)
	state, kind := "", crawlKindCrawl
	if ok {
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
		// The keys the named configuration set that this engine did not apply, the same
		// not-silent half the audit path reports (burpsy-react-ui-3ok6). Present because the crawler
		// object in a shipped Burp configuration was previously parsed into nothing at all: an
		// operator importing one had no way to know a third of it had not arrived.
		"config_name":           req.Config,
		"config_unapplied_keys": unapplied,
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

// crawlRenderer is the browser hand-off the crawler's rendered-DOM pass runs on
// (burpsy-react-ui-nx7b): the SAME lazy provider the audit's DOM checks use, so one process
// runs one browser rather than one per subsystem, and a crawl started with no -dom gets a
// nil function — which is the previous crawl to the byte, because a nil Render means no
// rendered pass and no skip recorded (nothing was declined).
//
// Built per crawl rather than stored on the server, because the provider is the scanner's
// capability, not the web layer's: the audit scanner is constructed with its browser at
// startup (cmd/burpsy/main.go), and the crawl borrows it for exactly as long as the crawl
// runs. A scan whose DOM checks declined for a missing browser reports the same decline to
// the crawl, which records it as SkipRenderUnavailable per URL rather than pretending the
// wire parse was the whole story.
func (s *Server) crawlRenderer() func(ctx context.Context, url string) (string, crawler.RenderOutcome, error) {
	if s.scanner == nil || !s.scanner.DOMCapabilityConfigured() {
		// NIL, not a zero-valued render. A no-DOM server is a crawl that never renders, and a
		// function that returns "" would be a render that always produced nothing -- which the engine
		// cannot tell from a page that genuinely had none, and would report as SkipRenderUnavailable
		// on every URL of a crawl that was never supposed to render one.
		return nil
	}
	return func(ctx context.Context, targetURL string) (string, crawler.RenderOutcome, error) {
		browser, err := s.scanner.BrowserForRender(ctx)
		if err != nil {
			return "", crawler.RenderOutcome{}, err
		}
		// The OUTCOME form, so a render that reached its cap is reported as capped. The previous
		// call read the DOM after a fixed 300 ms and said nothing about whether the page had settled
		// (burpsy-react-ui-efra): a client-rendered route populating after load contributed no links
		// and the crawl reported the application as having almost no locations, which is a confident
		// wrong answer rather than a missing feature.
		html, outcome, err := browser.RenderedDOMWithOptions(ctx, targetURL, domexec.RenderOptions{
			DOMQuiet:    domexec.DefaultDOMQuiet,
			NetworkIdle: domexec.DefaultNetworkIdle,
			MaxWait:     domexec.DefaultMaxRenderWait,
		})
		reqs := make([]crawler.RenderedRequest, 0, len(outcome.Requests))
		for _, r := range outcome.Requests {
			reqs = append(reqs, crawler.RenderedRequest{URL: r.URL, Method: r.Method})
		}
		return html, crawler.RenderOutcome{
			Settled:  outcome.Settled,
			Capped:   outcome.Capped,
			Waited:   outcome.Waited,
			Requests: reqs,
		}, err
	}
}

func (s *Server) startCrawl(req crawlStartReq) (taskID uint64, seeds []string, liveTaken int, unapplied []string, err error) {
	if berr := validateCrawlBounds(req); berr != nil {
		return 0, nil, 0, nil, berr
	}
	kind, kerr := scanKind(req.Kind)
	if kerr != nil {
		return 0, nil, 0, nil, kerr
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
			return 0, nil, 0, nil, errors.New("no seed URLs and no live-captured URLs held: the live audit has not admitted any in-scope traffic to seed from yet")
		}
		return 0, nil, 0, nil, errors.New("At least one seed URL is required")
	}

	poolLimit, err := s.resolveRunRate(req.Pool, req.RequestsPerSecond)
	if err != nil {
		return 0, nil, 0, nil, err
	}

	limits := crawler.DefaultLimits()
	// The error-handling family starts UNSET rather than at the engine's defaults, so a request that
	// names no threshold and no configuration inherits DefaultErrorHandling at the point the crawler
	// reads it. Seeding it here with the defaults would make "the file set all three to 0" and "the
	// file said nothing" the same value, which is the distinction the whole family rests on (o0c5).
	var eh crawler.ErrorHandling
	var configSpeculative bool
	var configSpeculativeLinks int
	// A named configuration's crawler half is overlaid UNDER the explicit per-request limits, so a
	// field the operator typed on this request still wins over the file they also named. The other
	// order would make a configuration silently override the request that named it.
	crawlCfgName, crawlUnapplied, cerr := s.resolveCrawlConfig(req.Config)
	if cerr != nil {
		return 0, nil, 0, nil, cerr
	}
	if req.Config != "" {
		whole := s.crawlConfigFromConfig(crawlCfgName)
		limits = whole.Limits
		eh = whole.ErrorHandling
		configSpeculative = whole.RequestSpeculative
		configSpeculativeLinks = whole.Limits.MaxSpeculativeLinks
	}
	// The error-handling keys overlay the named configuration the same way the limits do: a field the
	// operator typed on this request wins over the file they also named (o0c5).
	if req.PauseOnTimeoutCount != nil {
		eh.PauseOnTimeoutCount = req.PauseOnTimeoutCount
	}
	if req.PauseOnTimeoutPercent != nil {
		eh.PauseOnTimeoutPercent = req.PauseOnTimeoutPercent
	}
	if req.PauseOnAuthFailures != nil {
		eh.PauseOnAuthFailures = req.PauseOnAuthFailures
	}
	if req.FollowUpPasses != nil {
		eh.FollowUpPasses = req.FollowUpPasses
	}
	if err := eh.Validate(); err != nil {
		return 0, nil, 0, nil, err
	}
	// The speculative phase and its cap overlay UNDER the explicit per-request fields,
	// the same order as the limits: a field the operator typed on this request wins over
	// the file they also named. The cap lands on the limits; the switch itself is carried
	// to crawlConfig, which owns the Config literal.
	if req.RequestSpeculative {
		configSpeculative = true
	}
	if req.MaxSpeculativeLinks != nil {
		configSpeculativeLinks = *req.MaxSpeculativeLinks
	}
	if configSpeculativeLinks > 0 {
		limits.MaxSpeculativeLinks = configSpeculativeLinks
	}
	if req.MaxRequests > 0 {
		limits.MaxRequests = req.MaxRequests
	}
	if req.MaxDepth > 0 {
		limits.MaxDepth = req.MaxDepth
	}
	if req.MaxDurationSecs > 0 {
		limits.MaxDuration = time.Duration(req.MaxDurationSecs) * time.Second
	}
	// The eight bounds added in burpsy-react-ui-qzzy, each applied on the POINTER's presence rather
	// than on the value being positive, so a 0 is the operator's answer and not a synonym for "unset".
	// A negative is refused outright by applyCrawlBounds below rather than clamped: a bound of -1 is
	// not a bound, and silently reading it as the default would answer a question nobody asked.
	if req.MaxLocations != nil {
		limits.MaxLocations = *req.MaxLocations
	}
	if req.MaxFrontier != nil {
		limits.MaxFrontier = *req.MaxFrontier
	}
	if req.MaxLinksPerPage != nil {
		limits.MaxLinksPerPage = *req.MaxLinksPerPage
	}
	if req.MaxParseBytes != nil {
		limits.MaxParseBytes = *req.MaxParseBytes
	}
	if req.MaxTemplateVisits != nil {
		limits.MaxTemplateVisits = *req.MaxTemplateVisits
	}
	if req.MaxCaptureBytes != nil {
		limits.MaxCaptureBytes = *req.MaxCaptureBytes
	}
	if req.MaxFingerprints != nil {
		limits.MaxFingerprints = *req.MaxFingerprints
	}
	if req.MaxRelogins != nil {
		limits.MaxRelogins = *req.MaxRelogins
	}

	// The audit half's producer, built before the crawler because it is one of the crawler's
	// collaborators now rather than something applied to the report afterwards. It registers nothing
	// and starts nothing yet: a configuration mistake below must still be a 400 with no task row, so
	// the feed only becomes visible once the crawl goroutine starts it.
	var feed *crawlAuditFeed
	var auditOffer func(crawler.Fetch)
	if kind == crawlKindAudit {
		feed = newCrawlAuditFeed(s, "crawl of "+seedAuditHost(seeds))
		auditOffer = feed.offer
	}
	// The task row advances as the crawl fetches, not once after Run returns (burpsy-react-ui-hbjo):
	// before this an operator watching a crawl saw 0% and then 100%, and a long crawl was
	// indistinguishable from a hung one. The hook is bound to the task once it exists (see
	// progress.bind below); it fires only during Run, which starts after the bind.
	progress := &crawlProgress{}
	onFetch := progress.hook(auditOffer)

	// Built before the task is registered so a configuration mistake is a 400 the operator can fix,
	// not a task that appears in the dashboard only to fail immediately.
	c, err := crawler.New(s.crawlConfig(req, seeds, limits, poolLimit, onFetch, configSpeculative, eh))
	if err != nil {
		return 0, nil, 0, nil, err
	}
	// The dashboard's Pause all tasks reaches the crawl loop (burpsy-react-ui-cijs). GateCheck is
	// nil-receiver safe, so a process with no task registry attaches a gate that never holds.
	c.WithSuiteGate(s.tasks.GateCheck)
	// Site-map reuse (burpsy-react-ui-z8qf), before Run so the dedup table is seeded before the first
	// request. Origins are the seeds' own, so a map holding a hundred hosts seeds only the ones this
	// crawl was pointed at; the scope predicate keeps an out-of-scope host from being marked handled.
	if req.SeedFromSiteMap && s.sitemap != nil {
		var scopeAllows func(string, uint16, bool) bool
		if s.scope != nil {
			scopeAllows = s.scope.MayContainHost
		}
		c.SeedFromSiteMap(s.sitemap, seeds, scopeAllows)
	}

	task := s.tasks.Start(dash.KindCrawl, strings.Join(seeds, ", "), uint64(limits.MaxRequests))
	s.crawls.start(task.ID(), seeds, kind, limits)

	// Detached from the request context on purpose: a crawl outlives the HTTP call that started it,
	// and binding it to r.Context() would cancel the whole crawl the moment the operator's browser
	// navigated away. The bound that actually stops it is Limits.MaxDuration, which the engine
	// enforces, plus the request budget — both reported in the Report either way.
	// The one thing the capture handle could not be given at construction time: the task id does not
	// exist until the task is registered, and the config above is built before it on purpose (a
	// mistyped bound must be a 400, not a task that appears only to fail). Handing the crawler the id
	// afterwards is what makes "show me the traffic this scan produced" answerable at all.
	c.WithTaskID(task.ID())
	// Bound before the goroutine that calls Run starts, so every fetch the hook sees already has a row
	// to advance — the go statement orders this write before any read in the crawl.
	progress.bind(task)

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
		// The rendered-DOM audit over the crawl's locations (burpsy-react-ui-xuim): the crawl
		// captured wire bytes, so script-created content was never audited. This pass renders
		// each distinct location in the same headless browser the audit's DOM checks use and
		// reports the locations whose rendered DOM carried content the wire never contained.
		// It runs before finish so the Report an operator reads carries it; a crawl without a
		// browser gets SkipRenderUnavailable on the locations the pass would have rendered,
		// counted by the pass itself below — never silent.
		s.auditCrawlLocations(ctx, task.ID(), &rep)
		s.crawls.finish(task.ID(), &rep, nil)
		task.SetNote(fmt.Sprintf("%d fetched, %d refused, %d failed", rep.Fetched, rep.Refused, rep.Failed))
		// The fetches the hook already counted are not counted twice; only the remainder (requests the
		// report counts that never reached the capture path) is credited now.
		progress.settle(uint64(rep.Fetched))
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

	return task.ID(), seeds, liveTaken, crawlUnapplied, nil
}

// auditCrawlLocations runs the rendered-DOM audit over a finished crawl's distinct locations
// and folds its outcome into the crawl's Report (burpsy-react-ui-xuim).
//
// Locations, not fetches: the crawl's location identity is the content fingerprint, but the
// rendered pass asks about a URL, so the pass runs over the DISTINCT location URLs the crawl
// fetched — one render per page, not one per redirect chain that ended on it. A URL is keyed by
// the LAST fetch that captured it, so the wire body compared against is the one the crawl
// actually ended up with.
//
// Honesty rules, same two as the discovery pass (nx7b):
//   - A crawl with no browser does not get a silent nil block. The pass declines and the
//     locations it would have rendered are recorded as SkipRenderUnavailable, so the report
//     says what was not looked at rather than reading as a pass that found nothing. This is
//     the bead's criterion 3: without -dom the crawl reports the omission honestly.
//   - The findings are INFO and cite the crawl fetch's exchange, because "content exists only
//     after script runs" is a visibility fact, not a vulnerability — it changes what the rest
//     of the scan can claim to have covered, and the operator decides what that is worth.
func (s *Server) auditCrawlLocations(ctx context.Context, taskID uint64, rep *crawler.Report) {
	if rep == nil || len(rep.Fetches) == 0 {
		return
	}
	// Distinct location URLs: a Fetch whose Fingerprint is empty was not a location (a
	// redirect, an unreadable body), and the rendered pass asks about pages, not edges.
	locations := make(map[string]core.ExchangeID)
	for _, f := range rep.Fetches {
		if f.Fingerprint == "" {
			continue
		}
		locations[f.URL] = f.ExchangeID
	}
	if len(locations) == 0 {
		return
	}

	active := s.activeScanner()
	if active == nil || !active.DOMCapabilityConfigured() {
		// No browser: the decline is REPORTED, never silent (criterion 3). The skip ledger's
		// home is the crawler and this pass is the web layer's, so the omission is carried on
		// the Report's own block — a Declined RenderedAudit with the candidate count is the
		// honest shape: "N locations existed and none were looked at", which an absent block
		// could never say. The task note names it too, because the report and the dashboard
		// are two different operator views of the same fact.
		rep.RenderedAudit = &crawler.RenderedAuditReport{
			Candidates: len(locations),
			Declined:   "no DOM execution capability is configured: the crawl's locations were not rendered",
		}
		return
	}

	// The wire bodies for the comparison, read from the store: the crawl captured them, so
	// they are exactly the bytes the wire audit saw.
	wireByURL := make(map[string][]byte, len(locations))
	for u, id := range locations {
		ex, err := s.store.GetExchange(id)
		if err != nil || ex.Response == nil {
			continue
		}
		msg, err := s.store.Get(*ex.Response)
		if err != nil {
			continue
		}
		wireByURL[u] = msg.Body()
	}

	summary, findings, err := active.AuditCrawlLocations(ctx, locations, wireByURL)
	if err != nil {
		s.events.RecordFor(taskID, dash.EventAuditBounded, dash.SeverityWarn, fmt.Sprintf(
			"rendered-DOM audit of %s could not run: %v", rep.Seeds[0], err))
		return
	}
	if summary.Declined != "" {
		// A decline from the pass (the browser died mid-crawl, say) is the same honest
		// omission as no provider at all: carried on the block, with the candidate count.
		rep.RenderedAudit = &crawler.RenderedAuditReport{
			Candidates: summary.Candidates, Declined: summary.Declined,
		}
		s.events.RecordFor(taskID, dash.EventAuditBounded, dash.SeverityInfo, fmt.Sprintf(
			"rendered-DOM audit declined: %s", summary.Declined))
		return
	}

	// Fold into the Report: the counters block, then the findings, then the events. The task
	// note and the events read from the summary so the operator's two views cannot disagree.
	block := crawler.RenderedAuditReport{
		Candidates: summary.Candidates, NoScript: summary.NoScript, Capped: summary.Capped,
		Rendered: summary.Rendered, Failed: summary.Failed, ScriptOnly: summary.ScriptOnly,
		Declined: summary.Declined,
	}
	rep.RenderedAudit = &block
	for _, rf := range findings {
		finding := core.NewFinding{
			Name:     "Content visible only after script runs",
			Severity: core.ParseSeverity("info"),
			// Certain: the browser loaded the page and the text was observed in the rendered
			// DOM and absent from the wire body — this is a measurement, not an inference.
			Confidence: core.ParseConfidence("certain"),
			TaskID:     taskID,
			Target:     core.FindingTarget{Path: rf.URL},
			Occurrences: []core.Occurrence{{
				ExchangeID: rf.ExchangeID,
			}},
			Description: fmt.Sprintf(
				"The rendered DOM at %s carries visible content the wire response never contained (wire body %d bytes, rendered %d). "+
					"Every wire-bytes check, including this crawl's own audit, is blind to it: script-created content was never captured, "+
					"so a crawl-only scan has not covered it. This row is a visibility fact, not a vulnerability — it says what the rest "+
					"of the scan can honestly claim to have covered.",
				rf.URL, rf.WireBodyLength, rf.RenderedBodyLength),
		}
		s.findings.Add(finding)
	}
	if summary.ScriptOnly > 0 {
		s.events.RecordFor(taskID, dash.EventAuditBounded, dash.SeverityInfo, block.Summary())
	}
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

// crawlConfig is the crawler configuration an operator-launched crawl runs under, and it exists as a
// named method so a test can read what production actually builds.
//
// burpsy-react-ui-nc9s: the re-login seam was complete in crawler/session_gate.go, tested there, and
// wired to nothing — this literal simply omitted SessionCoordinator and LoginPagePattern, so every
// operator-launched crawl ran the unauthenticated one from the first expiry onwards with no signal
// that the session had been lost, and reported whatever the public pages yielded. A field missing
// from a struct literal nobody inspects is invisible, and that is the same shape as the Params
// field's own note about the wire dropping what the store kept.
func (s *Server) crawlConfig(req crawlStartReq, seeds []string, limits crawler.Limits, poolLimit *intruder.RateLimit, onFetch func(crawler.Fetch), speculative bool, eh crawler.ErrorHandling) crawler.Config {
	// The fetch hook for the crawl→audit bridge, built before the task is registered so a
	// configuration mistake is a 400 the operator can fix, not a task that appears in the dashboard
	// only to fail immediately. Declared here rather than at the call site so this method is the
	// whole configuration and nothing about it hides in the caller.
	_ = onFetch
	return crawler.Config{
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
		Query:              req.Query,
		RetentionQuery:     req.RetentionQuery,
		SubmitForms:        req.SubmitForms,
		RequestSpeculative: speculative,
		Limits:             limits,
		ErrorHandling:      eh,
		RequestWellKnown:   req.RequestWellKnown,
		RequestsPerSecond:  req.RequestsPerSecond,
		Pool:               poolLimit,
		UserAgent:          req.UserAgent,
		Headers:            req.Headers,
		OnFetch:            onFetch,
		Render:             nil,
		// The outcome form, so a capped render is visible in the queue (burpsy-react-ui-efra).
		RenderWithOutcome: s.crawlRenderer(),
		Logger:            s.logger,
		// The re-login seam (burpsy-react-ui-nc9s). This is the same coordinator every other tool
		// already routes through — Repeater, Intruder, the proxy — so a crawl uses the project's
		// session handling the way Burp's crawl_using_provided_logins_only says it does, and there
		// is no second, drift-prone way to think about re-login.
		//
		// It was complete and tested in crawler/session_gate.go and wired to nothing: every
		// operator-launched crawl ran the unauthenticated one from the first expiry onwards, with
		// no signal that the session had been lost. The crawl then reports whatever the public
		// pages yielded, which reads as a confident empty result.
		//
		SessionCoordinator: s.crawlSessionCoordinator(),
		LoginPagePattern:   req.LoginPagePattern,
	}
}

// resolveCrawlConfig resolves a scan configuration name for its CRAWL half: the limits it sets, and
// every `crawler/*` key it names that this engine has nowhere to put.
//
// Empty is the default and is not an error, and an unknown name is refused carrying the known ones —
// silently crawling under the defaults would run settings the operator did not ask for and report a
// successful crawl, which is the same class of lie as a skipped check reporting as a pass.
//
// The resolution lives here rather than at the two call sites so every path that can crawl under a
// name resolves that name the same way, and so the name the run records is the one that was applied.
func (s *Server) resolveCrawlConfig(name string) (string, []string, error) {
	if name == "" {
		return "", nil, nil
	}
	doc, found := s.savedScanConfigDocument(name)
	if !found {
		return "", nil, &unknownConfigError{Name: name, Known: s.knownConfigNames()}
	}
	cfg, err := crawler.ParseBurpCrawlConfig(doc)
	if err != nil {
		return "", nil, err
	}
	return name, append(cfg.UnrepresentableKeys, sectionPrefixes(cfg.UnknownSections)...), nil
}

// crawlLimitsFromConfig reads the crawler half of a named configuration and returns the limits it
// sets, over the defaults rather than over the caller's own — the caller merges the two in the
// order that lets an explicit request field win.
func (s *Server) crawlLimitsFromConfig(name string) crawler.Limits {
	return s.crawlConfigFromConfig(name).Limits
}

// crawlConfigFromConfig is the whole crawler half of a named configuration: its limits AND its
// error-handling family.
//
// Split from crawlLimitsFromConfig when the error_handling keys landed (burpsy-react-ui-o0c5), which
// are a different shape from Limits — pointers, because a 0 threshold means "never pause" — and a
// limits-only accessor would have made them unreachable from exactly the path that reaches every
// other crawler key.
func (s *Server) crawlConfigFromConfig(name string) crawler.CrawlConfig {
	doc, found := s.savedScanConfigDocument(name)
	if !found {
		return crawler.CrawlConfig{Limits: crawler.DefaultLimits()}
	}
	cfg, err := crawler.ParseBurpCrawlConfig(doc)
	if err != nil {
		// Unreachable: resolveCrawlConfig already parsed this document and refused it on error, so a
		// failure here means the store changed underneath two calls in one request. The defaults are
		// the honest fallback; the name was already refused to the operator if it was mistyped.
		return crawler.CrawlConfig{Limits: crawler.DefaultLimits()}
	}
	limits := crawler.DefaultLimits()
	overlayCrawlLimits(&limits, cfg.Limits)
	cfg.Limits = limits
	return cfg
}

// overlayCrawlLimits copies every field the configuration actually named. A field left at its zero
// value in cfg.Limits was not in the file and must not overwrite the caller's value with zero — which
// is the failure an overlay written as a struct copy always produces.
func overlayCrawlLimits(dst *crawler.Limits, src crawler.Limits) {
	if src.MaxRequests != 0 {
		dst.MaxRequests = src.MaxRequests
	}
	if src.MaxDepth != 0 {
		dst.MaxDepth = src.MaxDepth
	}
	if src.MaxDuration != 0 {
		dst.MaxDuration = src.MaxDuration
	}
	if src.MaxLocations != 0 {
		dst.MaxLocations = src.MaxLocations
	}
	if src.MaxSpeculativeLinks != 0 {
		dst.MaxSpeculativeLinks = src.MaxSpeculativeLinks
	}
	// max_submissions_per_form (u0k3) was parsed and then dropped here, so a named configuration's
	// form cap never reached the crawl. The crawl strategy's band rides the same path (8bp2).
	if src.MaxSubmissionsPerForm != 0 {
		dst.MaxSubmissionsPerForm = src.MaxSubmissionsPerForm
	}
	if src.LocationToleranceBand != nil {
		band := *src.LocationToleranceBand
		dst.LocationToleranceBand = &band
	}
}

// sectionPrefixes names unknown crawler sub-objects the way a key is named, so the unapplied list
// reads as one vocabulary rather than two.
func sectionPrefixes(sections []string) []string {
	out := make([]string, 0, len(sections))
	for _, s := range sections {
		out = append(out, s+" (whole section)")
	}
	return out
}

// savedScanConfigDocument returns the raw text of a saved configuration, which is what both halves of
// the loader parse. burpsy stores a configuration as the document the operator exported or authored,
// so the crawler half is read from the same bytes the scanner half is.
func (s *Server) savedScanConfigDocument(name string) ([]byte, bool) {
	if s.persist == nil {
		return nil, false
	}
	doc, found, err := s.persist.LoadScanConfigLibrary(name)
	if err != nil || !found {
		return nil, false
	}
	return []byte(doc), true
}

// crawlSessionCoordinator is the coordinator an operator-launched crawl re-logs in through, or nil
// when this process has none.
//
// The nil case is not an oversight and not a degraded mode: a server built without a session
// coordinator has no session rules to apply, so there is nothing to log in with. Passing a typed nil
// instead would put a non-nil interface holding a nil pointer in front of the crawler, which is
// exactly the shape that panics on first use rather than at the call.
func (s *Server) crawlSessionCoordinator() crawler.SessionCoordinator {
	if s.sessionCoordinator == nil {
		return nil
	}
	return s.sessionCoordinator
}
