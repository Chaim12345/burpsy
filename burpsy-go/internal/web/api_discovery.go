package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/extscan"
)

// ---- Content discovery ---------------------------------------------------------------------------
//
// internal/extscan wraps `ffuf` — content and parameter discovery, a capability burpsy has nowhere
// else in the tree — and nothing but `burpsy extscan` on the command line could reach it. Burp's
// equivalent is the "Discover content" engagement tool, which an operator opens from a site-map
// right-click; this file is the route behind that menu entry.
//
// # Why this is not behind sender.AuthorisedSender, and what stands in for it
//
// Every other request-originating handler in this package binds s.sender into a
// sender.AuthorisedSender for the target's own authority, so the scope check happens on the exact
// bytes about to go out. That is impossible here: ffuf is a separate process that dials the target
// itself, and by the time this process could object the request is already on the wire.
//
// extscan.Authorise is the substitute and it is stricter, not weaker. It asks scope twice — about the
// target path, and about an invented path beneath it — and refuses a host whose subtree is only
// partly in scope, because a wordlist picks its own paths and a path-scoped exclude cannot be honoured
// inside a tool that has never heard of it. So the handler refuses cases the per-request gate would
// have allowed one request at a time. Results are re-checked against scope after the run as well, and
// what that check drops is counted rather than quietly removed (see extscan.FFUFResult.OutOfScope).
//
// # Why the tool is not configured here
//
// Which binary may be executed is operator policy, supplied from the command line as -tools
// name=path and shared with the `run tool` bcheck runner. The server never builds an allowlist of its
// own: a route that could name its own executable would make the flag decorative. With no -tools the
// endpoint refuses and says which name is missing — it does not answer 200 with an empty list, which
// would read as "content discovery found nothing here".
//
// # Why discoveries do not enter history or the site map
//
// burpsy did not send these requests, so it holds no request or response bytes for them and cannot
// honestly file them as captured exchanges. They stay in the run record, attributed to the external
// tool that reported them, with the argv that produced them.

// discoveryRunsKept bounds retained discovery runs, for the reason crawlRunsKept exists: a run holds
// every path a wordlist matched, so a handful is a browsable history and an unbounded list grows with
// every sweep an operator starts and forgets.
const discoveryRunsKept = 20

// discoveryRun is one delegated content-discovery sweep: what was asked for, what state it is in, and
// what came back with the caveats attached.
type discoveryRun struct {
	TaskID     uint64 `json:"task_id"`
	Target     string `json:"target"`
	Wordlist   string `json:"wordlist"`
	Extensions string `json:"extensions,omitempty"`
	MatchCodes string `json:"match_codes,omitempty"`
	// State is this run's lifecycle as the dashboard sees it: running, done, stopped or failed.
	State    string     `json:"state"`
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished,omitempty"`
	// Outcome is extscan's own six-state verdict, carried through verbatim. It is the field that
	// separates "swept the wordlist and matched nothing" from "never swept anything", and it is not
	// derivable from len(Discoveries) — which is exactly why it is on the wire.
	Outcome string `json:"outcome"`
	// Looked is Outcome.Looked(): whether the tool actually examined the target. A caller may only
	// read an empty Discoveries list as "nothing is there" when this is true.
	Looked bool   `json:"looked"`
	Error  string `json:"error,omitempty"`
	// Command is the argv that ran, so a reader can see exactly what was executed against the target.
	Command  []string `json:"command,omitempty"`
	ExitCode int      `json:"exit_code"`
	// Discoveries is what survived the post-run scope re-check. Never nil once the run has finished,
	// so a client cannot mistake "no field" for "no result".
	Discoveries []extscan.Discovery `json:"discoveries"`
	Counts      discoveryCounts     `json:"counts"`
	// Summary is the one line that states the counts with their caveats, so a surface that renders
	// nothing else still cannot present a partial result as a complete one.
	Summary string `json:"summary"`
}

// discoveryCounts partitions what the tool reported: what is being shown, and what was dropped.
type discoveryCounts struct {
	// Discovered is len(Discoveries) — the paths this run is willing to report.
	Discovered int `json:"discovered"`
	// OutOfScope is how many reported paths the engagement scope refused, dropped from Discoveries.
	// Stated rather than folded into a smaller Discovered: a sweep that found forty paths and
	// discarded thirty-nine would otherwise render identically to one that found one.
	OutOfScope int `json:"out_of_scope"`
	// ByStatus groups the discoveries the way the report rows do, so a reader sees "eleven 403s" and
	// not four hundred undifferentiated lines.
	ByStatus []discoveryStatusCount `json:"by_status"`
}

type discoveryStatusCount struct {
	Status int `json:"status"`
	Count  int `json:"count"`
}

// discoveryRuns retains recent runs, keyed by the task id that produced them, so the dashboard row
// and the discovery result are one identity rather than two numbers to correlate by hand. Same shape
// as crawlRuns, deliberately: a long-running task started over HTTP has exactly one right answer for
// how its progress is reported, and inventing a second would leave the UI with two.
type discoveryRuns struct {
	mu    sync.RWMutex
	byID  map[uint64]*discoveryRun
	order []uint64
}

func newDiscoveryRuns() *discoveryRuns {
	return &discoveryRuns{byID: map[uint64]*discoveryRun{}}
}

func (d *discoveryRuns) start(taskID uint64, req discoveryStartReq, target string) *discoveryRun {
	d.mu.Lock()
	defer d.mu.Unlock()
	run := &discoveryRun{
		TaskID:     taskID,
		Target:     target,
		Wordlist:   req.Wordlist,
		Extensions: req.Extensions,
		MatchCodes: req.MatchCodes,
		State:      "running",
		Started:    time.Now(),
		Outcome:    "running",
		ExitCode:   -1,
		// Non-nil from the start: a running run must serialise `"discoveries": []` rather than null,
		// so a client reading the field cannot tell a run in progress from one that failed to record.
		Discoveries: []extscan.Discovery{},
		Summary:     "running: ffuf has not reported yet, so nothing about this target is known",
	}
	d.byID[taskID] = run
	d.order = append(d.order, taskID)
	for len(d.order) > discoveryRunsKept {
		delete(d.byID, d.order[0])
		d.order = d.order[1:]
	}
	return run
}

// finish records a run's outcome. It looks the run up again rather than writing through the pointer
// start returned, because a long sweep can outlive its own retention window — by the time it ends its
// entry may already have been evicted, and writing through a stale pointer would resurrect a record
// the eviction removed. Same reasoning as crawlRuns.finish.
func (d *discoveryRuns) finish(taskID uint64, state string, res extscan.FFUFResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	run := d.byID[taskID]
	if run == nil {
		return
	}
	now := time.Now()
	run.Finished = &now
	run.State = state
	run.Outcome = res.Outcome.String()
	run.Looked = res.Outcome.Looked()
	run.Command = res.Command
	run.ExitCode = res.ExitCode
	run.Discoveries = res.Discoveries
	if run.Discoveries == nil {
		run.Discoveries = []extscan.Discovery{}
	}
	run.Counts = discoveryCounts{
		Discovered: len(run.Discoveries),
		OutOfScope: res.OutOfScope,
		ByStatus:   statusCounts(run.Discoveries),
	}
	if res.Err != nil {
		run.Error = res.Err.Error()
	}
	run.Summary = discoverySummary(res)
}

func (d *discoveryRuns) get(taskID uint64) (*discoveryRun, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	run, ok := d.byID[taskID]
	return run, ok
}

// list returns the retained runs, newest first.
func (d *discoveryRuns) list() []*discoveryRun {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*discoveryRun, 0, len(d.order))
	for _, id := range d.order {
		if run := d.byID[id]; run != nil {
			out = append(out, run)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TaskID > out[j].TaskID })
	return out
}

// statusCounts groups discoveries by response status, ascending, so a rerun renders identically.
func statusCounts(in []extscan.Discovery) []discoveryStatusCount {
	tally := map[int]int{}
	for _, d := range in {
		tally[d.Status]++
	}
	out := make([]discoveryStatusCount, 0, len(tally))
	for status, count := range tally {
		out = append(out, discoveryStatusCount{Status: status, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Status < out[j].Status })
	return out
}

// discoverySummary states what happened in one line, caveats included.
//
// The two clauses that matter are "did the tool look" and "what was dropped". Without the first, an
// empty list reads as a clean target; without the second, a scope refusal disappears into a smaller
// number.
func discoverySummary(res extscan.FFUFResult) string {
	if !res.Outcome.Looked() {
		return fmt.Sprintf("nothing was swept: %s — this is not a result about the target", res.Outcome)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ffuf swept the wordlist and reported %d path(s)", len(res.Discoveries)+res.OutOfScope)
	if res.OutOfScope > 0 {
		fmt.Fprintf(&b, "; %d were dropped as outside the engagement scope, leaving %d",
			res.OutOfScope, len(res.Discoveries))
	}
	b.WriteString(". A path this wordlist does not contain was never asked for, so an absence here is " +
		"an absence of guesses rather than of content.")
	return b.String()
}

// discoveryToolState is what the endpoint can say about the tool before any run exists. It is on the
// GET response so an empty run list is never the whole answer: "no runs, and ffuf is not allowlisted"
// and "no runs yet" are different facts about this server.
type discoveryToolState struct {
	Name        string `json:"name"`
	Allowlisted bool   `json:"allowlisted"`
	Available   bool   `json:"available"`
	// Reason explains an Available of false. Empty exactly when the tool can be launched.
	Reason string `json:"reason,omitempty"`
}

// discoveryStartReq is the POST body. Everything but the target and the wordlist is optional and
// falls through to ffuf's own default rather than to a value invented here.
type discoveryStartReq struct {
	// Target is the URL whose path space is swept; FUZZ is appended to it by extscan.
	Target string `json:"target"`
	// Wordlist is a path on this host. Required: ffuf with no wordlist is not a smaller sweep, it is
	// no sweep. It is a request parameter rather than operator policy for the same reason it is a
	// flag on `burpsy extscan` — which words to guess is a per-engagement choice, unlike which binary
	// may be executed, which is not.
	Wordlist string `json:"wordlist"`
	// Extensions is ffuf's -e list ("php,bak"), extending every word.
	Extensions string `json:"extensions"`
	// MatchCodes overrides ffuf's -mc status matcher. Empty takes ffuf's own default.
	MatchCodes string `json:"match_codes"`
	Threads    int    `json:"threads"`
	// Rate caps requests per second. Zero is uncapped, which is ffuf's default; an engagement with a
	// rate agreement should set it.
	Rate int `json:"rate"`
}

// extscanConfig is the delegated-tool configuration for this process: the operator's allowlist and
// nothing else. Bounds fall through to extscan's documented defaults so "what bounds a delegated run"
// has one answer.
func (s *Server) extscanConfig() extscan.Config {
	return extscan.Config{Tools: s.externalTools}
}

// handleDiscovery serves POST /api/discovery (start) and GET /api/discovery (list, or one by ?task=).
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleDiscoveryGet(w, r)
	case http.MethodPost:
		s.handleDiscoveryStart(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDiscoveryGet(w http.ResponseWriter, r *http.Request) {
	if raw := r.URL.Query().Get("task"); raw != "" {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			http.Error(w, "task must be a whole number", http.StatusBadRequest)
			return
		}
		run, ok := s.discoveries.get(id)
		if !ok {
			http.Error(w, fmt.Sprintf("No content-discovery run %d is retained", id), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, run)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tool":     s.discoveryToolState(),
		"runs":     s.discoveries.list(),
		"retained": discoveryRunsKept,
	})
}

// discoveryToolState answers "could this server run a sweep at all", using the same allowlist
// resolution a run would.
func (s *Server) discoveryToolState() discoveryToolState {
	state := discoveryToolState{Name: extscan.ToolFFUF}
	_, allowlisted := s.externalTools[extscan.ToolFFUF]
	state.Allowlisted = allowlisted
	if err := s.extscanConfig().Available(extscan.ToolFFUF); err != nil {
		state.Reason = discoveryUnavailableReason(err)
		return state
	}
	state.Available = true
	return state
}

// discoveryUnavailableReason turns extscan's typed refusal into a sentence naming what to do about
// it. The two cases are genuinely different — one is a policy the operator has not granted, the other
// is a path that does not resolve — and collapsing them would send someone editing the wrong thing.
func discoveryUnavailableReason(err error) string {
	switch {
	case errors.Is(err, extscan.ErrNotAllowed):
		return fmt.Sprintf("%q is not on this process's external-tool allowlist, so content discovery "+
			"cannot run. Restart burpsy with -tools %s=%s (the same flag that gates `run tool` bchecks) "+
			"to allow it. Underlying refusal: %v", extscan.ToolFFUF, extscan.ToolFFUF, extscan.ToolFFUF, err)
	case errors.Is(err, extscan.ErrUnavailable):
		return fmt.Sprintf("%q is allowlisted but its binary could not be executed: %v",
			extscan.ToolFFUF, err)
	default:
		return err.Error()
	}
}

func (s *Server) handleDiscoveryStart(w http.ResponseWriter, r *http.Request) {
	var req discoveryStartReq
	if err := requestJSON(w, r, http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	req.Wordlist = strings.TrimSpace(req.Wordlist)
	if req.Target == "" {
		http.Error(w, "A target URL is required, e.g. https://target.test/app/", http.StatusBadRequest)
		return
	}
	if req.Wordlist == "" {
		http.Error(w, "A wordlist path is required: ffuf with no wordlist is not a smaller sweep, it is no sweep",
			http.StatusBadRequest)
		return
	}

	// Scope first. A target the engagement does not authorise is refused whether or not the tool is
	// even installed: telling an operator that ffuf is missing, for a host they were never allowed to
	// touch, buries the refusal that actually matters. extscan.Authorise is the whole scope gate for
	// this route — see the file comment on why it is stricter than the per-request one and not weaker.
	authorised, err := extscan.Authorise(s.scope, req.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Then the allowlist, before anything is registered. A configuration refusal is a 503 the operator
	// can act on, not a task that appears on the dashboard only to fail — and emphatically not a 200
	// with an empty discovery list, which would read as "this target has nothing to find".
	cfg := s.extscanConfig()
	if err := cfg.Available(extscan.ToolFFUF); err != nil {
		http.Error(w, discoveryUnavailableReason(err), http.StatusServiceUnavailable)
		return
	}

	opts := extscan.FFUFOptions{
		Wordlist:   req.Wordlist,
		Extensions: strings.TrimSpace(req.Extensions),
		MatchCodes: strings.TrimSpace(req.MatchCodes),
		Threads:    req.Threads,
		Rate:       req.Rate,
	}

	// Total is 0 — not the wordlist's line count. ffuf reports no progress through the JSON file it
	// writes at the end, and with -e set it sends several requests per word, so any total this handler
	// could state would be a guess the progress bar would then present as fact. dash renders an unknown
	// total as "N done, total not yet known", which is the true statement.
	task := s.tasks.Start(dash.KindDiscovery, authorised.URL, 0)
	run := s.discoveries.start(task.ID(), req, authorised.URL)
	task.SetNote("ffuf sweeping " + authorised.URL + " with " + req.Wordlist)

	// Detached from the request context on purpose, exactly as a crawl is: the sweep outlives the HTTP
	// call that started it, and binding it to r.Context() would kill ffuf the moment the operator's
	// browser navigated away. WithCancel registers a stop function against the task, so the dashboard's
	// stop button reaches the subprocess through extscan's exec.CommandContext rather than reporting a
	// cancellation it cannot perform.
	go func() {
		ctx, cancel := task.WithCancel(context.Background())
		defer cancel()

		res := extscan.RunFFUF(ctx, cfg, s.scope, authorised, opts)
		s.discoveries.finish(task.ID(), discoveryFinish(ctx, task, res), res)
		// Only the dashboard changes: these paths were never fetched by burpsy, so no history row, no
		// site-map node and no finding moved. Notifying changeHistory here would make the UI refetch a
		// store this run did not touch.
		s.live.notify(changeDashboard)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"task_id": task.ID(),
		"target":  authorised.URL,
		"state":   run.State,
	})
}

// discoveryFinish moves the task to its terminal state and returns the state to record on the run.
//
// Four endings, kept apart because they are four different things to tell an operator: the sweep ran
// (found is a real count, and an out-of-scope drop is gated work), the operator stopped it, the tool
// ran and failed, or the tool never looked at all. Collapsing any pair of these is how a bound turns
// into a clean bill of health.
func discoveryFinish(ctx context.Context, task *dash.Handle, res extscan.FFUFResult) string {
	switch {
	case res.Outcome == extscan.OutcomeCompleted:
		task.Advance(uint64(len(res.Discoveries)))
		// OutOfScope lands in Gated: a scope rule refused work the tool had already done, which is
		// precisely what that bucket means. It keeps Task.Complete() false for a run whose count is a
		// floor rather than a total.
		task.FinishWithNote(dash.Breakdown{
			Found: uint64(len(res.Discoveries)),
			Gated: uint64(res.OutOfScope),
		}, fmt.Sprintf("%d path(s) discovered, %d dropped as out of scope",
			len(res.Discoveries), res.OutOfScope))
		return "done"
	case ctx.Err() != nil:
		task.Stop(dash.Breakdown{Gated: 1},
			"stopped before ffuf reported, so how much of the wordlist was swept is not known")
		return "stopped"
	case res.Outcome == extscan.OutcomeFailed:
		task.Fail(res.Err)
		return "failed"
	default:
		// NotInvoked, NotAllowed, Unauthorised, Unavailable: the tool never looked. Gated rather than
		// errored — nothing broke, the run was refused — and never Found, which is what stops an
		// unstarted sweep reporting as a clean target.
		task.FinishWithNote(dash.Breakdown{Gated: 1}, res.Outcome.String()+": "+errText(res.Err))
		return "failed"
	}
}

func errText(err error) string {
	if err == nil {
		return "no reason was recorded"
	}
	return err.Error()
}
