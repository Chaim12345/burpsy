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

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// ---- Hidden-input guessing ------------------------------------------------------------------------
//
// Burp's Param Miner "Guess params" (burpsy-react-ui-wlz8), built in. POST /api/hidden-inputs starts a
// guessing run against one captured exchange as a background task on the dashboard; GET lists the
// retained runs, or one by ?task=. The engine is scanner.ActiveScanner.GuessHiddenInputs, which sends
// every guess through the same scope-checking probe gate an audit uses.
//
// # Why a pattern of its own and not /api/exchange/{id}/guess
//
// The manifest classifies a pattern, not a path. /api/exchange/ is riskLocal (GET a row, PATCH its
// notes), and a guess route under it would inherit that class — the confirmation gate would then wave
// an unattended caller's few hundred requests at a client's production host straight through. A
// literal pattern classed riskAttack, shaped like /api/discovery, is what puts it behind the gate.
//
// # Why it is not part of an audit
//
// In Burp this is an extension an operator runs on purpose, and its traffic is a few hundred requests
// per exchange that no audit check asked for. An ordinary audit therefore never dispatches it.

// hiddenInputRunsKept bounds retained runs, as discoveryRunsKept does.
const hiddenInputRunsKept = 20

// hiddenInputRun is one guessing run as the API reports it.
type hiddenInputRun struct {
	TaskID     uint64                    `json:"task_id"`
	ExchangeID core.ExchangeID           `json:"exchange_id"`
	Target     string                    `json:"target"`
	Kinds      []scanner.HiddenInputKind `json:"kinds"`
	// State is the task's lifecycle: running, then the engine's own terminal state (done, unstable,
	// budget, stopped, failed).
	State    string     `json:"state"`
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished,omitempty"`
	// Result is the engine's outcome; nil while running, so "no result yet" is not an empty one.
	Result *scanner.HiddenInputResult `json:"result"`
	// FindingIDs are the store findings this run filed, one per confirmed input. Never nil.
	FindingIDs []uint64 `json:"finding_ids"`
	Summary    string   `json:"summary"`
}

type hiddenInputRuns struct {
	mu    sync.RWMutex
	byID  map[uint64]*hiddenInputRun
	order []uint64
}

func newHiddenInputRuns() *hiddenInputRuns {
	return &hiddenInputRuns{byID: map[uint64]*hiddenInputRun{}}
}

func (h *hiddenInputRuns) start(run *hiddenInputRun) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.byID[run.TaskID] = run
	h.order = append(h.order, run.TaskID)
	for len(h.order) > hiddenInputRunsKept {
		delete(h.byID, h.order[0])
		h.order = h.order[1:]
	}
}

// finish looks the run up again rather than writing through a pointer, for discoveryRuns.finish's
// reason: a run that outlived its retention window must not be resurrected.
func (h *hiddenInputRuns) finish(taskID uint64, res scanner.HiddenInputResult, findingIDs []uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	run := h.byID[taskID]
	if run == nil {
		return
	}
	now := time.Now()
	run.Finished = &now
	run.State = res.State
	run.Result = &res
	run.FindingIDs = findingIDs
	run.Summary = res.Summary
}

func (h *hiddenInputRuns) get(taskID uint64) (hiddenInputRun, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	run, ok := h.byID[taskID]
	if !ok {
		return hiddenInputRun{}, false
	}
	return *run, true
}

func (h *hiddenInputRuns) list() []hiddenInputRun {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]hiddenInputRun, 0, len(h.order))
	for _, id := range h.order {
		if run := h.byID[id]; run != nil {
			out = append(out, *run)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TaskID > out[j].TaskID })
	return out
}

// hiddenInputStartReq is the POST body.
type hiddenInputStartReq struct {
	// ExchangeID is the captured exchange to guess against. Zero is a real id (the first capture).
	ExchangeID *core.ExchangeID `json:"exchange_id" desc:"the captured exchange to guess against"`
	// Kinds is any of "query", "cookie", "header". Required and non-empty: Burp's dialog makes the
	// operator pick, and an empty list read as "everything" would send traffic nobody chose.
	Kinds []string `json:"kinds" desc:"which inputs to guess, one or more of query, cookie, header; required"`
	// MaxRequests bounds the run; 0 takes scanner.DefaultHiddenInputBudget.
	MaxRequests int `json:"max_requests" desc:"request budget for the run, 0-5000; 0 takes the default"`
	// CacheBuster defaults to on; false turns off the per-request cache-buster query parameter.
	CacheBuster *bool `json:"cache_buster" desc:"add a per-request cache-buster query parameter; default true"`
}

// maxHiddenInputBudget caps what a caller may ask for. A run that needs more than this on one
// exchange is a run to split, not one to let a request body make unbounded.
const maxHiddenInputBudget = 5000

func (s *Server) handleHiddenInputs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if raw := r.URL.Query().Get("task"); raw != "" {
			id, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				http.Error(w, "task must be a whole number", http.StatusBadRequest)
				return
			}
			run, ok := s.hiddenInputs.get(id)
			if !ok {
				http.Error(w, fmt.Sprintf("No hidden-input run %d is retained", id), http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, run)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"runs":     s.hiddenInputs.list(),
			"retained": hiddenInputRunsKept,
			"wordlist": map[string]int{
				string(scanner.HiddenInputQuery):  len(scanner.HiddenInputWordlist(scanner.HiddenInputQuery)),
				string(scanner.HiddenInputCookie): len(scanner.HiddenInputWordlist(scanner.HiddenInputCookie)),
				string(scanner.HiddenInputHeader): len(scanner.HiddenInputWordlist(scanner.HiddenInputHeader)),
			},
			"default_budget": scanner.DefaultHiddenInputBudget,
		})
	case http.MethodPost:
		s.handleHiddenInputsStart(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHiddenInputsStart(w http.ResponseWriter, r *http.Request) {
	var req hiddenInputStartReq
	if err := requestJSON(w, r, http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.ExchangeID == nil {
		http.Error(w, "exchange_id is required", http.StatusBadRequest)
		return
	}
	if len(req.Kinds) == 0 {
		http.Error(w, "kinds is required: pick at least one of query, cookie, header", http.StatusBadRequest)
		return
	}
	var kinds []scanner.HiddenInputKind
	seen := map[scanner.HiddenInputKind]bool{}
	for _, raw := range req.Kinds {
		k, err := scanner.ParseHiddenInputKind(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !seen[k] {
			seen[k] = true
			kinds = append(kinds, k)
		}
	}
	if req.MaxRequests < 0 || req.MaxRequests > maxHiddenInputBudget {
		http.Error(w, fmt.Sprintf("max_requests must be between 0 (the default, %d) and %d",
			scanner.DefaultHiddenInputBudget, maxHiddenInputBudget), http.StatusBadRequest)
		return
	}
	id := *req.ExchangeID
	ex, err := s.store.GetExchange(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("No exchange %d: %v", id, err), http.StatusNotFound)
		return
	}
	reqMsg, err := s.store.Get(core.MsgOrZero(ex.Request))
	if ex.Request == nil || err != nil || len(reqMsg.Raw()) == 0 {
		http.Error(w, fmt.Sprintf("Exchange %d carries no request bytes to guess against", id), http.StatusUnprocessableEntity)
		return
	}
	// Scope before anything is registered, on the captured request's own bytes. The probe gate checks
	// every guess again; this is what keeps an out-of-scope exchange from becoming a dashboard row
	// that failed on its first request.
	if s.scope != nil {
		if err := s.scope.AuthoriseRaw(ex.Host, ex.Port, ex.TLS, reqMsg.Raw()); err != nil {
			http.Error(w, "Out of scope, so nothing was sent: "+err.Error(), http.StatusForbidden)
			return
		}
	}
	active := s.activeScanner()
	if !active.CanSendProbes() {
		http.Error(w, "This server's scanner has no network sender, so no guess could be sent",
			http.StatusServiceUnavailable)
		return
	}

	opts := scanner.HiddenInputOptions{Kinds: kinds, MaxRequests: req.MaxRequests,
		NoCacheBuster: req.CacheBuster != nil && !*req.CacheBuster}
	budget := opts.MaxRequests
	if budget == 0 {
		budget = scanner.DefaultHiddenInputBudget
	}
	target := fmt.Sprintf("%s %s%s", ex.Method, ex.Host, ex.Path)
	// Total is the request budget, the one bound known up front; Done is requests sent. A run that
	// finds nothing early stops well short of it, which the note says.
	task := s.tasks.Start(dash.KindHiddenInputs, target, uint64(budget))
	task.SetNote(fmt.Sprintf("guessing hidden %v against exchange %d", kinds, id))
	run := &hiddenInputRun{TaskID: task.ID(), ExchangeID: id, Target: target, Kinds: kinds, State: "running",
		Started: time.Now(), FindingIDs: []uint64{},
		Summary: "running: no name has been settled yet, so nothing about this exchange's hidden inputs is known"}
	// Read for the reply before the run is shared: once start publishes it and the goroutine below
	// exists, finish rewrites State under the registry's lock, and reading run.State here after that
	// was a data race (burpsy-react-ui-h68z). "running" is also the true answer for a 202 — the
	// reply reports the run as accepted, not however far it got before the response was written.
	acceptedState := run.State
	s.hiddenInputs.start(run)

	// Detached from the request, with the task's own cancel, as every long-running launch here is.
	go func() {
		ctx, cancel := task.WithCancel(context.Background())
		defer cancel()
		var sent uint64
		opts.Progress = func(n int) {
			task.Advance(uint64(n) - sent)
			sent = uint64(n)
		}
		res := active.GuessHiddenInputs(ctx, id, opts)
		ids := s.fileHiddenInputs(res, task.ID())
		s.toolLog.Record(toollog.ToolScanner, ex.Host, ex.Port, ex.TLS, ex.Method, ex.Path, 0, nil, 0,
			"hidden-input guessing", &ex.ID)
		s.hiddenInputs.finish(task.ID(), res, ids)
		finishHiddenInputTask(task, res)
		s.live.notify(changeIssues)
		s.live.notify(changeDashboard)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"task_id":     task.ID(),
		"exchange_id": id,
		"target":      target,
		"kinds":       kinds,
		"budget":      budget,
		"state":       acceptedState,
	})
}

// fileHiddenInputs records one finding per confirmed input and returns their ids.
func (s *Server) fileHiddenInputs(res scanner.HiddenInputResult, taskID uint64) []uint64 {
	ids := []uint64{}
	for _, in := range res.Inputs {
		f := &scanner.Finding{
			Name:       in.Issue,
			Severity:   "info",
			Confidence: in.Confidence,
			Param:      in.Name,
			ExchangeID: res.ExchangeID,
			Description: fmt.Sprintf("<p>The application supports the %s <b>%s</b>, which nothing in the "+
				"captured request or response mentions. It was found by guessing names from a built-in "+
				"wordlist and confirmed by repeating the request with and without it.</p><p>%s</p>",
				hiddenKindNoun(in.Kind), htmlEscape(in.Name), htmlEscape(in.Evidence)),
			Solution: "<p>Review what this input does. Hidden inputs are often debugging switches, " +
				"feature flags or trust assertions left reachable in production; they widen the attack " +
				"surface and should be tested like any other input — or removed.</p>",
		}
		nf := s.activeFinding(f, taskID)
		nf.Evidence = in.Evidence
		// One finding per hidden input, not one per endpoint: the store's default key is name plus
		// location, which would fold two hidden headers on one page into a single issue. The path
		// stays in the key so the same name on two endpoints is two findings. Query-stripped, the
		// same rule the store's dedup key applies: an endpoint is its path, and /login?next=/a is
		// not a second endpoint with the same hidden header.
		mergePath := nf.Target.Path
		if i := strings.IndexByte(mergePath, '?'); i >= 0 {
			mergePath = mergePath[:i]
		}
		nf.MergeKey = mergePath + "\x00" + string(in.Kind) + "\x00" + in.Name
		ids = append(ids, s.findings.Add(nf))
	}
	return ids
}

func hiddenKindNoun(k scanner.HiddenInputKind) string {
	switch k {
	case scanner.HiddenInputQuery:
		return "query parameter"
	case scanner.HiddenInputCookie:
		return "cookie"
	}
	return "header"
}

// finishHiddenInputTask moves the task to its terminal state. The unit of work is a guessed name:
// Found is confirmed inputs; Skipped is names the request already carried; Errored is names in a
// batch that changed the response but could not be isolated; Gated is names never sent — a stopped
// kind, the budget, an unstable page, or the operator.
func finishHiddenInputTask(task *dash.Handle, res scanner.HiddenInputResult) {
	var b dash.Breakdown
	b.Found = uint64(len(res.Inputs))
	for _, k := range res.Kinds {
		b.Skipped += uint64(k.Present)
		b.Errored += uint64(k.Unresolved)
		b.Gated += uint64(k.Untested)
	}
	switch res.State {
	case "stopped":
		task.Stop(b, res.Summary)
	case "failed":
		// A refused or failed request: the run broke, it did not finish looking.
		task.FailWith(b, errors.New(res.Summary))
	default:
		// done, unstable and budget all finished on their own terms; unstable and budget leave
		// Gated non-zero, so the row reads as a floor, not as a clean result.
		task.FinishWithNote(b, res.Summary)
	}
}
