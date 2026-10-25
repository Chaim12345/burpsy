package web

// A Repeater tab's custom action (burpsy-react-ui-1944): a small script on the ydmj sandbox that
// runs ON DEMAND and, when the tab asks, AUTO-RUNS as each response arrives for the tab (Burp:
// "Auto-run on send ... The custom action runs when Burp receives a response"). burpsy's script
// hooks were all pre-request (ydmj/xe82/q7f8); nothing answered a response. This is the
// post-response half.
//
// # The script is an untrusted principal (the 1944 remediation disposition)
//
// The route's four verbs are riskCredential: installing persistent code that runs over response
// traffic is the authority, and every mutating call passes the confirmation gate bound to method,
// path and body. GET is the DEFINITION only - the script, its switch, run counters and error
// metadata. Script-derived output (the log, the store, the rewritten draft, the error TEXT, any of
// which can carry response secrets) is served only by the gated POST run. There is no separate UI
// grant: the console is just another caller of the same gated surface.
//
// # Bounds, stated precisely
//
//   - CPU: the run's 500ms interrupt is a WALL-CLOCK interrupt, not a CPU budget.
//   - Egress: none by construction - run() binds no host objects, pinned by runtime probes and a
//     global-object enumeration whitelist in jsexec's tests.
//   - Inputs are capped BEFORE the run (1 MiB per body, header blocks bounded, flagged).
//   - Outputs are capped BEFORE commit: the log inside jsexec (20x512), the store at write time
//     (128 keys / 4 KiB / 256 KiB, script-visible), the rendered draft here at 1 MiB. The draft cap
//     bounds what is stored and served; it is NOT an in-VM allocation bound.
//   - MEMORY: a hard in-process bound is INFEASIBLE - goja allocates through the Go allocator and
//     has no per-VM cap. This is an accepted residual, not a guarantee; a subprocess+rlimits tier
//     is future work.
//   - Installs are bounded globally: 32 actions, 1 MiB of persisted script. A gated installer can
//     still squat IDs that are not live tabs - bounded, visible, deletable through the gated verbs,
//     and accepted as a stated residual. A server-owned tab registry is a separate bead if wanted.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/jsexec"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// The global install bounds (item 3 of the disposition, which REJECTED a server-owned registry in
// this bead): 32 actions and 1 MiB of persisted script. 32 is far past the open tabs of an
// interactive session (Burp's own strip is operator-managed, a handful at a time), and at the
// 64 KiB script cap the byte bound makes the worst case exact: sixteen maximal scripts.
const (
	maxRepeaterActions               = 32
	maxRepeaterActionsPersistedBytes = 1 << 20
)

// The pre-run input caps and the pre-commit draft cap.
const (
	maxScriptInputBodyBytes   = 1 << 20 // per body, request and response
	maxScriptInputHeaderValue = 8 * 1024
	maxScriptInputHeaderTotal = 64 * 1024
	maxRenderedDraftBytes     = 1 << 20
)

// errActionChangedMidRun discards a run whose action was replaced or removed while it executed:
// committing it would write a new script's output into the old script's state.
var errActionChangedMidRun = errors.New("the tab's action changed while the script ran; nothing was recorded")

// repeaterTabAction is the stored config: the script source and whether it fires on each response.
type repeaterTabAction struct {
	Script  string `json:"script"`
	AutoRun bool   `json:"auto_run"`
}

// repeaterTabActionRunReq is the POST run body: mode "run" (the default) executes against the
// tab's latest exchange; mode "last" replays the recorded run.
type repeaterTabActionRunReq struct {
	Mode string `json:"mode"`
}

// repeaterActionRun is what one run produced - SCRIPT-DERIVED output, served only by the gated
// POST run, never by GET. A run that failed is a run: the error is data, not an HTTP failure.
type repeaterActionRun struct {
	Log            []string          `json:"log"`
	Store          map[string]string `json:"store"`
	Request        string            `json:"request"`
	Error          string            `json:"error,omitempty"`
	ErrorKind      string            `json:"error_kind,omitempty"`
	RanAtMs        int64             `json:"ran_at_ms"`
	InputTruncated []string          `json:"input_truncated,omitempty"`
	DraftTruncated bool              `json:"draft_truncated,omitempty"`
}

// repeaterTabActionDef is the GET answer: the definition and run METADATA. It carries no
// script-derived content - no log, no store, no draft, and no error TEXT (a script can throw its
// secrets), only the error's kind.
type repeaterTabActionDef struct {
	Action        repeaterTabAction `json:"action"`
	Runs          uint64            `json:"runs"`
	HasError      bool              `json:"has_error"`
	ErrorKind     string            `json:"error_kind,omitempty"`
	LastRunAtMs   int64             `json:"last_run_at_ms,omitempty"`
	InstalledAtMs int64             `json:"installed_at_ms,omitempty"`
}

// repeaterTabActionState is one tab's action and everything the next run needs. The MAP is guarded
// by the server's repeaterActionsMu; the state's FIELDS by st.mu; runs on one tab serialize on
// st.runMu - execution holds no lock another tab needs, so one tab's script never starves the rest.
// generation invalidates an in-flight run when the action is replaced or removed.
type repeaterTabActionState struct {
	mu            sync.Mutex
	runMu         sync.Mutex
	generation    uint64
	action        repeaterTabAction
	store         map[string]string
	lastRun       *repeaterActionRun
	lastReq       []byte
	lastResp      []byte
	host          string
	port          uint16
	tls           bool
	runs          uint64
	installedAtMs int64
}

// tabActionState looks the tab's state up in the map (the only thing the map lock covers).
func (s *Server) tabActionState(tabID string) *repeaterTabActionState {
	s.repeaterActionsMu.Lock()
	defer s.repeaterActionsMu.Unlock()
	return s.repeaterActions[tabID]
}

// classifyRunError names the failure's kind: the store's write-time bounds, the wall-clock
// interrupt, or anything else the script threw.
func classifyRunError(err error) string {
	switch {
	case errors.Is(err, jsexec.ErrStoreFull):
		return "store_full"
	case errors.Is(err, jsexec.ErrTimeout):
		return "timeout"
	default:
		return "exception"
	}
}

// capScriptInput applies the pre-run input caps and names what it cut.
func capScriptInput(req jsexec.ScriptRequest, resp *jsexec.ScriptResponse) (jsexec.ScriptRequest, *jsexec.ScriptResponse, []string) {
	var truncated []string
	if len(req.Body) > maxScriptInputBodyBytes {
		req.Body = req.Body[:maxScriptInputBodyBytes]
		truncated = append(truncated, "request_body")
	}
	if capHeaders(req.Headers) {
		truncated = append(truncated, "request_headers")
	}
	if resp != nil {
		if len(resp.Body) > maxScriptInputBodyBytes {
			resp.Body = resp.Body[:maxScriptInputBodyBytes]
			truncated = append(truncated, "response_body")
		}
		if capHeaders(resp.Headers) {
			truncated = append(truncated, "response_headers")
		}
	}
	return req, resp, truncated
}

// capHeaders bounds each value and the block in all, keeping the first headers by name within
// budget so two runs of one script see the same cut.
func capHeaders(h map[string]string) bool {
	cut := false
	total := 0
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		v := h[name]
		if len(v) > maxScriptInputHeaderValue {
			v = v[:maxScriptInputHeaderValue]
			h[name] = v
			cut = true
		}
		total += len(name) + len(v)
		if total > maxScriptInputHeaderTotal {
			delete(h, name)
			cut = true
		}
	}
	return cut
}

// runRepeaterTabAction executes the tab's script against a SNAPSHOT of the tab's state and commits
// the outcome only if the action is still the one the run started on.
func (s *Server) runRepeaterTabAction(tabID string) (*repeaterActionRun, error) {
	st := s.tabActionState(tabID)
	if st == nil {
		return nil, fmt.Errorf("tab %q has no custom action", tabID)
	}
	st.runMu.Lock()
	defer st.runMu.Unlock()

	st.mu.Lock()
	if len(st.lastReq) == 0 {
		st.mu.Unlock()
		return nil, fmt.Errorf("tab %q has no exchange yet - send a request from it first", tabID)
	}
	script := st.action.Script
	storeSnapshot := make(map[string]string, len(st.store))
	for k, v := range st.store {
		storeSnapshot[k] = v
	}
	lastReq := append([]byte(nil), st.lastReq...)
	lastResp := append([]byte(nil), st.lastResp...)
	host, port, tls := st.host, st.port, st.tls
	gen := st.generation
	st.mu.Unlock()

	run := &repeaterActionRun{RanAtMs: time.Now().UnixMilli(), Store: storeSnapshot}
	step, err := session.MacroStepFromRequest(lastReq, host, port, tls)
	if err != nil {
		run.Error = err.Error()
		run.ErrorKind = "exception"
		s.commitRepeaterActionRun(tabID, st, gen, run, nil)
		return run, nil
	}
	head, body := splitRepeaterHeadBody(lastResp)
	resp := &jsexec.ScriptResponse{Status: intOrZero(parseResponseStatus(lastResp)), Headers: headerMapOf(head), Body: string(body)}
	scriptReq, scriptResp, truncated := capScriptInput(
		jsexec.ScriptRequest{Method: step.Method, URL: step.URL, Headers: step.Headers, Body: step.Body}, resp)
	run.InputTruncated = truncated

	result, err := jsexec.RunRequestScript(script, scriptReq, scriptResp, storeSnapshot)
	run.Log = result.Log
	if err != nil {
		run.Error = err.Error()
		run.ErrorKind = classifyRunError(err)
	} else {
		run.Store = result.Store
		run.Request = renderScriptRequest(result.Request)
		if len(run.Request) > maxRenderedDraftBytes {
			// A COMMIT bound on what is stored and served - not an in-VM allocation bound.
			run.Request = run.Request[:maxRenderedDraftBytes] + "…[truncated]"
			run.DraftTruncated = true
		}
	}
	if !s.commitRepeaterActionRun(tabID, st, gen, run, resultStoreOrNil(err, result)) {
		return nil, errActionChangedMidRun
	}
	return run, nil
}

// resultStoreOrNil is the store to commit: the script's on a clean run, nothing on a failed one.
func resultStoreOrNil(err error, result jsexec.ScriptResult) map[string]string {
	if err != nil {
		return nil
	}
	return result.Store
}

// commitRepeaterActionRun installs the run's outcome if the tab still holds the action the run
// started on (same state, same generation); otherwise the run is discarded. Lock order is
// map-then-state, the same as the install path.
func (s *Server) commitRepeaterActionRun(tabID string, st *repeaterTabActionState, gen uint64, run *repeaterActionRun, store map[string]string) bool {
	s.repeaterActionsMu.Lock()
	defer s.repeaterActionsMu.Unlock()
	if s.repeaterActions[tabID] != st {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.generation != gen {
		return false
	}
	if store != nil {
		st.store = store
	}
	st.lastRun = run
	st.runs++
	return true
}

// noteRepeaterTabExchange is the response-arrived hook (called from recordRepeaterExchange): the
// tab's latest exchange is what an on-demand run reads, and an auto-running action fires against
// it at once. Tabs with no action are not tracked - a per-send allocation for every tab that ever
// sent is not a price this feature may charge them.
func (s *Server) noteRepeaterTabExchange(spec repeaterSendSpec, rawResp []byte) {
	if spec.TabID == "" {
		return
	}
	st := s.tabActionState(spec.TabID)
	if st == nil {
		return
	}
	st.mu.Lock()
	st.lastReq = append([]byte(nil), spec.Raw...)
	st.lastResp = append([]byte(nil), rawResp...)
	st.host, st.port, st.tls = spec.Host, spec.Port, spec.TLS
	auto := st.action.AutoRun
	st.mu.Unlock()
	if auto {
		// Synchronous like every other capture at this point: the script's own timeout bounds it,
		// and its outcome must be the tab's last run before the operator reads it. The run holds
		// no lock another tab needs.
		_, _ = s.runRepeaterTabAction(spec.TabID)
	}
}

// splitRepeaterHeadBody parts a stored response at its own separator.
func splitRepeaterHeadBody(raw []byte) (head, body []byte) {
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return raw[:idx], raw[idx+4:]
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return raw[:idx], raw[idx+2:]
	}
	return raw, nil
}

// renderScriptRequest renders the request the script left as inspectable text: the request line,
// one "Name: value" per header (sorted, so two runs of one script diff cleanly), and the body.
func renderScriptRequest(req jsexec.ScriptRequest) string {
	var b strings.Builder
	target := req.URL
	b.WriteString(req.Method + " " + target + " HTTP/1.1\r\n")
	names := make([]string, 0, len(req.Headers))
	for name := range req.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b.WriteString(name + ": " + req.Headers[name] + "\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(req.Body)
	return b.String()
}

// handleRepeaterTabAction serves /api/repeater/tabs/{id}/action and .../action/run.
func (s *Server) handleRepeaterTabAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/repeater/tabs/"), "/")
	tabID, leaf, _ := strings.Cut(rest, "/")
	if tabID == "" {
		http.Error(w, "Invalid tab id", http.StatusBadRequest)
		return
	}
	if leaf == "action/run" {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRepeaterTabActionRun(w, r, tabID)
		return
	}
	if leaf != "action" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		st := s.tabActionState(tabID)
		if st == nil {
			http.Error(w, "No custom action on this tab", http.StatusNotFound)
			return
		}
		st.mu.Lock()
		def := repeaterTabActionDef{
			Action:        st.action,
			Runs:          st.runs,
			InstalledAtMs: st.installedAtMs,
		}
		if st.lastRun != nil {
			def.HasError = st.lastRun.Error != ""
			def.ErrorKind = st.lastRun.ErrorKind
			def.LastRunAtMs = st.lastRun.RanAtMs
		}
		st.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(def)
	case http.MethodPut:
		var action repeaterTabAction
		if err := requestJSON(w, r, nil).Decode(&action); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		// Refused at install, not on every response: a script that does not compile would fail
		// the tab's auto-run on each send, after the operator walked away.
		if err := jsexec.CheckRequestScript(action.Script); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// ONE OWNER for the write (1944): the cap check, the persist and the in-memory install
		// are one critical section, so two concurrent PUTs cannot invert memory and the DB.
		s.repeaterActionsMu.Lock()
		defer s.repeaterActionsMu.Unlock()
		st := s.repeaterActions[tabID]
		if st == nil && len(s.repeaterActions) >= maxRepeaterActions {
			http.Error(w, fmt.Sprintf("The %d-action install cap is reached; delete an action first", maxRepeaterActions), http.StatusConflict)
			return
		}
		persisted := len(action.Script)
		for id, other := range s.repeaterActions {
			if id != tabID {
				other.mu.Lock()
				persisted += len(other.action.Script)
				other.mu.Unlock()
			}
		}
		if persisted > maxRepeaterActionsPersistedBytes {
			http.Error(w, "The project holds the 1 MiB cap of persisted script; delete an action first", http.StatusRequestEntityTooLarge)
			return
		}
		// Persist BEFORE the in-memory install: a config the project never saved never runs, and
		// the failed write needs no rollback because nothing changed yet.
		if s.persist != nil {
			if err := s.persist.SaveRepeaterAction(tabID, action.Script, action.AutoRun); err != nil {
				http.Error(w, "The action was not saved: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if st == nil {
			st = &repeaterTabActionState{store: map[string]string{}}
			s.repeaterActions[tabID] = st
		}
		st.mu.Lock()
		st.action = action
		// A new script is a new program: its predecessor's store and last run describe a script
		// that no longer exists, and the generation bump discards any run of it in flight.
		st.store = map[string]string{}
		st.lastRun = nil
		st.runs = 0
		st.generation++
		st.installedAtMs = time.Now().UnixMilli()
		st.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(repeaterTabActionDef{Action: action, InstalledAtMs: time.Now().UnixMilli()})
	case http.MethodDelete:
		// Store-first, one owner: the row goes before the state, so a kept state never describes
		// an unsaved config.
		s.repeaterActionsMu.Lock()
		defer s.repeaterActionsMu.Unlock()
		if s.repeaterActions[tabID] == nil {
			http.Error(w, "No custom action on this tab", http.StatusNotFound)
			return
		}
		if s.persist != nil {
			if err := s.persist.DeleteRepeaterAction(tabID); err != nil {
				http.Error(w, "The removal was not saved: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		delete(s.repeaterActions, tabID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": tabID})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRepeaterTabActionRun is the GATED output surface: it runs the script on demand, or replays
// the recorded run, and its answer carries the script-derived output GET never serves.
func (s *Server) handleRepeaterTabActionRun(w http.ResponseWriter, r *http.Request, tabID string) {
	// The body parses first: the gate binds the confirmation to route AND body, so the body is
	// part of the call's shape before any state is consulted.
	var req repeaterTabActionRunReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	st := s.tabActionState(tabID)
	if st == nil {
		http.Error(w, "No custom action on this tab", http.StatusNotFound)
		return
	}
	switch req.Mode {
	case "", "run":
		run, err := s.runRepeaterTabAction(tabID)
		if err != nil {
			status := http.StatusConflict
			if errors.Is(err, errActionChangedMidRun) {
				status = http.StatusConflict
			}
			http.Error(w, err.Error(), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(run)
	case "last":
		st.mu.Lock()
		run := st.lastRun
		st.mu.Unlock()
		if run == nil {
			http.Error(w, "No run has been recorded for this tab yet", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(run)
	default:
		http.Error(w, "mode must be \"run\" or \"last\"", http.StatusBadRequest)
	}
}

// restoreRepeaterActions installs the project's saved actions (config only - a run log describes
// traffic from a session that is gone, so nothing but the script and its switch comes back).
func (s *Server) restoreRepeaterActions(p *persist.Store) {
	rows, err := p.LoadRepeaterActions()
	if err != nil {
		s.logger.Error("repeater actions: restore failed", zap.Error(err))
		return
	}
	s.repeaterActionsMu.Lock()
	defer s.repeaterActionsMu.Unlock()
	for _, row := range rows {
		s.repeaterActions[row.TabID] = &repeaterTabActionState{
			action: repeaterTabAction{Script: row.Script, AutoRun: row.AutoRun},
			store:  map[string]string{},
		}
	}
}
