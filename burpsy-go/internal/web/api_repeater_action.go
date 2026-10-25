package web

// A Repeater tab's custom action (burpsy-react-ui-1944): a small script on the ydmj sandbox that
// runs ON DEMAND and, when the tab asks, AUTO-RUNS as each response arrives for the tab (Burp:
// "Auto-run on send ... The custom action runs when Burp receives a response"). burpsy's script
// hooks were all pre-request (ydmj/xe82/q7f8); nothing answered a response. This is the
// post-response half, and it stays inside the sandbox's limits: the script reads the request and
// the response, writes a small string store, logs, and hands back a rewritten request DRAFT. It
// cannot send traffic, and the rewrite is inspectable state the console may offer the tab - it is
// never applied to the wire on its own.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/jsexec"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// repeaterTabAction is the stored config: the script source and whether it fires on each response.
type repeaterTabAction struct {
	Script  string `json:"script"`
	AutoRun bool   `json:"auto_run"`
}

// repeaterActionRun is what one run produced: the script's log, the request as the script left it
// (rendered for inspection), and the failure when the script threw or timed out. A run that failed
// is a run: the error is data, not an HTTP failure.
type repeaterActionRun struct {
	Log     []string `json:"log"`
	Request string   `json:"request"`
	Error   string   `json:"error,omitempty"`
	RanAtMs int64    `json:"ran_at_ms"`
}

// repeaterTabActionState is one tab's action and everything the next run needs: the script's
// store, the last run, and the tab's latest exchange (the request bytes as sent, the response as
// it arrived) for on-demand runs.
type repeaterTabActionState struct {
	action   repeaterTabAction
	store    map[string]string
	lastRun  *repeaterActionRun
	lastReq  []byte
	lastResp []byte
	host     string
	port     uint16
	tls      bool
}

// tabActionState returns the tab's state, or nil. The read lock is the server's own; runs mutate
// the state under the same lock, so a response arriving mid-run cannot read a half-written store.
func (s *Server) tabActionState(tabID string) *repeaterTabActionState {
	s.repeaterActionsMu.Lock()
	defer s.repeaterActionsMu.Unlock()
	return s.repeaterActions[tabID]
}

// runRepeaterTabAction executes the tab's script against the exchange the state carries and
// records the outcome as the tab's last run.
func (s *Server) runRepeaterTabAction(tabID string) (*repeaterActionRun, error) {
	s.repeaterActionsMu.Lock()
	defer s.repeaterActionsMu.Unlock()
	st := s.repeaterActions[tabID]
	if st == nil {
		return nil, fmt.Errorf("tab %q has no custom action", tabID)
	}
	if len(st.lastReq) == 0 {
		return nil, fmt.Errorf("tab %q has no exchange yet - send a request from it first", tabID)
	}
	run := &repeaterActionRun{RanAtMs: time.Now().UnixMilli()}

	step, err := session.MacroStepFromRequest(st.lastReq, st.host, st.port, st.tls)
	if err != nil {
		run.Error = err.Error()
		st.lastRun = run
		return run, nil
	}
	head, body := splitRepeaterHeadBody(st.lastResp)
	resp := &jsexec.ScriptResponse{Status: intOrZero(parseResponseStatus(st.lastResp)), Headers: headerMapOf(head), Body: string(body)}

	result, err := jsexec.RunRequestScript(st.action.Script,
		jsexec.ScriptRequest{Method: step.Method, URL: step.URL, Headers: step.Headers, Body: step.Body},
		resp, st.store)
	run.Log = result.Log
	if err != nil {
		run.Error = err.Error()
	} else {
		st.store = result.Store
		run.Request = renderScriptRequest(result.Request)
	}
	st.lastRun = run
	return run, nil
}

// noteRepeaterTabExchange is the response-arrived hook (called from recordRepeaterExchange): the
// tab's latest exchange is what an on-demand run reads, and an auto-running action fires against
// it at once. Tabs with no action are not tracked - a per-send allocation for every tab that ever
// sent is not a price this feature may charge them.
func (s *Server) noteRepeaterTabExchange(spec repeaterSendSpec, rawResp []byte) {
	if spec.TabID == "" {
		return
	}
	s.repeaterActionsMu.Lock()
	if _, ok := s.repeaterActions[spec.TabID]; !ok {
		s.repeaterActionsMu.Unlock()
		return
	}
	st := s.repeaterActions[spec.TabID]
	st.lastReq = append([]byte(nil), spec.Raw...)
	st.lastResp = append([]byte(nil), rawResp...)
	st.host, st.port, st.tls = spec.Host, spec.Port, spec.TLS
	auto := st.action.AutoRun
	s.repeaterActionsMu.Unlock()
	if auto {
		// Synchronous like every other capture at this point: the script's own timeout bounds it,
		// and its outcome must be the tab's last run before the operator reads it.
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

// repeaterTabActionResp is the GET answer: the config and the last run, when there is one.
type repeaterTabActionResp struct {
	Action  repeaterTabAction  `json:"action"`
	LastRun *repeaterActionRun `json:"last_run,omitempty"`
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
		s.handleRepeaterTabActionRun(w, tabID)
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(repeaterTabActionResp{Action: st.action, LastRun: st.lastRun})
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
		// Persist BEFORE the in-memory install: a config the project never saved never runs, and
		// the failed write needs no rollback because nothing changed yet.
		if s.persist != nil {
			if err := s.persist.SaveRepeaterAction(tabID, action.Script, action.AutoRun); err != nil {
				http.Error(w, "The action was not saved: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		s.repeaterActionsMu.Lock()
		st := s.repeaterActions[tabID]
		if st == nil {
			st = &repeaterTabActionState{store: map[string]string{}}
			s.repeaterActions[tabID] = st
		}
		st.action = action
		// A new script is a new program: its predecessor's store and last run describe a script
		// that no longer exists.
		st.store = map[string]string{}
		st.lastRun = nil
		s.repeaterActionsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(repeaterTabActionResp{Action: action})
	case http.MethodDelete:
		if s.tabActionState(tabID) == nil {
			http.Error(w, "No custom action on this tab", http.StatusNotFound)
			return
		}
		if s.persist != nil {
			if err := s.persist.DeleteRepeaterAction(tabID); err != nil {
				http.Error(w, "The removal was not saved: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		s.repeaterActionsMu.Lock()
		delete(s.repeaterActions, tabID)
		s.repeaterActionsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": tabID})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRepeaterTabActionRun is the on-demand half: run the tab's script against its latest
// exchange now.
func (s *Server) handleRepeaterTabActionRun(w http.ResponseWriter, tabID string) {
	if s.tabActionState(tabID) == nil {
		http.Error(w, "No custom action on this tab", http.StatusNotFound)
		return
	}
	run, err := s.runRepeaterTabAction(tabID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(run)
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
