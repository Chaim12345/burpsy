package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// ---- wire shapes (mirror session.ts) ------------------------------------------------------------

// sessionStepDto mirrors the UI's StepDto: headers as a [k,v] list, extracts omitted when absent.
type sessionStepDto struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers [][2]string         `json:"headers"`
	Body    string              `json:"body"`
	Extract []sessionExtractDto `json:"extract,omitempty"`
}

// sessionExtractDto mirrors the UI's ExtractionDto, flattened to the fields the UI actually edits.
type sessionExtractDto struct {
	Name    string `json:"name"`
	From    string `json:"from,omitempty"` // "body" or {header: name} handled via RawMessage below
	Pattern string `json:"pattern"`
	Group   int    `json:"group,omitempty"`
}

// sessionRuleDto mirrors the UI's RuleDto. scope is the shared ScopeInfo body (allow_all/rules);
// validity is the free-form validity JSON the UI edits as text.
type sessionRuleDto struct {
	ID          *int64           `json:"id,omitempty"`
	Name        string           `json:"name"`
	Enabled     bool             `json:"enabled"`
	Scope       json.RawMessage  `json:"scope,omitempty"`
	Steps       []sessionStepDto `json:"steps"`
	Validity    json.RawMessage  `json:"validity"`
	MaxAttempts *int             `json:"max_attempts,omitempty"`
}

// sessionRulesResp mirrors the UI's RulesResp.
type sessionRulesResp struct {
	Wired bool             `json:"wired"`
	Rules []sessionRuleDto `json:"rules"`
	Hint  string           `json:"hint,omitempty"`
}

// sessionCookiesResp mirrors the UI's CookiesResp.
type sessionCookiesResp struct {
	Wired   bool                 `json:"wired"`
	Cookies []sessionHostCookies `json:"cookies,omitempty"`
	Hint    string               `json:"hint,omitempty"`
}

type sessionHostCookies struct {
	Host    string              `json:"host"`
	Cookies []sessionCookiePair `json:"cookies"`
}

type sessionCookiePair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// sessionLoginReq mirrors the UI's login probe.
type sessionLoginReq struct {
	Probe sessionStepDto `json:"probe"`
}

// sessionLoginResp mirrors the UI's LoginResp.
type sessionLoginResp struct {
	Outcome string `json:"outcome,omitempty"` // "already_valid" | "recovered" | "failed" | "no_rule"
	Rule    string `json:"rule,omitempty"`
	RuleID  *int64 `json:"rule_id,omitempty"`
}

// ---- conversions --------------------------------------------------------------------------------

// ruleToDto converts a stored rule into the UI wire shape. Scope is expressed with the same
// ScopeInfo body as /api/scope so the UI's scopeSummary renders it the same way.
func ruleToDto(r *session.SessionRule) sessionRuleDto {
	dto := sessionRuleDto{
		Name:     r.Name,
		Enabled:  r.Enabled,
		Steps:    make([]sessionStepDto, 0, len(r.Steps)),
		Validity: json.RawMessage(`{}`),
	}
	if r.ID > 0 {
		id := int64(r.ID)
		dto.ID = &id
	}
	if r.MaxAttempts > 0 {
		ma := r.MaxAttempts
		dto.MaxAttempts = &ma
	}
	if r.Validity != nil {
		if b, err := json.Marshal(r.Validity); err == nil {
			dto.Validity = b
		}
	}
	// Scope: express ScopeHosts as rules in the ScopeInfo shape.
	if r.ScopeHosts != nil {
		hosts := make([]map[string]interface{}, 0, len(r.ScopeHosts))
		for _, h := range r.ScopeHosts {
			hosts = append(hosts, map[string]interface{}{"kind": "Include", "host": h})
		}
		if b, err := json.Marshal(map[string]interface{}{"allow_all": len(hosts) == 0, "rules": hosts}); err == nil {
			dto.Scope = b
		}
	}
	for _, step := range r.Steps {
		dto.Steps = append(dto.Steps, macroStepToDto(step))
	}
	return dto
}

func macroStepToDto(step session.MacroStep) sessionStepDto {
	d := sessionStepDto{Method: step.Method, URL: step.URL, Body: step.Body}
	for k, v := range step.Headers {
		d.Headers = append(d.Headers, [2]string{k, v})
	}
	return d
}

// dtoToRule converts the UI shape into a stored rule. Validity and scope are parsed from their
// free-form JSON; a malformed validity block is refused because a broken validity rule silently
// re-logging in on every request would be worse than an error.
func dtoToRule(dto sessionRuleDto) (*session.SessionRule, error) {
	var validity *session.ValidityRule
	if len(dto.Validity) > 0 {
		if err := json.Unmarshal(dto.Validity, &validity); err != nil {
			return nil, err
		}
	}
	var scopeHosts []string
	if len(dto.Scope) > 0 {
		var scope struct {
			AllowAll bool `json:"allow_all"`
			Rules    []struct {
				Kind string  `json:"kind"`
				Host *string `json:"host"`
			} `json:"rules"`
		}
		if err := json.Unmarshal(dto.Scope, &scope); err != nil {
			return nil, err
		}
		if !scope.AllowAll {
			for _, r := range scope.Rules {
				if r.Host != nil {
					scopeHosts = append(scopeHosts, *r.Host)
				}
			}
		}
	}
	rule := session.NewSessionRule(dto.Name, scopeHosts, nil)
	rule.Enabled = dto.Enabled
	rule.Validity = validity
	rule.MaxAttempts = 1
	if dto.MaxAttempts != nil {
		rule.MaxAttempts = *dto.MaxAttempts
	}
	for _, s := range dto.Steps {
		headers := make(map[string]string, len(s.Headers))
		for _, kv := range s.Headers {
			headers[kv[0]] = kv[1]
		}
		rule.Steps = append(rule.Steps, session.MacroStep{
			Method:  s.Method,
			URL:     s.URL,
			Headers: headers,
			Body:    s.Body,
		})
	}
	return rule, nil
}

// ---- handlers -----------------------------------------------------------------------------------

func (s *Server) handleSessionRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.sessionRulesGet(w, r)
	case http.MethodPost:
		s.sessionRulesPost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) sessionRulesGet(w http.ResponseWriter, r *http.Request) {
	rules := s.sessionCoordinator.AllRules()
	dtos := make([]sessionRuleDto, 0, len(rules))
	for _, rule := range rules {
		dtos = append(dtos, ruleToDto(rule))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessionRulesResp{Wired: true, Rules: dtos})
}

func (s *Server) sessionRulesPost(w http.ResponseWriter, r *http.Request) {
	var dto sessionRuleDto
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(dto.Name) == "" {
		http.Error(w, "A rule needs a name", http.StatusBadRequest)
		return
	}
	rule, err := dtoToRule(dto)
	if err != nil {
		http.Error(w, "Invalid validity/scope JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	id := s.sessionCoordinator.AddRule(rule)
	s.persistSessionRules()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"rule": ruleToDto(s.sessionCoordinator.Rule(id))})
}

func (s *Server) handleSessionRuleDetail(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/session/rules/")
	idStr = strings.TrimSuffix(idStr, "/")
	if strings.HasSuffix(idStr, "/update-macro") {
		s.sessionRuleUpdateMacro(w, r, idStr[:len(idStr)-len("/update-macro")])
		return
	}
	if strings.HasSuffix(idStr, "/run") {
		s.sessionRuleRunMacro(w, r, idStr[:len(idStr)-len("/run")])
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var dto sessionRuleDto
		if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		rule, err := dtoToRule(dto)
		if err != nil {
			http.Error(w, "Invalid validity/scope JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if !s.sessionCoordinator.UpdateRule(session.RuleID(id), rule) {
			http.Error(w, "Rule not found", http.StatusNotFound)
			return
		}
		s.persistSessionRules()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"rule": ruleToDto(s.sessionCoordinator.Rule(session.RuleID(id)))})
	case http.MethodDelete:
		if s.sessionCoordinator.Rule(session.RuleID(id)) == nil {
			http.Error(w, "Rule not found", http.StatusNotFound)
			return
		}
		s.sessionCoordinator.RemoveRule(session.RuleID(id))
		s.persistSessionRules()
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// sessionLoginRuns tracks what a login run most recently replayed per rule, so "update macro" can
// promote the observed steps back onto the rule. Kept in the web layer: the coordinator owns rules,
// not the observation of a one-off probe.
type sessionLoginRuns struct {
	mu    chan struct{}
	steps map[int64][]sessionStepDto
}

func newSessionLoginRuns() *sessionLoginRuns {
	return &sessionLoginRuns{mu: make(chan struct{}, 1), steps: map[int64][]sessionStepDto{}}
}

// remember stores the steps a successful run replayed for a rule.
func (lr *sessionLoginRuns) remember(ruleID int64, steps []sessionStepDto) {
	lr.mu <- struct{}{}
	defer func() { <-lr.mu }()
	lr.steps[ruleID] = steps
}

// observed returns the steps last observed for a rule, or nil.
func (lr *sessionLoginRuns) observed(ruleID int64) []sessionStepDto {
	lr.mu <- struct{}{}
	defer func() { <-lr.mu }()
	return lr.steps[ruleID]
}

func (s *Server) handleSessionLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req sessionLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	probe := req.Probe
	if strings.TrimSpace(probe.URL) == "" {
		http.Error(w, "A probe URL is required", http.StatusBadRequest)
		return
	}

	// Find the rule whose scope covers the probe host.
	host, _, _, err := targetParts(probe.URL)
	if err != nil {
		http.Error(w, "Invalid probe URL: "+err.Error(), http.StatusBadRequest)
		return
	}
	rule := s.sessionCoordinator.MatchingRule(host)
	if rule == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sessionLoginResp{Outcome: "no_rule"})
		return
	}

	// Replay the probe through the sender, absorbing any Set-Cookie into the coordinator's jar and
	// evaluating the rule's validity rule against the response.
	status, respBody, err := s.runMacroStep(r.Context(), probe)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sessionLoginResp{Outcome: "failed", Rule: rule.Name})
		return
	}
	state := session.Indeterminate
	if rule.Validity != nil {
		state = rule.Validity.Evaluate(status, nil, []byte(respBody))
	}
	id := int64(rule.ID)
	outcome := "recovered"
	if state == session.Valid {
		outcome = "already_valid"
	}
	s.loginRuns.remember(id, []sessionStepDto{probe})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessionLoginResp{Outcome: outcome, Rule: rule.Name, RuleID: &id})
}

// runMacroStep executes one macro/probe step through the HTTP sender and returns its status and
// body. Set-Cookie headers are absorbed into the coordinator's cookie jar so later steps in the
// macro carry the session.
func (s *Server) runMacroStep(ctx context.Context, step sessionStepDto) (int, string, error) {
	host, port, tls, err := targetParts(step.URL)
	if err != nil {
		return 0, "", err
	}
	method := strings.ToUpper(step.Method)
	if method == "" {
		method = "GET"
	}
	path := step.URL
	if i := strings.Index(step.URL, "://"); i >= 0 {
		if j := strings.Index(step.URL[i+3:], "/"); j >= 0 {
			path = step.URL[i+3+j:]
		} else {
			path = "/"
		}
	}
	req := &sender.Request{
		Method: method,
		Host:   host,
		Path:   path,
		Headers: map[string]string{
			"Host": host,
		},
		Body: []byte(step.Body),
		TLS:  tls,
		Port: port,
	}
	// Attach cookies the coordinator already holds for this authority.
	if cookie := s.sessionCoordinator.CookieHeader(host, port, tls); cookie != "" {
		req.Headers["Cookie"] = cookie
	}
	resp, err := s.sender.Send(ctx, req)
	if err != nil {
		s.toolLog.Record(toollog.ToolSession, host, port, tls, method, path, 0, 0, err.Error())
		return 0, "", err
	}
	// Absorb Set-Cookie into the jar so the next step authenticates.
	for k, v := range resp.Headers {
		if strings.EqualFold(k, "Set-Cookie") {
			s.sessionCoordinator.HandleResponse(host, port, tls, resp.StatusCode, map[string]string{"Set-Cookie": v}, resp.Body)
		}
	}
	s.toolLog.Record(toollog.ToolSession, host, port, tls, method, path, resp.StatusCode, uint64(resp.Duration.Milliseconds()), "")
	return resp.StatusCode, string(resp.Body), nil
}

func (s *Server) sessionRuleUpdateMacro(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	steps := s.loginRuns.observed(id)
	if len(steps) == 0 {
		// Nothing observed since the server started; refuse rather than offer a button that can
		// only fail.
		http.Error(w, "no macro run observed for this rule", http.StatusConflict)
		return
	}
	rule := s.sessionCoordinator.Rule(session.RuleID(id))
	if rule == nil {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}
	// Promote the observed steps onto the rule, preserving identity.
	stepsCopy := make([]session.MacroStep, 0, len(steps))
	for _, st := range steps {
		headers := make(map[string]string, len(st.Headers))
		for _, kv := range st.Headers {
			headers[kv[0]] = kv[1]
		}
		stepsCopy = append(stepsCopy, session.MacroStep{
			Method:  st.Method,
			URL:     st.URL,
			Headers: headers,
			Body:    st.Body,
		})
	}
	rule.Steps = stepsCopy
	s.sessionCoordinator.UpdateRule(session.RuleID(id), rule)
	s.persistSessionRules()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"steps": steps})
}

// sessionRunResp mirrors what a macro run reports: the steps actually sent (post-extraction), the
// per-step status codes, and the overall validity outcome.
type sessionRunResp struct {
	Outcome string           `json:"outcome"` // "valid" | "invalid" | "indeterminate" | "failed"
	Steps   []sessionRunStep `json:"steps"`
	Rule    string           `json:"rule,omitempty"`
	RuleID  *int64           `json:"rule_id,omitempty"`
}

type sessionRunStep struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Status *int   `json:"status,omitempty"` // nil when the step was skipped or failed to send
}

// sessionRuleRunMacro replays a rule's full macro through the sender, threading cookies and
// extractions. The run also leaves its trace in the login-run memory so "update macro" can promote
// what actually happened.
func (s *Server) sessionRuleRunMacro(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	rule := s.sessionCoordinator.Rule(session.RuleID(id))
	if rule == nil {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}

	runner := func(step session.MacroStep) (*session.StepResult, error) {
		// Adapt a coordinator step to the sender through the same path the probe uses, so
		// Set-Cookie absorption and tool-log recording are identical to a login run.
		host, port, tls, err := targetParts(step.URL)
		if err != nil {
			return nil, err
		}
		method := strings.ToUpper(step.Method)
		if method == "" {
			method = "GET"
		}
		path := step.URL
		if i := strings.Index(step.URL, "://"); i >= 0 {
			if j := strings.Index(step.URL[i+3:], "/"); j >= 0 {
				path = step.URL[i+3+j:]
			} else {
				path = "/"
			}
		}
		req := &sender.Request{
			Method:  method,
			Host:    host,
			Path:    path,
			Headers: map[string]string{"Host": host},
			Body:    []byte(step.Body),
			TLS:     tls,
			Port:    port,
		}
		for k, v := range step.Headers {
			req.Headers[k] = v
		}
		// The coordinator already attached the jar's cookies to the step; only add the jar's
		// current cookies when the step did not carry one.
		if _, has := req.Headers["Cookie"]; !has {
			if cookie := s.sessionCoordinator.CookieHeader(host, port, tls); cookie != "" {
				req.Headers["Cookie"] = cookie
			}
		}
		resp, err := s.sender.Send(r.Context(), req)
		if err != nil {
			s.toolLog.Record(toollog.ToolSession, host, port, tls, method, path, 0, 0, err.Error())
			return nil, err
		}
		// Absorb Set-Cookie into the jar so later steps authenticate.
		hdrs := make(map[string]string, len(resp.Headers))
		for k, v := range resp.Headers {
			hdrs[k] = v
			if strings.EqualFold(k, "Set-Cookie") {
				s.sessionCoordinator.HandleResponse(host, port, tls, resp.StatusCode, map[string]string{"Set-Cookie": v}, resp.Body)
			}
		}
		s.toolLog.Record(toollog.ToolSession, host, port, tls, method, path, resp.StatusCode, uint64(resp.Duration.Milliseconds()), "")
		return &session.StepResult{Status: resp.StatusCode, Headers: hdrs, Body: resp.Body}, nil
	}

	sent, results, state := s.sessionCoordinator.RunMacro(rule, runner)

	steps := make([]sessionRunStep, 0, len(sent))
	observed := make([]sessionStepDto, 0, len(sent))
	for i, st := range sent {
		var status *int
		if i < len(results) && results[i] != nil {
			sc := results[i].Status
			status = &sc
		}
		steps = append(steps, sessionRunStep{Method: st.Method, URL: st.URL, Status: status})
		if status != nil {
			observed = append(observed, macroStepToDto(st))
		}
	}
	// Remember what actually ran so "update macro" can promote it.
	if len(observed) > 0 {
		s.loginRuns.remember(id, observed)
	}

	outcome := "indeterminate"
	switch state {
	case session.Valid:
		outcome = "valid"
	case session.Invalid:
		outcome = "invalid"
	}
	resp := sessionRunResp{Outcome: outcome, Steps: steps, Rule: rule.Name, RuleID: &id}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleSessionCookies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The coordinator's cookie jar has no enumeration API, so the UI's cookie table is served from
	// what the coordinator reports per-authority — which it only does on request. Report wired with
	// an empty table rather than inventing cookies.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessionCookiesResp{Wired: true, Cookies: []sessionHostCookies{}})
}
