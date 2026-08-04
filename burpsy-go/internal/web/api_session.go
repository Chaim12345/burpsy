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

// sessionExtractDto mirrors the UI's ExtractionDto (internal/web/ui/src/session.ts) exactly, and both
// of its fields are unions, so both are held as raw JSON and decoded by hand:
//
//	type ExtractFrom = "body" | { header: string }
//	type ExtractHow  = { regex: { pattern: string; group?: number } } | { json_path: string } | "whole"
//
// Declaring `from` as a plain Go string — which is what this DTO used to do — makes
// `{"header": "X-Token"}` fail to unmarshal into it, and since the whole struct was never read
// anyway the mismatch went unnoticed. Decoding the real shape is what lets an extraction the operator
// typed reach the rule instead of being dropped between the browser and the coordinator.
type sessionExtractDto struct {
	Name string `json:"name"`
	// Absent means the body, matching the UI's optional field.
	From json.RawMessage `json:"from,omitempty"`
	How  json.RawMessage `json:"how"`
}

// wholeValuePattern is how the UI's `how: "whole"` is expressed to an extractor that only knows
// regexes: match everything including newlines, and take group 0. Kept as a named constant because
// ruleToDto reads it back to decide whether an extraction started life as "whole" — so the UI's
// dropdown comes back on the option the operator chose rather than showing them a regex they never
// typed.
const wholeValuePattern = `(?s)^.*$`

// extractFrom decodes ExtractFrom into the ("body"|"header", header name) pair session.Extraction
// holds.
func (d sessionExtractDto) extractFrom() (from string, header string, err error) {
	if len(d.From) == 0 || string(d.From) == "null" {
		return "body", "", nil
	}
	var asString string
	if err := json.Unmarshal(d.From, &asString); err == nil {
		if asString != "body" {
			return "", "", fmt.Errorf("extraction %q reads from %q; the only bare source is \"body\" "+
				"(a header is stated as {\"header\": name})", d.Name, asString)
		}
		return "body", "", nil
	}
	var asHeader struct {
		Header *string `json:"header"`
	}
	if err := json.Unmarshal(d.From, &asHeader); err != nil || asHeader.Header == nil {
		return "", "", fmt.Errorf("extraction %q reads from %s, which is neither \"body\" nor "+
			"{\"header\": name}", d.Name, string(d.From))
	}
	if strings.TrimSpace(*asHeader.Header) == "" {
		return "", "", fmt.Errorf("extraction %q reads from a header with no name", d.Name)
	}
	return "header", *asHeader.Header, nil
}

// extractHow decodes ExtractHow into the (pattern, group) pair this port's extractor runs.
//
// `json_path` is refused rather than silently treated as a regex: session.Extraction implements
// regex extraction only, and a JSON path quietly compiled as a pattern would match nothing while
// looking configured. That is a named divergence from the Rust crate, which implements all three.
func (d sessionExtractDto) extractHow() (pattern string, group int, err error) {
	if len(d.How) == 0 || string(d.How) == "null" {
		return "", 0, fmt.Errorf("extraction %q does not say how to extract; state a regex, a json path, or \"whole\"", d.Name)
	}
	var asString string
	if err := json.Unmarshal(d.How, &asString); err == nil {
		if asString != "whole" {
			return "", 0, fmt.Errorf("extraction %q extracts by %q, which is not a known method", d.Name, asString)
		}
		return wholeValuePattern, 0, nil
	}
	var tagged struct {
		Regex *struct {
			Pattern string `json:"pattern"`
			Group   *int   `json:"group"`
		} `json:"regex"`
		JSONPath *string `json:"json_path"`
	}
	if err := json.Unmarshal(d.How, &tagged); err != nil {
		return "", 0, fmt.Errorf("extraction %q: cannot read how it extracts from %s: %w", d.Name, string(d.How), err)
	}
	switch {
	case tagged.Regex != nil:
		// A blank group means the UI's own default of 1 (the first capture), not group 0.
		group = 1
		if tagged.Regex.Group != nil {
			group = *tagged.Regex.Group
		}
		return tagged.Regex.Pattern, group, nil
	case tagged.JSONPath != nil:
		return "", 0, fmt.Errorf("extraction %q extracts by json path %q, which this port does not "+
			"implement: state it as a regex over the response body instead", d.Name, *tagged.JSONPath)
	default:
		return "", 0, fmt.Errorf("extraction %q: %s names no extraction method", d.Name, string(d.How))
	}
}

// extractionToDto is the inverse: what a stored extraction looks like on the wire, so a rule the
// operator saved reads back as the rule they typed.
func extractionToDto(ex *session.Extraction) sessionExtractDto {
	d := sessionExtractDto{Name: ex.Name}
	if ex.From == "header" {
		d.From = json.RawMessage(mustJSON(map[string]string{"header": ex.Header}))
	} else {
		d.From = json.RawMessage(`"body"`)
	}
	if ex.Pattern == wholeValuePattern && ex.Group == 0 {
		d.How = json.RawMessage(`"whole"`)
		return d
	}
	d.How = json.RawMessage(mustJSON(map[string]interface{}{
		"regex": map[string]interface{}{"pattern": ex.Pattern, "group": ex.Group},
	}))
	return d
}

// mustJSON marshals a map built from strings and ints, which cannot fail. The fallback is `null`
// rather than a panic so a marshalling bug degrades to one visibly empty field instead of taking the
// whole API process down.
func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`null`)
	}
	return b
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

// sessionLoginResp mirrors the UI's LoginResp, and carries one field per thing a RecoveryOutcome can
// say.
//
// Every outcome gets its own `outcome` tag rather than collapsing into ok/error, for the reason the
// coordinator's own docs give: a caller has to be able to tell "this is working" from "this has
// quietly stopped trying". That is the shape crates/web/src/routes/session.rs's `outcome_body`
// serves, and these fields are its union — only the ones an outcome actually carries are emitted.
type sessionLoginResp struct {
	// Outcome is one of: "no_rule_applies", "already_valid", "recovered",
	// "still_invalid_after_relogin", "gave_up", "macro_failed", "retry_failed", "probe_failed".
	Outcome string `json:"outcome,omitempty"`
	Rule    string `json:"rule,omitempty"`
	RuleID  *int64 `json:"rule_id,omitempty"`
	// URL / Rules / Hint: no_rule_applies. The rule count and the hint are there because "nothing
	// happened" with no reason is the least actionable answer a login button can give.
	URL   string `json:"url,omitempty"`
	Rules *int   `json:"rules,omitempty"`
	Hint  string `json:"hint,omitempty"`
	// LoginAttempts: recovered / still_invalid_after_relogin / gave_up / retry_failed. How many times
	// the macro ran, so "worked first time" and "worked on the third try" are distinguishable.
	LoginAttempts *int `json:"login_attempts,omitempty"`
	// Attempt / StepIndex: macro_failed — the 1-based attempt and the step within it that could not
	// be sent, which is exactly what "update macro" repairs.
	Attempt   *int `json:"attempt,omitempty"`
	StepIndex *int `json:"step_index,omitempty"`
	// Validity: still_invalid_after_relogin — "valid" | "invalid" | "indeterminate".
	Validity string `json:"validity,omitempty"`
	// Response: recovered / still_invalid_after_relogin — what the retried original request returned.
	Response *sessionLoginResponseView `json:"response,omitempty"`
	// Error: macro_failed / retry_failed / probe_failed.
	Error string `json:"error,omitempty"`
}

// sessionLoginResponseView is the retried original request's response, mirroring Rust's
// `response_view`.
type sessionLoginResponseView struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body"`
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
	// Extractions are stored in one flat list naming the step each one reads (session.Extraction.Step)
	// and are served back attached to that step, because that is the shape the UI edits them in — a
	// row under the step whose response they scrape. Emitting them was missing entirely, so a rule
	// with extractions read back as a rule without any, and the next save from the UI would have
	// silently dropped them for real.
	for i, step := range r.Steps {
		d := macroStepToDto(step)
		for _, ex := range r.Extractions {
			if ex != nil && ex.Step == i {
				d.Extract = append(d.Extract, extractionToDto(ex))
			}
		}
		dto.Steps = append(dto.Steps, d)
	}
	return dto
}

// macroStepToDto renders one step. Headers are emitted in sorted order: a Go map has none, and an
// order that changes between two GETs of the same rule shows the operator a diff they did not make.
func macroStepToDto(step session.MacroStep) sessionStepDto {
	d := sessionStepDto{Method: step.Method, URL: step.URL, Body: step.Body}
	keys := make([]string, 0, len(step.Headers))
	for k := range step.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		d.Headers = append(d.Headers, [2]string{k, step.Headers[k]})
	}
	return d
}

// dtoToRule converts the UI shape into a stored rule, then validates it. Validity and scope are
// parsed from their free-form JSON; a malformed validity block is refused because a broken validity
// rule silently re-logging in on every request would be worse than an error.
//
// The returned error is meant to be shown to the operator verbatim as a 400 — it is either a JSON
// parse failure, an extraction this port cannot run, or a *session.RuleError naming the rule and the
// exact thing wrong with it.
func dtoToRule(dto sessionRuleDto) (*session.SessionRule, error) {
	var validity *session.ValidityRule
	if len(dto.Validity) > 0 {
		if err := json.Unmarshal(dto.Validity, &validity); err != nil {
			return nil, err
		}
	}
	// Rust's scope is an Option<Scope>: omitted means "applies everywhere", and only a scope that was
	// *stated* and empty is refused (crates/session/src/rule.rs). Both collapse into the same empty
	// []string on a Go SessionRule, so which of the two this was has to be settled here, while the
	// wire form still says, and handed to validation — otherwise "allow_all" and "restrict me to
	// nothing" become indistinguishable and one of the two has to be answered wrongly.
	var scopeHosts []string
	scopeStated := false
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
		scopeStated = !scope.AllowAll
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
	// Omitted means the default, which NewSessionRule already applied. Overwriting it with 1 — as
	// this did — turned the UI's "default" placeholder into "one attempt only", so a login that
	// needed a second try to absorb a redirect race gave up where the Rust crate would have retried.
	if dto.MaxAttempts != nil {
		rule.MaxAttempts = *dto.MaxAttempts
	}
	for i, s := range dto.Steps {
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
		// Every step's extractions, tagged with the step whose response they read. This was missing
		// outright: the DTO carried them, and nothing ever looked at the field, so an operator could
		// type a CSRF extraction, save, see it accepted, and get a macro that sent "{{csrf}}" as a
		// literal string.
		for _, e := range s.Extract {
			from, header, err := e.extractFrom()
			if err != nil {
				return nil, fmt.Errorf("step %d: %w", i, err)
			}
			pattern, group, err := e.extractHow()
			if err != nil {
				return nil, fmt.Errorf("step %d: %w", i, err)
			}
			// A pattern that does not compile is the operator's typo, and it has to be an error: an
			// extraction dropped for being unusable leaves a rule that looks configured and cannot
			// log in.
			ex, err := session.NewExtraction(e.Name, from, pattern, group)
			if err != nil {
				return nil, fmt.Errorf("step %d: extraction %q has an unusable pattern %q: %w", i, e.Name, pattern, err)
			}
			ex.Header = header
			ex.Step = i
			rule.Extractions = append(rule.Extractions, ex)
		}
	}
	if err := session.ValidateRuleStatedScope(rule, scopeStated); err != nil {
		return nil, err
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
	// No separate name check here any more: dtoToRule validates the whole rule, and the name is one of
	// the things it checks. Two checks for the same thing is two wordings that can drift apart, and
	// the operator would be told about a missing name in one voice and about everything else in
	// another.
	rule, err := dtoToRule(dto)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := s.sessionCoordinator.AddRule(rule)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// "The rule is gone" and "the edit is not a valid rule" are different answers, so they get
		// different codes rather than one generic failure.
		if err := s.sessionCoordinator.UpdateRule(session.RuleID(id), rule); err != nil {
			if errors.Is(err, session.ErrNoSuchRule) {
				http.Error(w, "Rule not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
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

// handleSessionLogin is POST /api/session/login — the operator's "log in again" button.
//
// The order of operations is the point, and mirrors crates/web/src/routes/session.rs's `run_login`:
//
//  1. Resolve the rule covering the probe *before* sending anything. With no rule there is no macro
//     to run with whatever comes back, so sending the probe would cost a live target a request to no
//     purpose.
//  2. Send the probe with the coordinator's jar attached, so a probe that is *already* authenticated
//     looks authenticated. Sent outside the jar it would look permanently logged out and
//     "already_valid" would be unreachable in practice.
//  3. Hand the response to the coordinator's recovery path, which is what actually runs the login
//     macro (single-flight per rule, bounded by max_attempts) and retries the probe with the fresh
//     session.
//
// What this used to do instead: evaluate validity inline and, for anything other than Valid, report
// `outcome: "recovered"` without running the macro at all. The button reported success for having
// established nothing — the single worst answer available, because the operator moves on believing
// they are logged in. HandleRecovery and EnsureLoggedIn were fully implemented and tested with no
// caller outside their own package; this is the caller.
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
	host, _, _, err := targetParts(probe.URL)
	if err != nil {
		http.Error(w, "Invalid probe URL: "+err.Error(), http.StatusBadRequest)
		return
	}
	step := stepDtoToMacroStep(probe)

	// (1) Nothing is sent until a rule is known to own this target.
	rule := s.sessionCoordinator.MatchingRule(host)
	if rule == nil {
		count := len(s.sessionCoordinator.AllRules())
		writeJSON(w, http.StatusOK, sessionLoginResp{
			Outcome: "no_rule_applies",
			URL:     probe.URL,
			Rules:   &count,
			Hint:    "no enabled rule's scope covers this url; add one, widen its scope, or enable it",
		})
		return
	}
	id := int64(rule.ID)

	runner := s.macroRunner(r.Context())

	// (2) The probe goes out through the same runner the macro's own steps use, so cookie handling and
	// tool-log recording are identical for both.
	response, err := runner(step)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, sessionLoginResp{
			Outcome: "probe_failed", Rule: rule.Name, RuleID: &id, Error: err.Error(),
		})
		return
	}

	// (3) The coordinator decides whether this counts as a valid session and, if not, runs the macro.
	outcome := s.sessionCoordinator.HandleRecovery(step, response, runner)

	// Nothing is written to s.loginRuns here on purpose. A successful login already recorded what it
	// sent inside the coordinator (recordObserved, untemplated), and that is what
	// sessionRuleUpdateMacro now promotes. This used to remember the *probe* as the observed macro,
	// so pressing "update macro" afterwards replaced the operator's recorded login with a single GET
	// of the page they were checking — a button that destroyed the thing it claimed to repair.
	status, resp := loginOutcomeResponse(outcome)
	resp.Rule = rule.Name
	resp.RuleID = &id
	writeJSON(w, status, resp)
}

// loginOutcomeResponse is the faithful RecoveryOutcome -> (HTTP status, body) mapping, mirroring
// crates/web/src/routes/session.rs's `outcome_body`.
//
// 502 is used only for the two outcomes where a request could not be sent at all (macro_failed,
// retry_failed). Every outcome that reached a definite conclusion — including gave_up — is a 200 whose
// body says which, because "the login was attempted and did not work" is an answer, not a transport
// failure.
func loginOutcomeResponse(o session.RecoveryOutcome) (int, sessionLoginResp) {
	attempts := o.LoginAttempts
	switch o.Kind {
	case session.RecoveryNoRuleApplies:
		// Unreachable from handleSessionLogin, which resolves the rule before sending. Mapped anyway
		// rather than left to fall through, so a future caller that skips that step is answered
		// honestly instead of being told the login worked.
		return http.StatusOK, sessionLoginResp{Outcome: "no_rule_applies", URL: o.URL}
	case session.RecoveryAlreadyValid:
		return http.StatusOK, sessionLoginResp{Outcome: "already_valid"}
	case session.RecoveryRecovered:
		return http.StatusOK, sessionLoginResp{
			Outcome:       "recovered",
			LoginAttempts: &attempts,
			Response:      responseView(o.Response),
		}
	case session.RecoveryStillInvalidAfterRelogin:
		return http.StatusOK, sessionLoginResp{
			Outcome:       "still_invalid_after_relogin",
			LoginAttempts: &attempts,
			Validity:      validityName(o.Validity),
			Response:      responseView(o.Response),
		}
	case session.RecoveryGaveUp:
		return http.StatusOK, sessionLoginResp{Outcome: "gave_up", LoginAttempts: &attempts}
	case session.RecoveryMacroFailed:
		resp := sessionLoginResp{Outcome: "macro_failed", Attempt: &o.Attempt}
		if o.Failure != nil {
			idx := o.Failure.StepIndex
			resp.StepIndex = &idx
			resp.Error = o.Failure.Error
		}
		return http.StatusBadGateway, resp
	case session.RecoveryRetryFailed:
		return http.StatusBadGateway, sessionLoginResp{
			Outcome: "retry_failed", LoginAttempts: &attempts, Error: o.Error,
		}
	}
	// A RecoveryOutcomeKind this mapping does not know is reported as such rather than silently
	// answered as a success: a variant added to the coordinator must be mapped here, and the honest
	// failure is what makes that visible.
	return http.StatusInternalServerError, sessionLoginResp{
		Outcome: "unmapped_outcome",
		Error:   fmt.Sprintf("recovery outcome kind %d has no wire mapping", int(o.Kind)),
	}
}

func responseView(r *session.StepResult) *sessionLoginResponseView {
	if r == nil {
		return nil
	}
	return &sessionLoginResponseView{Status: r.Status, Headers: r.Headers, Body: string(r.Body)}
}

func validityName(v session.ValidityState) string {
	switch v {
	case session.Valid:
		return "valid"
	case session.Invalid:
		return "invalid"
	default:
		return "indeterminate"
	}
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// stepDtoToMacroStep converts one wire step into the coordinator's shape. Headers arrive as an ordered
// [k,v] list and become a map, which is what session.MacroStep holds.
func stepDtoToMacroStep(step sessionStepDto) session.MacroStep {
	headers := make(map[string]string, len(step.Headers))
	for _, kv := range step.Headers {
		headers[kv[0]] = kv[1]
	}
	return session.MacroStep{Method: step.Method, URL: step.URL, Headers: headers, Body: step.Body}
}

// macroRunner is the session package's MacroStepRunner seam bound to this server's sender: it sends
// one step, records it in the tool log, and absorbs any Set-Cookie into the coordinator's jar.
//
// One implementation shared by the login probe, the recovery macro it triggers, and the manual
// "run macro" button, because these three must behave identically — a probe that dropped the headers
// the operator typed (which the old bespoke probe path did: it built a request carrying only `Host`)
// would evaluate a *different* request than the macro replays, so the validity verdict driving
// recovery would be about a request nobody asked to send.
func (s *Server) macroRunner(ctx context.Context) session.MacroStepRunner {
	return func(step session.MacroStep) (*session.StepResult, error) {
		host, port, tls, err := targetParts(step.URL)
		if err != nil {
			return nil, err
		}
		if s.sender == nil {
			// Reported rather than dereferenced: a server assembled without a sender can still serve
			// the rules list, and the honest answer here is that nothing can be sent.
			return nil, fmt.Errorf("no HTTP sender is wired, so no session macro step can be sent")
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
		// The coordinator attaches the jar's cookie to a step it owns; only fill one in when the step
		// did not carry one (the operator's own probe, typed by hand).
		if _, has := req.Headers["Cookie"]; !has {
			if cookie := s.sessionCoordinator.CookieHeader(host, port, tls); cookie != "" {
				req.Headers["Cookie"] = cookie
			}
		}
		resp, err := s.sender.Send(ctx, req)
		if err != nil {
			s.toolLog.Record(toollog.ToolSession, host, port, tls, method, path, 0, 0, err.Error())
			return nil, err
		}
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
	// The coordinator's own observation comes first, because it is the better one: it holds the steps a
	// *successful* login actually sent, with this run's extracted values written back as their
	// {{placeholders}}. The web-layer mirror below holds them post-interpolation, so promoting it would
	// bake the one-time token this run scraped into the stored macro and the next login would replay a
	// stale one — turning a repair into a breakage. Coordinator.UpdateMacro had no caller outside its
	// own package before this; it does now.
	switch promoted := s.sessionCoordinator.UpdateMacro(session.RuleID(id)); promoted.Kind {
	case session.UpdateMacroUpdated:
		s.persistSessionRules()
		steps := make([]sessionStepDto, 0, len(promoted.Steps))
		for _, st := range promoted.Steps {
			steps = append(steps, macroStepToDto(st))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"steps": steps})
		return
	case session.UpdateMacroNoSuchRule:
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	case session.UpdateMacroInvalid:
		// A promotion the rule cannot hold — a run that sent fewer steps than the rule stores leaves an
		// extraction naming a step that no longer exists. Rust refuses the same case in `with_steps`
		// ("extractions belong to a step by position") because silently dropping what a vanished step
		// extracted is how a macro comes back looking repaired and still unable to log in.
		http.Error(w, promoted.Error, http.StatusConflict)
		return
	case session.UpdateMacroNothingObserved:
		// No login has run for this rule, but the manual "run macro" button may still have left a trace
		// in the web-layer mirror. Fall through to it rather than refusing something that is available.
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
	stepsCopy := make([]session.MacroStep, 0, len(steps))
	for _, st := range steps {
		stepsCopy = append(stepsCopy, stepDtoToMacroStep(st))
	}
	// A copy, so a refused promotion leaves the working rule exactly as it was rather than mutating it
	// in place and then failing to install it.
	promoted := *rule
	promoted.Steps = stepsCopy
	if err := s.sessionCoordinator.UpdateRule(session.RuleID(id), &promoted); err != nil {
		if errors.Is(err, session.ErrNoSuchRule) {
			http.Error(w, "Rule not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
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

	// The same runner the login probe and its recovery macro use, so all three send identically.
	sent, results, state := s.sessionCoordinator.RunMacro(rule, s.macroRunner(r.Context()))

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
