package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/advisory"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/query"
	"go.uber.org/zap"
)

// handleHistory serves GET /api/history?limit=N[&q=query]. The UI expects a bare array of
// exchanges, newest first, capped at `limit` (default 300). `q`, when present, is a burpsy-query
// filter compiled against each exchange's host/path/method/status.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 300
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}

	exchanges := s.store.Exchanges()

	// Query filter (DSL-02), applied before the cap so a capped list is a truthful slice.
	var filter *queryFilter
	if q := r.URL.Query().Get("q"); strings.TrimSpace(q) != "" {
		var err error
		filter, err = compileQuery(q, s.store)
		if err != nil {
			// The UI renders this body verbatim with white-space:pre, caret and all — so send the
			// caret rendering (message, source line, caret), not just the one-line message.
			http.Error(w, query.Render(err), http.StatusBadRequest)
			return
		}
	}

	// Proxy history is proxy traffic — plus crawled traffic, which travels the identical
	// capture path (CRAWL-02), and anything no producer claimed, which hiding would make
	// invisible rather than absent. Tool-originated sends — Repeater resends, Intruder
	// payloads, Scanner probes — belong in Logger, the view whose whole subject is "requests
	// burpsy itself made"; showing them here would make HTTP history and Logger the same list
	// with different columns, and turn "how many requests did I proxy" into a question history
	// answers wrongly.
	//
	// Newest first (the store appends in arrival order).
	views := make([]*ExchangeView, 0, len(exchanges))
	for i := len(exchanges) - 1; i >= 0; i-- {
		ex := exchanges[i]
		switch ex.Source {
		case core.SourceRepeater, core.SourceIntruder, core.SourceScanner:
			continue
		}
		if filter != nil && !filter.match(ex) {
			continue
		}
		views = append(views, exchangeView(ex))
		if len(views) >= limit {
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(views)
}

// handleMessage serves GET /api/message/{id} -> MessageView{id,len,text}.
func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/api/message/"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", http.StatusBadRequest)
		return
	}
	msg, err := s.message(id)
	if err != nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messageView(msg))
}

// handleExchange serves GET /api/exchange/{id} (and the legacy /api/exchanges/{id}) -> ExchangeView,
// plus PATCH /api/exchange/{id} to annotate one -> the updated ExchangeView. The legacy alias stays
// read-only: it exists for the Rust UI's benefit, which never PATCHes anything, so widening it would
// be surface no consumer needs.
func (s *Server) handleExchange(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	legacy := strings.HasPrefix(path, "/api/exchanges/")
	path = strings.TrimPrefix(path, "/api/exchange/")
	path = strings.TrimPrefix(path, "/api/exchanges/")
	// The CSRF PoC generator rides the same subtree: /api/exchange/{id}/csrf.
	if strings.HasSuffix(path, "/csrf") {
		if legacy {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(path, "/csrf"), 10, 64)
		if err != nil {
			http.Error(w, "Invalid exchange ID", http.StatusBadRequest)
			return
		}
		s.handleCSRF(w, r, core.ExchangeID(id))
		return
	}
	id, err := strconv.ParseUint(path, 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange ID", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		ex, err := s.store.GetExchange(core.ExchangeID(id))
		if err != nil {
			http.Error(w, "Exchange not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(exchangeView(ex))
	case http.MethodPatch:
		if legacy {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handlePatchExchange(w, r, core.ExchangeID(id))
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePatchExchange serves PATCH /api/exchange/{id}: body {"notes": string|null, "highlight":
// string}, both optional. An omitted field is left unchanged; an explicit `null` on notes clears it
// (there is no way to express "clear" for highlight other than sending ""="none", so an omitted
// highlight and one explicitly sent as the empty string are indistinguishable on the wire — that is
// intentional, since "" already means "no highlight"). highlight must be "" or a member of
// core.ValidHighlights; anything else is a 400 and is never coerced to a nearby value. Responds with
// the updated ExchangeView.
func (s *Server) handlePatchExchange(w http.ResponseWriter, r *http.Request, id core.ExchangeID) {
	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var notes *string
	notesSet := false
	if raw, ok := body["notes"]; ok {
		notesSet = true
		if err := json.Unmarshal(raw, &notes); err != nil {
			http.Error(w, "notes must be a string or null", http.StatusBadRequest)
			return
		}
	}

	highlight := ""
	highlightSet := false
	if raw, ok := body["highlight"]; ok {
		highlightSet = true
		if err := json.Unmarshal(raw, &highlight); err != nil {
			http.Error(w, "highlight must be a string", http.StatusBadRequest)
			return
		}
		if highlight != "" && !core.ValidHighlights[highlight] {
			http.Error(w, fmt.Sprintf("Unknown highlight colour %q", highlight), http.StatusBadRequest)
			return
		}
	}

	ex, err := s.store.UpdateExchangeAnnotation(id, notes, notesSet, highlight, highlightSet)
	if err != nil {
		http.Error(w, "Exchange not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exchangeView(ex))
}

// handleStats serves GET /api/stats -> Stats{exchanges,messages,stored_bytes}.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	messages, exchanges := s.store.Count()
	w.Header().Set("Content-Type", "application/json")
	view := StatsView{
		Exchanges:   exchanges,
		Messages:    messages,
		StoredBytes: s.store.Bytes(),
		ProxyBind:   s.proxyBind,
		WebBind:     s.webBind,
	}
	// caCertPEM exists iff -intercept-tls was passed
	if s.caCertPEM != nil {
		view.TLSInterception = true
	}
	// "off" rather than "": a blank field is indistinguishable from a field this build does not
	// report, and the whole point of showing this is that an operator can tell the difference.
	view.DOMEngine = "off"
	if s.domEngine != "" {
		view.DOMEngine = s.domEngine
	}
	view.DOMChecks = s.scanner.DOMCapabilityConfigured()
	json.NewEncoder(w).Encode(view)
}

// ---- scope -------------------------------------------------------------------------------------

// ScopeRequest represents a scope modification request.
type ScopeRequest struct {
	Action  string `json:"action"` // "include", "exclude", "remove" or "clear"
	Kind    string `json:"kind"`   // optional rule kind for "remove": "include" or "exclude"
	Pattern string `json:"pattern"`
	// Path limits the rule to requests whose path starts with it, and Port to one port. Both optional;
	// omitted means the rule covers the whole host, which is what every rule meant before these
	// existed. core.Scope has supported both since it was written — NewScopeRuleWithPath and
	// NewScopeRuleWithPort — and the site map honours them, but this endpoint only ever built bare
	// host rules, so neither shape was reachable from the UI. Burp scopes by full URL; this is the
	// gap that left burpsy unable to say "this host, but not /admin".
	Path string  `json:"path,omitempty"`
	Port *uint16 `json:"port,omitempty"`
	// Protocol limits the rule to one scheme: "http" or "https". Empty means either.
	Protocol string `json:"protocol,omitempty"`
}

// normaliseScopePath validates an optional path prefix and returns nil for "no path".
//
// A prefix must start with "/", because it is matched with strings.HasPrefix against a request path
// that always does: accepting "admin" would build a rule that silently matches nothing, which is the
// worst outcome for a scope rule — the operator believes a restriction is in force and it is not.
func normaliseScopePath(raw string) (*string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	if !strings.HasPrefix(trimmed, "/") {
		return nil, fmt.Errorf("A scope path must start with /, so it can match a request path; got %q", trimmed)
	}
	return &trimmed, nil
}

// normaliseScopeProtocol validates an optional protocol arm and returns nil for "either scheme".
//
// Only "http" and "https" are accepted, because those are the only schemes a request through this
// proxy can speak. Anything else would build a rule that silently matches nothing — the worst outcome
// for a scope rule: the operator believes a restriction is in force and it is not.
func normaliseScopeProtocol(raw string) (*string, error) {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	if trimmed == "" {
		return nil, nil
	}
	if trimmed != "http" && trimmed != "https" {
		return nil, fmt.Errorf("A scope protocol must be http or https; got %q", raw)
	}
	return &trimmed, nil
}

// buildScopeRule turns a request into the narrowest rule it describes.
func buildScopeRule(kind core.ScopeRuleKind, req ScopeRequest) (*core.ScopeRule, error) {
	path, err := normaliseScopePath(req.Path)
	if err != nil {
		return nil, err
	}
	protocol, err := normaliseScopeProtocol(req.Protocol)
	if err != nil {
		return nil, err
	}
	rule := core.NewScopeRule(kind, req.Pattern)
	if path != nil {
		rule.PathPrefix = path
	}
	if req.Port != nil {
		rule.Port = req.Port
	}
	rule.Protocol = protocol
	return rule, nil
}

func (s *Server) handleScope(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getScope(w, r)
	case http.MethodPost:
		s.updateScope(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// scopeRuleView serialises one rule in the UI's ScopeInfo shape: kind is "Include"/"Exclude"
// (capitalised, as history.ts's client-side filter expects), host carries the raw pattern.
type scopeRuleView struct {
	Kind string  `json:"kind"`
	Host *string `json:"host"`
	// Path and Port are omitted for a host-wide rule. Reported so the UI can show what a rule actually
	// covers, and so it can hand the exact tuple back on remove — two rules on one host differing only
	// in path are the ordinary case, and removing by host alone would delete the wrong one.
	Path *string `json:"path,omitempty"`
	Port *uint16 `json:"port,omitempty"`
	// Protocol is omitted when the rule matches either scheme.
	Protocol *string `json:"protocol,omitempty"`
}

func (s *Server) getScope(w http.ResponseWriter, r *http.Request) {
	rules := s.scope.Rules()
	views := make([]scopeRuleView, 0, len(rules))
	for _, rule := range rules {
		kind := "Include"
		if rule.Kind == core.ScopeExclude {
			kind = "Exclude"
		}
		pattern := rule.Pattern
		views = append(views, scopeRuleView{Kind: kind, Host: &pattern, Path: rule.PathPrefix, Port: rule.Port, Protocol: rule.Protocol})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"allow_all": s.scope.AllowAll(),
		"rules":     views,
		"empty":     s.scope.Empty(),
	})
}

func (s *Server) updateScope(w http.ResponseWriter, r *http.Request) {
	var req ScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	switch req.Action {
	case "include", "exclude":
		kind := core.ScopeInclude
		if req.Action == "exclude" {
			kind = core.ScopeExclude
		}
		if req.Pattern == "" {
			http.Error(w, "Pattern is required", http.StatusBadRequest)
			return
		}
		rule, err := buildScopeRule(kind, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.scope.Add(rule)
	case "remove":
		if req.Pattern == "" {
			http.Error(w, "Pattern is required", http.StatusBadRequest)
			return
		}
		// Kind is optional and falls back to whichever rule carries the pattern. The path and port are
		// part of the identity, not a filter: removing include(h) must not take exclude(h, "/admin")
		// with it, which is exactly what matching on host alone used to do.
		path, err := normaliseScopePath(req.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var removed bool
		switch req.Kind {
		case "exclude":
			removed = s.scope.RemoveScoped(core.ScopeExclude, req.Pattern, path, req.Port)
		case "include":
			removed = s.scope.RemoveScoped(core.ScopeInclude, req.Pattern, path, req.Port)
		default:
			removed = s.scope.RemoveScoped(core.ScopeInclude, req.Pattern, path, req.Port) ||
				s.scope.RemoveScoped(core.ScopeExclude, req.Pattern, path, req.Port)
		}
		if !removed {
			http.Error(w, "No matching rule found", http.StatusNotFound)
			return
		}
	case "clear":
		s.scope.Clear()
	default:
		http.Error(w, "Unknown scope action", http.StatusBadRequest)
		return
	}
	s.persistScope()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ---- issues / findings -------------------------------------------------------------------------

// issueOccurrenceView mirrors the UI's Occurrence shape.
type issueOccurrenceView struct {
	ExchangeID core.ExchangeID `json:"exchange_id"`
	Response   uint64          `json:"response"`
	Path       string          `json:"path"`
}

// issueAdvisoryView is the catalogue entry attached to a finding.
//
// Description and Remediation are HTML fragments from the catalogue, not plain text. They are sent
// as-is and the UI renders them into a sanitised container — stripping the markup here would collapse
// multi-paragraph remediation advice into one run-on wall, which is the difference between advice an
// operator reads and advice they skip.
//
// TypicalSeverity is the severity the *class* usually carries and is deliberately separate from the
// finding's own severity. A catalogue lookup must never restate what the scanner concluded about this
// particular occurrence.
type issueAdvisoryView struct {
	TypeIndex string `json:"type_index"`
	Name      string `json:"name"`
	// Description and Remediation are the raw catalogue fragments, kept for any consumer that wants
	// them; DescriptionParagraphs and RemediationParagraphs are what the console renders. Plain text,
	// one entry per paragraph or list item, so the React side never needs dangerouslySetInnerHTML —
	// see advisory.PlainParagraphs for why the console and the report differ here on purpose.
	Description           string              `json:"description"`
	Remediation           string              `json:"remediation"`
	DescriptionParagraphs []string            `json:"description_paragraphs,omitempty"`
	RemediationParagraphs []string            `json:"remediation_paragraphs,omitempty"`
	TypicalSeverity       string              `json:"typical_severity"`
	References            []issueAdvisoryLink `json:"references,omitempty"`
	Classifications       []issueAdvisoryLink `json:"classifications,omitempty"`
}

type issueAdvisoryLink struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// issueFindingView mirrors the UI's Finding shape. check_name is the rule/check that fired;
// issue_name the human title; occurrences carry the exchange ids the check saw.
type issueFindingView struct {
	ID          uint64  `json:"id"`
	CheckName   string  `json:"check_name"`
	IssueName   *string `json:"issue_name"`
	Severity    string  `json:"severity"`
	Confidence  string  `json:"confidence"`
	Host        string  `json:"host"`
	Detail      *string `json:"detail"`
	Remediation *string `json:"remediation"`
	// Param is the parameter this finding was observed at, omitted when the finding is about a
	// resource rather than one of its inputs. An insertion-point BCheck or a DOM sink names it;
	// everything else stays absent so the UI renders an em dash, not an empty cell.
	Param string `json:"param,omitempty"`
	// Params is every parameter this finding covers. A finding that merged several observations of
	// the same issue at the same target — five reflected-XSS hits on /search — reports one row with
	// several occurrences, and this is what stops that row from hiding which five parameters were
	// vulnerable. Single-observation findings carry the one param here too, so the UI has one field
	// to read rather than two rules.
	Params      []string              `json:"params,omitempty"`
	Occurrences []issueOccurrenceView `json:"occurrences"`
	TimesSeen   int                   `json:"times_seen"`
	// Advisory is the catalogue entry for this issue class, when one resolves. Omitted rather than
	// emptied, so the UI can tell "no catalogue advisory" from "an advisory with blank fields".
	Advisory *issueAdvisoryView `json:"advisory,omitempty"`
	// AdvisoryNote explains why there is no advisory, for the checks that deliberately have none.
	// Empty when the check simply was not considered — those two states are different and the UI
	// says so rather than showing one blank panel for both.
	AdvisoryNote string `json:"advisory_note,omitempty"`
	// TaskID is the run that produced this finding, omitted when nothing tracked it. It is what ties
	// a coverage summary to the findings that came out of the same run.
	TaskID uint64 `json:"task_id,omitempty"`
}

// findingToIssueView converts a stored finding into the UI shape. Host is derived from the first
// occurrence's request message when the store can resolve it, otherwise the exchange host is left
// empty rather than guessed.
//
// Resolution goes through ExchangeByRequest, never GetExchange. This function previously called
// GetExchange(uint64(occ.Request)) — an exchange lookup keyed by a *message* id. Because both id
// spaces are dense counters from zero, that did not fail: it returned a real exchange belonging to
// some other request, so a finding on /search was reported against /login, and findings whose
// message id ran past the exchange count lost their host and path entirely. Attribution is the
// whole value of a finding, so the lookup that cannot silently mismatch is the only one used here.
func (s *Server) findingToIssueView(f *core.Finding) issueFindingView {
	v := issueFindingView{
		ID:          f.ID,
		CheckName:   f.Name,
		IssueName:   nil,
		Severity:    f.Severity.String(),
		Confidence:  f.Confidence.String(),
		Detail:      strPtr(f.Description),
		Remediation: strPtr(f.Remediation),
		Param:       f.Param,
		Params:      f.Params,
		TimesSeen:   len(f.Occurrences),
		TaskID:      f.TaskID,
	}
	if def, note := s.advisories.Resolve(f.Name); def != nil {
		v.Advisory = &issueAdvisoryView{
			TypeIndex:             def.HexIndex(),
			Name:                  def.Name,
			Description:           def.Description,
			Remediation:           def.Remediation,
			DescriptionParagraphs: advisory.PlainParagraphs(def.Description),
			RemediationParagraphs: advisory.PlainParagraphs(def.Remediation),
			TypicalSeverity:       string(def.Severity),
			References:            advisoryLinks(def.References, nil),
			Classifications:       advisoryLinks(nil, def.Classification),
		}
	} else {
		v.AdvisoryNote = note
	}
	for _, occ := range f.Occurrences {
		ex, err := s.store.ExchangeByRequest(occ.Request)
		if err == nil {
			if v.Host == "" {
				v.Host = ex.Host
			}
			v.Occurrences = append(v.Occurrences, issueOccurrenceView{
				ExchangeID: ex.ID,
				Response:   derefMsgID(ex.Response),
				Path:       ex.Path,
			})
			continue
		}
		// The request message is not in the store — a capture that rolled over, or a finding whose
		// exchange was never recorded. The occurrence is still surfaced, but with the exchange id
		// the producer recorded rather than a message id dressed up as one, and with no path, since
		// guessing a path is how a finding ends up blamed on the wrong endpoint.
		v.Occurrences = append(v.Occurrences, issueOccurrenceView{
			ExchangeID: occ.ExchangeID,
			Response:   derefMsgID(occ.Response),
			Path:       "",
		})
	}
	return v
}

func derefMsgID(id *core.MsgId) uint64 {
	if id == nil {
		return 0
	}
	return uint64(*id)
}

// handleIssues serves GET /api/issues. It follows the API's own "not configured" convention: a
// plain 200 with enabled:false and a hint when passive scanning has nothing to report, never an
// error-shaped body that would render as a broken panel. When a BCheck corpus is loaded via
// --bchecks, enabled is true and loaded names how many passive checks will run.
func (s *Server) handleIssues(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	findings := s.findings.All()
	views := make([]issueFindingView, 0, len(findings))
	for _, f := range findings {
		views = append(views, s.findingToIssueView(f))
	}

	loaded := 0
	if s.passiveScanner != nil {
		loaded = s.passiveScanner.Loaded()
	}
	// `enabled` is read by the UI as "passive scanning is in force" — scanner.tsx renders a warning
	// banner reading "passive scanning is not enabled" whenever it is false. It used to be defined as
	// `loaded > 0`, which measures something narrower: whether a BCheck *corpus* was loaded with
	// --bchecks. The built-in passive checks run regardless, so a server started without a corpus
	// served that banner above a list of hundreds of real findings it had just produced — the response
	// contradicting itself, and telling the operator to go and enable the thing that had evidently
	// already run.
	//
	// So it now means what its consumer reads it as: passive scanning has a source of findings, either
	// a loaded corpus or the built-in checks that demonstrably produced these. `loaded` is untouched
	// and remains the exact corpus count, which is the field to read for the narrower question.
	enabled := loaded > 0 || len(views) > 0
	hint := ""
	switch {
	case !enabled:
		hint = "passive BCheck scanning is not enabled; start with --bchecks DIR"
	case loaded == 0:
		// Not a warning, and not shown as one: these findings came from the built-in checks, and the
		// corpus is an addition rather than a precondition. Stated so "no corpus" stays visible
		// without being dressed up as a failure.
		hint = "these findings are from the built-in passive checks; no BCheck corpus is loaded (start with --bchecks DIR to add one)"
	}

	body := map[string]interface{}{
		"enabled":  enabled,
		"loaded":   loaded,
		"hint":     hint,
		"findings": views,
	}
	if len(views) > 0 {
		counts := map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
		for _, v := range views {
			if _, ok := counts[strings.ToLower(v.Severity)]; ok {
				counts[strings.ToLower(v.Severity)]++
			}
		}
		body["counts"] = counts
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(body)
}

// handleFindings is the legacy /api/findings endpoint, kept for tools that predate /api/issues.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	findings := s.findings.All()
	views := make([]FindingView, 0, len(findings))
	for _, f := range findings {
		views = append(views, FindingView{
			ID:          f.ID,
			Name:        f.Name,
			Severity:    f.Severity.String(),
			Confidence:  f.Confidence.String(),
			Description: f.Description,
			Param:       f.Param,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": views,
		"total":    len(views),
	})
}

func strPtr(s string) *string { return &s }

// ---- query filter ------------------------------------------------------------------------------

// queryFilter is a compiled burpsy-query expression evaluated against exchanges. Reuses the query
// package's parser and evaluator; this type adapts a stored exchange to its Queryable interface.
type queryFilter struct {
	expr  *query.Expr
	store *core.TrafficStore
}

func compileQuery(input string, store *core.TrafficStore) (*queryFilter, error) {
	e, err := query.Parse(input)
	if err != nil {
		return nil, err
	}
	return &queryFilter{expr: e, store: store}, nil
}

func (f *queryFilter) match(ex *core.Exchange) bool {
	if f == nil || f.expr == nil {
		return true
	}
	return f.expr.Match(filteredExchangeQuery{store: f.store, ex: ex})
}

// filteredExchangeQuery binds a store so Body() can resolve the request message. Mime is not
// carried on the exchange and stays empty, which the query evaluator reads as "absent" — so every
// `mime` comparison, `!=` included, is false here rather than some of them matching every row.
type filteredExchangeQuery struct {
	store *core.TrafficStore
	ex    *core.Exchange
}

func (f filteredExchangeQuery) Host() string   { return f.ex.Host }
func (f filteredExchangeQuery) Method() string { return f.ex.Method }
func (f filteredExchangeQuery) Path() string   { return f.ex.Path }
func (f filteredExchangeQuery) Status() int {
	if f.ex.Status == nil {
		return 0
	}
	return int(*f.ex.Status)
}
func (f filteredExchangeQuery) Mime() string { return "" }
func (f filteredExchangeQuery) Body() []byte {
	msg, err := f.store.Get(f.ex.Request)
	if err != nil {
		return nil
	}
	return msg.Body()
}

// sortable status helpers for the sitemap
func sortedUints(vs []uint16) []uint16 {
	out := make([]uint16, len(vs))
	copy(out, vs)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// handleCACert serves the proxy's CA certificate so a browser can be told to trust it.
//
// Without this there is no way to get the CA into a browser short of finding it on disk, and a
// browser that does not trust it cannot reach an HSTS host through the proxy at all — HSTS forbids
// clicking through a certificate warning, by design, so the operator is simply stuck. The frontend
// has always linked to this path (`#ca-link` in index.html, gated on a HEAD of this route in
// app.ts); the route itself was missing, so the link stayed hidden and the reason was invisible.
//
// HEAD is answered because that is how the UI decides whether to show the link: a 200 means
// interception is on and there is a CA worth importing.
//
// A 404 when interception is off, rather than an empty 200: a zero-byte certificate file is worse
// than no file, because a browser will accept the download and then fail to import it, which sends
// the operator looking for the fault in their browser rather than in their burpsy flags.
func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(s.caCertPEM) == 0 {
		http.Error(w, "TLS interception is not enabled, so there is no CA to trust; start with -intercept-tls", http.StatusNotFound)
		return
	}
	// application/x-x509-ca-cert is what browsers recognise as a CA to import. The filename matters
	// for the download the UI link triggers.
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-ca.crt"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(s.caCertPEM)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if _, err := w.Write(s.caCertPEM); err != nil {
		s.logger.Warn("failed to write CA certificate", zap.Error(err))
	}
}

// advisoryLinks flattens either link kind into the wire shape. Two source types, one output, because
// references and classifications differ only in what they point at, and the UI groups them itself.
func advisoryLinks(refs []advisory.Reference, cls []advisory.Classification) []issueAdvisoryLink {
	out := make([]issueAdvisoryLink, 0, len(refs)+len(cls))
	for _, r := range refs {
		out = append(out, issueAdvisoryLink{Title: r.Title, URL: r.URL})
	}
	for _, c := range cls {
		out = append(out, issueAdvisoryLink{Title: c.Title, URL: c.URL})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
