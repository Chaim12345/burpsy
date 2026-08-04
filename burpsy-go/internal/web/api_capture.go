package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/query"
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

	// Newest first (the store appends in arrival order).
	views := make([]*ExchangeView, 0, len(exchanges))
	for i := len(exchanges) - 1; i >= 0; i-- {
		ex := exchanges[i]
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

// handleExchange serves GET /api/exchange/{id} (and the legacy /api/exchanges/{id}) -> ExchangeView.
func (s *Server) handleExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/exchange/")
	path = strings.TrimPrefix(path, "/api/exchanges/")
	id, err := strconv.ParseUint(path, 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange ID", http.StatusBadRequest)
		return
	}
	ex, err := s.store.GetExchange(id)
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
	json.NewEncoder(w).Encode(StatsView{
		Exchanges:   exchanges,
		Messages:    messages,
		StoredBytes: s.store.Bytes(),
	})
}

// ---- scope -------------------------------------------------------------------------------------

// ScopeRequest represents a scope modification request.
type ScopeRequest struct {
	Action  string `json:"action"` // "include", "exclude", "remove" or "clear"
	Kind    string `json:"kind"`   // optional rule kind for "remove": "include" or "exclude"
	Pattern string `json:"pattern"`
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
		views = append(views, scopeRuleView{Kind: kind, Host: &pattern})
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
		s.scope.Add(core.NewScopeRule(kind, req.Pattern))
	case "remove":
		if req.Pattern == "" {
			http.Error(w, "Pattern is required", http.StatusBadRequest)
			return
		}
		// Kind is optional and falls back to whichever rule carries the pattern.
		var removed bool
		switch req.Kind {
		case "exclude":
			removed = s.scope.Remove(core.ScopeExclude, req.Pattern)
		case "include":
			removed = s.scope.Remove(core.ScopeInclude, req.Pattern)
		default:
			removed = s.scope.Remove(core.ScopeInclude, req.Pattern) || s.scope.Remove(core.ScopeExclude, req.Pattern)
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
	ExchangeID uint64 `json:"exchange_id"`
	Response   uint64 `json:"response"`
	Path       string `json:"path"`
}

// issueFindingView mirrors the UI's Finding shape. check_name is the rule/check that fired;
// issue_name the human title; occurrences carry the exchange ids the check saw.
type issueFindingView struct {
	ID          uint64                `json:"id"`
	CheckName   string                `json:"check_name"`
	IssueName   *string               `json:"issue_name"`
	Severity    string                `json:"severity"`
	Confidence  string                `json:"confidence"`
	Host        string                `json:"host"`
	Detail      *string               `json:"detail"`
	Remediation *string               `json:"remediation"`
	Occurrences []issueOccurrenceView `json:"occurrences"`
	TimesSeen   int                   `json:"times_seen"`
}

// findingToIssueView converts a stored finding into the UI shape. Host is derived from the first
// occurrence's request message when the store can resolve it, otherwise the exchange host is left
// empty rather than guessed.
func (s *Server) findingToIssueView(f *core.Finding) issueFindingView {
	v := issueFindingView{
		ID:          f.ID,
		CheckName:   f.Name,
		IssueName:   nil,
		Severity:    f.Severity.String(),
		Confidence:  f.Confidence.String(),
		Detail:      strPtr(f.Description),
		Remediation: strPtr(f.Remediation),
		TimesSeen:   len(f.Occurrences),
	}
	for _, occ := range f.Occurrences {
		ex, err := s.store.GetExchange(uint64(occ.Request))
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
		// Request not resolvable to an exchange; still surface the occurrence with the raw ids.
		v.Occurrences = append(v.Occurrences, issueOccurrenceView{
			ExchangeID: uint64(occ.Request),
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
	enabled := loaded > 0
	hint := ""
	if !enabled {
		hint = "passive BCheck scanning is not enabled; start with --bchecks DIR"
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
