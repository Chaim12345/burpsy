package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/advisory"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/query"
	"go.uber.org/zap"
)

// handleHistory serves GET /api/history, the listing the UI has always read.
//
// A DELETE here is refused with a pointer rather than a bare 405: until burpsy-react-ui-gf68 this
// pattern also served Burp's "Delete items" / "Clear (tool)", and it did so under this pattern's
// riskRead class, which is to say past the confirmation gate. The removal now lives at
// /api/history/rows, classed riskDestructive; a caller still sending the old verb is told where it
// went instead of being left to guess whether history was cleared.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.historyGet(w, r)
	case http.MethodDelete:
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "DELETE /api/history moved to DELETE /api/history/rows, which needs a confirmation; nothing was removed", http.StatusMethodNotAllowed)
	default:
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHistoryRows serves DELETE /api/history/rows (burpsy-react-ui-r6li, gated since gf68): Burp's
// "Delete items" / "Clear (tool)". The confirmation gate stands in front of it as riskDestructive, so
// by the time a request is here a human-minted token has been spent on it.
func (s *Server) handleHistoryRows(w http.ResponseWriter, r *http.Request) {
	s.historyDelete(w, r)
}

// historyDeleteReq is the request body historyDelete decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type historyDeleteReq struct {
	IDs []core.ExchangeID `json:"ids"`
}

// historyDelete removes exchanges from the operator's view. With a JSON body {"ids":[..]} the
// named exchanges go; with no body (or an empty ids array) the whole capture clears — Burp's
// "Clear (tool)". The response reports removed and requested separately, so a caller that named
// a row already gone (or never present) can say so rather than reading a bare 200 as success.
// Deletion is a view-level tombstone (core.TrafficStore.DeleteExchanges): positional ids stay
// stable, so nothing else on the wire is renumbered by a cleanup.
func (s *Server) historyDelete(w http.ResponseWriter, r *http.Request) {
	var req historyDeleteReq
	if r.Body != nil {
		if err := requestJSON(w, r, io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil && err != io.EOF {
			http.Error(w, "body must be JSON {\"ids\":[..]} or empty", http.StatusBadRequest)
			return
		}
	}
	var removed int
	if len(req.IDs) == 0 {
		removed = s.store.ClearExchanges()
	} else {
		removed = s.store.DeleteExchanges(req.IDs)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"removed": removed, "requested": len(req.IDs)})
}

// historyGet serves GET /api/history?limit=N[&q=query][&search=term&search_case&search_regex&search_negate].
// The UI expects a bare array of exchanges, newest first, capped at `limit` (default 300). `q`, when
// present, is a burpsy-query filter compiled against each exchange's host/path/method/status.
//
// `search` is Burp's Search box (burpsy-react-ui-ngcj), and it is deliberately NOT the DSL: the
// Search box's three modifiers (case-sensitive, regex, negative — Burp's proxyHttpSearch*
// checkboxes) have no spelling in the query grammar, and the grammar's `body` field searches the
// REQUEST's bytes only, so a page title in a response body would stay unfindable no matter how the
// box was routed. Burp's doc states the load-bearing promise: "The search applies to the underlying
// data, regardless of any filters you have applied" — the capture, not the page of rows a browser
// happens to hold. So the scan runs here, over the store, before the cap: every row column the
// table can show (including notes and the page title the Proxy recorded), plus both messages'
// bytes, headers and body. The bytes half reuses the suite-search matcher (vs9k) verbatim; the
// only thing this endpoint adds to it is the row-column haystack, which no bytes scan can see.
func (s *Server) historyGet(w http.ResponseWriter, r *http.Request) {
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

	// The Search box, compiled the same way /api/search compiles its own (same error text, same
	// linear-time regex, same folded-literal fast path) so two searches that look identical to
	// the operator cannot behave differently because they were typed in different boxes.
	var search *historySearch
	if raw := r.URL.Query().Get("search"); strings.TrimSpace(raw) != "" {
		opts := suiteSearchOptions{
			term:          raw,
			caseSensitive: truthy(r.URL.Query().Get("search_case")),
			regex:         truthy(r.URL.Query().Get("search_regex")),
		}
		if len(opts.term) > suiteSearchMaxTermLen {
			http.Error(w, fmt.Sprintf("The search term is longer than the %d bytes this search accepts.", suiteSearchMaxTermLen), http.StatusBadRequest)
			return
		}
		matcher, err := newSuiteSearchMatcher(opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		search = &historySearch{matcher: matcher, negate: truthy(r.URL.Query().Get("search_negate"))}
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
		if search != nil && !s.historySearchMatch(search, ex) {
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
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", http.StatusBadRequest)
		return
	}
	msg, err := s.message(id)
	if err != nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}
	// byte_offset / max_bytes / pattern / decoded read a window of the body instead of the whole
	// message (burpsy-react-ui-yahm, api_message_window.go). Without them the reply is unchanged.
	if wantsWindow(r) {
		s.messageWindow(w, r, id, msg.Raw())
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

// exchangePatchReq is PATCH /api/exchange/{id}'s body. Both members are raw so the handler can tell
// "omitted" (nil: leave unchanged) from an explicit null (clear the notes) — a typed *string cannot.
type exchangePatchReq struct {
	Notes     json.RawMessage `json:"notes" desc:"a string sets the notes; null clears them; omit to leave them unchanged"`
	Highlight json.RawMessage `json:"highlight" desc:"a highlight colour name, or \"\" for none; omit to leave it unchanged"`
}

// handlePatchExchange serves PATCH /api/exchange/{id}: body {"notes": string|null, "highlight":
// string}, both optional. An omitted field is left unchanged; an explicit `null` on notes clears it
// (there is no way to express "clear" for highlight other than sending ""="none", so an omitted
// highlight and one explicitly sent as the empty string are indistinguishable on the wire — that is
// intentional, since "" already means "no highlight"). highlight must be "" or a member of
// core.ValidHighlights; anything else is a 400 and is never coerced to a nearby value. Responds with
// the updated ExchangeView.
func (s *Server) handlePatchExchange(w http.ResponseWriter, r *http.Request, id core.ExchangeID) {
	var body exchangePatchReq
	if err := requestJSON(w, r, nil).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var notes *string
	notesSet := false
	if body.Notes != nil {
		notesSet = true
		if err := json.Unmarshal(body.Notes, &notes); err != nil {
			http.Error(w, "notes must be a string or null", http.StatusBadRequest)
			return
		}
	}

	highlight := ""
	highlightSet := false
	if body.Highlight != nil {
		highlightSet = true
		if err := json.Unmarshal(body.Highlight, &highlight); err != nil {
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
	messages, exchanges := s.store.Count()
	w.Header().Set("Content-Type", "application/json")
	view := StatsView{
		Exchanges:   exchanges,
		Messages:    messages,
		StoredBytes: s.store.Bytes(),
		ProxyBind:   s.proxyBind,
		WebBind:     s.webBind,
	}
	// interception is live-switchable (PUT /api/proxy/interception): the policy's engine says whether it is on now
	if s.tlsPolicy != nil {
		view.TLSInterception = s.tlsPolicy.Engine() != nil
	} else if s.caCertPEM != nil {
		view.TLSInterception = true
	}
	// "off" rather than "": a blank field is indistinguishable from a field this build does not
	// report, and the whole point of showing this is that an operator can tell the difference.
	view.DOMEngine = "off"
	if l := s.domEngineLabel(); l != "" {
		view.DOMEngine = l
	}
	view.DOMChecks = s.wiredScanner().DOMCapabilityConfigured()
	json.NewEncoder(w).Encode(view)
}

// ---- scope -------------------------------------------------------------------------------------

// ScopeRequest represents a scope modification request.
type ScopeRequest struct {
	// Action is "include", "exclude", "remove", "edit", "clear", "toggle", "drop_out_of_scope", or one
	// of the three library actions — "library_save", "library_load", "library_delete" — which operate
	// on a named copy of the whole rule set rather than on one rule. See updateScopeLibrary for why
	// they are actions here rather than a route of their own.
	Action  string `json:"action" enum:"include|exclude|remove|edit|clear|toggle|drop_out_of_scope|library_save|library_load|library_delete" desc:"what to do; include/exclude add a rule"`
	Kind    string `json:"kind" enum:"include|exclude" desc:"the rule kind, for remove and toggle"` // optional rule kind for "remove" and "toggle": "include" or "exclude"
	Pattern string `json:"pattern" desc:"the host pattern: a hostname, *.wildcard, regex:… or range:CIDR"`
	// Name is the library a library_* action names. Unused by every other action, and deliberately
	// separate from Pattern: a library is named after an engagement, not after a host.
	Name string `json:"name,omitempty"`
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
	// Old* names the rule an "edit" replaces: the tuple as the table showed it. Separate from
	// the replacement fields because the usual edit changes the pattern itself.
	OldPattern string  `json:"old_pattern,omitempty"`
	OldKind    string  `json:"old_kind,omitempty"`
	OldPath    string  `json:"old_path,omitempty"`
	OldPort    *uint16 `json:"old_port,omitempty"`
	// OldProtocol is the scheme the rule being edited was limited to; empty means either.
	OldProtocol string `json:"old_protocol,omitempty"`
	// Enabled is required on "toggle" (the switch's target state); a nil there is a client
	// that did not send the field, refused rather than guessed. On "include"/"exclude" a nil
	// reads as the default (true): a rule is created active unless a caller says otherwise.
	Enabled *bool `json:"enabled,omitempty"`
	// Mode and DropRules are the "drop_scope" action (burpsy-react-ui-47ed): Burp's "Use suite scope"
	// ("suite") or "Use custom scope" ("custom") for which requests the drop switch drops, and the
	// custom scope's rules, each in the include/exclude shape (action is the rule's kind).
	Mode      string         `json:"mode,omitempty"`
	DropRules []ScopeRequest `json:"drop_rules,omitempty"`
}

// normaliseScopePath validates an optional path prefix and returns nil for "no path".
//
// A prefix must start with "/", because it is matched with strings.HasPrefix against a request path
// that always does: accepting "admin" would build a rule that silently matches nothing, which is the
// worst outcome for a scope rule — the operator believes a restriction is in force and it is not.
//
// A path arm tagged core.ScopeRegexArm is a regular expression over the whole path instead
// (burpsy-react-ui-c09), and is exempt from the leading "/" rule because an expression may legally
// begin with a group or a character class. The expression itself is checked by core, not here: the
// same string is the rule's identity on remove, toggle and edit, so this function normalises it and
// core.NewScopeRuleFrom decides whether it compiles. Both halves matter — add and remove have to
// normalise identically or a rule becomes unremovable.
func normaliseScopePath(raw string) (*string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, core.ScopeRegexArm) {
		return &trimmed, nil
	}
	if !strings.HasPrefix(trimmed, "/") {
		return nil, fmt.Errorf("A scope path must start with /, so it can match a request path; got %q. To match the path with a regular expression instead, prefix it with %q.", trimmed, core.ScopeRegexArm)
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
//
// The arm tags — a `regex:` host pattern or path, a `range:` IP block — are compiled by
// core.NewScopeRuleFrom rather than checked here, deliberately: this endpoint and the config
// importer both build rules, and a second copy of "does this regular expression compile" is a second
// answer waiting to disagree with the engine that actually matches. What this layer still owns is
// its own vocabulary — a path starts with "/", a protocol is http or https.
//
// The error is a 400 at both callers. A scope rule whose arm cannot be read is an operator typo, and
// the only moment it can be fixed cheaply is before it is stored: once stored, the engine refuses
// every request rather than applying a document it cannot read.
func buildScopeRule(kind core.ScopeRuleKind, req ScopeRequest) (*core.ScopeRule, error) {
	path, err := normaliseScopePath(req.Path)
	if err != nil {
		return nil, err
	}
	protocol, err := normaliseScopeProtocol(req.Protocol)
	if err != nil {
		return nil, err
	}
	rule, err := core.NewScopeRuleFrom(kind, req.Pattern, path, req.Port, protocol)
	if err != nil {
		return nil, err
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	return rule, nil
}

// buildDropScope reads a drop_scope action into the custom rules and whether they are in force.
//
// "suite" keeps the custom rules already set, as Burp's panel does. "custom" with drop_rules replaces
// them; "custom" without drop_rules puts the kept rules back in force.
//
// A custom scope in force must include something. With no include rule core.Scope allows by default,
// so an empty custom scope would drop nothing while the panel said a custom fence was up; refusing it
// is clearer than either reading.
func buildDropScope(req ScopeRequest, live *core.Scope) (*core.Scope, bool, error) {
	kept, _ := live.DropScope()
	switch req.Mode {
	case "suite":
		if len(req.DropRules) > 0 {
			return nil, false, fmt.Errorf("drop_rules are only read with mode \"custom\"; mode \"suite\" drops by the suite scope")
		}
		return kept, false, nil
	case "custom":
		if req.DropRules == nil {
			if kept == nil {
				return nil, false, fmt.Errorf("mode \"custom\" needs drop_rules: no custom drop scope has been set yet")
			}
			return kept, true, nil
		}
	default:
		return nil, false, fmt.Errorf("drop_scope wants mode \"suite\" (Use suite scope) or \"custom\" (Use custom scope), not %q", req.Mode)
	}
	custom := core.NewScope()
	includes := 0
	for i, dr := range req.DropRules {
		kind, ok := scopeKindFromString(dr.Action)
		if !ok {
			return nil, false, fmt.Errorf("drop_rules[%d].action must be \"include\" or \"exclude\", not %q", i, dr.Action)
		}
		if dr.Pattern == "" {
			return nil, false, fmt.Errorf("drop_rules[%d].pattern is required", i)
		}
		rule, err := buildScopeRule(kind, dr)
		if err != nil {
			return nil, false, fmt.Errorf("drop_rules[%d]: %v", i, err)
		}
		if kind == core.ScopeInclude && rule.Enabled {
			includes++
		}
		custom.Add(rule)
	}
	if includes == 0 {
		return nil, false, fmt.Errorf("a custom drop scope needs at least one enabled include rule: without one it would " +
			"admit every request, and the drop switch would drop nothing")
	}
	if err := custom.Validate(); err != nil {
		return nil, false, err
	}
	return custom, true, nil
}

type dropScopeViewBody struct {
	Mode  string          `json:"mode"`
	Rules []scopeRuleView `json:"rules"`
}

func dropScopeView(custom *core.Scope, use bool) dropScopeViewBody {
	view := dropScopeViewBody{Mode: "suite", Rules: []scopeRuleView{}}
	if use {
		view.Mode = "custom"
	}
	if custom == nil {
		return view
	}
	for _, rule := range custom.Rules() {
		kind := "Include"
		if rule.Kind == core.ScopeExclude {
			kind = "Exclude"
		}
		pattern := rule.Pattern
		view.Rules = append(view.Rules, scopeRuleView{Kind: kind, Host: &pattern, Path: rule.PathPrefix,
			Port: rule.Port, Protocol: rule.Protocol, Enabled: rule.Enabled})
	}
	return view
}

// scopeKindFromString maps the wire's kind to the engine's. Kept beside the handler so both
// "remove" (optional kind) and "toggle" (required kind) agree on the vocabulary.
func scopeKindFromString(kind string) (core.ScopeRuleKind, bool) {
	switch kind {
	case "include":
		return core.ScopeInclude, true
	case "exclude":
		return core.ScopeExclude, true
	default:
		return core.ScopeInclude, false
	}
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
	// Enabled is always reported: the UI's per-row switch has to read the current state, and
	// a field present only when false would make "active" indistinguishable from "absent".
	Enabled bool `json:"enabled"`
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
		views = append(views, scopeRuleView{Kind: kind, Host: &pattern, Path: rule.PathPrefix, Port: rule.Port, Protocol: rule.Protocol, Enabled: rule.Enabled})
	}
	// The saved rule sets ride this response rather than a second route: they are state of the same
	// resource, and a page that had to read two URLs to draw one scope could draw a scope that never
	// existed at either of them. Cheap, too — names and counts, no rule bodies.
	libraries, librariesErr := s.scopeLibraries()
	body := map[string]interface{}{
		"allow_all": s.scope.AllowAll(),
		"rules":     views,
		"empty":     s.scope.Empty(),
		// Burp's "Out-of-scope request handling: Drop all out-of-scope requests". Reported
		// unconditionally, like enabled: the UI's switch has to read the state it toggles.
		"drop_out_of_scope": s.scope.DropOutOfScope(),
		// Which scope the drop switch drops by (47ed): always present, rules always an array.
		"drop_scope": dropScopeView(s.scope.DropScope()),
		// Always an array, never null: the console reads .length on it, and a nil slice marshals to
		// null, which would take the page down instead of showing an empty picker.
		"libraries": libraries,
	}
	if librariesErr != nil {
		// Reported rather than swallowed. An empty list from a failed read says "nothing is saved",
		// and an operator who believes that re-creates a rule set that is already on disk — or, worse,
		// stops trusting the one they saved.
		body["libraries_error"] = librariesErr.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(body)
}

func (s *Server) updateScope(w http.ResponseWriter, r *http.Request) {
	var req ScopeRequest
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// The library actions answer for themselves — a count, and whether a save replaced something —
	// so they return before the shared "status: ok" tail below, and before persistScope: a save or a
	// delete does not touch the live rule list, and a load persists it itself.
	switch req.Action {
	case "library_save", "library_load", "library_delete":
		s.updateScopeLibrary(w, req)
		return
	}

	switch req.Action {
	case "drop_out_of_scope":
		// One round trip for the switch, like "toggle" for a rule row. When on, every scope
		// refusal becomes an egress refusal — the proxy stops issuing requests to hosts the
		// scope excludes — which is the safety control 5j4i asks for. The switch itself is
		// not persisted here; persistence rides the same save the scope rows ride (see
		// persistScope), so the durable document is never a half-state.
		if req.Enabled == nil {
			http.Error(w, "Enabled is required for drop_out_of_scope", http.StatusBadRequest)
			return
		}
		s.scope.SetDropOutOfScope(*req.Enabled)
		if s.persist != nil {
			s.persist.SaveScopeDropOutOfScope(*req.Enabled)
		}
	case "drop_scope":
		custom, use, err := buildDropScope(req, s.scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.scope.SetDropScope(custom, use)
		if s.persist != nil {
			s.persist.SaveScopeDropScope(custom, use)
		}
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
		// An identical rule (kind, pattern, path, port, protocol) adds nothing to what scope decides,
		// and two of them gave the console two rows with one identity
		// (burpsy-react-ui-scope-duplicate-rules). The request succeeds and the list is unchanged.
		if !scopeHasRule(s.scope, rule) {
			s.scope.Add(rule)
		}
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
	case "edit":
		// Burp's "Edit the selected item" (k5l): the tuple names the rule being replaced
		// (old_* — the row as the table showed it), the remaining fields are the replacement.
		// Split naming matters because the common edit narrows a host (example.com →
		// api.example.com): the replacement's pattern is the NEW one, so the old tuple cannot
		// ride on it. Refusal when nothing matches is a 404, not a silent append — an edit that
		// reports ok while the table refetches to show two rules is a lie about what happened.
		if req.OldPattern == "" {
			http.Error(w, "old_pattern is required for edit: it names the rule being replaced", http.StatusBadRequest)
			return
		}
		if req.Pattern == "" {
			http.Error(w, "pattern is required for edit: it is the replacement rule's host", http.StatusBadRequest)
			return
		}
		oldPath, err := normaliseScopePath(req.OldPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		oldKind := core.ScopeInclude
		if strings.EqualFold(req.OldKind, "exclude") {
			oldKind = core.ScopeExclude
		}
		newKind := core.ScopeInclude
		if strings.EqualFold(req.Kind, "exclude") {
			newKind = core.ScopeExclude
		}
		replacement, err := buildScopeRule(newKind, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var oldProtocol *string
		if req.OldProtocol != "" {
			p := req.OldProtocol
			oldProtocol = &p
		}
		replaced := s.scope.ReplaceScoped(oldKind, req.OldPattern, oldPath, req.OldPort, oldProtocol, replacement)
		if !replaced {
			http.Error(w, "No matching rule found: the rule may have been removed or changed by another request — refetch and retry", http.StatusNotFound)
			return
		}
	case "toggle":
		// One round trip for the switch, so a slow double-click cannot land two edits — and
		// because the server, not the client, owns the truth: the client sends what it saw,
		// the server refuses when the row has moved on, and the refetch shows the real state.
		if req.Pattern == "" {
			http.Error(w, "Pattern is required", http.StatusBadRequest)
			return
		}
		path, err := normaliseScopePath(req.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		kind, ok := scopeKindFromString(req.Kind)
		if !ok {
			http.Error(w, "Kind must be include or exclude for toggle", http.StatusBadRequest)
			return
		}
		if !s.scope.SetRuleEnabled(kind, req.Pattern, path, req.Port, req.Enabled == nil || *req.Enabled) {
			http.Error(w, "No matching rule found", http.StatusNotFound)
			return
		}
	case "clear":
		s.scope.Clear()
	default:
		http.Error(w, "Unknown scope action: expected include, exclude, remove, edit, toggle, clear, drop_out_of_scope, drop_scope, library_save, library_load or library_delete", http.StatusBadRequest)
		return
	}
	s.persistScope()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ---- scope libraries (burpsy-react-ui-e365) ------------------------------------------------------
//
// Burp's scope panel carries "Save to library": a rule set is named, stored, and loaded back later —
// across projects, and across the "clear it and try something else" step that otherwise costs an
// operator the scope they spent an afternoon getting right. burpsy had only the live rule list.
//
// # Why this is the same resource rather than /api/scope/library
//
// A library is a saved copy of this endpoint's own state, so it lives on this endpoint: the actions
// ride the switch POST /api/scope already multiplexes (include, exclude, remove, edit, toggle,
// clear, drop_out_of_scope), and the listing rides the GET that already reports the rule list. The
// rejected alternative was a second route, /api/scope/library, which reads tidier — until you notice
// it would give the console two URLs that can disagree about what the scope is, and a client would
// have to read both to draw one page. One resource, one round trip, one answer.

// scopeLibraryName trims the operator's name and refuses an empty one.
//
// Whitespace-only is refused rather than trimmed to "" and accepted, because an unnamed library
// cannot be found again by the person who saved it — it would sit in the picker as a blank row, and
// the next save under the same blank name would replace it without anyone being able to tell the two
// apart. Trimming happens here *and* in persist, deliberately: the two must agree on identity or a
// library becomes unloadable by the name the picker shows.
func scopeLibraryName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New("A scope library needs a name, so it can be found again")
	}
	return name, nil
}

// scopeLibraryNamesInStore lists what exists, for a 404 body. A refusal that only says "not found"
// leaves an operator guessing at their own typo; one that names the libraries that do exist is a
// refusal they can act on in one step.
func (s *Server) scopeLibraryNamesInStore() string {
	libs, err := s.persist.LoadScopeLibraries()
	if err != nil || len(libs) == 0 {
		return "no scope libraries are saved"
	}
	names := make([]string, 0, len(libs))
	for _, lib := range libs {
		names = append(names, strconv.Quote(lib.Name))
	}
	return "saved libraries: " + strings.Join(names, ", ")
}

// scopeLibraries is what GET /api/scope reports beside the rules: every saved rule set as name, rule
// count and write time. The rule bodies are not included — the list feeds a picker, and a library's
// rules are only ever wanted by the one load that installs them.
//
// The error is returned rather than swallowed so the GET can carry it as a field. An empty list on a
// failed read would tell the operator "nothing is saved", which is the same shape of lie as loading a
// corrupt library as an empty scope: they would go and re-create a rule set that is already there.
func (s *Server) scopeLibraries() ([]persist.ScopeLibrary, error) {
	if s.persist == nil {
		// No project database: libraries are a durable thing and this console has nowhere durable.
		// Not an error — the console runs like this on purpose — so the list is simply empty.
		return []persist.ScopeLibrary{}, nil
	}
	libs, err := s.persist.LoadScopeLibraries()
	if err != nil {
		return []persist.ScopeLibrary{}, err
	}
	return libs, nil
}

// updateScopeLibrary serves the three library actions of POST /api/scope. It writes its own response
// — a count and whether a save replaced something — because "status: ok" cannot say how many rules
// are now in force, which is the one number the operator needs after a load.
func (s *Server) updateScopeLibrary(w http.ResponseWriter, req ScopeRequest) {
	// A library only exists on disk, so a console running without a project database has nowhere to
	// put one. 503, not 500: the request is well formed and this configuration simply cannot serve
	// it — the same reading /api/backup takes of the same condition.
	if s.persist == nil {
		http.Error(w, "No project database is open, so scope libraries cannot be saved or loaded", http.StatusServiceUnavailable)
		return
	}
	name, err := scopeLibraryName(req.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.Action {
	case "library_save":
		// The live rule list as it stands, which is what the operator can see on the page. Disabled
		// rules go in as disabled: a library is a photograph of the scope, not an edit of it.
		rules := s.scope.Rules()
		replaced, err := s.persist.SaveScopeLibrary(name, rules)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"saved": true, "replaced": replaced, "rules": len(rules), "name": name})
	case "library_load":
		// # Why the live scope is not touched until every rule has been built
		//
		// Loading replaces the rule list. The obvious shape — clear, then add each stored rule — leaves
		// the scope empty if any rule fails to build, and an empty core.Scope is default-allow: a
		// library with one uncompilable regular expression would take an engagement from "these six
		// hosts" to "everything" and report an error while it did. So every rule is constructed first,
		// through core.NewScopeRuleFrom (which compiles the `regex:` and `range:` arms and refuses what
		// does not compile — see core/scope.go), and the live scope is only cleared once all of them
		// exist. A refused load leaves the operator with exactly the scope they already had.
		stored, found, err := s.persist.LoadScopeLibrary(name)
		if err != nil {
			// The library exists and cannot be read. Refused by name rather than loaded as the empty
			// list json.Unmarshal would otherwise leave behind.
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, fmt.Sprintf("No scope library called %q; %s", name, s.scopeLibraryNamesInStore()), http.StatusNotFound)
			return
		}
		built := make([]*core.ScopeRule, 0, len(stored))
		for i, row := range stored {
			// The kind is read strictly rather than defaulted. A stored "excluded" — a typo, an older
			// vocabulary, a hand-edited document — falling through to include would turn an exclusion
			// into an authorisation, which is the widening this whole endpoint refuses by name
			// elsewhere; it must not arrive through a default branch here.
			var kind core.ScopeRuleKind
			switch {
			case strings.EqualFold(row.Kind, "include"):
				kind = core.ScopeInclude
			case strings.EqualFold(row.Kind, "exclude"):
				kind = core.ScopeExclude
			default:
				http.Error(w, fmt.Sprintf("Scope library %q cannot be loaded: rule %d (%s) states a kind that is neither include nor exclude — the current scope is unchanged",
					name, i+1, row.Kind), http.StatusInternalServerError)
				return
			}
			rule, err := core.NewScopeRuleFrom(kind, row.Pattern, row.PathPrefix, row.Port, row.Protocol)
			if err != nil {
				http.Error(w, fmt.Sprintf("Scope library %q cannot be loaded: rule %d (%s %s) does not compile: %v — the current scope is unchanged",
					name, i+1, row.Kind, row.Pattern, err), http.StatusInternalServerError)
				return
			}
			rule.Enabled = row.Enabled
			built = append(built, rule)
		}
		// Replace, not merge. Merging would make loading a library twice a different result from
		// loading it once, and would leave an operator unable to *narrow* a scope with a library at
		// all — the rules they wanted gone would still be there, which is the failure direction that
		// matters. The page says so before it calls this; see pages/scope.tsx.
		s.scope.Clear()
		for _, rule := range built {
			s.scope.Add(rule)
		}
		// The live rule list has changed, so the durable one has to follow — the same write every
		// other arm of this endpoint ends with.
		s.persistScope()
		writeJSON(w, http.StatusOK, map[string]any{"loaded": true, "rules": len(built), "name": name})
	case "library_delete":
		deleted, err := s.persist.DeleteScopeLibrary(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !deleted {
			// 404 rather than a silent ok: an operator told "deleted" about a name they mistyped
			// believes a rule set is gone while it is still on disk, and stops looking for it.
			http.Error(w, fmt.Sprintf("No scope library called %q; %s", name, s.scopeLibraryNamesInStore()), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "name": name})
	}
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
	// Isolated marks a finding raised only on an isolated scan's traffic (13uw). Present only on a
	// listing that asked for them (?include_isolated=1); the default listing — "All issues" — omits them.
	Isolated    bool    `json:"isolated,omitempty"`
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
	// Params is every distinct parameter a merged finding covers, in first-seen order. Findings of one
	// type against one target are merged into a single row, so a reflected XSS reachable through five
	// parameters is one row here — and without this field that row shows only the first, which makes
	// the merge read as four results going missing.
	//
	// core.Finding.Params, the TypeScript `params?: string[]`, and TestIssuesSurfacesMergedParams all
	// existed before this field did: the store kept the set, the console rendered it, the test asserted
	// it, and the wire shape in between silently dropped it. Nothing about that was visible except the
	// one red test, which is why it is wired here rather than left to the next reader.
	Params      []string              `json:"params,omitempty"`
	Occurrences []issueOccurrenceView `json:"occurrences"`
	TimesSeen   int                   `json:"times_seen"`
	// MergedCount is how many later observations a keep_existing merge folded into this finding
	// (burpsy-react-ui-oorl) — distinct from times_seen, which counts occurrences and so also counts
	// several filed at once by one producer.
	MergedCount int `json:"merged_count"`
	// Evidence is the excerpt the check quoted — for a leaked secret, the redacted key that says WHICH
	// one leaked (burpsy-react-ui-cx31/8j0d). Omitted when the check quoted nothing.
	Evidence string `json:"evidence,omitempty"`
	// Triage state (burpsy-react-ui-pwd). Severity/Confidence are the *effective* values — the
	// operator's override when one stands, the engine's report otherwise — so every consumer that
	// just displays or counts by severity keeps working without learning about overrides. The
	// original engine values ride alongside as original_severity/original_confidence, present only
	// when an override stands, so the UI can show what was overruled.
	SeverityOverride   *string `json:"severity_override,omitempty"`
	OriginalSeverity   string  `json:"original_severity,omitempty"`
	ConfidenceOverride *string `json:"confidence_override,omitempty"`
	OriginalConfidence string  `json:"original_confidence,omitempty"`
	FalsePositive      bool    `json:"false_positive"`
	Comment            string  `json:"comment"`
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
	// TimestampUnixMs is when the finding was first raised, set by FindingStore.Add. Projected here
	// for the first time in burpsy-react-ui-exiu: the store has kept it since the beginning, and
	// without it the Issues list is an unordered set of rows from every producer in the project, so
	// an operator cannot tell a finding from ten minutes ago from one from last month.
	//
	// It is the FIRST observation's time and is never rewritten by a merge — a later sighting of the
	// same issue is evidence about the issue, not a new time of day, and moving the timestamp would
	// make an old finding look continuously re-discovered.
	TimestampUnixMs int64 `json:"timestamp_unix_ms"`
	// Source is this finding's provenance, derived rather than stored. There is no provenance field
	// on core.Finding, and inventing one would be a schema change to answer a display question; what
	// the finding actually knows is enough for the two states an operator needs to tell apart.
	//
	// "scan" means a run raised it (TaskID names which), and "manual" means nothing tracked it — a
	// recording an operator added, or a collaborator result imported from elsewhere. Those two are
	// the distinction that matters, because "the scanner found this" and "a person found this" are
	// different claims with different follow-ups. It deliberately does NOT distinguish BCheck from a
	// native check: the finding does not record which, and guessing from the check name would put an
	// unverifiable claim in a column an operator would filter on.
	Source string `json:"source"`
	// Confirm is the DOM dynamic tier's machine verdict for a static-pass finding
	// (burpsy-react-ui-m97j): "promoted", "retired", "unavailable" or "unsupported-source",
	// omitted for every finding the tier never saw. Carried so the issues list can show which
	// tentative DOM candidates a browser confirmed — a verdict visible only in the log is a
	// verdict nobody receives.
	Confirm string `json:"confirm,omitempty"`
	// Triage is the LLM second look's note (ei0v), carried verbatim: verdict + reasoning +
	// the model that produced it. ADVICE never promotion — a triage line never moves
	// Severity or Confidence, and the view holds them beside each other so an operator can
	// weigh both. Omitted = not investigated (the feature off, the finding outside the
	// gate, or the pass not yet run — the reasons the route states).
	Triage *core.TriageNote `json:"triage,omitempty"`
}

// issueSource classifies a finding by what raised it, from what the finding knows.
//
// Two states, and only two, because only two are knowable without inventing a provenance field the
// store does not have: a TaskID names a run, and its absence means nothing tracked it. Burp splits
// this further into BCheck / Scan check / Extension / manually generated, and this does not pretend
// to — see the field's own doc on why a guess from the check name would be worse than the
// admission.
func issueSource(f *core.Finding) string {
	if f.TaskID > 0 {
		return "scan"
	}
	return "manual"
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
// exchangeIndex is one snapshot of ExchangeBriefs, so a list of findings resolves every
// occurrence without taking the store lock again per row.
type exchangeIndex struct {
	byRequest map[core.MsgId]core.ExchangeBrief
	byID      map[core.ExchangeID]core.ExchangeBrief
}

func (s *Server) exchangeIndex() exchangeIndex {
	if s.store == nil {
		return exchangeIndex{}
	}
	byRequest, byID := s.store.ExchangeBriefs()
	return exchangeIndex{byRequest: byRequest, byID: byID}
}

func (s *Server) findingToIssueView(f *core.Finding) issueFindingView {
	return s.issueView(f, nil, false)
}

// issueView builds one finding's wire row. idx, when non-nil, is the list's shared snapshot;
// nil falls back to a per-occurrence lookup, which is the right cost for a single finding.
// brief omits the prose (detail, remediation, evidence, the catalogue advisory, triage notes):
// those strings are what make a few thousand findings a multi-megabyte document, and the list
// does not render them. GET /api/issues/{id} is the full row, fetched when one is opened.
func (s *Server) issueView(f *core.Finding, idx *exchangeIndex, brief bool) issueFindingView {
	v := issueFindingView{
		ID:              f.ID,
		CheckName:       f.Name,
		IssueName:       nil,
		Severity:        f.EffectiveSeverity().String(),
		Confidence:      f.EffectiveConfidence().String(),
		Param:           f.Param,
		Params:          f.Params,
		TimesSeen:       len(f.Occurrences),
		MergedCount:     f.MergedCount,
		TaskID:          f.TaskID,
		TimestampUnixMs: int64(f.Timestamp),
		Source:          issueSource(f),
		Confirm:         f.Confirm,
	}
	if !brief {
		v.Detail = strPtr(f.Description)
		v.Remediation = strPtr(f.Remediation)
		v.Evidence = f.Evidence
		v.Triage = f.Triage
		v.Comment = f.Comment
	}
	if f.SeverityOverride != nil {
		over := f.SeverityOverride.String()
		v.SeverityOverride = &over
		v.OriginalSeverity = f.Severity.String()
	}
	if f.ConfidenceOverride != nil {
		over := f.ConfidenceOverride.String()
		v.ConfidenceOverride = &over
		v.OriginalConfidence = f.Confidence.String()
	}
	v.FalsePositive = f.FalsePositive
	if !brief {
		if def, note := s.advisories.Resolve(f.Name); def != nil {
			// Built by the same function GET /api/advisories/{typeIndex} uses, so the browsable catalogue
			// and a finding's attached advisory cannot come to disagree about the shape they share.
			view := advisoryDetailView(def)
			v.Advisory = &view
		} else {
			v.AdvisoryNote = note
		}
	}
	// Empty, not nil. A finding can legitimately have no occurrences — activeFinding leaves them
	// off when the exchange has rolled out of the store, on the documented principle that no
	// location is honest and a partial one is not — and a nil slice marshals to JSON `null`.
	// types.attack.ts declares `occurrences: Occurrence[]`, so scanner.tsx reads `.length` on it
	// without a guard, inside groupFindings, which runs over the WHOLE list on every render: one
	// such finding blanked the entire Issues tab, not just its own row (burpsy-react-ui-qmlk).
	//
	// Newly reachable rather than theoretical: GetExchange could not fail for a live id until
	// history gained Delete items and Clear.
	v.Occurrences = []issueOccurrenceView{}
	for _, occ := range f.Occurrences {
		if hit, ok := resolveOccurrence(s, idx, occ); ok {
			if v.Host == "" {
				v.Host = hit.host
			}
			v.Occurrences = append(v.Occurrences, issueOccurrenceView{
				ExchangeID: hit.id,
				Response:   hit.response,
				Path:       hit.path,
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

// occurrenceHit is one occurrence resolved to the exchange it was observed on.
type occurrenceHit struct {
	id       core.ExchangeID
	host     string
	path     string
	response uint64
}

// resolveOccurrence finds the exchange this occurrence was observed on.
//
// The request message is the lookup that cannot confuse a message id with an exchange id. When
// that message is not indexed — a nil request, or a request id the exchange no longer carries —
// the occurrence's own exchange id is the location the producer recorded, and it still has the
// host and path. Leaving those blank made every finding on a restored project sit under
// "(no host)". A list passes idx so either lookup is a map read.
func resolveOccurrence(s *Server, idx *exchangeIndex, occ core.Occurrence) (occurrenceHit, bool) {
	if occ.Request != nil {
		if hit, ok := occurrenceByRequest(s, idx, *occ.Request); ok {
			return hit, true
		}
	}
	return occurrenceByExchange(s, idx, occ.ExchangeID)
}

func occurrenceByRequest(s *Server, idx *exchangeIndex, req core.MsgId) (occurrenceHit, bool) {
	if idx != nil {
		b, ok := idx.byRequest[req]
		if !ok {
			return occurrenceHit{}, false
		}
		return hitFromBrief(b), true
	}
	if s.store == nil {
		return occurrenceHit{}, false
	}
	ex, err := s.store.ExchangeByRequest(req)
	if err != nil {
		return occurrenceHit{}, false
	}
	return hitFromExchange(ex), true
}

func occurrenceByExchange(s *Server, idx *exchangeIndex, id core.ExchangeID) (occurrenceHit, bool) {
	if idx != nil {
		b, ok := idx.byID[id]
		if !ok {
			return occurrenceHit{}, false
		}
		return hitFromBrief(b), true
	}
	if s.store == nil {
		return occurrenceHit{}, false
	}
	ex, err := s.store.GetExchange(id)
	if err != nil || ex == nil {
		return occurrenceHit{}, false
	}
	return hitFromExchange(ex), true
}

func hitFromBrief(b core.ExchangeBrief) occurrenceHit {
	return occurrenceHit{id: b.ID, host: b.Host, path: b.Path, response: derefMsgID(b.Response)}
}

func hitFromExchange(ex *core.Exchange) occurrenceHit {
	return occurrenceHit{id: ex.ID, host: ex.Host, path: ex.Path, response: derefMsgID(ex.Response)}
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
	findings := s.findings.All()
	// truthy, not == "1": the route declares a boolean, so an agent sends "true" (route_schemas.go).
	includeIsolated := truthy(r.URL.Query().Get("include_isolated"))
	// count is the dock's badge: the shell is mounted on every page, so it must not download a row
	// per finding. summary is the Issues tree and the site map: same rows, without the advisory
	// prose and the evidence excerpt, which are what made the document grow with the issue count.
	countOnly := truthy(r.URL.Query().Get("count"))
	brief := countOnly || truthy(r.URL.Query().Get("summary"))
	idx := s.exchangeIndex()
	views := make([]issueFindingView, 0, len(findings))
	for _, f := range findings {
		// Burp: "Results from isolated scans do not appear in ... Dashboard > All issues" (13uw). A
		// task's own view asks for them with include_isolated=1 and gets them flagged.
		isolated := s.isolatedAgainst(f, &idx)
		if isolated && !includeIsolated {
			continue
		}
		if countOnly {
			views = append(views, issueFindingView{Severity: f.EffectiveSeverity().String(), FalsePositive: f.FalsePositive})
			continue
		}
		v := s.issueView(f, &idx, brief)
		v.Isolated = isolated
		views = append(views, v)
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
		// Keyed on core.Severity's own String() values, lower-cased, because the previous keys were
		// guessed and two of them did not exist: findings report "Informational" and "Critical",
		// while the map held "info" and had no critical bucket at all. The `if _, ok` guard then
		// dropped both classes silently, so the headline disagreed with its own list — a Critical
		// finding did not appear in the counts anywhere, and `info: 0` positively asserted there
		// were no informational findings while several sat in the same response.
		//
		// "info" is still emitted alongside "informational" because the dashboard's tiles read that
		// key; dropping it would trade a wrong number for a missing one.
		counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0, "info": 0}
		unknown := map[string]int{}
		// A finding marked a false positive sits outside the operator's working set, so it counts
		// towards none of the severity buckets — that is the point of marking one. The number that
		// were excluded is reported rather than dropped on the floor, so the headline can never
		// silently disagree with the list it is drawn from.
		falsePositives := 0
		for _, v := range views {
			if v.FalsePositive {
				falsePositives++
				continue
			}
			key := strings.ToLower(v.Severity)
			if _, ok := counts[key]; ok {
				counts[key]++
				if key == "informational" {
					counts["info"]++
				}
				continue
			}
			// A severity this handler does not recognise is reported, never discarded. Silently
			// dropping it is what produced this bug; a named bucket makes the next new severity
			// visible the first time it is returned instead of the first time someone adds up the
			// column by hand.
			unknown[key]++
		}
		if len(unknown) > 0 {
			counts["unrecognised"] = 0
			for _, n := range unknown {
				counts["unrecognised"] += n
			}
			body["unrecognised_severities"] = unknown
		}
		body["counts"] = counts
		// A finding marked a false positive is out of the operator's working set, so it counts
		// towards none of the severity buckets — that is the point of marking one. It is not
		// hidden: false_positives below says how many were excluded, so the headline can never
		// silently disagree with the list it is drawn from. counted is the included number.
		body["false_positives"] = falsePositives
		// The invariant the old code broke, now stated on the wire: the buckets account for every
		// finding in `findings`. "info" is a duplicate of "informational" and is excluded from the sum.
		body["counted"] = len(views) - falsePositives
	}
	if countOnly {
		// The tally above already walked the rows. The dock reads `counted` and must not receive
		// a findings array that grows with the project — an empty array, not null, so a client
		// that still reads .length does not throw.
		body["findings"] = []issueFindingView{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(body)
}

// handleIssueByID routes /api/issues/{id} to the triage and delete paths. It exists as its own
// tiny handler so the subtree registration cannot silently swallow paths meant for another
// feature: anything that is not exactly an id is a 404, not a fall-through.
func (s *Server) handleIssueByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/issues/")
	// The LLM second look's one-finding arm (ei0v): POST /api/issues/{id}/triage runs the
	// operator's hand on one finding, outside the sweep gate. Routed here rather than as its
	// own top-level pattern because the id owns the subtree and the triage pass is one of
	// its verbs.
	if strings.HasSuffix(id, "/triage") && r.Method == http.MethodPost {
		s.handleIssueTriageOne(w, r, strings.TrimSuffix(id, "/triage"))
		return
	}
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "Invalid issue ID", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		s.handleIssueGet(w, id)
		return
	}
	s.handleIssueTriage(w, r, id)
}

// handleIssueGet serves GET /api/issues/{id}: the full finding, including the detail, the
// remediation and the catalogue advisory the list omits. The Issues tree selects a row from
// the summary list and reads this for the advisory pane, so opening one issue does not require
// the list response to have carried every issue's prose.
func (s *Server) handleIssueGet(w http.ResponseWriter, idStr string) {
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid issue ID", http.StatusBadRequest)
		return
	}
	f, err := s.findings.Get(id)
	if err != nil {
		http.Error(w, "Issue not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.findingToIssueView(f))
}

// issueTriageReq is the request body handleIssueTriage decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type issueTriageReq struct {
	// Severity/Confidence use the same lower-case vocabulary the views emit
	// ("informational".."critical", "certain"|"firm"|"tentative"). Empty clears the override.
	Severity      *string `json:"severity"`
	Confidence    *string `json:"confidence"`
	FalsePositive *bool   `json:"false_positive"`
	Comment       *string `json:"comment"`
}

// handleIssueTriage serves PUT /api/issues/{id} (operator triage: severity, confidence,
// false-positive, comment) and DELETE /api/issues/{id} (remove the finding). These are the write
// paths the read-only /api/issues never had; the store applies every decision under one lock and
// mirrors it to SQLite, so an override outlives both a re-audit (which merges into the same
// finding rather than replacing it) and a restart.
//
// PUT is used rather than PATCH because the body is total: absent fields clear their override, so
// "severity gone" means "engine severity stands again", never "leave it as it was". A partial
// protocol here is how a cleared override comes back as a ghost on the next restart.
func (s *Server) handleIssueTriage(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid issue ID", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if !s.findings.Delete(id) {
			http.Error(w, "Issue not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPut, http.MethodPatch:
		// fall through to the body below
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req issueTriageReq
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	if len(body) > 0 {
		if err := requestJSON(w, r, bytes.NewReader(body)).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
	}
	if req.Severity != nil && *req.Severity != "" {
		// Validated before the store is touched: ParseSeverity maps an unrecognised word to
		// Informational, so without this a typo would silently reclassify rather than be rejected.
		over := core.ParseSeverity(*req.Severity)
		if over == core.SeverityInformational && !strings.EqualFold(*req.Severity, "informational") && !strings.EqualFold(*req.Severity, "info") {
			http.Error(w, "Invalid severity; want informational, low, medium, high or critical", http.StatusBadRequest)
			return
		}
	}
	if req.Confidence != nil && *req.Confidence != "" {
		// Same contract as severity: ParseConfidence's fallback is Tentative, which must not be
		// reachable by misspelling "certain".
		over := core.ParseConfidence(*req.Confidence)
		if over == core.ConfidenceTentative && !strings.EqualFold(*req.Confidence, "tentative") {
			http.Error(w, "Invalid confidence; want certain, firm or tentative", http.StatusBadRequest)
			return
		}
	}
	if req.Comment != nil && len(*req.Comment) > 8192 {
		http.Error(w, "Comment too long (max 8192 bytes)", http.StatusBadRequest)
		return
	}

	ok := s.findings.Triage(id, func(f *core.Finding) {
		if req.Severity != nil {
			if *req.Severity == "" {
				f.SeverityOverride = nil
			} else {
				over := core.ParseSeverity(*req.Severity)
				f.SeverityOverride = &over
			}
		}
		if req.Confidence != nil {
			if *req.Confidence == "" {
				f.ConfidenceOverride = nil
			} else {
				over := core.ParseConfidence(*req.Confidence)
				f.ConfidenceOverride = &over
			}
		}
		if req.FalsePositive != nil {
			f.FalsePositive = *req.FalsePositive
		}
		if req.Comment != nil {
			f.Comment = *req.Comment
		}
	})
	if !ok {
		http.Error(w, "Issue not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// ---- Record an issue (burpsy-react-ui-4qqz) -----------------------------------------------------

// manualIssueReq is the body POST /api/issues/record takes: the operator's description of an
// issue they found by hand, attached to one exchange they name.
type manualIssueReq struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	// ExchangeID is a pointer so "absent" is distinguishable from exchange 0: the stores are
	// dense counters from zero, and the first exchange ever captured IS exchange 0 — a flat
	// uint64 would reject the very first pair with the required-field error.
	ExchangeID *uint64 `json:"exchange_id"`
	// Comment rides the finding's operator-note field rather than being folded into the
	// description: the description is what the operator says about the *vulnerability*, the
	// comment is what they say about *this record* — how they found it, what to re-check.
	Comment string `json:"comment"`
}

// handleIssueRecord serves POST /api/issues/record — Burp's "Record an issue" context-menu
// action. A finding created this way is a first-class finding: it rides the same store, the
// same triage endpoints, the same persistence as a scanner-produced one, because the operator
// authored it with more certainty about the vulnerability than any scanner has.
//
// The exchange is mandatory and must exist. An issue pointing at nothing cannot be jumped to
// from the UI and cannot be verified later, which is the failure mode this feature exists to
// avoid: Burp attaches the selected request/response pair, and so does this.
//
// Dedup is deliberately bypassed by naming the issue uniquely per record (the caller's name is
// used as-is; two records with the same name on one host merge into one finding with two
// occurrences, which is the ordinary semantics — "add to a previously created issue", which is
// Burp's other documented mode for this action).
func (s *Server) handleIssueRecord(w http.ResponseWriter, r *http.Request) {
	var req manualIssueReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		http.Error(w, "Name is required: name the issue the way it should read in the report", http.StatusBadRequest)
		return
	}
	if req.ExchangeID == nil {
		http.Error(w, "exchange_id is required: an issue must point at the request/response pair it describes", http.StatusBadRequest)
		return
	}
	exchange, err := s.store.GetExchange(core.ExchangeID(*req.ExchangeID))
	if err != nil || exchange == nil {
		http.Error(w, fmt.Sprintf("no exchange %d: the pair this issue describes was not found", *req.ExchangeID), http.StatusNotFound)
		return
	}

	host, port := exchange.Host, exchange.Port
	if host == "" {
		http.Error(w, "the exchange carries no host, so no issue target can be derived from it", http.StatusBadRequest)
		return
	}
	// Severity defaults to Low (Burp's "Medium" default for hand-recorded issues differs by
	// installation; Low is the conservative choice here because a hand-recorded issue the
	// operator forgot to grade should not inflate a High count), confidence to Certain — the
	// operator saw it themselves, which is stronger evidence than any scanner produces.
	severity := core.ParseSeverity(req.Severity)
	if strings.TrimSpace(req.Severity) == "" {
		severity = core.SeverityLow
	}
	confidence := core.ParseConfidence(req.Confidence)
	if strings.TrimSpace(req.Confidence) == "" {
		confidence = core.ConfidenceCertain
	}

	description := strings.TrimSpace(req.Description)
	if description == "" {
		description = "Manually recorded by the operator from exchange #" + strconv.FormatUint(*req.ExchangeID, 10) + "."
	}

	id := s.findings.Add(core.NewFinding{
		Name:        strings.TrimSpace(req.Name),
		Severity:    severity,
		Confidence:  confidence,
		Description: description,
		Remediation: strings.TrimSpace(req.Remediation),
		Occurrences: []core.Occurrence{{
			ExchangeID: core.ExchangeID(*req.ExchangeID),
			Request:    exchange.Request,
			Response:   exchange.Response,
		}},
		Target: core.FindingTarget{Host: host, Port: port, TLS: exchange.TLS},
	})
	// Comment lives on Finding (it is operator state, not engine state), so it rides the same
	// Triage path the edit-comment UI action uses — one write path for operator-authored text.
	if comment := strings.TrimSpace(req.Comment); comment != "" {
		s.findings.Triage(id, func(f *core.Finding) { f.Comment = comment })
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"id": id, "recorded": true})
}

// handleFindings is the legacy /api/findings endpoint, kept for tools that predate /api/issues.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	findings := s.findings.All()
	views := make([]FindingView, 0, len(findings))
	for _, f := range findings {
		if s.findingIsolated(f) {
			continue // an isolated scan's findings are not on the issue list (13uw)
		}
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

// ---- the Search box (burpsy-react-ui-ngcj) -------------------------------------------------------

// historySearch is the Search box's compiled form: the vs9k byte matcher plus the negative flag.
// The matcher itself lives in api_search.go with the suite dialog that owns it; what lives here is
// the half /api/history adds — the row-column haystack no bytes scan can see — and the wiring that
// runs both halves for every row before the cap.
type historySearch struct {
	matcher *suiteSearchMatcher
	negate  bool
}

// historyRowColumns is the non-bytes half of the Search box's haystack: the fields a history row
// renders as columns. The five the old client-side filter could see (method, host, path, MIME,
// comment) are joined by the ones it structurally could not: the recorded page Title (which lives
// on the row, not in any message), the highlight annotation, the server IP, and the listener port
// (Burp's own filter dialog calls that one out as "useful when testing access controls", and an
// operator's search for the port they remember is a search over exactly this field). Every field
// the bytes half already covers is absent on purpose: matching a header twice would make a
// negative search answer a question it was never asked.
func historyRowColumns(ex *core.Exchange) string {
	var b strings.Builder
	b.WriteString(ex.Method)
	b.WriteByte(' ')
	b.WriteString(ex.Host)
	b.WriteByte(' ')
	b.WriteString(ex.Path)
	if ex.Mime != "" {
		b.WriteByte(' ')
		b.WriteString(ex.Mime)
	}
	// Notes is a pointer because absent is not empty here: a row nobody annotated must not
	// contribute a lone space to the haystack, and dereferencing nil to find out would be the
	// whole crash.
	if ex.Notes != nil && *ex.Notes != "" {
		b.WriteByte(' ')
		b.WriteString(*ex.Notes)
	}
	if ex.Title != "" {
		b.WriteByte(' ')
		b.WriteString(ex.Title)
	}
	if ex.Highlight != "" {
		b.WriteByte(' ')
		b.WriteString(ex.Highlight)
	}
	if ex.ServerIP != "" {
		b.WriteByte(' ')
		b.WriteString(ex.ServerIP)
	}
	if ex.ListenerPort != 0 {
		b.WriteString(fmt.Sprintf(" :%d", ex.ListenerPort))
	}
	return b.String()
}

// match answers whether one exchange passes the Search box. The row-column half goes through the
// SAME matcher as the bytes, so a regex is one regex everywhere; the bytes half scans both
// directions, headers and body, with the vs9k region logic — including its no-request guard, which
// searches a request-less row for what it does have rather than scanning message 0 and reporting
// another exchange's matches (the wtov defect, reached through search; the guard is borrowed, not
// re-implemented).
func (s *Server) historySearchMatch(h *historySearch, ex *core.Exchange) bool {
	if h == nil {
		return true
	}
	hit := len(h.matcher.allIn([]byte(historyRowColumns(ex)))) > 0
	if !hit {
		// Both directions, whole messages: headers and body, the way Burp's "across all columns"
		// reads when the column is the bytes a message carried.
		_, total := s.searchExchange(ex, suiteSearchOptions{area: suiteSearchAreaBoth}, h.matcher)
		hit = total > 0
	}
	if hit == h.negate {
		return false
	}
	return true
}

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

// filteredExchangeQuery binds a store so Body() can resolve the request message.
//
// Mime used to be hardcoded empty here, with a comment explaining that the exchange did not carry
// it. That was true and it made every `mime` comparison in a /api/history?q= query false — so the
// DSL field the grammar advertises, and that reference.ts documents to the operator, silently
// matched nothing at all. core.Exchange.Mime now carries it, denormalised at capture, so the
// comparison is answered from the index row without resolving a response.
type filteredExchangeQuery struct {
	store *core.TrafficStore
	ex    *core.Exchange
}

// TaskID answers from the exchange's own attribution — the whole point of the field existing.
// (ex.TaskID, true): the history row knows what run produced it, and 0 is the real answer for
// operator-proxied traffic, exactly the row `task != 0` is how you exclude.
func (f filteredExchangeQuery) TaskID() (uint64, bool) { return f.ex.TaskID, true }

func (f filteredExchangeQuery) Host() string   { return f.ex.Host }
func (f filteredExchangeQuery) Method() string { return f.ex.Method }
func (f filteredExchangeQuery) Path() string   { return f.ex.Path }
func (f filteredExchangeQuery) Status() int {
	if f.ex.Status == nil {
		return 0
	}
	return int(*f.ex.Status)
}

// Mime is the stored media type, "" when the response declared none or has not arrived. The query
// evaluator reads "" as absent, so every comparison on it stays false rather than half of them
// matching every untyped row — which is the right reading for both of those cases.
func (f filteredExchangeQuery) Mime() string { return f.ex.Mime }
func (f filteredExchangeQuery) Body() []byte {
	msg, err := f.store.Get(core.MsgOrZero(f.ex.Request))
	if err != nil {
		return nil
	}
	return msg.Body()
}

// ResponseLen answers from the index row, which is the whole point of ResponseLen existing on
// core.Exchange: /api/history serves index rows and must not open a response to size one.
//
// Presence is decided by Response, not by the length being non-zero. A 204 is a zero-length
// response and a request still in flight is no response at all; collapsing those would make
// `length = 0` match every pending request, and `length != 0` hide every empty one.
func (f filteredExchangeQuery) ResponseLen() (int64, bool) {
	if f.ex.Response == nil {
		return 0, false
	}
	return int64(f.ex.ResponseLen), true
}

// Annotation answers from the index row, which is where both live. known is unconditionally true:
// this consumer is a captured exchange, so "no highlight" and "no comment" are real answers about it
// rather than an inability to tell.
//
// core.Exchange.Notes is a *string because an unset note and an empty note are distinguishable in
// the store; both read as "" here, which is right for a text search — an operator asking
// `comment ~ "x"` does not care which kind of nothing they have.
func (f filteredExchangeQuery) Annotation() (string, string, bool) {
	comment := ""
	if f.ex.Notes != nil {
		comment = *f.ex.Notes
	}
	return f.ex.Highlight, comment, true
}

// Header reads the RESPONSE head, resolved from the store on demand.
//
// Note the asymmetry with Body above, which deliberately returns the *request* body for the history
// filter. Headers are the response's: `header["set-cookie"]` and `header["server"]` are questions
// about what came back, and no operator writing a history filter means the request's headers by
// that word. Stated here because the two fields on the same type reading opposite messages would
// otherwise look like a bug.
//
// Resolved lazily and not memoised, unlike auditedExchangeQuery: this type is constructed per row
// per request and discarded, so there is no second call to save. A query naming no header field
// never reaches this method and so never opens a response.
func (f filteredExchangeQuery) Header(name string) ([]string, bool) {
	if f.ex.Response == nil {
		return nil, false
	}
	msg, err := f.store.Get(*f.ex.Response)
	if err != nil {
		// Unreadable is absent, not empty: every comparison fails, and the alternative would be
		// reporting "no such header" as a fact about the response.
		return nil, false
	}
	raw, present := msg.HeaderValues(name)
	if !present {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		out = append(out, string(value))
	}
	return out, true
}

// DurationUs carries core.ExchangeDuration's Measured flag straight through rather than reducing it
// to a number. That flag exists so an exchange nobody timed does not report as instantaneous, and
// flattening it here would undo it at the one place an operator can ask about timing.
func (f filteredExchangeQuery) DurationUs() (int64, bool) {
	if !f.ex.Duration.Measured {
		return 0, false
	}
	return int64(f.ex.Duration.Us), true
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
	pemBytes := s.currentCACertPEM()
	if len(pemBytes) == 0 {
		http.Error(w, "TLS interception is not enabled, so there is no CA to trust; start with -intercept-tls or PUT /api/proxy/interception {\"enabled\": true}", http.StatusNotFound)
		return
	}
	// application/x-x509-ca-cert is what browsers recognise as a CA to import. The filename matters
	// for the download the UI link triggers.
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="burpsy-ca.crt"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(pemBytes)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if _, err := w.Write(pemBytes); err != nil {
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

// findingIsolated reports whether every occurrence of a finding is on an isolated scan's exchange
// (13uw). A finding also seen on ordinary traffic is not isolated: it belongs on the issue list.
func (s *Server) findingIsolated(f *core.Finding) bool {
	return s.isolatedAgainst(f, nil)
}

// isolatedAgainst reports whether every occurrence sits on an isolated scan's exchange.
// idx, when non-nil, answers from the list snapshot; nil asks the store per occurrence.
func (s *Server) isolatedAgainst(f *core.Finding, idx *exchangeIndex) bool {
	if f == nil || len(f.Occurrences) == 0 {
		return false
	}
	for _, occ := range f.Occurrences {
		var isolated, ok bool
		if idx != nil {
			b, found := idx.byID[occ.ExchangeID]
			ok, isolated = found, b.Isolated
		} else if s.store != nil {
			ex, err := s.store.GetExchange(occ.ExchangeID)
			ok = err == nil && ex != nil
			isolated = ok && ex.Source.Isolated()
		}
		if !ok || !isolated {
			return false
		}
	}
	return true
}

// scopeHasRule reports whether scope already holds a rule identical to r in every arm.
func scopeHasRule(scope *core.Scope, r *core.ScopeRule) bool {
	same := func(x, y *string) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	for _, e := range scope.Rules() {
		if e.Kind == r.Kind && e.Pattern == r.Pattern && same(e.PathPrefix, r.PathPrefix) && same(e.Protocol, r.Protocol) &&
			(e.Port == nil) == (r.Port == nil) && (e.Port == nil || *e.Port == *r.Port) {
			return true
		}
	}
	return false
}
