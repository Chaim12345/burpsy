package web

import (
	"encoding/json"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/session"
)

// ---- Import/export of the operator's configuration surfaces -------------------------------------
//
// Burp treats scope, match/replace and session handling rules as portable engagement state. burpsy
// kept every rule inside the running process: restart the console and the setup was gone. One
// bundle carries all three surfaces; export reads them as they are, import applies a whole bundle
// or none of it. The atomicity is the point — a half-imported configuration leaves the operator
// unable to tell which rules are really theirs, and on a testing proxy an ambiguous scope means
// sends that should have been scoped going out unscoped.
//
// A section absent from the bundle leaves its surface untouched; a section present replaces it
// wholesale. Export always writes all three keys, so a plain export→import round trip reproduces
// the donor setup exactly.

const configBundleVersion = 1

type configScopeSection struct {
	Rules []scopeRuleView `json:"rules"`
}

type configRuleState struct {
	Active bool                `json:"active"`
	Rules  []interceptRuleSpec `json:"rules"`
}

type configBundle struct {
	Version      int                        `json:"version"`
	Scope        *configScopeSection        `json:"scope,omitempty"`
	Intercept    map[string]configRuleState `json:"intercept,omitempty"`
	SessionRules []sessionRuleDto           `json:"session_rules,omitempty"`
}

func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bundle := configBundle{
		Version:   configBundleVersion,
		Scope:     &configScopeSection{},
		Intercept: map[string]configRuleState{},
	}
	for _, rule := range s.scope.Rules() {
		kind := "Include"
		if rule.Kind == core.ScopeExclude {
			kind = "Exclude"
		}
		pattern := rule.Pattern
		bundle.Scope.Rules = append(bundle.Scope.Rules, scopeRuleView{Kind: kind, Host: &pattern, Path: rule.PathPrefix, Port: rule.Port})
	}
	for name, dir := range map[string]intercept.Direction{"requests": intercept.DirectionRequest, "responses": intercept.DirectionResponse} {
		list := s.intercept.Rules(dir)
		bundle.Intercept[name] = configRuleState{Active: list.Active, Rules: rulesToSpecs(list.Rules)}
	}
	for _, rule := range s.sessionCoordinator.AllRules() {
		bundle.SessionRules = append(bundle.SessionRules, ruleToDto(rule))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bundle)
}

func (s *Server) handleConfigImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var bundle configBundle
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Phase one — convert every section into its internal form. Nothing below mutates state, so a
	// failure anywhere in this phase costs the caller nothing.
	scopeRules := []*core.ScopeRule{}
	if bundle.Scope != nil {
		for _, view := range bundle.Scope.Rules {
			if view.Host == nil || *view.Host == "" {
				http.Error(w, "Invalid bundle: a scope rule without a host pattern", http.StatusBadRequest)
				return
			}
			req := ScopeRequest{
				Action:  "include",
				Pattern: *view.Host,
				Path:    derefString(view.Path),
			}
			kind := core.ScopeInclude
			switch view.Kind {
			case "Include":
			case "Exclude":
				req.Action = "exclude"
				kind = core.ScopeExclude
			default:
				http.Error(w, "Invalid bundle: scope rule kind must be \"Include\" or \"Exclude\"", http.StatusBadRequest)
				return
			}
			rule, err := buildScopeRule(kind, req)
			if err != nil {
				http.Error(w, "Invalid bundle: "+err.Error(), http.StatusBadRequest)
				return
			}
			scopeRules = append(scopeRules, rule)
		}
	}

	interceptSets := map[intercept.Direction]struct {
		active bool
		rules  []intercept.Rule
	}{}
	for name, state := range bundle.Intercept {
		dir, ok := directionFor(name)
		if !ok {
			http.Error(w, "Invalid bundle: unknown intercept direction "+name, http.StatusBadRequest)
			return
		}
		rules, err := specToRules(state.Rules)
		if err != nil {
			http.Error(w, "Invalid bundle: "+err.Error(), http.StatusBadRequest)
			return
		}
		interceptSets[dir] = struct {
			active bool
			rules  []intercept.Rule
		}{state.Active, rules}
	}

	sessionRules := []*session.SessionRule{}
	for _, dto := range bundle.SessionRules {
		// The id belongs to the donor process; AddRule mints fresh ones. Carrying a stale id into
		// AddRule would either collide or imply an ordering the import cannot honour.
		dto.ID = nil
		rule, err := dtoToRule(dto)
		if err != nil {
			http.Error(w, "Invalid bundle: "+err.Error(), http.StatusBadRequest)
			return
		}
		sessionRules = append(sessionRules, rule)
	}

	// Phase two — everything converted, so every write below succeeds or the process is broken in a
	// way no request shape can fix.
	if bundle.Scope != nil {
		s.scope.Clear()
		for _, rule := range scopeRules {
			s.scope.Add(rule)
		}
	}
	for dir, set := range interceptSets {
		if err := s.intercept.SetRules(dir, set.active, set.rules); err != nil {
			http.Error(w, "Invalid bundle: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if bundle.SessionRules != nil {
		for _, existing := range s.sessionCoordinator.AllRules() {
			s.sessionCoordinator.RemoveRule(existing.ID)
		}
		for _, rule := range sessionRules {
			if _, err := s.sessionCoordinator.AddRule(rule); err != nil {
				http.Error(w, "Invalid bundle: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		s.persistSessionRules()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":         "ok",
		"scope_rules":    len(scopeRules),
		"intercept_dirs": len(interceptSets),
		"session_rules":  len(sessionRules),
	})
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
