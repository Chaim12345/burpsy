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

// ---- what this bundle carries, and what it does not ---------------------------------------
//
// `Export configuration` used to download `burpsy-config.json` carrying scope, intercept and
// session rules, and drop every other configuration surface without a word. The menu item did
// not say "partial", the file recorded no manifest, and the import result counted only the
// three sections it knew about.
//
// Nothing behaved incorrectly, which is why the parity audit filed it as §2.2 rather than as a
// defect — and then said it is worse in practice than most defects: an operator carries that
// file to a new machine, believes their engagement configuration travelled, and discovers
// otherwise later, during work, when the missing settings matter.
//
// So the bundle now states its own coverage. The name still promises more than it delivers, but
// the file no longer does, and the UI says "partial" where the operator chooses it.
//
// # The lists, and how they were derived
//
// Not copied from the audit's prose — that said "3 of ~11" and this is 3 of 15. Derived from
// the durable configuration surfaces in internal/persist:
//
//	grep -oE 'func \(s \*Store\) Save[A-Za-z]+' internal/persist/*.go
//
// which yields 17 savers. Five are traffic and history rather than configuration —
// SaveMessage, SaveExchange, SaveFinding, SaveToolLog, SaveOrganizer — and are deliberately not
// listed here: a config bundle that carried captured traffic would be a different feature with
// very different privacy properties. The remaining 12 are configuration, plus intercept rules,
// which never reach persist (they live in-process only) and are nonetheless exported.
//
// Included is bound to reality by a test: every JSON key handleConfigExport actually writes must
// appear in configIncludedSections. Omitted is hand-maintained, which is a real residual risk —
// adding a new persisted config surface will not fail any test until someone lists it here. It
// is recorded as a known weakness rather than dressed up as a guarantee.
var (
	configIncludedSections = []string{
		"scope",
		"intercept",
		"session_rules",
		"uninteresting_headers",
	}
	configOmittedSections = []string{
		"client_certificates",
		"match_replace_rules",
		"network_settings",
		"platform_authentication",
		"proxy_options",
		"resource_pools",
		"scanner_config",
		"scheduled_tasks",
		"tls_passthrough",
		"upstream_proxy",
	}
)

// configCoverage travels inside the bundle so the file is self-describing: a bundle read on
// another machine, or by a future version, says what it was capable of carrying without the
// reader having to know which burpsy wrote it.
type configCoverage struct {
	// Partial is the one field a reader should branch on. It is derived, not declared, so it
	// cannot claim completeness while Omitted is non-empty.
	Partial  bool     `json:"partial"`
	Included []string `json:"included"`
	Omitted  []string `json:"omitted"`
	// Note is for a human opening the file in an editor, which is the most likely way this
	// gets read at the moment it matters.
	Note string `json:"note"`
}

func exportCoverage() configCoverage {
	return configCoverage{
		Partial:  len(configOmittedSections) > 0,
		Included: configIncludedSections,
		Omitted:  configOmittedSections,
		Note: "This bundle carries only the sections listed in \"included\". The sections in " +
			"\"omitted\" are configured on this instance but are NOT exported, and importing this " +
			"file elsewhere will leave them at that machine's own settings.",
	}
}

type configScopeSection struct {
	Rules []scopeRuleView `json:"rules"`
}

type configRuleState struct {
	Active bool                `json:"active"`
	Rules  []interceptRuleSpec `json:"rules"`
}

type configBundle struct {
	Version int `json:"version"`
	// Coverage is written on export and ignored on import — a bundle's own account of what it
	// carries is evidence about the file, not an instruction to the importer. Omitted on import
	// so an older bundle without it is not treated as a bundle claiming to carry everything.
	Coverage  *configCoverage            `json:"coverage,omitempty"`
	Scope     *configScopeSection        `json:"scope,omitempty"`
	Intercept map[string]configRuleState `json:"intercept,omitempty"`
	// No `omitempty` on SessionRules, and that is load-bearing.
	//
	// Import gates on `bundle.SessionRules != nil` so that a section absent from a bundle leaves
	// its surface untouched. With `omitempty`, a donor holding *no* session rules dropped the key
	// entirely — so importing that bundle onto a machine that did have session rules left them in
	// place. The operator believed they had replicated a clean setup and silently inherited
	// foreign session rules, which on this tool decide when the scanner re-authenticates.
	//
	// That contradicted this file's own header claim that "a plain export→import round trip
	// reproduces the donor setup exactly". Export now always writes the key — `[]` for a donor
	// with none — so "exported and empty" is distinguishable from "not exported", which are
	// different facts and were being conflated. A pre-manifest bundle with no key at all still
	// decodes to nil and is still left untouched.
	SessionRules []sessionRuleDto `json:"session_rules"`
	// UninterestingHeaders is the Comparer's discount lists — W6 #81/#82. Added to the bundle in the
	// same commit that created the setting, deliberately: a new configuration surface that the
	// importer accepts and the exporter never writes is the exact defect fixed in 58d4611 for
	// session_rules and again for the WebSocket intercept directions. A pointer so an older bundle
	// with no such key leaves the recipient's lists alone, rather than silently clearing them.
	UninterestingHeaders *configUninterestingHeaders `json:"uninteresting_headers,omitempty"`
}

// configUninterestingHeaders carries both directions. Not omitempty on the inner slices: exported
// and empty must stay distinguishable from not exported, which is what decides whether an import
// clears the recipient's list or leaves it.
type configUninterestingHeaders struct {
	Request  []string `json:"request"`
	Response []string `json:"response"`
}

func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ?level=user|project narrows the bundle to one half of the configuration
	// (burpsy-react-ui-wfiw). Absent means both, which is what every existing caller sends.
	level, narrowed, levelErr := parseConfigLevel(r)
	if levelErr != nil {
		http.Error(w, "level must be \"user\" or \"project\"", http.StatusBadRequest)
		return
	}
	coverage := exportCoverageAt(level, narrowed)
	bundle := configBundle{
		Version:  configBundleVersion,
		Coverage: &coverage,
	}
	// Each section is initialised ONLY when the requested level includes it. The
	// non-nil-means-present rule still holds within a level: a section this bundle covers is
	// written even when its surface is empty, and a section the level excludes is absent entirely
	// — which the importer already reads as "do not touch this surface".
	if sectionInLevel("scope", level, narrowed) {
		bundle.Scope = &configScopeSection{}
	}
	if sectionInLevel("intercept", level, narrowed) {
		bundle.Intercept = map[string]configRuleState{}
	}
	if sectionInLevel("session_rules", level, narrowed) {
		bundle.SessionRules = []sessionRuleDto{}
	}
	for _, rule := range s.scope.Rules() {
		if bundle.Scope == nil {
			break
		}
		kind := "Include"
		if rule.Kind == core.ScopeExclude {
			kind = "Exclude"
		}
		pattern := rule.Pattern
		bundle.Scope.Rules = append(bundle.Scope.Rules, scopeRuleView{Kind: kind, Host: &pattern, Path: rule.PathPrefix, Port: rule.Port})
	}
	// Every direction the importer accepts, from the one table in api_intercept.go.
	// Previously a literal map naming two of them, which meant a direction added
	// later was importable but never exported — see interceptDirectionNames.
	for _, d := range interceptDirectionNames {
		if bundle.Intercept == nil {
			break
		}
		list := s.intercept.Rules(d.Dir)
		bundle.Intercept[d.Name] = configRuleState{Active: list.Active, Rules: rulesToSpecs(list.Rules)}
	}
	if bundle.SessionRules != nil {
		for _, rule := range s.sessionCoordinator.AllRules() {
			bundle.SessionRules = append(bundle.SessionRules, ruleToDto(rule))
		}
	}
	if sectionInLevel("uninteresting_headers", level, narrowed) {
		bundle.UninterestingHeaders = &configUninterestingHeaders{
			Request:  s.uninteresting.headers(false),
			Response: s.uninteresting.headers(true),
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bundle)
}

func (s *Server) handleConfigImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ?level=user|project narrows which sections of the bundle are APPLIED (burpsy-react-ui-wfiw),
	// so restoring your own preferences cannot overwrite an engagement's scope and handing someone
	// an engagement cannot overwrite their proxy settings. Absent means both, which is what every
	// existing caller sends.
	//
	// The narrowing composes with the absent-section rule rather than replacing it: a section the
	// level excludes is left untouched for exactly the same reason a section the bundle never
	// mentioned is.
	level, narrowed, levelErr := parseConfigLevel(r)
	if levelErr != nil {
		http.Error(w, "level must be \"user\" or \"project\"", http.StatusBadRequest)
		return
	}

	var bundle configBundle
	if err := requestJSON(w, r, nil).Decode(&bundle); err != nil {
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
				Action:   "include",
				Pattern:  *view.Host,
				Path:     derefString(view.Path),
				Protocol: derefString(view.Protocol),
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
	if bundle.Scope != nil && sectionInLevel("scope", level, narrowed) {
		s.scope.Clear()
		for _, rule := range scopeRules {
			s.scope.Add(rule)
		}
	}
	for dir, set := range interceptSets {
		if !sectionInLevel("intercept", level, narrowed) {
			break
		}
		if err := s.intercept.SetRules(dir, set.active, set.rules); err != nil {
			http.Error(w, "Invalid bundle: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if bundle.UninterestingHeaders != nil && sectionInLevel("uninteresting_headers", level, narrowed) {
		// Nothing to validate: any string is an acceptable header name once normalised, and set()
		// drops the empties. So this belongs in phase two with the other writes rather than needing
		// a phase-one conversion.
		s.uninteresting.set(false, bundle.UninterestingHeaders.Request)
		s.uninteresting.set(true, bundle.UninterestingHeaders.Response)
	}
	if bundle.SessionRules != nil && sectionInLevel("session_rules", level, narrowed) {
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
		"status":                "ok",
		"scope_rules":           len(scopeRules),
		"intercept_dirs":        len(interceptSets),
		"session_rules":         len(sessionRules),
		"uninteresting_headers": bundle.UninterestingHeaders != nil,
	})
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
