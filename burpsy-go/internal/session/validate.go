package session

// Config-time validation of a session-handling rule: every operator mistake this package can catch
// without touching the network, caught before the rule is installed rather than mid-login.
//
// This is the Go form of crates/session/src/rule.rs's `SessionRule::new`, which is the *only* way to
// a runnable Rust rule — construction and validation are the same act there, so an invalid rule
// cannot exist. Go cannot borrow that trick: SessionRule is a plain struct whose fields callers
// assemble one at a time (the CLI sets Validity after building the rule, a DTO conversion appends
// steps in a loop), so validation is a separate pass instead, and Coordinator.AddRule and
// Coordinator.UpdateRule run it on every path that installs a rule so nothing gets in behind its
// back. NewSessionRule stays deliberately permissive: it is the inert spec, matching Rust's
// `SessionRuleSpec`, and holding one proves nothing has been checked.
//
// What is checked, and why each one is worth a refusal rather than a rule that quietly does nothing:
//
//   - No name. Every outcome and error this package reports names its rule, and "rule 3" is not a
//     name an operator can act on.
//   - A scope that was stated and is empty. It matches nothing, so the rule would never fire — see
//     ValidateRuleStatedScope for why only the *stated* case can be caught here.
//   - A tools scope naming an empty tool. No request is ever attributed to a tool with no name, so
//     such an entry is a restriction that can never match — the same dead arm as a host pattern of
//     "", which is why this check exists here and not only at the wire. Whether a *non-empty* name
//     is one burpsy has is not this package's question: the vocabulary belongs to internal/toollog
//     and the wire refuses an unrecognised name against it.
//   - max_attempts below 1. The macro could never run at all.
//   - A macro with no steps. There is nothing to run.
//   - A step with no method, or a URL with no readable host. A hostless URL cannot be keyed in the
//     cookie jar and cannot be matched against a scope, so the rule could never do its job for it.
//   - A {{name}} no *earlier* step extracts. Values are resolved immediately before a step is sent,
//     so a reference to this step's own response — or to a later one — is a value that does not exist
//     yet, and the placeholder would go out on the wire verbatim.
//   - Two extractions with the same name. The later one silently wins, so which value a {{name}}
//     carries would depend on a step order nobody stated.
//   - An extraction with an unusable pattern, an unreferable name, or an out-of-range step.
//   - An extraction that says how it works twice (a pattern *and* a json path) or not at all.
//   - A json path outside the supported subset, named by the construct that is unsupported. This is
//     the one refusal whose *timing* is the point: a path accepted here and unwalkable at login time
//     would report as "the token was not in the response", which blames the target for a limit of this
//     scanner. See jsonpath.go for the grammar and internal/session/jsonpath.go's package docs for why
//     it is a subset at all.
//
// Every one of those otherwise surfaces as "the log in again button did nothing", with the reason
// buried in whichever step produced no value.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// RuleError says why a rule was refused, naming the rule so a rejected list says which entry to fix.
// Mirrors crates/session/src/rule.rs's RuleError, including its "<unnamed>" fallback: an error about
// a rule with no name still has to be about something an operator can find in the list.
type RuleError struct {
	// Rule is the rule's trimmed name, or "<unnamed>" when the missing name is what was wrong.
	Rule    string
	Message string
}

func (e *RuleError) Error() string {
	return fmt.Sprintf("session rule %q: %s", e.Rule, e.Message)
}

// ValidateRule checks everything about `rule` that can be checked without sending anything.
//
// Treats a rule with no scope hosts as "applies everywhere", which is what MatchHost now does and
// what Rust's `scope: None` means. A caller that can tell an *omitted* scope from a stated-but-empty
// one should use ValidateRuleStatedScope instead.
func ValidateRule(rule *SessionRule) error {
	return validateRule(rule, false)
}

// ValidateRuleStatedScope is ValidateRule for a caller whose configuration form can express
// "restrict this rule to nothing".
//
// Rust's scope is an `Option<Scope>`: absent means "applies everywhere", and only a scope that was
// *stated* and empty is refused. A Go SessionRule holds a plain []string, which cannot tell those two
// apart — both are an empty slice by the time the rule exists. So the distinction has to be settled
// by whoever still has the wire form in hand (see internal/web/api_session.go's dtoToRule, where
// `{"allow_all": false, "rules": []}` and an omitted `scope` arrive as the same nil slice) and passed
// in here, so the refusal and its wording live with the rest of the checks rather than being
// duplicated in each caller.
func ValidateRuleStatedScope(rule *SessionRule, scopeStated bool) error {
	return validateRule(rule, scopeStated)
}

// ruleLabel is how a rule is named in a refusal: its trimmed name, or "<unnamed>" when that is the
// thing missing. Shared with the refusals Coordinator raises outside this file (RestoreRule's), so a
// rule is identified the same way whichever check turned it down.
func ruleLabel(rule *SessionRule) string {
	if rule == nil {
		return "<unnamed>"
	}
	if label := strings.TrimSpace(rule.Name); label != "" {
		return label
	}
	return "<unnamed>"
}

func validateRule(rule *SessionRule, scopeStated bool) error {
	if rule == nil {
		return &RuleError{Rule: "<unnamed>", Message: "there is no rule to install"}
	}
	label := ruleLabel(rule)
	refuse := func(format string, args ...interface{}) error {
		return &RuleError{Rule: label, Message: fmt.Sprintf(format, args...)}
	}

	if strings.TrimSpace(rule.Name) == "" {
		return refuse("a rule needs a name: every outcome and error this package reports names its rule")
	}
	if scopeStated && len(rule.ScopeHosts) == 0 && rule.ScopeMode != "suite" && !rule.StatesURLArms() {
		// Stated-and-empty in every axis the rule can be scoped by (7nh2): no hosts, no path, no
		// port, no scheme, and not delegated to the suite scope. This is the reading Rust's
		// Option<Scope> cannot express and the web layer hands in as scopeStated, so it keeps its
		// refusal — but the wording now names the axes, because "the scope has no hosts" stopped
		// being the only way to state a scope without stating nothing.
		return refuse("the scope states no hosts, no path, no port and no protocol, so it can only be read as one that matches nothing; " +
			"omit the scope (or set allow_all) to apply everywhere, or state a host, a path prefix, a port or a scheme")
	}
	// The tools scope is checked for the one fault this package can see without knowing the tool
	// vocabulary: an empty name, which no request can ever carry. A near-miss against a real tool
	// name cannot be caught here and is caught at the wire instead (see MatchTools' doc for why
	// the comparison is exact rather than fuzzy).
	for _, tool := range rule.ScopeTools {
		if strings.TrimSpace(tool) == "" {
			return refuse("the tools scope names an empty tool, which no request can be attributed to; " +
				"remove the entry or name a tool")
		}
	}
	// Refused only when the rule actually runs a macro. `max_attempts` and the macro itself are
	// meaningless for a rule whose actions are "set a header" or "add the jar's cookies", and
	// demanding them anyway would make the two actions that need nothing else impossible to install
	// — the shape of refusal that teaches an operator to fill a login flow in to satisfy a form.
	runsMacro := rule.effectiveActionsRunMacro()
	if runsMacro && rule.MaxAttempts < 1 {
		return refuse("max_attempts must be at least 1, or the macro can never run; %d is the default",
			DefaultMaxAttempts)
	}
	if runsMacro && len(rule.Steps) == 0 {
		return refuse("an action runs a macro, but the rule's macro has no steps, so there is nothing to run")
	}
	// Checked before the per-step walk so an extraction pointing past the end of the macro is named
	// as such, rather than being skipped by extractionsFor and never mentioned again.
	for _, ex := range rule.Extractions {
		if ex == nil {
			return refuse("the rule holds an empty extraction slot; a rule's extractions must all name a value to lift")
		}
		if ex.Step < 0 || ex.Step >= len(rule.Steps) {
			return refuse("the extraction %q reads step %d, but the macro has %d step(s): nothing would ever run it",
				ex.Name, ex.Step, len(rule.Steps))
		}
	}

	// name -> index of the step that extracts it. Walked in step order so "earlier" means what it
	// says: a value is available to a step only if a strictly lower-indexed step produced it.
	definedBy := make(map[string]int)
	for index, step := range rule.Steps {
		if strings.TrimSpace(step.Method) == "" {
			return refuse("step %d has an empty method", index)
		}
		if hostOf(step.URL) == "" {
			return refuse("step %d has no host in its url %q; a macro step needs a full scheme://host[:port]/path",
				index, step.URL)
		}
		for _, name := range placeholderNames(step) {
			if _, ok := definedBy[name]; !ok {
				return refuse("step %d refers to {{%s}}, which no earlier step extracts", index, name)
			}
		}
		for _, ex := range rule.extractionsFor(index) {
			if !referableName(ex.Name) {
				return refuse("step %d extracts %q, a name no {{placeholder}} could refer to: "+
					"a name must be non-empty and carry no whitespace or braces", index, ex.Name)
			}
			switch ex.From {
			case "body", "header":
			default:
				return refuse("step %d extracts %q from %q, which is neither \"body\" nor \"header\"",
					index, ex.Name, ex.From)
			}
			// An extraction says how it works exactly once. Both stated would mean the behaviour depends
			// on which branch the runtime tests first, and neither stated is an extraction that can only
			// ever lift an empty value.
			if ex.Pattern != "" && ex.JSONPath != "" {
				return refuse("step %d extracts %q both by the pattern %q and by the json path %q; "+
					"an extraction can only work one way", index, ex.Name, ex.Pattern, ex.JSONPath)
			}
			if ex.Pattern == "" && ex.JSONPath == "" {
				return refuse("step %d extracts %q with neither a pattern nor a json path, which lifts an "+
					"empty value and leaves every {{%s}} unresolved on the wire", index, ex.Name, ex.Name)
			}
			if ex.JSONPath != "" {
				// The whole point of implementing a *subset* is that everything outside it is named here,
				// while the rule is being installed. A path this package cannot walk, accepted now and
				// resolving nothing at login time, would read to an operator as "the token was not in the
				// response" — a statement about the target, when the truth is a statement about this
				// scanner. See jsonpath.go for the supported grammar.
				if ex.Group != 0 {
					return refuse("step %d extracts %q by a json path and also names capture group %d; a "+
						"capture group is part of a regex and nothing here would use it", index, ex.Name, ex.Group)
				}
				if ex.From == "header" && strings.TrimSpace(ex.Header) == "" {
					return refuse("step %d extracts %q by a json path from a header without naming the header; "+
						"a regex extraction can use its pattern to select the header, a json path cannot", index, ex.Name)
				}
				if ex.path == nil {
					// The same two distinct faults the regex arm reports apart: a path outside the
					// supported subset is the operator's to fix and names what is unsupported, while a
					// path that parses but was never parsed *here* is a caller that skipped
					// NewJSONPathExtraction/Recompile.
					if _, err := parseJSONPath(ex.JSONPath); err != nil {
						return refuse("step %d extracts %q by an unsupported json path: %v", index, ex.Name, err)
					}
					return refuse("step %d extracts %q with an unparsed json path: build it with "+
						"NewJSONPathExtraction, or call Recompile after unmarshalling one, so what runs is what was validated",
						index, ex.Name)
				}
			} else {
				if ex.re == nil {
					// Two distinct faults, reported apart: a pattern that cannot compile is the
					// operator's to fix, while a pattern that compiles but was never compiled *here* is
					// a caller that built an Extraction by hand and skipped NewExtraction/Recompile —
					// leaving an extraction that runs and silently returns nothing.
					if _, err := regexp.Compile(ex.Pattern); err != nil {
						return refuse("step %d extracts %q with an unusable pattern %q: %v",
							index, ex.Name, ex.Pattern, err)
					}
					return refuse("step %d extracts %q with an uncompiled pattern: build it with "+
						"NewExtraction, or call Recompile after unmarshalling one, so what runs is what was validated",
						index, ex.Name)
				}
				if ex.Group < 0 {
					return refuse("step %d extracts %q from capture group %d; a group index cannot be negative",
						index, ex.Name, ex.Group)
				}
			}
			if from, clash := definedBy[ex.Name]; clash {
				return refuse("step %d extracts %q, which step %d already extracts: the later one would "+
					"silently win, so which value {{%s}} carries would depend on a step order nobody stated",
					index, ex.Name, from, ex.Name)
			}
			definedBy[ex.Name] = index
		}
	}
	// The action list last, so a fault in the macro is reported as a macro fault rather than as an
	// action that happens to run one.
	return rule.validateActions(refuse)
}

// validateActions checks the rule's ordered action list, including the two faults only an action
// list can have: a value naming a {{placeholder}} no action in the rule produces, and an action
// whose kind cannot be executed because nothing is attached to execute it with.
//
// The placeholder check is deliberately coarser than the per-step one above, and says so rather than
// pretending otherwise: a step walk can name *which* earlier step extracts a value, while an action
// graph with a conditional branch cannot say that a name is defined on every path without
// evaluating the rule. What it can say — and what catches the real mistake, a typo — is that nothing
// anywhere in the rule extracts the name at all. When that is true the placeholder reaches the wire
// verbatim, which is the failure the operator sees as "the target rejected a real attempt".
func (r *SessionRule) validateActions(refuse func(format string, args ...interface{}) error) error {
	actions := r.EffectiveActions()
	if err := ValidateActions(actions); err != nil {
		return refuse("%v", err)
	}
	produced := make(map[string]bool)
	for _, ex := range r.Extractions {
		if ex != nil {
			produced[ex.Name] = true
		}
	}
	collectActionMacroExtractions(r, actions, produced)
	for i, name := range actionPlaceholdersIn(actions) {
		if !produced[name] {
			return refuse("action %d's value refers to {{%s}}, which no action in this rule extracts: "+
				"the placeholder would go out on the wire verbatim", i+1, name)
		}
	}
	return nil
}

// collectActionMacroExtractions records every extraction name a macro in the list can produce.
//
// Names come from the rule's own extraction list, which is also what a macro *action* holding its
// own Macro falls back to for extractions (see runMacroOnce): an action that names its own steps
// still reads the rule's extractions, because Extraction carries the step index it belongs to and a
// per-action extraction list would need a second index space.
func collectActionMacroExtractions(rule *SessionRule, actions []*Action, into map[string]bool) {
	for _, ex := range rule.Extractions {
		if ex != nil {
			into[ex.Name] = true
		}
	}
	for _, a := range actions {
		if a == nil {
			continue
		}
		if a.Kind == ActionCheckValidity {
			collectActionMacroExtractions(rule, a.Then, into)
			collectActionMacroExtractions(rule, a.Else, into)
		}
	}
}

// actionPlaceholdersIn flattens every placeholder an action list refers to, keeping the position of
// the action that named it so a refusal can point at it.
func actionPlaceholdersIn(actions []*Action) []string {
	var out []string
	var walk func(list []*Action)
	walk = func(list []*Action) {
		for _, a := range list {
			out = append(out, actionPlaceholders(a)...)
			if a != nil && a.Kind == ActionCheckValidity {
				walk(a.Then)
				walk(a.Else)
			}
		}
	}
	walk(actions)
	return out
}

// effectiveActionsRunMacro reports whether any enabled action in this rule runs a macro, at any depth.
//
// Disabled actions do not count: an operator who turned "run a macro" off has said the rule no longer
// logs in, and refusing to save that rule for want of a macro it would not run is the opposite of
// what they asked for.
func (r *SessionRule) effectiveActionsRunMacro() bool {
	var walk func(list []*Action) bool
	walk = func(list []*Action) bool {
		for _, a := range list {
			if a == nil || !a.Enabled {
				continue
			}
			switch a.Kind {
			case ActionRunMacro, ActionRunPostRequestMacro:
				return true
			case ActionCheckValidity:
				if walk(a.Then) || walk(a.Else) {
					return true
				}
			}
		}
		return false
	}
	return walk(r.EffectiveActions())
}

// placeholderToken matches one {{name}} reference. Braces are excluded from the name so `{{{a}}}`
// yields `a` rather than swallowing a brace that a naive replacement could never reproduce.
var placeholderToken = regexp.MustCompile(`\{\{([^{}]*)\}\}`)

// placeholderNames returns every {{name}} a step refers to, deduplicated, in a stable order.
//
// Header keys are visited in sorted order rather than map order: with two undefined references in
// different headers, the error must name the same one on every run, or the same broken rule produces
// a different message each time it is submitted. Mirrors crates/session/src/extract.rs's
// `placeholders`, whose header list is already ordered.
func placeholderNames(step MacroStep) []string {
	var found []string
	seen := make(map[string]bool)
	scan := func(text string) {
		if !strings.Contains(text, "{{") {
			return
		}
		for _, m := range placeholderToken.FindAllStringSubmatch(text, -1) {
			name := m[1]
			// A token this package could never define is not reported as an undefined reference the
			// operator has no way to satisfy: referableName is the same predicate that decides what
			// an extraction may be called, so the two cannot disagree.
			if !referableName(name) || seen[name] {
				continue
			}
			seen[name] = true
			found = append(found, name)
		}
	}
	scan(step.URL)
	keys := make([]string, 0, len(step.Headers))
	for k := range step.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		scan(k)
		scan(step.Headers[k])
	}
	scan(step.Body)
	return found
}

// referableName says whether `name` can be written as {{name}} and found again by the naive
// string replacement resolveStep performs. One predicate for both directions — what an extraction may
// be called and what counts as a reference — so the two can never disagree about whether a token is
// satisfiable. Mirrors crates/session/src/extract.rs's is_referable.
func referableName(name string) bool {
	if name == "" || strings.ContainsAny(name, "{}") {
		return false
	}
	return strings.IndexFunc(name, unicode.IsSpace) < 0
}
