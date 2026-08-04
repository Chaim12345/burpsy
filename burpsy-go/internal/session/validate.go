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

func validateRule(rule *SessionRule, scopeStated bool) error {
	if rule == nil {
		return &RuleError{Rule: "<unnamed>", Message: "there is no rule to install"}
	}
	label := strings.TrimSpace(rule.Name)
	if label == "" {
		label = "<unnamed>"
	}
	refuse := func(format string, args ...interface{}) error {
		return &RuleError{Rule: label, Message: fmt.Sprintf(format, args...)}
	}

	if strings.TrimSpace(rule.Name) == "" {
		return refuse("a rule needs a name: every outcome and error this package reports names its rule")
	}
	if scopeStated && len(rule.ScopeHosts) == 0 {
		return refuse("the scope has no hosts, so it matches nothing and this rule would never fire; " +
			"omit the scope (or set allow_all) to apply everywhere")
	}
	if rule.MaxAttempts < 1 {
		return refuse("max_attempts must be at least 1, or the macro can never run; %d is the default",
			DefaultMaxAttempts)
	}
	if len(rule.Steps) == 0 {
		return refuse("the login macro has no steps, so there is nothing to run")
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
			if ex.Pattern == "" {
				return refuse("step %d extracts %q with an empty pattern, which lifts an empty value "+
					"and leaves every {{%s}} unresolved on the wire", index, ex.Name, ex.Name)
			}
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
			if from, clash := definedBy[ex.Name]; clash {
				return refuse("step %d extracts %q, which step %d already extracts: the later one would "+
					"silently win, so which value {{%s}} carries would depend on a step order nobody stated",
					index, ex.Name, from, ex.Name)
			}
			definedBy[ex.Name] = index
		}
	}
	return nil
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
