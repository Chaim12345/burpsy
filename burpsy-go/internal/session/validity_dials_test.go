package session

import (
	"testing"
)

// Burp's validity search offers a literal-or-regex choice, case sensitivity, and can inspect
// "the URL of any redirection target" (session-handling-rules.html, burpsy-react-ui-9prk).
// burpsy's ValidityRule gains Regex + CaseSensitive over the body clauses and URLContains over
// the redirect target the macro runner resolves.

// Literal matching keeps its old behaviour: substring, case-folded unless told otherwise.
func TestLiteralBodyMatchingIsCaseFoldedByDefault(t *testing.T) {
	rule := &ValidityRule{BodyContains: "WELCOME"}
	if got := rule.Evaluate(200, nil, []byte("welcome back"), ""); got != Valid {
		t.Errorf("case-folded literal = %d, want Valid — WELCOME matched welcome back", got)
	}
	rule.CaseSensitive = true
	if got := rule.Evaluate(200, nil, []byte("welcome back"), ""); got != Invalid {
		t.Errorf("case-sensitive literal = %d, want Invalid — WELCOME is not in 'welcome back' byte for byte", got)
	}
	if got := rule.Evaluate(200, nil, []byte("WELCOME back"), ""); got != Valid {
		t.Errorf("case-sensitive literal on an exact-case body = %d, want Valid", got)
	}
}

// The regex dial: BodyContains becomes a pattern, case-folded unless the pattern carries its
// own flag or CaseSensitive is set.
func TestRegexDialMakesBodyContainsAPattern(t *testing.T) {
	rule := &ValidityRule{Regex: true, BodyContains: `token=[a-f0-9]{8}`}
	if got := rule.Evaluate(200, nil, []byte("set: token=deadbeef here"), ""); got != Valid {
		t.Errorf("regex body = %d, want Valid", got)
	}
	if got := rule.Evaluate(200, nil, []byte("set: token=XYZ here"), ""); got != Invalid {
		t.Errorf("regex body on a non-matching value = %d, want Invalid", got)
	}
	// Case folding applies to regexes too until the operator opts out.
	folded := &ValidityRule{Regex: true, BodyContains: "logged-in"}
	if got := folded.Evaluate(200, nil, []byte("LOGGED-IN as user"), ""); got != Valid {
		t.Errorf("case-folded regex = %d, want Valid", got)
	}
	folded.CaseSensitive = true
	if got := folded.Evaluate(200, nil, []byte("LOGGED-IN as user"), ""); got != Invalid {
		t.Errorf("case-sensitive regex = %d, want Invalid — the dial must reach regexes, not only literals", got)
	}
	// A pattern that carries its own flag is not double-folded: the operator's (?s) must stay.
	dotall := &ValidityRule{Regex: true, BodyContains: `(?s)START.*END`}
	if got := dotall.Evaluate(200, nil, []byte("START\nmiddle\nEND"), ""); got != Valid {
		t.Errorf("inline-flag regex = %d, want Valid — (?s) must survive the case-folding prefix logic", got)
	}
}

// An uncompilable regex never matches rather than panicking: Evaluate is configuration
// executed inside the login check.
func TestAnUncompilableRegexReportsNoMatch(t *testing.T) {
	rule := &ValidityRule{Regex: true, BodyContains: "([bad"}
	if got := rule.Evaluate(200, nil, []byte("anything"), ""); got != Invalid {
		t.Errorf("uncompilable regex = %d, want Invalid (no match) — not a panic", got)
	}
}

// BodyNotContains runs under the same dials.
func TestBodyNotContainsHonoursTheDials(t *testing.T) {
	rule := &ValidityRule{Regex: true, BodyNotContains: `login.*required`}
	if got := rule.Evaluate(200, nil, []byte("LOGIN REQUIRED page"), ""); got != Invalid {
		t.Errorf("regex not-contains = %d, want Invalid — the folded pattern matched", got)
	}
	if got := rule.Evaluate(200, nil, []byte("welcome"), ""); got != Valid {
		t.Errorf("regex not-contains on a clean body = %d, want Valid", got)
	}
}

// URLContains matches the redirect target the runner resolved: literal by default, regex or
// case-sensitive under the same dials.
func TestURLContainsMatchesTheRedirectTarget(t *testing.T) {
	rule := &ValidityRule{URLContains: "/dashboard"}
	if got := rule.Evaluate(302, nil, nil, "https://app.test/dashboard"); got != Valid {
		t.Errorf("redirect target match = %d, want Valid", got)
	}
	if got := rule.Evaluate(302, nil, nil, "https://app.test/login"); got != Invalid {
		t.Errorf("redirect target miss = %d, want Invalid", got)
	}
	// Regex over the target: the canonical "we were sent to a lockout page" check.
	re := &ValidityRule{Regex: true, URLContains: `error=\d{3}$`}
	if got := re.Evaluate(302, nil, nil, "https://app.test/blocked?error=423"); got != Valid {
		t.Errorf("regex redirect target = %d, want Valid", got)
	}
	// Case-sensitive dial reaches the URL clause.
	cs := &ValidityRule{URLContains: "DASHBOARD", CaseSensitive: true}
	if got := cs.Evaluate(302, nil, nil, "https://app.test/dashboard"); got != Invalid {
		t.Errorf("case-sensitive URL = %d, want Invalid", got)
	}
}

// A response that did not redirect has no target: the clause is unmeasured, not failed —
// the same treatment a missing status gets.
func TestURLContainsWithNoRedirectIsIndeterminate(t *testing.T) {
	rule := &ValidityRule{URLContains: "/dashboard"}
	if got := rule.Evaluate(200, nil, []byte("ok"), ""); got != Indeterminate {
		t.Errorf("no-redirect URL clause = %d, want Indeterminate — a page that did not redirect is not evidence about a target", got)
	}
	// Combined with a satisfied clause, the whole rule is Indeterminate: precedence follows
	// All{} — a definite Invalid wins, an unmeasured clause softens a Valid.
	combined := &ValidityRule{StatusIs: new(200), URLContains: "/dashboard"}
	if got := combined.Evaluate(200, nil, nil, ""); got != Indeterminate {
		t.Errorf("status + unmeasured URL = %d, want Indeterminate", got)
	}
	if got := combined.Evaluate(200, nil, nil, "https://app.test/dashboard"); got != Valid {
		t.Errorf("status + measured URL = %d, want Valid", got)
	}
	if got := combined.Evaluate(500, nil, nil, "https://app.test/dashboard"); got != Invalid {
		t.Errorf("failing status + measured URL = %d, want Invalid — a definite Invalid outranks", got)
	}
}

// The composition operators pass the target through: a URL clause inside All/Any/Not is
// evaluated against the same response the parent saw.
func TestURLClauseComposesThroughAllAnyNot(t *testing.T) {
	inAll := &ValidityRule{All: []*ValidityRule{
		{StatusIs: new(302)},
		{URLContains: "/dashboard"},
	}}
	if got := inAll.Evaluate(302, nil, nil, "https://app.test/dashboard"); got != Valid {
		t.Errorf("URL clause inside All{} = %d, want Valid", got)
	}
	inNot := &ValidityRule{Not: &ValidityRule{URLContains: "/locked"}}
	if got := inNot.Evaluate(302, nil, nil, "https://app.test/dashboard"); got != Valid {
		t.Errorf("URL clause inside Not{} on a clean target = %d, want Valid", got)
	}
	if got := inNot.Evaluate(302, nil, nil, "https://app.test/locked"); got != Invalid {
		t.Errorf("URL clause inside Not{} on a locked target = %d, want Invalid", got)
	}
}
