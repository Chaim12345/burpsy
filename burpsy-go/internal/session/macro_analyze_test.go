package session

// Automatic macro parameter analysis (burpsy-react-ui-e23c). These tests hold the analyzer to
// the contract Burp's own docs state — "identifying parameters whose values can be determined
// from the preceding response ... form field values, redirection targets, or query strings in
// links" — and to the honesty rules that make a suggestion checkable:
//
//   - the three source classes are found where they really are, with the value the response
//     actually carried, so the operator can see the relationship is real before applying it;
//   - a skipped step (no response) contributes nothing — analysis over a step that never ran
//     would hallucinate;
//   - a name the rule already extracts is not re-suggested;
//   - each suggestion's pattern actually lifts the value on the next run — tested by compiling
//     the pattern and running it against the same body, which is the property the whole
//     feature exists for: apply a suggestion and the {{name}} marker resolves.
import (
	"regexp"
	"testing"
)

// analysisFixture builds a report with one live step carrying a login page's shape.
func analysisFixture() MacroRunReport {
	return MacroRunReport{
		Steps: []MacroStepReport{{
			Index: 0,
			Response: &StepResult{
				Status:  200,
				Headers: map[string]string{},
				Body: []byte(`<html><body>
<form action="/login" method="post">
<input type="text" name="username" value="admin">
<input type="hidden" name="csrf_token" value="tok-abc123">
<input name="nonce" type="hidden" value="n-42">
</form>
<a href="/next?session=xyz&mode=fast">continue</a>
</body></html>`),
				FinalURL: "http://app.test/login",
			},
			SetCookies: []string{"sess=abc123; Path=/; HttpOnly", "csrf=deadbeef; Path=/"},
		}},
	}
}

func analyzeFixtureRule() *SessionRule {
	return &SessionRule{Name: "login"}
}

func TestAnalysisFindsHiddenFormFieldsWithTheValueItCarries(t *testing.T) {
	suggestions := AnalyzeMacro(analyzeFixtureRule(), analysisFixture())
	var csrf, nonce *ExtractionSuggestion
	for i := range suggestions {
		switch suggestions[i].Name {
		case "csrf_token":
			csrf = &suggestions[i]
		case "nonce":
			nonce = &suggestions[i]
		}
	}
	if csrf == nil {
		t.Fatal("no suggestion for the hidden csrf_token field — the classic cross-step value this feature exists for")
	}
	if csrf.Value != "tok-abc123" || csrf.Source != "hidden form field" || csrf.Step != 0 || csrf.From != "body" {
		t.Errorf("csrf suggestion = %+v, want the hidden field's own value, source and step", csrf)
	}
	if nonce == nil {
		t.Fatal("no suggestion for the hidden nonce field with attributes in the other order — attribute order is not a contract")
	}
	if nonce.Value != "n-42" {
		t.Errorf("nonce suggestion value = %q, want n-42", nonce.Value)
	}
}

func TestAnalysisDoesNotSuggestVisibleFormFields(t *testing.T) {
	suggestions := AnalyzeMacro(analyzeFixtureRule(), analysisFixture())
	for _, s := range suggestions {
		if s.Name == "username" {
			t.Errorf("suggested the visible username field: %q — a visible field's value is the operator's to type, not the response's to determine", s.Name)
		}
	}
}

func TestAnalysisFindsSetCookiesAndQueryStringsInLinks(t *testing.T) {
	suggestions := AnalyzeMacro(analyzeFixtureRule(), analysisFixture())
	var sess, linkSession *ExtractionSuggestion
	for i := range suggestions {
		switch suggestions[i].Name {
		case "sess":
			sess = &suggestions[i]
		case "session":
			linkSession = &suggestions[i]
		}
	}
	if sess == nil {
		t.Fatal("no suggestion for the Set-Cookie sess — a response that mints a value names it")
	}
	if sess.From != "header" || sess.Header != "Set-Cookie" || sess.Source != "set-cookie" || sess.Value != "abc123" {
		t.Errorf("sess suggestion = %+v, want a Set-Cookie header extraction carrying the minted value", sess)
	}
	if linkSession == nil {
		t.Fatal("no suggestion for the session parameter in the link's query string")
	}
	if linkSession.Source != "query in link" || linkSession.Value != "xyz" {
		t.Errorf("link session suggestion = %+v, want the query-in-link source and its value", linkSession)
	}
}

func TestAnalysisSkipsAStepThatNeverRan(t *testing.T) {
	report := MacroRunReport{
		Steps: []MacroStepReport{{
			Index:   0,
			Skipped: "out of scope",
			// No Response: a skipped step has nothing to read.
		}},
	}
	if got := AnalyzeMacro(analyzeFixtureRule(), report); len(got) != 0 {
		t.Errorf("suggestions over a skipped step = %v — analysis without a response hallucinates", got)
	}
}

func TestAnalysisDoesNotReSuggestANameTheRuleAlreadyExtracts(t *testing.T) {
	rule := analyzeFixtureRule()
	rule.Extractions = []*Extraction{{Name: "csrf_token", From: "body", Pattern: "already-wired", Group: 1}}
	suggestions := AnalyzeMacro(rule, analysisFixture())
	for _, s := range suggestions {
		if s.Name == "csrf_token" {
			t.Errorf("re-suggested csrf_token, which the rule already extracts — the operator wired that one")
		}
	}
}

// The load-bearing property: every suggestion's pattern compiles and lifts its value from the
// body it was found in, so Apply really wires a working extraction rather than a plausible one.
func TestEverySuggestedPatternActuallyLiftsTheValue(t *testing.T) {
	report := analysisFixture()
	suggestions := AnalyzeMacro(analyzeFixtureRule(), report)
	if len(suggestions) == 0 {
		t.Fatal("fixture produced no suggestions")
	}
	for _, s := range suggestions {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			t.Errorf("suggestion %q pattern %q does not compile: %v", s.Name, s.Pattern, err)
			continue
		}
		if s.From == "header" {
			continue // header suggestions read the Set-Cookie header, not the body
		}
		step := report.Steps[s.Step]
		if step.Response == nil {
			continue
		}
		m := re.FindStringSubmatch(string(step.Response.Body))
		if m == nil {
			t.Errorf("suggestion %q pattern %q does not match the body it was derived from", s.Name, s.Pattern)
			continue
		}
		if m[s.Group] != s.Value {
			t.Errorf("suggestion %q lifted %q, want %q — the applied extraction would resolve to the wrong thing", s.Name, m[s.Group], s.Value)
		}
	}
}
