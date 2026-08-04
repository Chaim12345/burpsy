package session

import (
	"strings"
	"testing"
)

// The path a login flow actually needs resolves a real token out of a real body.
func TestJSONPathExtractionResolvesATokenFromABody(t *testing.T) {
	body := []byte(`{"ok":true,"data":{"token":"eyJhbGciOiJIUzI1NiJ9.abc","expires":3600},
		"items":[{"id":9007199254740993},{"id":2}],"empty":"","nothing":null}`)

	for _, tc := range []struct {
		path string
		want string
		why  string
	}{
		{"data.token", "eyJhbGciOiJIUzI1NiJ9.abc", "a dotted path is the shape a login flow uses"},
		{"$.data.token", "eyJhbGciOiJIUzI1NiJ9.abc", "a leading $ is how a path is conventionally written"},
		{"data.expires", "3600", "a number is lifted as text"},
		{"ok", "true", "a boolean is lifted as text"},
		{"items[0].id", "9007199254740993", "an id beyond float64's exact range keeps every digit"},
		{"items[1].id", "2", "an array index selects the element"},
		{"$[0]", "", "a top-level index needs an array, and this document is an object"},
	} {
		ex, err := NewJSONPathExtraction("v", "body", tc.path)
		if err != nil {
			t.Fatalf("%s: NewJSONPathExtraction(%q): %v", tc.why, tc.path, err)
		}
		res := ex.RunResult(nil, body)
		if tc.want == "" {
			// The one negative row above: it must not resolve, and must not be reported as an empty value.
			if res.Outcome.Resolved() {
				t.Errorf("%q resolved to %q against an object; want a refusal to resolve", tc.path, res.Value)
			}
			continue
		}
		if !res.Outcome.Resolved() || res.Value != tc.want {
			t.Errorf("%q gave %+v, want %q (%s)", tc.path, res, tc.want, tc.why)
		}
	}
}

// An empty value that *is* there is a resolved value. This is the baseline every other outcome below
// has to be distinguishable from.
func TestJSONPathAnEmptyValueIsAResolvedValue(t *testing.T) {
	ex, err := NewJSONPathExtraction("v", "body", "empty")
	if err != nil {
		t.Fatalf("NewJSONPathExtraction: %v", err)
	}
	res := ex.RunResult(nil, []byte(`{"empty":""}`))
	if res.Outcome != ExtractResolved {
		t.Fatalf("outcome is %s, want resolved: the key is present and its value is the empty string", res.Outcome)
	}
	if res.Value != "" {
		t.Fatalf("value is %q, want the empty string", res.Value)
	}
}

// The four ways a json-path extraction can fail to produce a value are each distinguishable from an
// empty value and from each other. Collapsing them into "" is the defect: an operator would read "the
// token was not in the response" for a body that was not JSON at all.
func TestJSONPathFailuresAreDistinguishable(t *testing.T) {
	for _, tc := range []struct {
		name        string
		path        string
		body        string
		want        ExtractOutcome
		detailNames string
	}{
		{
			name:        "a path that does not resolve",
			path:        "data.token",
			body:        `{"data":{"other":"x"}}`,
			want:        ExtractNoValue,
			detailNames: `no key "token"`,
		},
		{
			name:        "an index past the end",
			path:        "items[3].id",
			body:        `{"items":[{"id":1}]}`,
			want:        ExtractNoValue,
			detailNames: "element(s)",
		},
		{
			name:        "a hop into the wrong kind of container",
			path:        "data[0]",
			body:        `{"data":{"a":1}}`,
			want:        ExtractNoValue,
			detailNames: "an object",
		},
		{
			name:        "a body that is not JSON",
			path:        "data.token",
			body:        "<html><body>gateway timeout</body></html>",
			want:        ExtractSourceNotJSON,
			detailNames: "",
		},
		{
			name:        "a truncated body",
			path:        "data.token",
			body:        `{"data":{"token":"abc`,
			want:        ExtractSourceNotJSON,
			detailNames: "",
		},
		{
			name:        "a path that lands on a container",
			path:        "data",
			body:        `{"data":{"token":"abc"}}`,
			want:        ExtractNotAScalar,
			detailNames: "an object",
		},
		{
			name:        "a null value",
			path:        "data.token",
			body:        `{"data":{"token":null}}`,
			want:        ExtractNullValue,
			detailNames: "null",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex, err := NewJSONPathExtraction("v", "body", tc.path)
			if err != nil {
				t.Fatalf("NewJSONPathExtraction(%q): %v", tc.path, err)
			}
			res := ex.RunResult(nil, []byte(tc.body))
			if res.Outcome != tc.want {
				t.Fatalf("outcome is %s (%q), want %s", res.Outcome, res.Detail, tc.want)
			}
			if res.Outcome == ExtractResolved {
				t.Fatal("a failure was reported as a resolved value")
			}
			if res.Detail == "" {
				t.Error("the failure carries no detail, so nothing says what went wrong")
			}
			if tc.detailNames != "" && !strings.Contains(res.Detail, tc.detailNames) {
				t.Errorf("detail %q does not name %q, so it cannot be acted on", res.Detail, tc.detailNames)
			}
			// The property that actually matters: none of these is the empty value an operator would read
			// as "the server sent an empty token".
			if res.Value != "" {
				t.Errorf("a failure carried the value %q", res.Value)
			}
		})
	}
}

// Every path shape outside the documented subset is refused when the rule is built — naming the
// construct — rather than at login time, where it would look like the value was missing from the
// response.
func TestUnsupportedJSONPathsAreRefusedAtConfigurationTime(t *testing.T) {
	for _, tc := range []struct{ path, names string }{
		{"a..b", "recursive descent"},
		{"..token", "recursive descent"},
		{"data.*", "wildcard"},
		{"items[*].id", "wildcard"},
		{"items[1:3]", "array slice"},
		{"items[?(@.id==1)]", "filter expression"},
		{"data['a.b']", "quoted key"},
		{"items[-1]", "negative index"},
		{"items[x]", "not an index"},
		{"items[0", "never closes"},
		{"data.", "ends with a dot"},
		{".data", "empty key"},
		{"", "empty"},
		{"$", "whole document"},
		{"data token", "whitespace"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			_, err := NewJSONPathExtraction("v", "body", tc.path)
			if err == nil {
				t.Fatalf("%q was accepted; an unsupported path must be refused while the rule is being saved, "+
					"not resolve nothing at login time", tc.path)
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("refusing %q said %q, which does not name %q — an operator cannot act on it",
					tc.path, err, tc.names)
			}
		})
	}
}

// The refusal also fires through rule validation, which is the path a hand-built or restored rule
// takes. Nothing may install a rule whose extraction cannot run.
func TestValidateRuleRefusesAnUnsupportedJSONPath(t *testing.T) {
	rule := NewSessionRule("r", nil, []MacroStep{{Method: "GET", URL: "https://app.test/token"}})
	// Built by hand rather than through the constructor, exactly as a caller assembling a DTO or a
	// restore that skipped Recompile would leave it.
	rule.Extractions = []*Extraction{{Name: "tok", From: "body", JSONPath: "data..token"}}

	err := ValidateRule(rule)
	if err == nil {
		t.Fatal("a rule carrying an unsupported json path validated")
	}
	if !strings.Contains(err.Error(), "recursive descent") {
		t.Fatalf("the refusal is %q; it must name the unsupported construct", err)
	}
}

// A json path that parses but was never parsed *here* is its own refusal, distinct from an unsupported
// one: the first is the operator's mistake, the second is a caller that skipped the constructor and
// would otherwise ship an extraction that runs and lifts nothing.
func TestValidateRuleRefusesAnUnparsedJSONPath(t *testing.T) {
	rule := NewSessionRule("r", nil, []MacroStep{{Method: "GET", URL: "https://app.test/token"}})
	rule.Extractions = []*Extraction{{Name: "tok", From: "body", JSONPath: "data.token"}}

	err := ValidateRule(rule)
	if err == nil {
		t.Fatal("a rule with an unparsed json path validated; it would run and lift nothing")
	}
	if !strings.Contains(err.Error(), "unparsed json path") {
		t.Fatalf("the refusal is %q; it must say the path was never parsed, not that it is unsupported", err)
	}
	if strings.Contains(err.Error(), "recursive descent") {
		t.Fatalf("the refusal is %q; a supportable path must not be reported as unsupported", err)
	}
}

// An extraction says how it works exactly once.
func TestValidateRuleRefusesBothAPatternAndAJSONPath(t *testing.T) {
	rule := NewSessionRule("r", nil, []MacroStep{{Method: "GET", URL: "https://app.test/token"}})
	ex, err := NewExtraction("tok", "body", `"token":"([^"]+)"`, 1)
	if err != nil {
		t.Fatalf("NewExtraction: %v", err)
	}
	ex.JSONPath = "data.token"
	rule.Extractions = []*Extraction{ex}

	if err := ValidateRule(rule); err == nil {
		t.Fatal("an extraction stating both a pattern and a json path validated; which one ran would " +
			"depend on the order the runtime tests them in")
	}
	// Recompile has to refuse it too: that is the door a restore comes through.
	if err := ex.Recompile(); err == nil {
		t.Fatal("Recompile accepted an extraction stating both a pattern and a json path")
	}
}

// A json path over a header has to name the header. A regex extraction can use its pattern to select
// one; a path cannot, so the nameless form is refused rather than silently reading nothing.
func TestValidateRuleRefusesAJSONPathHeaderWithNoName(t *testing.T) {
	rule := NewSessionRule("r", nil, []MacroStep{{Method: "GET", URL: "https://app.test/token"}})
	ex, err := NewJSONPathExtraction("tok", "header", "data.token")
	if err != nil {
		t.Fatalf("NewJSONPathExtraction: %v", err)
	}
	rule.Extractions = []*Extraction{ex}

	err = ValidateRule(rule)
	if err == nil {
		t.Fatal("a json-path extraction from an unnamed header validated")
	}
	if !strings.Contains(err.Error(), "without naming the header") {
		t.Fatalf("the refusal is %q; it must say the header was not named", err)
	}

	// Named, it validates and works — including saying so when the header is absent.
	ex.Header = "X-Session"
	if err := ValidateRule(rule); err != nil {
		t.Fatalf("a named json-path header extraction was refused: %v", err)
	}
	got := ex.RunResult(map[string]string{"X-Session": `{"data":{"token":"h-tok"}}`}, nil)
	if !got.Outcome.Resolved() || got.Value != "h-tok" {
		t.Fatalf("reading the named header gave %+v, want the token", got)
	}
	missing := ex.RunResult(map[string]string{"Content-Type": "application/json"}, nil)
	if missing.Outcome != ExtractNoSuchHeader {
		t.Fatalf("a missing header reported %s; it must be distinguishable from a header that is present "+
			"and carries nothing useful", missing.Outcome)
	}
}

// A capture group means nothing for a json path, so stating one is a refusal rather than a field that
// is silently ignored.
func TestValidateRuleRefusesAGroupOnAJSONPath(t *testing.T) {
	rule := NewSessionRule("r", nil, []MacroStep{{Method: "GET", URL: "https://app.test/token"}})
	ex, err := NewJSONPathExtraction("tok", "body", "data.token")
	if err != nil {
		t.Fatalf("NewJSONPathExtraction: %v", err)
	}
	ex.Group = 1
	rule.Extractions = []*Extraction{ex}

	if err := ValidateRule(rule); err == nil {
		t.Fatal("a json-path extraction naming capture group 1 validated; nothing would use it")
	}
}

// The regex arm keeps its outcomes too: a pattern that does not match, and a header that is not there,
// are both distinguishable from an empty value.
func TestRegexExtractionOutcomesStayDistinguishable(t *testing.T) {
	ex, err := NewExtraction("tok", "body", `"token":"([^"]*)"`, 1)
	if err != nil {
		t.Fatalf("NewExtraction: %v", err)
	}
	empty := ex.RunResult(nil, []byte(`{"token":""}`))
	if empty.Outcome != ExtractResolved || empty.Value != "" {
		t.Fatalf("a matched empty capture gave %+v, want a resolved empty value", empty)
	}
	absent := ex.RunResult(nil, []byte(`{"other":"x"}`))
	if absent.Outcome != ExtractNoValue {
		t.Fatalf("an unmatched pattern gave %s, want no-value", absent.Outcome)
	}
	if absent.Value != "" || absent.Detail == "" {
		t.Fatalf("an unmatched pattern gave %+v, want no value and a reason", absent)
	}

	hdr, err := NewExtraction("tok", "header", `(.+)`, 1)
	if err != nil {
		t.Fatalf("NewExtraction: %v", err)
	}
	hdr.Header = "X-Token"
	if got := hdr.RunResult(map[string]string{"X-Other": "v"}, nil); got.Outcome != ExtractNoSuchHeader {
		t.Fatalf("a missing header gave %s, want no-such-header", got.Outcome)
	}
}

// Every outcome has a name and a line an operator can act on, and the set is enumerable — the same
// property scanner.ScanSkipAll carries, for the same reason: a caller must be able to render a legend
// without hard-coding the set, and an outcome added later must not read as "unknown".
func TestExtractOutcomesAreAllNamed(t *testing.T) {
	seen := map[string]bool{}
	for _, o := range ExtractOutcomeAll {
		if o.String() == "unknown" {
			t.Errorf("outcome %d has no name", int(o))
		}
		if o.Explanation() == "unknown outcome" {
			t.Errorf("outcome %s has no explanation", o)
		}
		if seen[o.String()] {
			t.Errorf("two outcomes are both called %q", o.String())
		}
		seen[o.String()] = true
	}
	if len(seen) != len(ExtractOutcomeAll) {
		t.Fatalf("%d names for %d outcomes", len(seen), len(ExtractOutcomeAll))
	}
	if !ExtractResolved.Resolved() {
		t.Error("ExtractResolved does not report itself as resolved")
	}
	for _, o := range ExtractOutcomeAll {
		if o != ExtractResolved && o.Resolved() {
			t.Errorf("%s reports itself as resolved", o)
		}
	}
}

// A macro threads a json-path value into the next step, which is the whole point of implementing this
// at all: the token lifted from step 1's JSON reaches step 2's header.
func TestMacroThreadsAJSONPathValueIntoALaterStep(t *testing.T) {
	c := NewCoordinator(nil)
	rule := NewSessionRule("token login", nil, []MacroStep{
		{Method: "POST", URL: "https://app.test/token"},
		{Method: "GET", URL: "https://app.test/me", Headers: map[string]string{"Authorization": "Bearer {{tok}}"}},
	})
	ex, err := NewJSONPathExtraction("tok", "body", "data.token")
	if err != nil {
		t.Fatalf("NewJSONPathExtraction: %v", err)
	}
	rule.Extractions = []*Extraction{ex}
	if err := ValidateRule(rule); err != nil {
		t.Fatalf("the rule does not validate: %v", err)
	}

	var sent []MacroStep
	_, _, _ = c.RunMacro(rule, func(step MacroStep) (*StepResult, error) {
		sent = append(sent, step)
		if strings.HasSuffix(step.URL, "/token") {
			return &StepResult{Status: 200, Body: []byte(`{"data":{"token":"tok-42"}}`)}, nil
		}
		return &StepResult{Status: 200, Body: []byte("ok")}, nil
	})

	if len(sent) != 2 {
		t.Fatalf("sent %d steps, want 2", len(sent))
	}
	if got := sent[1].Headers["Authorization"]; got != "Bearer tok-42" {
		t.Fatalf("step 2 carried %q; the json-path value never reached it", got)
	}
}
