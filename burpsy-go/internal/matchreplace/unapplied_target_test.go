package matchreplace

import (
	"bytes"
	"testing"
)

// ---- the param targets now have real appliers -----------------------------------------
//
// These two targets were refused for months because applyOne's default was
// `return applyBody(r, raw)` — a parameter rule executed as a whole-body substring
// rewrite, renaming unrelated parameters. The appliers (applyParamName /
// applyParamValue) rewrite only the addressed half of each query-string pair, so
// these tests pin the field boundary the whole defect was about.

// The request shape the proxy actually hands Apply: request line, headers, body.
const paramRequest = "GET /pay?user=admin&secret=hunter2&nonsecret=keep HTTP/1.1\r\n" +
	"Host: shop.test\r\n" +
	"\r\n"

// The exact collision that proved the original defect: renaming one parameter must
// not rename an unrelated one whose name merely contains the match string.
func TestAParamNameRuleRewritesOnlyTheAddressedPair(t *testing.T) {
	rule, err := NewRule(TargetRequestParamName, CategoryLiteral, "secret", "harmless", "")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	rs := NewRuleSet()
	rs.SetRules([]*Rule{rule})

	got := string(rs.Apply(DirRequest, []byte(paramRequest)))

	// `nonsecret` contains `secret`, but it is a different pair and stays untouched.
	const want = "GET /pay?user=admin&harmless=hunter2&nonsecret=keep HTTP/1.1\r\n" +
		"Host: shop.test\r\n" +
		"\r\n"
	if got != want {
		t.Fatalf("param-name rewrite =\n  %q\nwant\n  %q", got, want)
	}
}

func TestAParamValueRuleRewritesOnlyValuesAndNeverSpillsIntoTheNextPair(t *testing.T) {
	rule, err := NewRule(TargetRequestParamValue, CategoryLiteral, "hunter2", "X", "")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	rs := NewRuleSet()
	rs.SetRules([]*Rule{rule})

	got := string(rs.Apply(DirRequest, []byte(paramRequest)))

	const want = "GET /pay?user=admin&secret=X&nonsecret=keep HTTP/1.1\r\n" +
		"Host: shop.test\r\n" +
		"\r\n"
	if got != want {
		t.Fatalf("param-value rewrite =\n  %q\nwant\n  %q", got, want)
	}
}

// A value rule must not rewrite the name half: `secret` appears in both halves of
// `secret=hunter2`, and only the value is the value rule's addressable unit.
func TestAParamValueRuleLeavesNamesAlone(t *testing.T) {
	rule, err := NewRule(TargetRequestParamValue, CategoryLiteral, "secret", "X", "")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	rs := NewRuleSet()
	rs.SetRules([]*Rule{rule})

	got := string(rs.Apply(DirRequest, []byte(paramRequest)))
	if bytes.Contains([]byte(got), []byte("X=admin")) {
		t.Fatalf("value rule rewrote a parameter name: %q", got)
	}
	if !bytes.Contains([]byte(got), []byte("secret=hunter2")) {
		t.Fatalf("value rule altered the wrong pair: %q", got)
	}
}

// A bare name pair (`?flag`) has no `=`: a name rule may rewrite it, a value rule
// has nothing to address.
func TestBareNamePairsAreAddressableByNameOnly(t *testing.T) {
	const req = "GET /f?flag&secret=hunter2 HTTP/1.1\r\nHost: shop.test\r\n\r\n"

	nameRule, err := NewRule(TargetRequestParamName, CategoryLiteral, "flag", "enabled", "")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	got := string(NewRuleSet().with(ruleSetOf(nameRule)).Apply(DirRequest, []byte(req)))
	if !bytes.Contains([]byte(got), []byte("enabled&secret=hunter2")) {
		t.Fatalf("bare name not rewritten by a name rule: %q", got)
	}

	valueRule, err := NewRule(TargetRequestParamValue, CategoryLiteral, "flag", "enabled", "")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	got = string(NewRuleSet().with(ruleSetOf(valueRule)).Apply(DirRequest, []byte(req)))
	if got != req {
		t.Fatalf("bare name rewritten by a value rule: %q", got)
	}
}

// The query string ends at the first space in the request line (HTTP/1.x is
// METHOD SP TARGET SP VERSION); bytes after it are the version, not parameters.
func TestTheQueryEndsAtTheRequestLineSpace(t *testing.T) {
	const req = "GET /p?a=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	rule, err := NewRule(TargetRequestParamValue, CategoryLiteral, "1", "2", "")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	got := string(NewRuleSet().with(ruleSetOf(rule)).Apply(DirRequest, []byte(req)))
	const want = "GET /p?a=2 HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	if got != want {
		t.Fatalf("version tail mangled:\n  got  %q\n  want %q", got, want)
	}
}

// A request with no query string has nothing to address: no rule fires, no copy.
func TestARequestWithoutAQueryIsUntouchedByParamRules(t *testing.T) {
	const req = "GET /plain HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	for _, target := range []Target{TargetRequestParamName, TargetRequestParamValue} {
		rule, err := NewRule(target, CategoryLiteral, "plain", "X", "")
		if err != nil {
			t.Fatalf("NewRule(%d): %v", int(target), err)
		}
		got := NewRuleSet().with(ruleSetOf(rule)).Apply(DirRequest, []byte(req))
		if !bytes.Equal(got, []byte(req)) {
			t.Errorf("target %d rewrote a query-less request: %q", int(target), got)
		}
	}
}

// The five pre-existing targets still behave; the param work must not have
// disturbed them.
func TestTheImplementedTargetsStillApply(t *testing.T) {
	req := []byte("POST /submit?a=1 HTTP/1.1\r\n" +
		"Host: shop.test\r\n" +
		"X-Trace: trace-me\r\n" +
		"Content-Length: 7\r\n" +
		"\r\n" +
		"REQ-IN=X")

	cases := []struct {
		target Target
		match  string
		want   string
	}{
		{TargetRequestHeader, "trace-me", "X-Trace: rewritten"},
		{TargetRequestFirstLine, "/submit", "/elsewhere"},
		{TargetRequestBody, "REQ-IN", "REQ-OUT"},
	}
	for _, tc := range cases {
		rule, err := NewRule(tc.target, CategoryLiteral, tc.match, tc.want, "")
		if err != nil {
			t.Fatalf("NewRule(%d): %v", int(tc.target), err)
		}
		got := string(NewRuleSet().with(ruleSetOf(rule)).Apply(DirRequest, req))
		if !bytes.Contains([]byte(got), []byte(tc.want)) {
			t.Errorf("target %d: output %q does not contain %q", int(tc.target), got, tc.want)
		}
	}
}

// Regex name rules keep regex semantics - the pattern is anchored by the regex itself, not
// by the field boundary, so an operator says whole-name with ^secret$.
func TestARegexParamNameRuleUsesRegexSemantics(t *testing.T) {
	rule, err := NewRule(TargetRequestParamName, CategoryRegex, "^secret$", "harmless", "")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	got := string(NewRuleSet().with(ruleSetOf(rule)).Apply(DirRequest, []byte(paramRequest)))
	const want = "GET /pay?user=admin&harmless=hunter2&nonsecret=keep HTTP/1.1\r\n" +
		"Host: shop.test\r\n" +
		"\r\n"
	if got != want {
		t.Fatalf("regex param-name rewrite =\n  %q\nwant\n  %q", got, want)
	}
}

// helper: build a single-rule set without repeating the compile boilerplate
func ruleSetOf(r *Rule) []*Rule { return []*Rule{r} }

func (rs *RuleSet) with(rules []*Rule) *RuleSet {
	rs.SetRules(rules)
	return rs
}
