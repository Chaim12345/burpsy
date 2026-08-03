package bcheck

import (
	"regexp"
	"strings"
	"testing"
)

// f1 is the canonical minimal passive check from the research notes.
const f1 = `
metadata:
  language: v1-beta
  name: "NuGet API Key"
  description: "Looks for NuGet API keys in page source."
  author: "@puzzlepeaches"
  tags: "nuget", "token", "exposure"

given response then
  if {latest.response} matches "oy2[a-z0-9]{43}" then
      report issue:
          severity: info
          confidence: tentative
          detail: "NuGet API key found in page."
          remediation: "Review and remove unnecessary exposure."
  end if
`

func TestParseMinimalPassive(t *testing.T) {
	c, err := Parse(f1)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if c.Name != "NuGet API Key" {
		t.Errorf("name = %q, want %q", c.Name, "NuGet API Key")
	}
	if c.Given != "response" {
		t.Errorf("given = %q, want %q", c.Given, "response")
	}
	if len(c.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(c.Statements))
	}
	if _, ok := c.Statements[0].(*IfStatement); !ok {
		t.Fatalf("statement 0 is %T, want *IfStatement", c.Statements[0])
	}
	if len(c.Metadata.Reference) != 3 {
		t.Errorf("tags = %v, want 3 tags", c.Metadata.Reference)
	}
}

func TestRunPassiveMatchesRegex(t *testing.T) {
	c, err := Parse(f1)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Positive: the response contains a NuGet key.
	ctx := NewContext()
	ctx.Response = []byte("https://example.com/nuget/oy2abc1234567890123456789012345678901234567xyz")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Severity != SeverityInfo {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityInfo)
	}
	if findings[0].Confidence != ConfidenceTentative {
		t.Errorf("confidence = %q, want %q", findings[0].Confidence, ConfidenceTentative)
	}

	// Negative: no key in the response.
	ctx2 := NewContext()
	ctx2.Response = []byte("no secrets here")
	findings2, err := RunPassive(c, ctx2)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings2) != 0 {
		t.Errorf("findings = %d, want 0", len(findings2))
	}
}

func TestParseInOperator(t *testing.T) {
	src := `
given response then
  if "secret" in {latest.response} then
      report issue:
          severity: low
          confidence: certain
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	ctx := NewContext()
	ctx.Response = []byte("the secret is here")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (needle on LEFT containment)", len(findings))
	}

	ctx2 := NewContext()
	ctx2.Response = []byte("nothing interesting")
	findings2, _ := RunPassive(c, ctx2)
	if len(findings2) != 0 {
		t.Errorf("findings = %d, want 0", len(findings2))
	}
}

func TestParseDefineAndForEach(t *testing.T) {
	src := `
metadata:
  name: "iterated check"

define:
  needle = "admin"

run for each:
  path = "/login", "/admin"

given response then
  if {needle} in {latest.response} then
      report issue:
          severity: medium
          confidence: firm
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(c.Defines) != 1 || c.Defines[0].Name != "needle" {
		t.Errorf("defines = %+v, want needle define", c.Defines)
	}
	if len(c.ForEach) != 1 || c.ForEach[0].Iterator != "path" || len(c.ForEach[0].Values) != 2 {
		t.Errorf("for_each = %+v, want path with 2 values", c.ForEach)
	}

	// The define should be bound before the body runs.
	ctx := NewContext()
	ctx.Response = []byte("admin panel")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	// Plain `report issue` ends the check, so the second iteration never runs.
	// This check is the reason that is the right reading: its condition does not
	// mention `path` at all, so reporting once per surviving value would file the
	// same issue twice for one underlying defect.
	if len(findings) != 1 {
		t.Errorf("findings = %d, want 1: a plain `report issue` ends the check, "+
			"so the second iteration must not run", len(findings))
	}
}

// A plain report ends the check; only `and continue` keeps iterating. These two
// are the observable difference between the forms, which the parser previously
// discarded — before this, both spellings behaved as `and continue`.
func TestReportIssueAndContinueRunsEveryIteration(t *testing.T) {
	src := `
metadata:
  name: "iterated check"

run for each:
  path = "/login", "/admin"

given response then
  if "admin" in {latest.response} then
      report issue and continue:
          severity: medium
          confidence: firm
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(c.Statements) == 0 {
		t.Fatalf("no statements parsed")
	}
	ctx := NewContext()
	ctx.Response = []byte("admin panel")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 2 {
		t.Errorf("findings = %d, want 2: `and continue` must not end the check, "+
			"so both iterations report", len(findings))
	}
}

func TestMultipleIterablesRunTheFullCartesianProduct(t *testing.T) {
	// Two iterables, 2x3, with `and continue` so nothing stops early. The old
	// evaluator walked only the first iterable and produced 2.
	src := `
metadata:
  name: "product check"

run for each:
  scheme = "http", "https"
  path = "/a", "/b", "/c"

given response then
  if "admin" in {latest.response} then
      report issue and continue:
          severity: medium
          confidence: firm
          detail: ` + "`{scheme}{path}`" + `
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(c.ForEach) != 2 {
		t.Fatalf("for_each = %d iterables, want 2", len(c.ForEach))
	}
	ctx := NewContext()
	ctx.Response = []byte("admin panel")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 6 {
		t.Fatalf("findings = %d, want 6: a check declaring 2x3 iterables must run "+
			"every combination, not just the first iterable", len(findings))
	}
	// Every combination must appear exactly once, and each must carry its own
	// bindings — a leaked binding would show up as a duplicate here.
	seen := map[string]bool{}
	for _, f := range findings {
		if seen[f.Description] {
			t.Errorf("combination %q reported twice: iteration bindings leaked "+
				"between runs instead of each combination getting its own", f.Description)
		}
		seen[f.Description] = true
	}
	for _, want := range []string{"http/a", "http/b", "http/c", "https/a", "https/b", "https/c"} {
		if !seen[want] {
			t.Errorf("combination %q never ran; the product is missing it", want)
		}
	}
}

func TestForEachIterationsDoNotLeakBindings(t *testing.T) {
	// `seen` is defined inside the body on the first iteration only. Under a
	// shared context it would still be bound on the second, and the else branch
	// would never run.
	src := `
metadata:
  name: "leak check"

run for each:
  path = "/a", "/b"

given response then
  if {seen} is "" then
      report issue and continue:
          severity: low
          confidence: firm
          detail: ` + "`unbound at {path}`" + `
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	ctx := NewContext()
	ctx.Response = []byte("body")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 2 {
		t.Errorf("findings = %d, want 2: each iteration must start from the "+
			"parent's bindings, not from what the previous iteration left behind", len(findings))
	}
}

func TestEmptyIterableRunsNothing(t *testing.T) {
	c := &Check{
		Given:   "response",
		ForEach: []RunForEachStatement{{Iterator: "p", Values: nil}},
		Statements: []Statement{&ReportIssueStatement{
			IssueName:  Value{Type: "str", StringVal: "x"},
			Severity:   string(SeverityLow),
			Confidence: string(ConfidenceFirm),
		}},
	}
	findings, err := RunPassive(c, NewContext())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0: an empty iterable declares no combination "+
			"to test, so the body must not run with the iterator unbound", len(findings))
	}
}

func TestParseElseIfChain(t *testing.T) {
	src := `
given response then
  if {latest.response} matches "critical" then
      report issue:
          severity: high
          confidence: certain
  else if {latest.response} matches "warning" then
      report issue:
          severity: medium
          confidence: certain
  else then
      report issue:
          severity: info
          confidence: certain
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	run := func(body string) int {
		ctx := NewContext()
		ctx.Response = []byte(body)
		f, err := RunPassive(c, ctx)
		if err != nil {
			t.Fatalf("run failed: %v", err)
		}
		return len(f)
	}
	if got := run("critical issue"); got != 1 {
		t.Errorf("critical branch findings = %d, want 1", got)
	}
	if got := run("warning only"); got != 1 {
		t.Errorf("warning branch findings = %d, want 1", got)
	}
	if got := run("nothing"); got != 1 {
		t.Errorf("else branch findings = %d, want 1", got)
	}
}

func TestParseAndOrNot(t *testing.T) {
	src := `
given response then
  if {latest.response} contains "a" and {latest.response} contains "b" then
      report issue:
          severity: low
          confidence: certain
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	ctx := NewContext()
	ctx.Response = []byte("has a and b")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("and-branch findings = %d, want 1", len(findings))
	}
	ctx2 := NewContext()
	ctx2.Response = []byte("only a")
	findings2, _ := RunPassive(c, ctx2)
	if len(findings2) != 0 {
		t.Errorf("and-branch negative findings = %d, want 0", len(findings2))
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"missing given", `if x then end if`, "given"},
		{"missing end if", "given response then\n  if {a} is \"b\" then\n    report issue:\n      severity: low\n      confidence: certain\n", "end if"},
		{"bad severity", `
given response then
  report issue:
    severity: catastrophic
    confidence: certain
`, "severity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.src)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

// The blank line between headers and body is a whole "\r\n\r\n", not a single
// "\r\n". The body field used to carry the second half of the blank line, so
// `{base.response.body}` came back with a leading "\r\n" no server would send.
func TestResponseBodyHasNoLeadingBlankLine(t *testing.T) {
	ctx := NewContext()
	ctx.Response = []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello world")
	got := ctx.resolvePath("base.response.body")
	if got != "hello world" {
		t.Errorf("body = %q, want %q (the header/body separator must be skipped whole)", got, "hello world")
	}
}

// A three-level `else if` chain shares ONE terminating `end if`, and the
// enclosing if has its own. The parser used to let every level of the chain eat
// an `end if`, so the middle levels swallowed the enclosing if's terminator and
// parsing died at EOF — this is the exact shape of the one corpus file that
// would not parse (other/uuid-detected-guid-versions.bcheck).
func TestDeepElseIfChainSharesOneEndIf(t *testing.T) {
	src := `
given response then
  if "outer" in {latest.response} then
    if {latest.response} matches "a" then
      report issue and continue:
        severity: low
        confidence: firm
    else if {latest.response} matches "b" then
      report issue and continue:
        severity: low
        confidence: firm
    else if {latest.response} matches "c" then
      report issue and continue:
        severity: low
        confidence: firm
    else if {latest.response} matches "d" then
      report issue and continue:
        severity: low
        confidence: firm
    end if
  end if
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	// The body must be exactly one IfStatement (the outer), whose Then is one
	// IfStatement (the chain head), whose Else is one IfStatement (the first
	// else-if), and so on down.
	outer, ok := c.Statements[0].(*IfStatement)
	if !ok {
		t.Fatalf("outer statement is %T, want *IfStatement", c.Statements[0])
	}
	inner, ok := outer.Then[0].(*IfStatement)
	if !ok {
		t.Fatalf("inner statement is %T, want *IfStatement", outer.Then[0])
	}
	// Walk the else-if spine: each level's Else holds exactly one nested if.
	depth := 1
	for cur := inner; len(cur.Else) == 1; {
		next, ok := cur.Else[0].(*IfStatement)
		if !ok {
			t.Fatalf("else-if level %d is %T, want *IfStatement", depth, cur.Else[0])
		}
		cur = next
		depth++
	}
	if depth != 4 {
		t.Errorf("else-if chain depth = %d, want 4 (the four uuid branches)", depth)
	}

	// And it must still evaluate: "d" matches only the last branch.
	ctx := NewContext()
	ctx.Response = []byte("outer d")
	findings, err := RunPassive(c, ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("findings = %d, want 1 from the last else-if branch", len(findings))
	}
}

func TestRunPassiveIgnoresNonResponseChecks(t *testing.T) {
	src := `given host then
  report issue:
    severity: low
    confidence: certain
`
	c, err := Parse(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	findings, err := RunPassive(c, NewContext())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0 for host-given check", len(findings))
	}
}

func TestJavaBackrefsRewritesJavaGroupReferences(t *testing.T) {
	// The corpus writes Java-style replacements; Go's regexp takes `$1eyJ…`
	// to be a *named* group and drops the capture AND the literal — see
	// other/tokens/jwt-none-algorithm.bcheck:15. java_backrefs must turn
	// `$1eyJ…` into `${1}eyJ…` so group 1 and the literal both survive.
	cases := []struct {
		in, want, why string
	}{
		{"$1eyJhbGciOiJub25l", "${1}eyJhbGciOiJub25l", "digits followed by letters"},
		{"$1.php", "${1}.php", "a dot cannot continue the group"},
		{"${1}x", "${1}x", "already Go's spelling is left alone"},
		{"cost $ and $x", "cost $ and $x", "not a group reference"},
		{"$12abc", "${12}abc", "all the digits, as Java takes them"},
		{"$", "$", "a lone dollar is not a reference"},
	}
	for _, c := range cases {
		if got := javaBackrefs(c.in); got != c.want {
			t.Errorf("javaBackrefs(%q) = %q, want %q — %s", c.in, got, c.want, c.why)
		}
	}
}

func TestJavaBackrefsMakesTheJwtHeaderSurviveReplacement(t *testing.T) {
	// The exact corpus premise: without translation Go reads `1eyJ…` as a
	// group *name*, finds none, and empties the whole payload header.
	re := regexp.MustCompile(`^(Bearer )?[a-zA-Z0-9_\-]+`)
	raw := "$1eyJhbGciOiJub25l"
	if got := re.ReplaceAllString("Bearer eyJabc.rest", raw); got != ".rest" {
		t.Fatalf("premise: Go eats it, got %q, want %q", got, ".rest")
	}
	got := re.ReplaceAllString("Bearer eyJabc.rest", javaBackrefs(raw))
	want := "Bearer eyJhbGciOiJub25l.rest"
	if got != want {
		t.Errorf("translated = %q, want %q", got, want)
	}
}

func TestRandomStrDrawsFromTheSafeAlphabet(t *testing.T) {
	var st uint64 = 0x9e3779b97f4a7c15
	s := randomStr(&st, 64)
	if len(s) != 64 {
		t.Fatalf("len = %d, want 64", len(s))
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
			t.Errorf("randomStr produced %q — outside the path-safe alphabet", r)
		}
	}
}

func TestRandomStrIsReproducibleForASeed(t *testing.T) {
	a, b := uint64(42), uint64(42)
	if got, want := randomStr(&a, 12), randomStr(&b, 12); got != want {
		t.Errorf("same seed produced %q and %q", got, want)
	}
	// Advancing the state yields a different value; this also exercises the
	// xorshift path past the first draw.
	next := uint64(42)
	if first, second := randomStr(&next, 8), randomStr(&next, 8); first == second {
		t.Error("two draws from one state must differ")
	}
}

func TestRegexReplaceAppliesJavaBackrefsToTheReplacement(t *testing.T) {
	// End-to-end through resolveRef, the way the evaluator calls it. The
	// subject is brace-wrapped, the pattern and replacement are quoted — the
	// exact corpus shape — and the replacement is Java's `$1…` spelling, which
	// must mean group 1 + literal, not a named group.
	ctx := NewContext()
	ctx.Variables["base.request.url"] = Value{Type: "str", StringVal: "/jwt/eyJabc.rest"}
	got := ctx.resolveRef(`regex_replace({base.request.url}, "^/jwt/", "$1eyJhbGciOiJub25l")`)
	want := "eyJhbGciOiJub25leyJabc.rest"
	if got != want {
		t.Errorf("resolveRef = %q, want %q (quoted args + Java `$1` must both survive)", got, want)
	}
}

func TestRandomStrResolvesThroughTheEvaluator(t *testing.T) {
	// The corpus calls random_str with a bare numeric literal; the argument
	// must resolve to that number, not to a path binding.
	ctx := NewContext()
	s := ctx.resolveRef("random_str(8)")
	if len(s) != 8 {
		t.Errorf("random_str(8) resolved to %q (len %d), want 8 chars", s, len(s))
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
			t.Errorf("random_str(8) produced %q — outside the path-safe alphabet", s)
			break
		}
	}
}

func TestRandomStrIsSeededFromTheResponse(t *testing.T) {
	// Same response bytes, same probe value — a reported finding can be
	// re-checked. Different bodies must not collide.
	a := NewContext()
	a.Response = []byte("HTTP/1.1 200 OK\r\n\r\nbody-one")
	b := NewContext()
	b.Response = []byte("HTTP/1.1 200 OK\r\n\r\nbody-one")
	if x, y := a.resolveRef("random_str(12)"), b.resolveRef("random_str(12)"); x != y {
		t.Errorf("same body produced %q and %q", x, y)
	}
	c := NewContext()
	c.Response = []byte("HTTP/1.1 200 OK\r\n\r\nbody-two")
	if x, y := a.resolveRef("random_str(12)"), c.resolveRef("random_str(12)"); x == y {
		t.Error("different bodies produced the same probe value")
	}
}

// Templates are the only place report text can reference a binding, so a broken
// brace scan does not fail loudly — it files findings whose detail line still
// says `{name}`. This pins the substitution itself.
func TestTemplateReferencesAreSubstitutedNotEmittedLiterally(t *testing.T) {
	ctx := NewContext()
	ctx.Variables["who"] = Value{Type: "str", StringVal: "admin"}
	ctx.Variables["what"] = Value{Type: "str", StringVal: "panel"}

	cases := []struct {
		in, want, why string
	}{
		{"{who}", "admin", "a lone reference"},
		{"{who}{what}", "adminpanel", "two adjacent references"},
		{"saw {who} at {what}!", "saw admin at panel!", "references surrounded by text"},
		{"{nosuch}", "", "an unknown reference resolves empty, matching Burp"},
		{"no refs here", "no refs here", "text with no reference is untouched"},
		{"a { b", "a { b", "an unterminated brace is literal text"},
		{`\{who\}`, "{who}", "an escaped brace is not a reference"},
	}
	for _, c := range cases {
		if got := ctx.interpolate(c.in); got != c.want {
			t.Errorf("interpolate(%q) = %q, want %q — %s", c.in, got, c.want, c.why)
		}
	}
}
