package matchreplace

import "testing"

// ---- an unimplemented target must change nothing --------------------------------------
//
// `applyOne` implements five of the seven Targets. TargetRequestParamName and
// TargetRequestParamValue have no case, and the default used to be
// `return applyBody(r, raw)` — so a parameter rule was silently executed as a whole-body
// substring rewrite.
//
// That is not a missing feature behaving conservatively. It is a rule doing something the
// operator did not ask for, to live traffic, while the API reported it compiled.

// The exact collision that proved the defect: renaming one parameter also renamed an
// unrelated one whose name merely contains the match string.
func TestAParamNameRuleDoesNotRewriteUnrelatedParameters(t *testing.T) {
	rule, err := NewRule(TargetRequestParamName, CategoryLiteral, "secret", "harmless", "")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	rs := NewRuleSet()
	rs.SetRules([]*Rule{rule})

	const body = "user=admin&secret=hunter2&nonsecret=keep"
	got := string(rs.Apply(DirRequest, []byte(body)))

	// The old behaviour produced "user=admin&harmless=hunter2&nonharmless=keep": `nonsecret`
	// became `nonharmless` because a body rewrite has no idea what a parameter is.
	if got == "user=admin&harmless=hunter2&nonharmless=keep" {
		t.Fatal("a param-name rule was applied as a whole-body rewrite and renamed the unrelated " +
			"parameter `nonsecret` — this is the defect, still present")
	}
	if got != body {
		t.Fatalf("an unimplemented target changed the bytes:\n  in:  %s\n  out: %s\n"+
			"until applyOne implements this target it must be a no-op", body, got)
	}
}

// Both param targets behave identically, which is itself the evidence that neither is
// implemented — a real applier would treat a name rule and a value rule differently.
func TestBothParamTargetsAreNoOpsAndAreIndistinguishable(t *testing.T) {
	const body = "user=admin&secret=hunter2"
	out := map[Target]string{}
	for _, target := range []Target{TargetRequestParamName, TargetRequestParamValue} {
		rule, err := NewRule(target, CategoryLiteral, "secret", "harmless", "")
		if err != nil {
			t.Fatalf("NewRule(%d): %v", int(target), err)
		}
		rs := NewRuleSet()
		rs.SetRules([]*Rule{rule})
		out[target] = string(rs.Apply(DirRequest, []byte(body)))
	}
	for target, got := range out {
		if got != body {
			t.Errorf("Target %d altered the request: %q", int(target), got)
		}
	}
	// Stated rather than asserted-away: when the appliers land, these two SHOULD diverge and
	// this expectation is the thing to update. It is recorded so the update is deliberate.
	if out[TargetRequestParamName] != out[TargetRequestParamValue] {
		t.Log("the param targets now differ — an applier has landed; update this test and " +
			"matchReplaceUnappliedTargets in internal/web/api_toolkit.go")
	}
}

// The five implemented targets must be unaffected by making the default a no-op. Without
// this, the fix above could quietly disable real rules and the suite would still pass.
func TestTheImplementedTargetsStillApply(t *testing.T) {
	cases := []struct {
		name   string
		target Target
		dir    Direction
		in     string
		want   string
	}{
		{"request body", TargetRequestRequestBodyAlias(), DirRequest,
			"POST /x HTTP/1.1\r\nHost: h\r\n\r\nfind me", "POST /x HTTP/1.1\r\nHost: h\r\n\r\nGOT me"},
		{"request header", TargetRequestHeader, DirRequest,
			"GET /x HTTP/1.1\r\nX-A: find\r\n\r\n", "GET /x HTTP/1.1\r\nX-A: GOT\r\n\r\n"},
		{"request first line", TargetRequestFirstLine, DirRequest,
			"GET /find HTTP/1.1\r\nHost: h\r\n\r\n", "GET /GOT HTTP/1.1\r\nHost: h\r\n\r\n"},
		{"response body", TargetResponseBody, DirResponse,
			"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nfind me", ""},
		{"response header", TargetResponseHeader, DirResponse,
			"HTTP/1.1 200 OK\r\nX-A: find\r\n\r\n", "HTTP/1.1 200 OK\r\nX-A: GOT\r\n\r\n"},
	}
	for _, c := range cases {
		rule, err := NewRule(c.target, CategoryLiteral, "find", "GOT", "")
		if err != nil {
			t.Fatalf("%s: NewRule: %v", c.name, err)
		}
		rs := NewRuleSet()
		rs.SetRules([]*Rule{rule})
		got := string(rs.Apply(c.dir, []byte(c.in)))
		if got == c.in {
			t.Errorf("%s: rule did not fire — the no-op default may have swallowed an "+
				"implemented target\n  in: %q", c.name, c.in)
		}
		if c.want != "" && got != c.want {
			t.Errorf("%s:\n  got  %q\n  want %q", c.name, got, c.want)
		}
	}
}

// TargetRequestRequestBodyAlias keeps the table above readable without hard-coding the
// iota value; it exists only so a rename of the constant fails to compile here too.
func TargetRequestRequestBodyAlias() Target { return TargetRequestBody }
