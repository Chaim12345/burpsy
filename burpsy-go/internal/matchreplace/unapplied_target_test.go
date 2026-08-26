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
	// became `nonharmless` because a body rewrite has no concept of a parameter.
	if got == "user=admin&harmless=hunter2&nonharmless=keep" {
		t.Fatal("a param-name rule was applied as a whole-body rewrite and renamed the " +
			"unrelated parameter `nonsecret` — this is the defect, still present")
	}
	if got != body {
		t.Fatalf("an unimplemented target changed the bytes:\n  in:  %s\n  out: %s\n"+
			"until applyOne implements this target it must be a no-op", body, got)
	}
}

// Both param targets behave identically, which is itself evidence that neither is
// implemented — a real applier would treat a name rule and a value rule differently.
func TestBothParamTargetsAreNoOps(t *testing.T) {
	const body = "user=admin&secret=hunter2"
	for _, target := range []Target{TargetRequestParamName, TargetRequestParamValue} {
		rule, err := NewRule(target, CategoryLiteral, "secret", "harmless", "")
		if err != nil {
			t.Fatalf("NewRule(%d): %v", int(target), err)
		}
		rs := NewRuleSet()
		rs.SetRules([]*Rule{rule})
		if got := string(rs.Apply(DirRequest, []byte(body))); got != body {
			t.Errorf("Target %d altered the request: %q", int(target), got)
		}
	}
}

// The five implemented targets must be unaffected by making the default a no-op.
//
// Without this, the fix above could quietly disable every real rule and the suite would
// still pass — a no-op default is only correct for targets that have no applier.
func TestTheImplementedTargetsStillApply(t *testing.T) {
	cases := []struct {
		name   string
		target Target
		dir    Direction
		in     string
	}{
		{"request body", TargetRequestBody, DirRequest,
			"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 7\r\n\r\nfind me"},
		{"request header", TargetRequestHeader, DirRequest,
			"GET /x HTTP/1.1\r\nX-A: find\r\n\r\n"},
		{"request first line", TargetRequestFirstLine, DirRequest,
			"GET /find HTTP/1.1\r\nHost: h\r\n\r\n"},
		{"response body", TargetResponseBody, DirResponse,
			"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nfind me"},
		{"response header", TargetResponseHeader, DirResponse,
			"HTTP/1.1 200 OK\r\nX-A: find\r\n\r\n"},
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
			t.Errorf("%s: the rule did not fire — the no-op default may have swallowed an "+
				"implemented target\n  in: %q", c.name, c.in)
			continue
		}
		if !contains(got, "GOT") {
			t.Errorf("%s: replacement missing from output %q", c.name, got)
		}
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && indexOf(hay, needle) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
