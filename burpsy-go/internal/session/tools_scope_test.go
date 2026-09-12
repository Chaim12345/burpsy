package session

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

// Burp's tools scope for a session-handling rule (settings/sessions/session-handling-rules.html,
// burpsy-react-ui-so3): the Scope tab's first axis, and the one with no substitute. URL scope is a
// coarser host/path match, parameter scope needs request content the rule can inspect, but "not
// Intruder" cannot be expressed any other way — which is why Burp's own shipped default rule is
// defined by it ("this rule does not apply when the Scanner is managing its own sessions").
//
// The tests below pin three directions, because they fail differently:
//
//   - A request from a tool the rule excludes is refused. That is the feature.
//   - A rule that states no tools still applies to every tool. That is the reading that keeps the
//     rules every operator already has alive, and the one whose absence made the analogous host
//     scope dead on arrival once before.
//   - A request no caller attributed still applies. That is the direction the host-only entry
//     points need, and it is documented at MatchTools rather than left to be discovered.

// toolsFor is a rule restricted to the named tools, with a name and one step so AddRule accepts it.
func toolsFor(name string, tools ...string) *SessionRule {
	r := NewSessionRule(name, nil, []MacroStep{{Method: "POST", URL: "https://app.test/login"}})
	r.ScopeTools = tools
	return r
}

// The acceptance criterion for so3, stated as Burp states it: the same request, made by two
// different tools, gets different answers — and the answer is decided by the rule's own tools scope.
//
// The request is identical in every other axis on purpose. Asserting with two requests that differ
// in host as well would pass even if the tool were never consulted, which is exactly the shape of
// test that let the host-only scope look implemented.
func TestTheSameRequestTakesDifferentRulesForDifferentTools(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	crawlOnly := toolsFor("crawl login", "crawler")
	sessionOnly := toolsFor("session login", "session")
	for _, r := range []*SessionRule{crawlOnly, sessionOnly} {
		if _, err := c.AddRule(r); err != nil {
			t.Fatalf("AddRule(%s): %v", r.Name, err)
		}
	}

	req := RequestIdentity{Host: "app.test", Path: "/account", Port: 443, TLS: true}

	asCrawler := req
	asCrawler.Tool = "crawler"
	if got := c.MatchingRuleForRequest(asCrawler, nil, nil); got != crawlOnly {
		t.Fatalf("a crawler request matched %v; the rule restricted to the crawler must claim it", got)
	}
	asSession := req
	asSession.Tool = "session"
	if got := c.MatchingRuleForRequest(asSession, nil, nil); got != sessionOnly {
		t.Fatalf("a session request matched %v; the rules are per-tool, so it must not take the crawler's", got)
	}
}

// The operator's stated exclusion is what this feature is for, so the refusal is asserted on its
// own rather than only as a side effect of which rule won: a rule restricted to the crawler must
// not fire for traffic from a tool it does not name, even when nothing else would match.
//
// The Intruder case is the one the issue names: an attack deliberately fuzzing the session cookie
// must not have its 302 repaired by a re-login rule mid-flight.
func TestARuleRestrictedToAToolRefusesRequestsFromAnother(t *testing.T) {
	r := toolsFor("crawl login", "crawler")
	req := RequestIdentity{Host: "app.test", Path: "/account", Tool: "intruder"}
	if r.MatchRequest(req, nil) {
		t.Fatal("a rule restricted to the crawler fired for Intruder traffic; an Intruder attack fuzzing " +
			"the session cookie would have its 302 silently repaired mid-flight")
	}
	req.Tool = "crawler"
	if !r.MatchRequest(req, nil) {
		t.Fatal("the same request from the crawler was refused by a rule that names only the crawler")
	}
}

// A rule that states no tools applies to every tool — the reading that keeps every rule written
// before this field existed firing.
func TestARuleWithNoToolsScopeAppliesToEveryTool(t *testing.T) {
	r := NewSessionRule("plain login", nil, []MacroStep{{Method: "POST", URL: "https://app.test/login"}})
	for _, tool := range []string{"", "crawler", "intruder", "scanner"} {
		if !r.MatchTools(tool) {
			t.Errorf("a rule with no tools scope refused tool %q; silence is not a restriction", tool)
		}
	}
}

// An unattributed request still matches a tool-restricted rule, and this is a deliberate direction
// rather than an oversight: "" is a caller saying which tool it cannot say, and the host-only entry
// points (MatchingRule, MatchingRuleFor, HandleResponse) are exactly those callers. Refusing would
// make a tool-restricted rule vanish for them — enabled, listed, and silently never firing, which
// MatchHost's doc calls the worst failure a session rule can have.
//
// It is pinned here rather than left in a comment so that a later change to fail-closed has to
// change this test, and therefore read why.
func TestAnUnattributedRequestStillMatchesAToolRestrictedRule(t *testing.T) {
	r := toolsFor("crawl login", "crawler")
	if !r.MatchRequest(RequestIdentity{Host: "app.test", Path: "/account"}, nil) {
		t.Fatal("a request no caller attributed was refused by a tool-restricted rule; the host-only " +
			"entry points would then lose session handling for traffic the rule was written to handle")
	}
	// But the direction is one-way: attribution must actually be consulted, or the fail-open reading
	// would swallow the whole feature.
	if r.MatchRequest(RequestIdentity{Host: "app.test", Tool: "intruder"}, nil) {
		t.Fatal("an attributed request from an excluded tool was covered")
	}
}

// The tool axis is orthogonal to the URL axes, so a URL restriction must not smuggle a tool past the
// check: a rule in "Use suite scope" mode that names the crawler is still only the crawler's.
//
// This is the branch that made the ordering of the two checks load-bearing (see MatchRequest): the
// suite arm answers a different question and returns before the custom arms would ever be consulted,
// so a tool check placed with the arms would have left every suite-mode rule applying to every tool.
func TestASuiteScopedRuleStillHonoursItsToolsScope(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	r := toolsFor("suite crawl login", "crawler")
	r.ScopeMode = "suite"
	if _, err := c.AddRule(r); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	c.SetSuiteScopePredicate(func(req RequestIdentity) bool { return req.Host == "app.test" })

	inScope := RequestIdentity{Host: "app.test", Path: "/account", Tool: "crawler"}
	if got := c.MatchingRuleForRequest(inScope, nil, nil); got != r {
		t.Fatalf("a suite-scoped, crawler-only rule did not match crawler traffic in scope: got %v", got)
	}
	outOfScopeTool := RequestIdentity{Host: "app.test", Path: "/account", Tool: "intruder"}
	if got := c.MatchingRuleForRequest(outOfScopeTool, nil, nil); got != nil {
		t.Fatal("a suite-scoped rule restricted to the crawler matched Intruder traffic; the tool axis " +
			"was skipped because the suite arm answered first")
	}
}

// A path-only or tool-only rule with no host list is a real rule, so the tools check must not be
// implemented as a second host-like condition that also has to be non-empty.
func TestAToolsOnlyRuleNeedsNoHostsToMatch(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	r := toolsFor("crawl login", "crawler")
	if _, err := c.AddRule(r); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	got := c.MatchingRuleForRequest(RequestIdentity{Host: "anything.test", Path: "/x", Tool: "crawler"}, nil, nil)
	if got != r {
		t.Fatalf("a rule naming only a tool did not match that tool's traffic: got %v", got)
	}
}

// HandleRecovery takes the tool as its own argument, and this is the test that says the recovery
// path consults it rather than the match site alone: a rule restricted to the crawler must not
// recover a request made by another tool, or the very first thing the coordinator does about an
// expired session is ignore the operator's scope.
func TestRecoveryRefusesToRunARuleRestrictedToAnotherTool(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	r := toolsFor("crawl login", "crawler")
	if _, err := c.AddRule(r); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	orig := getStep("https://app.test/account")
	fake := newFakeSender()
	fake.script("https://app.test/login", validResponse(), nil)

	out := c.HandleRecovery("intruder", orig, invalidResponse(), fake.runner())
	if out.Kind != RecoveryNoRuleApplies {
		t.Fatalf("recovery reported %v for an Intruder request against a crawler-only rule; it must "+
			"find no rule that applies", out.Kind)
	}

	// And the same call attributed to the crawler does reach the rule, or the test above would pass
	// for a coordinator that never matched anything.
	out = c.HandleRecovery("crawler", orig, invalidResponse(), fake.runner())
	if out.Kind == RecoveryNoRuleApplies {
		t.Fatal("recovery found no rule for a crawler request against a crawler-only rule")
	}
}

// A tools scope naming an empty tool is a restriction no request can satisfy, so it is refused at
// configuration time — the same dead-arm refusal a host pattern of "" would earn. Whether a
// non-empty name is a tool burpsy *has* is not this package's question: the vocabulary belongs to
// internal/toollog and the wire refuses an unrecognised name against it.
func TestARuleNamingAnEmptyToolIsRefused(t *testing.T) {
	r := toolsFor("bad tools", "crawler", "")
	err := ValidateRule(r)
	if err == nil {
		t.Fatal("a rule whose tools scope names an empty tool was accepted; no request can be attributed " +
			"to it, so the entry is a restriction that can never match")
	}
	if got := err.Error(); !strings.Contains(got, "empty tool") {
		t.Fatalf("the refusal reads %q; it must name the empty tool as the fault", got)
	}
}
