package session

import (
	"testing"

	"go.uber.org/zap"
)

// Burp's URL scope for a session-handling rule (settings/sessions/session-handling-rules.html,
// burpsy-react-ui-7nh2): the radio offers "Include all URLs", "Use suite scope [defined in Target
// tab]" and "Use custom scope", and the custom scope is a URL-matching rule — protocol, host, port
// and path — rather than the host list alone the rule editor used to offer.
//
// The tests below pin the two directions that matter, because they fail differently. Over-matching
// is the dangerous one: a rule scoped to /api that fires its login macro for /logout puts
// credentials on a request the operator's own editor excludes. Under-matching is merely a rule that
// does not help, and the arms exist so that does not happen either.

// installable is a rule the coordinator will accept: a name, optional host patterns, and one macro
// step, because AddRule refuses a rule with nothing to run.
func installable(name string, hosts []string) *SessionRule {
	return NewSessionRule(name, hosts, []MacroStep{{Method: "POST", URL: "https://app.test/login"}})
}

// A custom rule's path arm is what decides it: a request under the prefix is covered, one outside
// it is not — and the second half is the assertion that matters, because the old host-only match
// answered true for both.
func TestACustomScopePathPrefixCoversOnlyRequestsUnderIt(t *testing.T) {
	r := NewSessionRule("api login", []string{"app.test"}, nil)
	r.ScopeMode = "custom"
	r.ScopePathPrefix = "/api"

	if !r.MatchRequest(RequestIdentity{Host: "app.test", Path: "/api/orders"}, nil) {
		t.Error("a request under the rule's own path prefix was refused; the prefix exists to cover it")
	}
	if r.MatchRequest(RequestIdentity{Host: "app.test", Path: "/logout"}, nil) {
		t.Error("a request outside the rule's path prefix was covered; a rule scoped to /api must not claim /logout")
	}
	if r.MatchRequest(RequestIdentity{Host: "app.test", Path: "/"}, nil) {
		t.Error("a request to the origin path was covered by a rule scoped to /api; the prefix is a prefix of the path, not of the host")
	}
}

// The port and protocol arms are separate axes, and each one alone is enough to refuse. A rule
// scoped to https must not claim the same host's http traffic — the credential-bearing case, since
// that is the plaintext request the operator scoped the rule away from.
func TestACustomScopePortAndProtocolArmsEachRefuseOnTheirOwn(t *testing.T) {
	https := uint16(443)
	r := NewSessionRule("tls only", nil, nil)
	r.ScopeMode = "custom"
	r.ScopePort = &https
	r.ScopeProtocol = "https"

	if !r.MatchRequest(RequestIdentity{Host: "app.test", Path: "/", Port: 443, TLS: true}, nil) {
		t.Error("the request matching both arms was refused")
	}
	if r.MatchRequest(RequestIdentity{Host: "app.test", Path: "/", Port: 443, TLS: false}, nil) {
		t.Error("an http request matched a rule scoped to https; the scheme arm must refuse it")
	}
	if r.MatchRequest(RequestIdentity{Host: "app.test", Path: "/", Port: 8443, TLS: true}, nil) {
		t.Error("a request on 8443 matched a rule scoped to port 443")
	}
}

// Suite mode is the live Target scope, not a snapshot: the same rule must answer differently once
// the operator changes the scope, because that is the whole difference between this and copying the
// scope onto the rule at save time.
func TestASuiteScopedRuleReadsTheSuiteScopeAtMatchTime(t *testing.T) {
	r := NewSessionRule("suite login", nil, nil)
	r.ScopeMode = "suite"

	inScope := false
	verdict := func() bool { return inScope }
	req := RequestIdentity{Host: "app.test", Path: "/account"}

	if r.MatchRequest(req, verdict) {
		t.Error("a suite-scoped rule matched while the suite scope excluded the request")
	}
	inScope = true
	if !r.MatchRequest(req, verdict) {
		t.Error("a suite-scoped rule refused after the suite scope came to include the request; the verdict is read live, not frozen")
	}
}

// A suite-scoped rule in a process with no scope answer has nothing to match. Refusing is the
// documented answer: falling open would fire a login macro at every host in the engagement.
func TestASuiteScopedRuleWithNoScopeAnswerMatchesNothing(t *testing.T) {
	r := NewSessionRule("suite login", nil, nil)
	r.ScopeMode = "suite"
	if r.MatchRequest(RequestIdentity{Host: "app.test", Path: "/"}, nil) {
		t.Error("a suite-scoped rule with no suite verdict fell open to every request")
	}
}

// The coordinator's installed predicate is what keeps suite-mode rules reachable from the match
// sites inside this package that own no scope handle — HandleRecovery above all. Passing nil
// explicitly must consult it rather than refuse.
func TestTheInstalledSuitePredicateAnswersWhenTheCallerHasNone(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	r := installable("suite login", nil)
	r.ScopeMode = "suite"
	if _, err := c.AddRule(r); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if got := c.MatchingRuleForRequest(RequestIdentity{Host: "app.test", Path: "/"}, nil, nil); got != nil {
		t.Fatal("with no predicate installed a suite-scoped rule matched; it has no scope to consult")
	}

	c.SetSuiteScopePredicate(func(req RequestIdentity) bool { return req.Host == "app.test" && req.Path == "/account" })
	if got := c.MatchingRuleForRequest(RequestIdentity{Host: "app.test", Path: "/account"}, nil, nil); got != r {
		t.Fatal("the installed predicate was not consulted for a caller that had none of its own")
	}
	if got := c.MatchingRuleForRequest(RequestIdentity{Host: "app.test", Path: "/logout"}, nil, nil); got != nil {
		t.Fatal("the installed predicate was consulted with the wrong identity; the path is part of the question")
	}
}

// A caller that hands over only a host must not collect a rule scoped to a path. The host-only
// lookup is the old signature kept for callers that genuinely have nothing else, and the honest
// answer for a path-scoped rule is "not covered" rather than "covered, we did not check".
func TestAHostOnlyLookupDoesNotCollectAPathScopedRule(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	scoped := installable("api login", nil)
	scoped.ScopeMode = "custom"
	scoped.ScopePathPrefix = "/api"
	if _, err := c.AddRule(scoped); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if got := c.MatchingRule("app.test"); got != nil {
		t.Error("a host-only lookup collected a rule whose own editor scopes it to /api")
	}
	if got := c.MatchingRuleForRequest(RequestIdentity{Host: "app.test", Path: "/api/x"}, nil, nil); got != scoped {
		t.Error("the path-scoped rule was not collected for a request under its prefix")
	}
}

// Rule order is still the precedence rule once scopes are involved: a request matching both a
// narrow and a general rule takes the narrow one only because it comes first, and falls through to
// the general one when the narrow rule's arms refuse.
func TestAPathScopedRuleFallsThroughToTheGeneralRuleOutsideItsPath(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	narrow := installable("api login", nil)
	narrow.ScopeMode = "custom"
	narrow.ScopePathPrefix = "/api"
	general := installable("general login", []string{"app.test"})
	for _, r := range []*SessionRule{narrow, general} {
		if _, err := c.AddRule(r); err != nil {
			t.Fatalf("AddRule(%s): %v", r.Name, err)
		}
	}

	if got := c.MatchingRuleForRequest(RequestIdentity{Host: "app.test", Path: "/api/orders"}, nil, nil); got != narrow {
		t.Fatalf("got %v for an /api request; the narrow rule is first and must claim it", got)
	}
	if got := c.MatchingRuleForRequest(RequestIdentity{Host: "app.test", Path: "/account"}, nil, nil); got != general {
		t.Fatalf("got %v for a request outside /api; it must fall through to the general rule", got)
	}
}

// A macro's own steps are judged by the arms the rule states about itself, never by the suite
// scope: a suite-scoped rule whose login URL sits outside the Target scope must still send its
// login. Judging the steps by the suite scope would leave the rule matching and unable to log in.
func TestAMacroStepIsNotSkippedByTheSuiteScope(t *testing.T) {
	r := NewSessionRule("suite login", nil, nil)
	r.ScopeMode = "suite"
	step := RequestIdentity{Host: "login.test", Path: "/auth", Port: 443, TLS: true}

	if !r.MatchCustomArms(step) {
		t.Error("MatchCustomArms refused a step for a suite-mode rule; the suite scope is not the rule's own arms")
	}
	rout := NewSessionRule("api login", nil, nil)
	rout.ScopeMode = "custom"
	rout.ScopePathPrefix = "/api"
	if rout.MatchCustomArms(RequestIdentity{Host: "login.test", Path: "/auth"}) {
		t.Error("MatchCustomArms covered a step outside the rule's own path prefix")
	}
}

// identityOf is what turns a macro step's URL into the arms' answer, and its two edge cases are the
// ones that decide whether a path-scoped rule over- or under-matches: a URL with no path is "/",
// and a query or fragment is not part of the path.
func TestTheStepIdentityKeepsThePathAndDropsTheQuery(t *testing.T) {
	cases := []struct {
		url      string
		wantPath string
		wantTLS  bool
		wantPort uint16
	}{
		{"https://app.test/api/orders?page=2#top", "/api/orders", true, 443},
		{"http://app.test:8080/api", "/api", false, 8080},
		{"https://app.test", "/", true, 443},
		{"https://app.test/", "/", true, 443},
	}
	for _, tc := range cases {
		got := identityOf(tc.url)
		if got.Path != tc.wantPath {
			t.Errorf("identityOf(%q).Path = %q, want %q", tc.url, got.Path, tc.wantPath)
		}
		if got.TLS != tc.wantTLS {
			t.Errorf("identityOf(%q).TLS = %v, want %v", tc.url, got.TLS, tc.wantTLS)
		}
		if got.Port != tc.wantPort {
			t.Errorf("identityOf(%q).Port = %d, want %d", tc.url, got.Port, tc.wantPort)
		}
	}
}

// A custom scope that states a path and no host is a real rule — Burp's arms are independent — so
// the stated-but-empty refusal must not swallow it. The refusal it must still raise is the one for
// a scope that states nothing in any axis.
func TestAStatedScopeWithOnlyAPathArmIsNotTheStatedEmptyCase(t *testing.T) {
	pathOnly := NewSessionRule("api login", nil, []MacroStep{{Method: "POST", URL: "https://app.test/login"}})
	pathOnly.ScopeMode = "custom"
	pathOnly.ScopePathPrefix = "/api"
	if err := ValidateRuleStatedScope(pathOnly, true); err != nil {
		t.Fatalf("a custom scope stating a path prefix was refused: %v", err)
	}

	nothing := NewSessionRule("nothing", nil, []MacroStep{{Method: "POST", URL: "https://app.test/login"}})
	nothing.ScopeMode = "custom"
	if err := ValidateRuleStatedScope(nothing, true); err == nil {
		t.Fatal("a stated scope with no hosts, no path, no port and no scheme was accepted; it can only be read as matching nothing")
	}
}
