package core

import (
	"strings"
	"testing"
)

// The arms this file pins are burpsy-react-ui-c09: a scope rule could only ever name a host as a
// literal glob and a path as a literal prefix, where Burp takes a regular expression per URL
// component and an IP range. The rules below are opt-in per rule, tagged inside the pattern the
// store already round-trips, and every claim here is about one of two things: that a new arm means
// what it says, or that it cannot mean "more than the operator wrote".

// --- the regular-expression arm ------------------------------------------------------------------

func TestAHostArmCanBeARegularExpressionOverTheWholeHost(t *testing.T) {
	s := NewScope()
	s.Add(NewScopeRule(ScopeInclude, ScopeRegexArm+`api[0-9]+\.example\.test`))

	if !s.Contains("api7.example.test", 443, "/anything", true) {
		t.Error("a host the regular expression describes was refused; the regex arm does not match " +
			"what it states, which makes every rule written with it a scope nobody can use")
	}
	if s.Contains("apiX.example.test", 443, "/anything", true) {
		t.Error("a host the expression does not describe was allowed; a host arm that over-matches " +
			"authorises traffic outside the engagement")
	}
	// Anchoring is the documented decision, and it is the half that decides whether a regex arm can
	// be widened by a hostname an attacker controls.
	if s.Contains("api7.example.test.attacker.invalid", 443, "/", true) {
		t.Error("an unanchored match let a suffix-extended host in: api7.example.test.attacker.invalid " +
			"is a host the attacker names, and authorising it is the widening this arm must not do")
	}
	if s.Contains("prefix-api7.example.test", 443, "/", true) {
		t.Error("an unanchored match let a prefix-extended host in; the arm matches the whole host " +
			"or it matches nothing")
	}
}

func TestAPathArmCanBeARegularExpressionOverTheWholePath(t *testing.T) {
	rule, err := NewScopeRuleFrom(ScopeInclude, "api.test", strptr(ScopeRegexArm+`/v[0-9]+/orders(/.*)?`), nil, nil)
	if err != nil {
		t.Fatalf("a valid path regular expression was refused: %v; the arm is unusable if a correct "+
			"expression cannot be stored", err)
	}
	s := NewScope()
	s.Add(rule)

	for _, in := range []string{"/v1/orders", "/v2/orders/17"} {
		if !s.Contains("api.test", 443, in, true) {
			t.Errorf("path %q was refused though the expression describes it; the path arm does not "+
				"match what it states", in)
		}
	}
	for _, out := range []string{"/v1/ordersx", "/admin/v1/orders", "/"} {
		if s.Contains("api.test", 443, out, true) {
			t.Errorf("path %q was allowed though the expression does not describe it; a path arm that "+
				"over-matches authorises requests the rule excluded", out)
		}
	}
}

func TestAnInvalidRegularExpressionIsRefusedAtConstructionAndNeverMatches(t *testing.T) {
	if _, err := NewScopeRuleFrom(ScopeInclude, ScopeRegexArm+`api[0-9`, nil, nil, nil); err == nil {
		t.Fatal("an unparseable regular expression was accepted as a rule; the endpoint would store " +
			"a rule whose behaviour nobody stated")
	} else if !strings.Contains(err.Error(), "api[0-9") {
		t.Errorf("the refusal did not quote the expression it refused: %v; an operator cannot fix a "+
			"rule the error does not name", err)
	}
	if _, err := NewScopeRuleFrom(ScopeInclude, ScopeRegexArm, nil, nil, nil); err == nil {
		t.Error("an empty regular expression was accepted; Burp's \"leave blank to match any item\" " +
			"is exactly the implicit widening this package refuses, and a blank arm here would be a " +
			"rule that looks armed and is not")
	}
	if _, err := NewScopeRuleFrom(ScopeInclude, "api.test", strptr(ScopeRegexArm+`(`), nil, nil); err == nil {
		t.Error("an unparseable path expression was accepted; the path arm is refused on the same " +
			"terms as the host arm or the two disagree about what a broken rule is")
	}

	// The same pattern reaching the engine without an endpoint in front of it — a hand-edited store,
	// or a build that did not know the arm — is recorded rather than panicking, because this
	// constructor is on persist's restore path and a panic there is a server that cannot start.
	rule := NewScopeRule(ScopeExclude, ScopeRegexArm+`api[0-9`)
	if rule.ArmFault() == nil {
		t.Fatal("a rule built from an unparseable expression reported no fault; nothing downstream " +
			"would know the rule does not mean what it says")
	}
	if rule.Matches("api1.test", 443) {
		t.Error("an uninterpretable rule matched a host; a rule that could not be compiled must not " +
			"decide anything")
	}
}

// The half that separates "never matches" from "never allows", and the reason Contains refuses
// outright: a broken *exclude* that merely matched nothing would hand back "in scope" for exactly
// the requests it was written to keep out.
func TestAScopeHoldingAnUninterpretableRuleAuthorisesNothing(t *testing.T) {
	s := NewScope()
	s.AddInclude("app.test")
	s.Add(NewScopeRule(ScopeExclude, ScopeRegexArm+`admin(`))

	if s.Contains("app.test", 443, "/admin", true) {
		t.Error("a request was in scope while the scope held an exclude rule that does not compile; " +
			"skipping the broken rule is fail-open — the operator wrote it to keep this request out")
	}
	if s.Contains("app.test", 443, "/", true) {
		t.Error("the rest of the scope kept authorising while one rule was unreadable; the document " +
			"is not the one the operator wrote, so no part of it can be relied on")
	}
	if s.MayContainHost("app.test", 443, true) {
		t.Error("the host-level pre-filter kept saying yes; it is the only gate Repeater and Intruder " +
			"apply to their target, so it must not outlive Contains' refusal")
	}
	if err := s.AuthoriseRaw("app.test", 443, true, []byte("GET /admin HTTP/1.1\r\n\r\n")); err == nil {
		t.Error("AuthoriseRaw allowed a request under an unreadable scope; this is the gate the " +
			"sender asks before it dials")
	}

	// And the operator is told which rule, not merely that something is wrong.
	err := s.Validate()
	if err == nil {
		t.Fatal("Validate reported a healthy scope while a rule could not be compiled; the invariant " +
			"the scope decisions rely on is not checkable")
	}
	if !strings.Contains(err.Error(), "admin(") || !strings.Contains(err.Error(), "exclude") {
		t.Errorf("Validate did not name the offending rule: %v; a scope that refuses everything "+
			"without saying which rule broke it cannot be repaired", err)
	}
	if msg := s.Explain("app.test", 443, "/admin", true); !strings.Contains(msg, "cannot be applied") {
		t.Errorf("Explain said %q, which describes the wrong cause; the operator would go and edit "+
			"their include list when the fix is one unparseable rule", msg)
	}
}

// --- the IP-range arm ----------------------------------------------------------------------------

func TestAnIPRangeArmMatchesAddressesInTheRangeAndOnlyThose(t *testing.T) {
	s := NewScope()
	s.Add(NewScopeRule(ScopeInclude, ScopeRangeArm+"10.0.0.0/24"))

	if !s.Contains("10.0.0.7", 80, "/", false) {
		t.Error("an address inside the range was refused; the range arm does not match what it states")
	}
	if s.Contains("10.0.1.7", 80, "/", false) {
		t.Error("an address outside the range was allowed; a range arm that over-matches authorises " +
			"hosts on networks the engagement does not cover")
	}
	// A name is never resolved to decide this: a scope answer that depended on a DNS reply would be
	// an answer an attacker with a resolver could move.
	if s.Contains("inside.example.test", 80, "/", false) {
		t.Error("a hostname matched an IP-range arm; deciding it would require resolving the name, " +
			"which puts the scope verdict in a resolver's hands")
	}
	// The same address written two ways must get one answer.
	if !s.Contains("::ffff:10.0.0.7", 80, "/", false) {
		t.Error("an IPv4-mapped literal was refused by a v4 range; the same host written two ways got " +
			"two different scope answers")
	}
	if !s.Contains("[10.0.0.7]", 80, "/", false) {
		t.Error("a bracketed literal was refused; brackets are authority syntax, not part of the address")
	}
}

func TestABareAddressInARangeArmMeansThatAddressAlone(t *testing.T) {
	s := NewScope()
	s.Add(NewScopeRule(ScopeInclude, ScopeRangeArm+"192.168.1.5"))

	if !s.Contains("192.168.1.5", 8080, "/", false) {
		t.Error("the named address was refused; writing one host in the range field is the ordinary case")
	}
	if s.Contains("192.168.1.6", 8080, "/", false) {
		t.Error("a neighbouring address matched a single-address arm; the arm widened itself to the " +
			"surrounding network")
	}
}

func TestAnIPRangeThatCannotBeReadIsRefusedRatherThanGuessedAt(t *testing.T) {
	for _, bad := range []string{"10.0.0.0/33", "not-an-address", "", "10.0.0.0/8/8"} {
		if _, err := NewScopeRuleFrom(ScopeInclude, ScopeRangeArm+bad, nil, nil, nil); err == nil {
			t.Errorf("the IP range %q was accepted; a range nobody can read is a rule whose width is "+
				"unknown, and for an include that width is the authorised surface", bad)
		}
	}
	// Host bits are the case where guessing is worst: 10.0.0.5/8 is either 10.0.0.0/8 — sixteen
	// million addresses — or 10.0.0.5/32, and the two are not close enough to pick between.
	_, err := NewScopeRuleFrom(ScopeInclude, ScopeRangeArm+"10.0.0.5/8", nil, nil, nil)
	if err == nil {
		t.Fatal("a CIDR block with host bits set was accepted; masking it silently would authorise a " +
			"/8 for an operator who wrote one address, and refusing to mask is the only reading that " +
			"cannot widen")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/8") || !strings.Contains(err.Error(), "10.0.0.5") {
		t.Errorf("the refusal did not offer both readings: %v; the operator has to be told which two "+
			"rules they might have meant", err)
	}
}

// --- what must not change ------------------------------------------------------------------------

// The regression pin for burpsy-react-ui-c09's hard constraint: the arms that existed before this
// work keep deciding exactly what they decided. Every case here passed before the tagged arms
// existed and must still pass with them.
func TestTheGlobAndPrefixArmsKeepTheirExistingSemantics(t *testing.T) {
	s := NewScope()
	s.AddInclude("*.example.com")
	s.Add(NewScopeRuleWithPath(ScopeExclude, "app.example.com", "/admin"))
	s.Add(NewScopeRuleWithPort(ScopeInclude, "api.test", 8443))

	cases := []struct {
		host string
		port uint16
		path string
		tls  bool
		want bool
		why  string
	}{
		{"app.example.com", 443, "/", true, true, "a host under the wildcard is in scope"},
		{"example.com", 443, "/", true, true, "*.example.com covers the bare domain (zero labels)"},
		{"app.example.com", 443, "/admin", true, false, "a path-prefixed exclude removes that path"},
		{"app.example.com", 443, "/admin/users", true, false, "the exclude is a prefix, so it covers what is under it"},
		{"app.example.com", 443, "/administration", true, false, "the prefix is literal, and this path starts with it"},
		{"other.test", 443, "/", true, false, "a host named by no include rule is out of scope"},
		{"api.test", 8443, "/", true, true, "the port-scoped include matches its port"},
		{"api.test", 443, "/", true, false, "and only its port"},
	}
	for _, c := range cases {
		if got := s.Contains(c.host, c.port, c.path, c.tls); got != c.want {
			t.Errorf("Contains(%q:%d%q) = %v, want %v — %s. This is the pre-existing behaviour the "+
				"new arms were required not to touch, so a failure here is a scope decision that "+
				"changed under rules nobody edited", c.host, c.port, c.path, got, c.want, c.why)
		}
	}
	// And a literal pattern is still literal: the tags are the only way to ask for anything else.
	s2 := NewScope()
	s2.AddInclude(`api[0-9].test`)
	if s2.Contains("api7.test", 443, "/", true) {
		t.Error("a pattern containing regex metacharacters was matched as a regular expression; " +
			"host patterns are globs unless they carry an arm tag, and reinterpreting stored " +
			"patterns would change what every existing rule authorises")
	}
	if !s2.Contains(`api[0-9].test`, 443, "/", true) {
		t.Error("the literal host was not matched by its own literal pattern")
	}
}

// The invariant internal/sender depends on, stated on its own: "no pattern compiled" reads as
// "does not match", never as "matches anything".
func TestARuleWithNoCompiledPatternMatchesNothing(t *testing.T) {
	rule := &ScopeRule{Kind: ScopeInclude, Pattern: "app.test", Enabled: true}
	if rule.Matches("app.test", 443) {
		t.Error("a rule with no compiled pattern matched its own host; it has nothing to match with")
	}
	if rule.Matches("anything-at-all.invalid", 80) {
		t.Fatal("a rule with no compiled pattern matched an arbitrary host. core.Scope is what the " +
			"sender asks before every dial, so this reading authorises the whole internet from a " +
			"rule that failed to build")
	}
	if rule.ArmFault() == nil {
		t.Error("the rule reported no fault, so a scope holding it would go on answering questions " +
			"with a rule that cannot answer them")
	}

	// Both layers, separately. The two assertions above pass because ArmFault stops the rule before
	// the host arms are consulted at all — which is the outer gate, not the invariant. The invariant
	// is in the host-arm selection itself, so it is asserted where it lives: a mutation turning that
	// final default into "true" must fail a test, and with only the assertions above it did not.
	if rule.matchesHost("anything-at-all.invalid") {
		t.Error("the host-arm selection fell through to a match with no arm to match on. This is the " +
			"line every other guard is defence in depth for: \"nothing compiled\" has to read as " +
			"\"does not match\", because the opposite reading is a scope that authorises everything")
	}
}

// persist rebuilds every rule with NewScopeRule and then assigns PathPrefix directly, so a path arm
// that needs compiling has none when it arrives. Scope.Add is where that is repaired, and this is
// the shape of the restore path rather than a hypothetical.
func TestARestoredRuleGetsItsArmsCompiledOnTheWayIn(t *testing.T) {
	restored := NewScopeRule(ScopeExclude, ScopeRangeArm+"10.0.0.0/8")
	prefix := ScopeRegexArm + `/internal/.*`
	restored.PathPrefix = &prefix

	s := NewScope()
	s.AddInclude("*")
	s.Add(restored)

	if err := s.Validate(); err != nil {
		t.Fatalf("a rule assembled the way the restore path assembles one was uninterpretable: %v; "+
			"a scope that restarts into a refusal is as broken as one that restarts wide open", err)
	}
	if s.Contains("10.1.2.3", 443, "/internal/keys", true) {
		t.Error("the restored exclude did not exclude; an exclude that lapses across a restart is " +
			"traffic going to a host the operator had already ruled out, with nothing saying so")
	}
	if !s.Contains("10.1.2.3", 443, "/public", true) {
		t.Error("the restored exclude removed a path it does not name; the path arm was widened on " +
			"the way back in")
	}
}
