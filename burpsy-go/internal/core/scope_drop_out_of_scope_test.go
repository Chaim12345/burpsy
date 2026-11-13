package core

import (
	"strings"
	"testing"
)

// ---- Burp's "Out-of-scope request handling: Drop all out-of-scope requests" (5j4i) -------------
//
// The switch is egress control, deliberately separate from every rule-list decision: Contains
// answers "is this retained", and with the switch on a scope refusal also means "may it be
// sent at all — no". The enforcement points are the two places a request is actually issued:
// AuthoriseRequest and AuthoriseRaw. MayContainHost deliberately stays a host-level
// pre-filter — see its doc comment for why the switch must not reach it.

// With the switch on, a request to a host the include list does not name is refused by
// AuthoriseRequest — the gate per-request senders ask before dialing.
func TestDropOutOfScopeMakesAuthoriseRequestRefuseAnUnnamedHost(t *testing.T) {
	s := NewScope()
	s.AddInclude("example.test")
	if !s.AuthoriseRequest("example.test", 80, "/", false) {
		t.Fatal("setup: the named host should be authorised before the switch is turned on")
	}

	s.SetDropOutOfScope(true)
	if s.AuthoriseRequest("ghost.test", 80, "/", false) {
		t.Error("with Drop all out-of-scope requests on, a host the include list does not name must not be authorised to send")
	}
	if !s.AuthoriseRequest("example.test", 80, "/", false) {
		t.Error("a host the include list names must stay authorised while the switch is on")
	}
}

// An empty include list still means "everything", even with the switch on: the switch's
// decision rides the scope's own semantics, it does not invent a new definition of out-of-scope.
func TestDropOutOfScopeWithAnEmptyIncludeListStillAllowsEverything(t *testing.T) {
	s := NewScope()
	s.SetDropOutOfScope(true)
	if !s.AuthoriseRequest("anything.test", 80, "/", false) {
		t.Error("an empty include list means everything; the drop switch must not narrow it")
	}
	if !s.Contains("anything.test", 80, "/", false) {
		t.Error("default-allow must survive the switch for Contains too — retention semantics are unchanged")
	}
}

// Excludes still win: with the switch on, an excluded host is unreachable even on an
// otherwise-empty include list.
func TestDropOutOfScopeKeepsExcludesWinning(t *testing.T) {
	s := NewScope()
	s.SetDropOutOfScope(true)
	s.AddExclude("secret.test")
	if s.AuthoriseRequest("secret.test", 80, "/", false) {
		t.Error("an excluded host must be refused while the drop switch is on; excludes win over default-allow")
	}
	if !s.AuthoriseRequest("other.test", 80, "/", false) {
		t.Error("a host no rule names stays allowed on an empty include list, switch or not")
	}
}

// Disabled rules are inert for the switch too: a disabled include cannot admit a host, exactly
// as it cannot in Contains (the 1xb semantics). With every include disabled and the switch on,
// no host is authorised — not even one named by the disabled rule.
func TestDropOutOfScopeHonoursDisabledIncludes(t *testing.T) {
	s := NewScope()
	s.Add(NewScopeRule(ScopeInclude, "example.test"))
	s.SetRuleEnabled(ScopeInclude, "example.test", nil, nil, nil, false)
	s.SetDropOutOfScope(true)
	if s.AuthoriseRequest("example.test", 80, "/", false) {
		t.Error("a disabled include must not authorise its host while the drop switch is on")
	}
}

// With the switch on, AuthoriseRaw's refusal says "dropped" and names the deciding rule, so an
// operator can tell an egress refusal from an ordinary retention one in the tool's reply.
func TestAuthoriseRawNamesTheDropWhenTheSwitchIsOn(t *testing.T) {
	s := NewScope()
	s.AddInclude("example.test")
	s.SetDropOutOfScope(true)

	err := s.AuthoriseRaw("ghost.test", 80, false, []byte("GET / HTTP/1.1\r\nHost: ghost.test\r\n\r\n"))
	if err == nil {
		t.Fatal("an out-of-scope request must be refused while the switch is on")
	}
	msg := err.Error()
	if !strings.Contains(msg, "dropped") {
		t.Errorf("the refusal must say the request was dropped, not merely refused; got %q", msg)
	}
	if !strings.Contains(msg, "matches no include rule") {
		t.Errorf("the refusal must still name the deciding rule; got %q", msg)
	}

	if err := s.AuthoriseRaw("example.test", 80, false, []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")); err != nil {
		t.Errorf("an in-scope request must still pass while the switch is on: %v", err)
	}
}

// With the switch off the refusals are worded exactly as they always were: the switch is an
// addition, not a rewording of every scope error.
func TestAuthoriseRawKeepsThePlainRefusalWhenTheSwitchIsOff(t *testing.T) {
	s := NewScope()
	s.AddInclude("example.test")

	err := s.AuthoriseRaw("ghost.test", 80, false, []byte("GET / HTTP/1.1\r\nHost: ghost.test\r\n\r\n"))
	if err == nil {
		t.Fatal("setup: the request must be refused")
	}
	if strings.Contains(err.Error(), "dropped") {
		t.Errorf("with the switch off, a refusal is a retention refusal and must not say 'dropped'; got %q", err.Error())
	}
}

// The pre-filter's contract is unchanged by the switch: MayContainHost answers "is this host
// worth considering at all" with Contains' own semantics, on or off. Filtering the include
// list on Enabled here would re-open the cj7x disagreement (see MayContainHost's doc).
func TestMayContainHostIsUnchangedByTheDropSwitch(t *testing.T) {
	s := NewScope()
	s.AddInclude("example.test")
	s.SetDropOutOfScope(true)

	// The named host passes both with and without the switch: the pre-filter is a
	// "worth considering" verdict, not a send permission.
	if !s.MayContainHost("example.test", 80, false) {
		t.Error("a named host must still pass the pre-filter while the switch is on")
	}

	// And a disabled include cannot pass the pre-filter, exactly as in Contains.
	s.SetRuleEnabled(ScopeInclude, "example.test", nil, nil, nil, false)
	if s.MayContainHost("example.test", 80, false) {
		t.Error("a disabled include must not pass the pre-filter — MayContainHost must keep agreeing with Contains")
	}
}
