package intercept

import (
	"testing"
)

func mustActionRule(t *testing.T, field Field, cat Category, match string, action RuleAction) Rule {
	t.Helper()
	r, err := NewRule(field, cat, match, true, "", action)
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	return *r
}

// First matching rule wins: a pass rule ahead of a hold rule lets its match through,
// and everything else still holds. This is Burp's per-rule Do/Don't intercept.
func TestFirstMatchingRuleWinsBetweenPassAndHold(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(DirectionRequest, true, []Rule{
		mustActionRule(t, FieldExtension, CategoryLiteral, "png", RuleActionPass),
		mustActionRule(t, FieldHost, CategoryLiteral, "assets.test", RuleActionHold),
	}); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	if h := e.Hold(reqMessage("assets.test", "GET", "/logo.png")); h != nil {
		t.Errorf("excluded .png held: the pass rule matches first and must win")
	}
	if h := e.Hold(reqMessage("assets.test", "GET", "/index")); h == nil {
		t.Errorf("non-excluded same-host request passed: the hold rule matches and nothing earlier does")
	}
	if h := e.Hold(reqMessage("other.test", "GET", "/logo.png")); h != nil {
		t.Errorf("other-host .png held: only the pass rule matches it")
	}
}

// A hold-only list evaluates exactly as before actions existed: first match holds,
// no match passes when rules are present, everything holds when the list is empty.
func TestHoldOnlyListKeepsTheOldSemantics(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(DirectionRequest, true, []Rule{
		mustActionRule(t, FieldHost, CategoryLiteral, "a.test", RuleActionHold),
		mustActionRule(t, FieldHost, CategoryLiteral, "b.test", RuleActionHold),
	}); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	if h := e.Hold(reqMessage("b.test", "GET", "/")); h == nil {
		t.Errorf("second rule's match passed: first-match-wins must hold it like the old OR did")
	}
	if h := e.Hold(reqMessage("c.test", "GET", "/")); h != nil {
		t.Errorf("unmatched message held despite enabled rules present")
	}
}

func TestParseRuleActionRefusesUnknown(t *testing.T) {
	for _, s := range []string{"hold", "intercept", "", "pass", "dont_intercept", "don't intercept"} {
		if _, err := ParseRuleAction(s); err != nil {
			t.Errorf("ParseRuleAction(%q) refused a known action: %v", s, err)
		}
	}
	if _, err := ParseRuleAction("maybe"); err == nil {
		t.Errorf("ParseRuleAction accepted an unknown action")
	}
}

// Arming holds exactly one response: the next with identical attributes.
func TestArmedResponseHoldFiresOnce(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	// Responses pass by default here: no response rules at all.
	if err := e.SetRules(DirectionResponse, false, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	req := e.Hold(reqMessage("shop.test", "GET", "/cart"))
	if req == nil {
		t.Fatalf("request not held")
	}
	if err := e.ArmResponseHold(req.ID); err != nil {
		t.Fatalf("ArmResponseHold: %v", err)
	}
	// Port 80, like the request above: the arming matches exact attributes.
	resp := &Message{Direction: DirectionResponse, Host: "shop.test", Port: 80, Method: "GET", Path: "/cart", Raw: []byte("HTTP/1.1 200 OK\r\n\r\n")}
	if h := e.Hold(resp); h == nil {
		t.Fatalf("armed response passed through")
	}
	if n := e.PendingResponses(); n != 0 {
		t.Errorf("pending holds = %d after firing, want consumed to 0", n)
	}
	if h := e.Hold(resp); h != nil {
		t.Errorf("second identical response held: the arming must fire exactly once")
	}
}

// Dropping the request retracts its arming: no response is coming, and a stale
// entry must never fire on later unrelated traffic with identical attributes.
func TestDroppedRequestRetractsItsArming(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	req := e.Hold(reqMessage("shop.test", "GET", "/cart"))
	if req == nil {
		t.Fatalf("request not held")
	}
	if err := e.ArmResponseHold(req.ID); err != nil {
		t.Fatalf("ArmResponseHold: %v", err)
	}
	if err := e.Drop(req.ID, "test"); err != nil {
		t.Fatalf("Drop: %v", err)
	}
	resp := &Message{Direction: DirectionResponse, Host: "shop.test", Port: 80, Method: "GET", Path: "/cart", Raw: []byte("HTTP/1.1 200 OK\r\n\r\n")}
	if h := e.Hold(resp); h != nil {
		t.Errorf("response held after its request was dropped: stale arming fired")
	}
}

// Arming from anything but a held request is refused.
func TestArmResponseHoldNeedsAHeldRequest(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.ArmResponseHold(999); err == nil {
		t.Errorf("arming from a missing id succeeded")
	}
}
