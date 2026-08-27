package intercept

import "testing"

// ---- "Only intercept in-scope messages" (burpsy-react-ui-cz1) ----------------------------------
//
// The filter itself is two lines. What is worth testing is where it sits and what it does when it
// has nothing to consult.
//
// It is checked in shouldHold, before the rule lists, because it narrows what the queue may contain
// at all rather than being another rule to match against — and because shouldHold is the single gate
// all five of the relay's Hold call sites pass through. Putting it at the call sites instead would
// have been five places to forget one, and the WebSocket path is the one that would have been
// forgotten.

// stubScope admits exactly the hosts it was given.
type stubScope struct{ allowed map[string]bool }

func (s stubScope) Contains(host string, _ uint16, _ string, _ bool) bool { return s.allowed[host] }

func engineHolding(t *testing.T, dir Direction) *Engine {
	t.Helper()
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(dir, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	return e
}

func msg(host string) *Message {
	return &Message{Direction: DirectionRequest, Host: host, Port: 443, TLS: true, Path: "/x", Raw: []byte("GET /x HTTP/1.1\r\n\r\n")}
}

// Off by default, matching Burp. A queue that silently skipped traffic out of the box would make an
// operator think interception was broken rather than filtered.
func TestInScopeOnlyIsOffByDefault(t *testing.T) {
	e := engineHolding(t, DirectionRequest)
	if e.InScopeOnly() {
		t.Error("the in-scope-only filter defaults to on")
	}
	if held := e.Hold(msg("anything.test")); held == nil {
		t.Error("an unconditional list did not hold with the filter off")
	}
}

func TestInScopeOnlyHoldsOnlyWhatTheScopeAllows(t *testing.T) {
	e := engineHolding(t, DirectionRequest)
	e.SetScope(stubScope{allowed: map[string]bool{"target.test": true}})
	e.SetInScopeOnly(true)

	if held := e.Hold(msg("target.test")); held == nil {
		t.Error("an in-scope message was not held")
	}
	if held := e.Hold(msg("cdn.other.test")); held != nil {
		t.Error("an out-of-scope message was held while the filter was on")
	}
}

// The case that would have been a silent outage. A nil scope means nothing has told the engine what
// is in scope; treating that as "nothing is in scope" would empty the queue while the toggle claimed
// only to be narrowing it, and the operator would see interception stop with no way to connect it to
// the switch they flipped.
func TestWithNoScopeAttachedTheFilterRefusesToFilter(t *testing.T) {
	e := engineHolding(t, DirectionRequest)
	e.SetInScopeOnly(true) // on, but nothing to consult

	if e.ScopeAttached() {
		t.Fatal("no scope was attached, yet ScopeAttached reports one")
	}
	if held := e.Hold(msg("target.test")); held == nil {
		t.Error("the queue was emptied by a filter with no scope to consult. Refusing to filter is the " +
			"safe direction: an unfiltered queue is a visible inconvenience, an empty one is an outage " +
			"the operator cannot attribute to anything they did")
	}
}

// ScopeAttached is what lets a surface disable the control and say why, rather than offering a
// toggle that changes nothing.
func TestScopeAttachedReportsWhetherTheFilterCanWork(t *testing.T) {
	e := engineHolding(t, DirectionRequest)
	if e.ScopeAttached() {
		t.Error("ScopeAttached is true before a scope was set")
	}
	e.SetScope(stubScope{allowed: map[string]bool{}})
	if !e.ScopeAttached() {
		t.Error("ScopeAttached is false after a scope was set")
	}
}

// Messages already held are untouched, exactly as SetEnabled leaves them: a held message was held
// under the rules in force at the time, and discarding it now because the filter changed would throw
// away traffic an operator is mid-decision on.
func TestTurningTheFilterOnDoesNotDiscardHeldMessages(t *testing.T) {
	e := engineHolding(t, DirectionRequest)
	e.SetScope(stubScope{allowed: map[string]bool{"target.test": true}})

	held := e.Hold(msg("out.of.scope.test"))
	if held == nil {
		t.Fatal("the message was not held with the filter off")
	}
	e.SetInScopeOnly(true)

	queue := e.Held()
	if len(queue) != 1 {
		t.Fatalf("the queue holds %d messages after turning the filter on, want the 1 already held", len(queue))
	}
	if queue[0].Host != "out.of.scope.test" {
		t.Errorf("the held message is %q; the one held before the filter changed must survive it", queue[0].Host)
	}
}

// It applies to every direction, which is the point of gating in shouldHold rather than at the call
// sites. A WebSocket frame is the direction most likely to be missed by a per-call-site check.
func TestTheFilterAppliesToEveryDirection(t *testing.T) {
	for _, dir := range []Direction{
		DirectionRequest, DirectionResponse, DirectionWebSocketToServer, DirectionWebSocketToClient,
	} {
		e := engineHolding(t, dir)
		e.SetScope(stubScope{allowed: map[string]bool{"target.test": true}})
		e.SetInScopeOnly(true)

		out := &Message{Direction: dir, Host: "out.test", Port: 443, TLS: true, Path: "/x", Raw: []byte("x")}
		if held := e.Hold(out); held != nil {
			t.Errorf("direction %v held an out-of-scope message; the filter must not depend on which "+
				"direction the message travelled", dir)
		}
		in := &Message{Direction: dir, Host: "target.test", Port: 443, TLS: true, Path: "/x", Raw: []byte("x")}
		if held := e.Hold(in); held == nil {
			t.Errorf("direction %v refused an in-scope message", dir)
		}
	}
}
