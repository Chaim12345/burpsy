package intercept

import (
	"strings"
	"testing"
)

// ---- directions are addressed, not branched on ------------------------------------------
//
// The engine held two named lists, `requests` and `responses`, selected in three places with
// `if d == DirectionRequest { … } else { … }`. That else is a silent misroute waiting for a
// third direction: a WebSocket frame would have been matched against the *response* rules and
// held or released on the wrong operator's intent, with `Direction.String()` calling it
// "response" in the API, the held queue and the logs.
//
// Both are now indexed by direction. These tests pin the properties that make that safe, and
// the first one fails for any future direction added without a name.

// Exhaustiveness. A direction added to the const block without a row in directionNames shows
// up here rather than in production as an empty label.
func TestEveryDirectionHasADistinctName(t *testing.T) {
	if DirectionCount == 0 {
		t.Fatal("DirectionCount is 0; the sentinel is not last in the const block")
	}
	// The sentinel is only a count if it sits after the last real direction.
	if got, want := int(DirectionWebSocketToClient), DirectionCount-1; got != want {
		t.Fatalf("DirectionWebSocketToClient = %d but DirectionCount-1 = %d; the sentinel must be "+
			"the last constant or every loop over directions stops short", got, want)
	}

	seen := map[string]Direction{}
	for d := Direction(0); int(d) < DirectionCount; d++ {
		name := d.String()
		if name == "" {
			t.Errorf("direction %d has an empty name", int(d))
			continue
		}
		if name == "unknown_direction" {
			t.Errorf("direction %d is in range but names itself unknown; add a directionNames row", int(d))
			continue
		}
		if prior, dup := seen[name]; dup {
			t.Errorf("directions %d and %d share the name %q; the API cannot distinguish them",
				int(prior), int(d), name)
		}
		seen[name] = d
	}
}

// Out of range must say so rather than borrowing a neighbour's label. This is the specific
// regression the old two-value String() would have caused.
func TestAnOutOfRangeDirectionDoesNotBorrowAName(t *testing.T) {
	for _, d := range []Direction{-1, Direction(DirectionCount), Direction(DirectionCount + 7)} {
		got := d.String()
		if got == "response" || got == "request" {
			t.Errorf("Direction(%d).String() = %q — an unknown direction must not present as a "+
				"real one", int(d), got)
		}
		if !strings.Contains(got, "unknown") {
			t.Errorf("Direction(%d).String() = %q, which does not say it is unknown", int(d), got)
		}
	}
}

// Each direction owns its own list. Setting one must not be visible through another — the
// property the `else` branch could not guarantee.
func TestEachDirectionKeepsItsOwnRuleList(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)

	// One distinctive rule per direction, so a cross-wired read is identifiable by content.
	for d := Direction(0); int(d) < DirectionCount; d++ {
		if err := e.SetRules(d, true, []Rule{{
			Field:       FieldHost,
			Category:    CategoryLiteral,
			StringMatch: d.String() + ".test",
			Enabled:     true,
		}}); err != nil {
			t.Fatalf("SetRules(%s): %v", d, err)
		}
	}

	for d := Direction(0); int(d) < DirectionCount; d++ {
		list := e.Rules(d)
		if !list.Active {
			t.Errorf("%s: list is inactive after SetRules(active=true)", d)
			continue
		}
		if len(list.Rules) != 1 {
			t.Errorf("%s: %d rules, want 1", d, len(list.Rules))
			continue
		}
		if want := d.String() + ".test"; list.Rules[0].StringMatch != want {
			t.Errorf("%s: reads back rule %q, want %q — the lists are cross-wired",
				d, list.Rules[0].StringMatch, want)
		}
	}
}

// A held frame must carry the direction it was held in, all the way to the queue the API
// renders. Getting this wrong is how an operator forwards an incoming frame believing it is
// outgoing.
func TestAHeldMessageReportsTheDirectionItWasHeldIn(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	for d := Direction(0); int(d) < DirectionCount; d++ {
		if err := e.SetRules(d, true, nil); err != nil { // unconditional: hold everything
			t.Fatalf("SetRules(%s): %v", d, err)
		}
	}

	for d := Direction(0); int(d) < DirectionCount; d++ {
		held := e.Hold(&Message{Direction: d, Host: "example.test", Port: 443, Path: "/"})
		if held == nil {
			t.Fatalf("%s: an unconditional active list did not hold", d)
		}
		if held.Direction != d {
			t.Errorf("held in %s but the queue entry says %s", d, held.Direction)
		}
		// Release it so the queue does not carry state into the next iteration.
		held.resolve(ActionForward, held.Raw, nil, "")
	}
}

// An unknown direction from a decoded API request must be refused, not written into whichever
// array slot is adjacent — and must not panic the proxy goroutine that called it.
func TestSetRulesRefusesAnUnknownDirection(t *testing.T) {
	e := NewEngine()
	for _, d := range []Direction{-1, Direction(DirectionCount)} {
		err := e.SetRules(d, true, nil)
		if err == nil {
			t.Errorf("SetRules(%d) was accepted; an out-of-range direction is an array index", int(d))
			continue
		}
		if !strings.Contains(err.Error(), "direction") {
			t.Errorf("SetRules(%d) error does not name the problem: %v", int(d), err)
		}
	}
	// And reading one is the zero list rather than a neighbour's.
	if got := e.Rules(Direction(DirectionCount)); got.Active || len(got.Rules) != 0 {
		t.Errorf("Rules(out of range) = %+v, want the zero list", got)
	}
}

// IsWebSocket must agree with the constants rather than being a second list to keep in step.
func TestIsWebSocketCoversExactlyTheWebSocketDirections(t *testing.T) {
	cases := map[Direction]bool{
		DirectionRequest:           false,
		DirectionResponse:          false,
		DirectionWebSocketToServer: true,
		DirectionWebSocketToClient: true,
	}
	if len(cases) != DirectionCount {
		t.Fatalf("this table covers %d directions but DirectionCount is %d; a direction was "+
			"added without deciding whether it is WebSocket", len(cases), DirectionCount)
	}
	for d, want := range cases {
		if got := d.IsWebSocket(); got != want {
			t.Errorf("%s.IsWebSocket() = %v, want %v", d, got, want)
		}
	}
}
