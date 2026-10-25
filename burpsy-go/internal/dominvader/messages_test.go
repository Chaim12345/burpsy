package dominvader

import (
	"testing"
	"time"
)

func TestMessageHoldCanOnlyBeDecidedAndConsumedByItsOwnFrame(t *testing.T) {
	s := NewMessageStore()
	a := s.OpenFrame(1, "top")
	b := s.OpenFrame(1, "child")
	msg, err := s.Record(a, Message{Body: `{"hello":"world"}`, Origin: "https://target.example"}, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if msg.State != "held" || msg.HoldID == "" {
		t.Fatalf("message wasn't held: %+v", msg)
	}
	if err := s.Decide(b, msg.HoldID, MessageDecision{Action: "drop"}, time.Now()); err == nil {
		t.Fatal("other frame decided a hold")
	}
	if err := s.Decide(a, msg.HoldID, MessageDecision{Action: "forward", Body: `"edited"`, Origin: "https://synthetic.example"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := s.Poll(b, time.Now()); len(got) != 0 {
		t.Fatal("decision crossed frame boundary")
	}
	got := s.Poll(a, time.Now())
	if len(got) != 1 || got[0].Body != `"edited"` || !got[0].Synthetic {
		t.Fatalf("edited synthetic replay missing: %+v", got)
	}
	if len(s.Poll(a, time.Now())) != 0 {
		t.Fatal("decision replayed twice")
	}
}

func TestMessageTimeoutIsLoggedAsForwardedOnTimeoutAndCannotBeDecidedLater(t *testing.T) {
	s := NewMessageStore()
	token := s.OpenFrame(1, "top")
	now := time.Now()
	m, err := s.Record(token, Message{Body: `"original"`}, true, now)
	if err != nil {
		t.Fatal(err)
	}
	late := now.Add(MessageTimeout)
	if err := s.Decide(token, m.HoldID, MessageDecision{Action: "drop"}, late); err == nil {
		t.Fatal("expired hold accepted a drop")
	}
	rows := s.Messages(late)
	if len(rows) != 1 || rows[0].State != "forwarded-on-timeout" {
		t.Fatalf("timeout auto-release concealed: %+v", rows)
	}
}

func TestMessagePortObservationsAreLoggedButNeverHeldForJSONReplay(t *testing.T) {
	s := NewMessageStore()
	token := s.OpenFrame(4, "child")
	m, err := s.Record(token, Message{Body: `null`, HasPorts: true}, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if m.State != "not-replayable-ports" || m.HoldID != "" {
		t.Fatalf("port message offered for replay: %+v", m)
	}
}

func TestMessageQueueOverflowIsAnExplicitForwardedBypass(t *testing.T) {
	s := NewMessageStore()
	token := s.OpenFrame(4, "top")
	now := time.Now()
	for i := 0; i < MaxHeldMessages; i++ {
		if _, err := s.Record(token, Message{Body: `1`}, true, now); err != nil {
			t.Fatal(err)
		}
	}
	m, err := s.Record(token, Message{Body: `2`}, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if m.State != "forwarded-queue-full" || m.HoldID != "" {
		t.Fatalf("full queue concealed bypass: %+v", m)
	}
}

func TestBusyMessageLogRetainsHeldRowsUntilTheirTimeoutIsVisible(t *testing.T) {
	s := NewMessageStore()
	token := s.OpenFrame(1, "top")
	now := time.Now()
	held, err := s.Record(token, Message{Body: `"held"`}, true, now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2100; i++ {
		if _, err := s.Record(token, Message{Body: `null`}, false, now); err != nil {
			t.Fatal(err)
		}
	}
	rows := s.Messages(now.Add(MessageTimeout))
	found := false
	for _, m := range rows {
		if m.ID == held.ID {
			found = true
			if m.State != "forwarded-on-timeout" {
				t.Fatalf("timeout hidden by busy log: %+v", m)
			}
		}
	}
	if !found {
		t.Fatal("busy log evicted held row and concealed its timeout")
	}
	if len(rows) > 2000 {
		t.Fatal("message log exceeded bound")
	}
}

func TestMessageDecisionDeliveryDoesNotClaimThePageAppliedIt(t *testing.T) {
	s := NewMessageStore()
	token := s.OpenFrame(1, "top")
	now := time.Now()
	m, err := s.Record(token, Message{Body: `null`}, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Decide(token, m.HoldID, MessageDecision{Action: "drop"}, now); err != nil {
		t.Fatal(err)
	}
	s.Poll(token, now)
	if got := s.Messages(now)[0].State; got != "drop-decision-delivered" {
		t.Fatalf("decision delivery was confused with browser execution: %s", got)
	}
}
