package dominvader

import (
	"strings"
	"testing"
	"time"
)

func held(t *testing.T, s *MessageStore, token string, now time.Time) Message {
	t.Helper()
	m, err := s.Record(token, Message{Body: `{"a":1}`, Origin: "https://t.example"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if m.State != "held" {
		t.Fatalf("expected held, got %s", m.State)
	}
	return m
}

// Interception is controller state. A worker report (Record) can never switch it on.
func TestWorkerReportCannotEnableInterception(t *testing.T) {
	s := NewMessageStore()
	tok := s.OpenFrame(1, "top")
	m, err := s.Record(tok, Message{Body: `1`, State: "held", HoldID: "forged"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if m.State != "observed" || m.HoldID != "" {
		t.Fatalf("report self-selected a held state: %+v", m)
	}
	if s.Intercept() {
		t.Fatal("interception enabled without controller")
	}
}

// The controller decides by server-issued hold ID alone; a frame token or a
// page/worker-supplied ID never authorizes a decision.
func TestControllerDecisionResolvesFrameFromServerHoldAndRejectsGuessedIDs(t *testing.T) {
	s := NewMessageStore()
	s.SetIntercept(true)
	a := s.OpenFrame(1, "top")
	b := s.OpenFrame(1, "child")
	now := time.Now()
	m := held(t, s, a, now)
	for _, id := range []string{"", "1", a, b, "forged"} {
		if err := s.ControllerDecide(id, MessageDecision{Action: "drop"}, now); err == nil {
			t.Fatalf("decision accepted for non-hold id %q", id)
		}
	}
	if err := s.ControllerDecide(m.HoldID, MessageDecision{Action: "bogus"}, now); err == nil {
		t.Fatal("invalid action accepted")
	}
	if err := s.ControllerDecide(m.HoldID, MessageDecision{Action: "forward", Body: `{bad`}, now); err == nil {
		t.Fatal("invalid forward body accepted")
	}
	if err := s.ControllerDecide(m.HoldID, MessageDecision{Action: "forward", Body: `"x"`}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ControllerDecide(m.HoldID, MessageDecision{Action: "drop"}, now); err == nil {
		t.Fatal("hold decided twice")
	}
	if got := s.Poll(b, now); len(got) != 0 {
		t.Fatal("decision crossed frame boundary")
	}
	got := s.Poll(a, now)
	if len(got) != 1 || got[0].HoldID != m.HoldID || !got[0].Synthetic {
		t.Fatalf("own frame did not receive decision: %+v", got)
	}
}

// Delivery to the worker, and the worker's report of dispatch, are different
// states, and neither is proof the page consumed or applied the message.
func TestAcknowledgmentIsFrameSpecificSingleUseAndLabelledUntrusted(t *testing.T) {
	s := NewMessageStore()
	s.SetIntercept(true)
	a := s.OpenFrame(1, "top")
	b := s.OpenFrame(1, "child")
	now := time.Now()
	m := held(t, s, a, now)
	if err := s.Acknowledge(a, m.HoldID, "dispatched", now); err == nil {
		t.Fatal("ack accepted before any decision was delivered")
	}
	if err := s.ControllerDecide(m.HoldID, MessageDecision{Action: "drop"}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Acknowledge(a, m.HoldID, "dispatched", now); err == nil {
		t.Fatal("ack accepted before delivery to worker")
	}
	s.Poll(a, now)
	if got := s.Messages(now)[0].State; got != "drop-decision-delivered-to-worker" {
		t.Fatalf("state after poll: %s", got)
	}
	if err := s.Acknowledge(b, m.HoldID, "dispatched", now); err == nil {
		t.Fatal("other frame acknowledged a hold")
	}
	if err := s.Acknowledge(a, m.HoldID, "applied-for-sure", now); err == nil {
		t.Fatal("unknown ack outcome accepted")
	}
	if err := s.Acknowledge(a, m.HoldID, "dispatched", now); err != nil {
		t.Fatal(err)
	}
	if err := s.Acknowledge(a, m.HoldID, "dispatched", now); err == nil {
		t.Fatal("ack accepted twice")
	}
	got := s.Messages(now)[0].State
	if got != "drop-worker-reported-dispatched-unverified" || strings.Contains(got, "applied") {
		t.Fatalf("ack state overclaims: %s", got)
	}
}

func TestDeliveredButUnacknowledgedDecisionExpiresVisibly(t *testing.T) {
	s := NewMessageStore()
	s.SetIntercept(true)
	a := s.OpenFrame(1, "top")
	now := time.Now()
	m := held(t, s, a, now)
	if err := s.ControllerDecide(m.HoldID, MessageDecision{Action: "forward", Body: `1`}, now); err != nil {
		t.Fatal(err)
	}
	s.Poll(a, now)
	later := now.Add(MessageTimeout + time.Second)
	if got := s.Messages(later)[0].State; got != "forward-delivered-unacknowledged" {
		t.Fatalf("unacknowledged delivery not visible: %s", got)
	}
	if err := s.Acknowledge(a, m.HoldID, "dispatched", later); err == nil {
		t.Fatal("late ack accepted after expiry")
	}
}

func TestDisablingInterceptionReleasesNothingSilently(t *testing.T) {
	s := NewMessageStore()
	s.SetIntercept(true)
	a := s.OpenFrame(1, "top")
	now := time.Now()
	m := held(t, s, a, now)
	s.SetIntercept(false)
	if got := s.Messages(now)[0]; got.State != "held" || got.HoldID != m.HoldID {
		t.Fatalf("existing hold changed by toggle: %+v", got)
	}
	n, _ := s.Record(a, Message{Body: `2`}, now)
	if n.State != "observed" {
		t.Fatalf("new message held while interception off: %s", n.State)
	}
}
