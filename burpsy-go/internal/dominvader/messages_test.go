package dominvader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMessageHoldCanOnlyBeDecidedAndConsumedByItsOwnFrame(t *testing.T) {
	s := NewMessageStore()
	s.SetIntercept(true)
	a := s.OpenFrame(1, "top")
	b := s.OpenFrame(1, "child")
	msg, err := s.Record(a, Message{Body: `{"hello":"world"}`, Origin: "https://target.example"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if msg.State != "held" || msg.HoldID == "" {
		t.Fatalf("message wasn't held: %+v", msg)
	}
	if err := s.ControllerDecide(msg.HoldID, MessageDecision{Action: "forward", Body: `"edited"`, Origin: "https://synthetic.example"}, time.Now()); err != nil {
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
	s.SetIntercept(true)
	token := s.OpenFrame(1, "top")
	now := time.Now()
	m, err := s.Record(token, Message{Body: `"original"`}, now)
	if err != nil {
		t.Fatal(err)
	}
	late := now.Add(MessageTimeout)
	if err := s.ControllerDecide(m.HoldID, MessageDecision{Action: "drop"}, late); err == nil {
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
	m, err := s.Record(token, Message{Body: `null`, HasPorts: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if m.State != "not-replayable-ports" || m.HoldID != "" {
		t.Fatalf("port message offered for replay: %+v", m)
	}
}

func TestMessageQueueOverflowIsAnExplicitForwardedBypass(t *testing.T) {
	s := NewMessageStore()
	s.SetIntercept(true)
	token := s.OpenFrame(4, "top")
	now := time.Now()
	for i := 0; i < MaxHeldMessages; i++ {
		if _, err := s.Record(token, Message{Body: `1`}, now); err != nil {
			t.Fatal(err)
		}
	}
	m, err := s.Record(token, Message{Body: `2`}, now)
	if err != nil {
		t.Fatal(err)
	}
	if m.State != "forwarded-queue-full" || m.HoldID != "" {
		t.Fatalf("full queue concealed bypass: %+v", m)
	}
}

func TestBusyMessageLogRetainsHeldRowsUntilTheirTimeoutIsVisible(t *testing.T) {
	s := NewMessageStore()
	s.SetIntercept(true)
	token := s.OpenFrame(1, "top")
	now := time.Now()
	held, err := s.Record(token, Message{Body: `"held"`}, now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2100; i++ {
		if _, err := s.Record(token, Message{Body: `null`}, now); err != nil {
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
	s.SetIntercept(true)
	token := s.OpenFrame(1, "top")
	now := time.Now()
	m, err := s.Record(token, Message{Body: `null`}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ControllerDecide(m.HoldID, MessageDecision{Action: "drop"}, now); err != nil {
		t.Fatal(err)
	}
	s.Poll(token, now)
	if got := s.Messages(now)[0].State; got != "drop-decision-delivered-to-worker" {
		t.Fatalf("decision delivery was confused with browser execution: %s", got)
	}
}

func TestWorkerLaunchCapabilityIsPrivateToTheWorkerAndRotates(t *testing.T) {
	s := NewStore()
	cfg := s.BeginWorkerLaunch("http://localhost/hit")
	if cfg.WorkerCapability == "" || !s.WorkerAuthorized(cfg.WorkerCapability) {
		t.Fatal("launch did not establish worker capability")
	}
	dir, err := Materialise(t.TempDir(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	main, err := os.ReadFile(filepath.Join(dir, "config.js"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(main), cfg.WorkerCapability) {
		t.Fatal("worker capability leaked into page-world config")
	}
	worker, err := os.ReadFile(filepath.Join(dir, "worker-config.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(worker), cfg.WorkerCapability) {
		t.Fatal("worker cannot authenticate its own launch")
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifest), "worker-config.js") {
		t.Fatal("worker-only config declared page accessible")
	}
	next := s.BeginWorkerLaunch("http://localhost/hit")
	if next.WorkerCapability == cfg.WorkerCapability || s.WorkerAuthorized(cfg.WorkerCapability) || s.WorkerAuthorized("") {
		t.Fatal("stale/empty capability remained authorized")
	}
}
