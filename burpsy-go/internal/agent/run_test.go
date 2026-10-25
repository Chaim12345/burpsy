package agent

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// scriptedPlanner returns a fixed list of proposals, one per turn, then Done.
type scriptedPlanner struct {
	mu    sync.Mutex
	turns []Proposal
	seen  [][]StepView
}

func (p *scriptedPlanner) Next(_ context.Context, tv TaskView) (Proposal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, tv.History)
	if len(p.seen) > len(p.turns) {
		return Proposal{Done: true, Summary: "finished"}, nil
	}
	return p.turns[len(p.seen)-1], nil
}

type fakeInvoker struct {
	mu      sync.Mutex
	calls   []Call
	need428 map[string]bool // tool -> answer 428 unless a token is present
	block   chan struct{}
}

func (f *fakeInvoker) Invoke(ctx context.Context, c Call) (Outcome, error) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return Outcome{}, ctx.Err()
		}
	}
	if f.need428[c.Tool] && c.Confirm == "" {
		return Outcome{Status: 428, Body: []byte(`{"error":"confirmation required"}`)}, nil
	}
	return Outcome{Status: 200, Body: []byte(`{"ok":true}`)}, nil
}

func (f *fakeInvoker) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

type fakeApprover struct {
	mu      sync.Mutex
	pending []Pending
	decide  func(Pending) Decision
}

func (a *fakeApprover) Approve(_ context.Context, p Pending) (Decision, error) {
	a.mu.Lock()
	a.pending = append(a.pending, p)
	a.mu.Unlock()
	return a.decide(p), nil
}

var risks = map[string]Risk{
	"GET /api/history":    RiskRead,
	"POST /api/repeater":  RiskEgress,
	"POST /api/audit":     RiskAttack,
	"POST /api/annotate":  RiskLocal,
	"DELETE /api/history": RiskDestructive,
}

func classify(tool string) (Risk, bool) { r, ok := risks[tool]; return r, ok }

func call(tool string) Call { return Call{Tool: tool, Args: json.RawMessage(`{}`)} }

func newSup(inv Invoker, ap Approver, pol Policy) *Supervisor {
	return &Supervisor{Classify: classify, Invoker: inv, Approver: ap, Policy: pol, MaxSteps: 20}
}

func runTask(t *testing.T, s *Supervisor, pl Planner, task Task) *Run {
	t.Helper()
	r := s.Start(context.Background(), task, pl)
	done := make(chan struct{})
	go func() { r.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not finish")
	}
	return r
}

func TestReadAutoRunsAttackWaitsForApproval(t *testing.T) {
	inv := &fakeInvoker{}
	ap := &fakeApprover{decide: func(p Pending) Decision { return Decision{Approved: true, Token: "tok-" + p.Call.Tool} }}
	pl := &scriptedPlanner{turns: []Proposal{
		{Calls: []Call{call("GET /api/history")}},
		{Calls: []Call{call("POST /api/audit")}},
	}}
	r := runTask(t, newSup(inv, ap, Policy{}), pl, Task{ID: "t1", Goal: "look around"})
	snap := r.Snapshot()
	if snap.Status != StatusDone {
		t.Fatalf("status %s: %s", snap.Status, snap.Error)
	}
	if len(ap.pending) != 1 || ap.pending[0].Call.Tool != "POST /api/audit" || ap.pending[0].Risk != RiskAttack {
		t.Fatalf("approver saw %+v, want only the audit with its risk", ap.pending)
	}
	if inv.calls[0].Confirm != "" || inv.calls[1].Confirm != "tok-POST /api/audit" {
		t.Fatalf("tokens %q %q: the read must carry none and the audit the approver's token", inv.calls[0].Confirm, inv.calls[1].Confirm)
	}
	if snap.Summary != "finished" {
		t.Errorf("summary %q", snap.Summary)
	}
}

func TestDeniedStepIsNeverInvokedAndPlannerSeesTheDenial(t *testing.T) {
	inv := &fakeInvoker{}
	ap := &fakeApprover{decide: func(Pending) Decision { return Decision{Approved: false, Reason: "not now"} }}
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("DELETE /api/history")}}}}
	r := runTask(t, newSup(inv, ap, Policy{}), pl, Task{ID: "t"})
	if inv.count() != 0 {
		t.Fatalf("a denied step was invoked %d times", inv.count())
	}
	last := pl.seen[len(pl.seen)-1]
	if len(last) != 1 || last[0].Status != StepDenied || last[0].Reason != "not now" {
		t.Fatalf("planner history %+v", last)
	}
	if r.Snapshot().Status != StatusDone {
		t.Fatalf("a denial must not fail the run, status %s", r.Snapshot().Status)
	}
}

func TestUnknownToolIsRefusedNotInvoked(t *testing.T) {
	inv := &fakeInvoker{}
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("POST /api/made-up")}}}}
	r := runTask(t, newSup(inv, &fakeApprover{decide: func(Pending) Decision { return Decision{Approved: true} }}, Policy{}), pl, Task{ID: "t"})
	if inv.count() != 0 {
		t.Fatal("a tool the manifest does not name was invoked")
	}
	if s := r.Snapshot().Steps[0]; s.Status != StepRefused || s.Reason == "" {
		t.Fatalf("step %+v", s)
	}
}

func TestDisabledToolIsRefused(t *testing.T) {
	inv := &fakeInvoker{}
	pol := Policy{Tools: map[string]ToolSetting{"GET /api/history": SettingDisabled}}
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("GET /api/history")}}}}
	r := runTask(t, newSup(inv, nil, pol), pl, Task{ID: "t"})
	if inv.count() != 0 || r.Snapshot().Steps[0].Status != StepRefused {
		t.Fatalf("disabled tool ran or was not refused: %+v", r.Snapshot().Steps)
	}
}

func TestServerGate428EscalatesInsteadOfRetryingBlind(t *testing.T) {
	// The policy lets a local-write through, but the console's gate says 428. The supervisor asks.
	inv := &fakeInvoker{need428: map[string]bool{"POST /api/annotate": true}}
	ap := &fakeApprover{decide: func(Pending) Decision { return Decision{Approved: true, Token: "tok"} }}
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("POST /api/annotate")}}}}
	r := runTask(t, newSup(inv, ap, Policy{}), pl, Task{ID: "t"})
	if inv.count() != 2 || inv.calls[0].Confirm != "" || inv.calls[1].Confirm != "tok" {
		t.Fatalf("calls %+v", inv.calls)
	}
	if len(ap.pending) != 1 {
		t.Fatalf("approver asked %d times", len(ap.pending))
	}
	if r.Snapshot().Steps[0].Status != StepDone {
		t.Fatalf("step %+v", r.Snapshot().Steps[0])
	}
}

func TestServerGate428WithoutApproverFails(t *testing.T) {
	inv := &fakeInvoker{need428: map[string]bool{"POST /api/annotate": true}}
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("POST /api/annotate")}}}}
	r := runTask(t, newSup(inv, nil, Policy{}), pl, Task{ID: "t"})
	if inv.count() != 1 {
		t.Fatalf("retried without a token: %d calls", inv.count())
	}
	if s := r.Snapshot().Steps[0]; s.Status != StepDenied {
		t.Fatalf("step %+v", s)
	}
}

func TestTranscriptRecordsEveryEventInOrder(t *testing.T) {
	inv := &fakeInvoker{}
	ap := &fakeApprover{decide: func(Pending) Decision { return Decision{Approved: true, Token: "x"} }}
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("POST /api/audit")}}}}
	r := runTask(t, newSup(inv, ap, Policy{}), pl, Task{ID: "t", Goal: "g"})
	var kinds []EventKind
	for _, e := range r.Snapshot().Transcript {
		kinds = append(kinds, e.Kind)
	}
	want := []EventKind{EventTask, EventProposed, EventDecision, EventResult, EventDone}
	if len(kinds) != len(want) {
		t.Fatalf("events %v want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("events %v want %v", kinds, want)
		}
	}
	for i, e := range r.Snapshot().Transcript {
		if e.Seq != i+1 {
			t.Fatalf("seq %d at %d", e.Seq, i)
		}
	}
	res := r.Snapshot().Transcript[3]
	if res.Status != 200 || string(res.Body) != `{"ok":true}` {
		t.Fatalf("result event %+v", res)
	}
}

func TestResultBodyIsCappedAndFlagged(t *testing.T) {
	big := make([]byte, MaxTranscriptBody+10)
	for i := range big {
		big[i] = 'a'
	}
	inv := invokerFunc(func(context.Context, Call) (Outcome, error) { return Outcome{Status: 200, Body: big}, nil })
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("GET /api/history")}}}}
	r := runTask(t, newSup(inv, nil, Policy{}), pl, Task{ID: "t"})
	var res Event
	for _, e := range r.Snapshot().Transcript {
		if e.Kind == EventResult {
			res = e
		}
	}
	if len(res.Body) != MaxTranscriptBody || !res.Truncated {
		t.Fatalf("body %d truncated %v", len(res.Body), res.Truncated)
	}
}

type invokerFunc func(context.Context, Call) (Outcome, error)

func (f invokerFunc) Invoke(ctx context.Context, c Call) (Outcome, error) { return f(ctx, c) }

func TestMaxStepsStopsARunawayPlanner(t *testing.T) {
	inv := &fakeInvoker{}
	pl := plannerFunc(func(context.Context, TaskView) (Proposal, error) {
		return Proposal{Calls: []Call{call("GET /api/history")}}, nil
	})
	s := newSup(inv, nil, Policy{})
	s.MaxSteps = 3
	r := runTask(t, s, pl, Task{ID: "t"})
	if r.Snapshot().Status != StatusLimit || inv.count() != 3 {
		t.Fatalf("status %s, %d calls", r.Snapshot().Status, inv.count())
	}
}

type plannerFunc func(context.Context, TaskView) (Proposal, error)

func (f plannerFunc) Next(ctx context.Context, tv TaskView) (Proposal, error) { return f(ctx, tv) }

func TestPlannerErrorFailsTheRun(t *testing.T) {
	pl := plannerFunc(func(context.Context, TaskView) (Proposal, error) { return Proposal{}, errors.New("llm down") })
	r := runTask(t, newSup(&fakeInvoker{}, nil, Policy{}), pl, Task{ID: "t"})
	if s := r.Snapshot(); s.Status != StatusFailed || s.Error != "llm down" {
		t.Fatalf("%+v", s)
	}
}

func TestStopInterruptsAnInFlightCall(t *testing.T) {
	inv := &fakeInvoker{block: make(chan struct{})}
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("GET /api/history")}}}}
	r := newSup(inv, nil, Policy{}).Start(context.Background(), Task{ID: "t"}, pl)
	deadline := time.After(3 * time.Second)
	for inv.count() == 0 {
		select {
		case <-deadline:
			t.Fatal("call never started")
		case <-time.After(5 * time.Millisecond):
		}
	}
	r.Stop()
	done := make(chan struct{})
	go func() { r.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not interrupt the in-flight call")
	}
	if r.Snapshot().Status != StatusStopped {
		t.Fatalf("status %s", r.Snapshot().Status)
	}
}

func TestStopWhileAwaitingApprovalReleasesTheApprover(t *testing.T) {
	released := make(chan struct{})
	ap := approverFunc(func(ctx context.Context, _ Pending) (Decision, error) {
		<-ctx.Done()
		close(released)
		return Decision{}, ctx.Err()
	})
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("POST /api/audit")}}}}
	inv := &fakeInvoker{}
	r := newSup(inv, ap, Policy{}).Start(context.Background(), Task{ID: "t"}, pl)
	for r.Snapshot().Status != StatusAwaitingApproval {
		time.Sleep(5 * time.Millisecond)
	}
	r.Stop()
	r.Wait()
	<-released
	if inv.count() != 0 || r.Snapshot().Status != StatusStopped {
		t.Fatalf("calls %d status %s", inv.count(), r.Snapshot().Status)
	}
}

type approverFunc func(context.Context, Pending) (Decision, error)

func (f approverFunc) Approve(ctx context.Context, p Pending) (Decision, error) { return f(ctx, p) }

func TestPendingCarriesRunIdentityAndScope(t *testing.T) {
	ap := &fakeApprover{decide: func(Pending) Decision { return Decision{Approved: true, Token: "x"} }}
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{{Tool: "POST /api/audit", Args: json.RawMessage(`{"u":1}`), Rationale: "probe"}}}}}
	runTask(t, newSup(&fakeInvoker{}, ap, Policy{}), pl, Task{ID: "run-9", Goal: "g", Scope: []string{"example.test"}})
	p := ap.pending[0]
	if p.RunID != "run-9" || p.Call.Rationale != "probe" || string(p.Call.Args) != `{"u":1}` || p.Reason == "" {
		t.Fatalf("%+v", p)
	}
}

func TestStartingScopeIsPassedToTheInvoker(t *testing.T) {
	var got []string
	inv := invokerFunc(func(_ context.Context, c Call) (Outcome, error) { got = c.Scope; return Outcome{Status: 200}, nil })
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("GET /api/history")}}}}
	runTask(t, newSup(inv, nil, Policy{}), pl, Task{ID: "t", Scope: []string{"a.test"}})
	if len(got) != 1 || got[0] != "a.test" {
		t.Fatalf("scope %v", got)
	}
}
