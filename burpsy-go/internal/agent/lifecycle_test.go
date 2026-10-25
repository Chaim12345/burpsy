package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDedupSameTurnReissuedCallRunsOnce(t *testing.T) {
	inv := &fakeInvoker{}
	ap := &fakeApprover{decide: func(Pending) Decision { return Decision{Approved: true, Token: "x"} }}
	// Same tool, args spelled with different key order and whitespace: one canonical call.
	a := Call{Tool: "POST /api/audit", Args: json.RawMessage(`{"a":1,"b":2}`)}
	b := Call{Tool: "POST /api/audit", Args: json.RawMessage(`{ "b": 2, "a": 1 }`)}
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{a, b}}}}
	r := runTask(t, newSup(inv, ap, Policy{}), pl, Task{ID: "t"})
	if inv.count() != 1 || len(ap.pending) != 1 {
		t.Fatalf("invoked %d times, asked %d times; a re-issued call must not resend or re-ask", inv.count(), len(ap.pending))
	}
	steps := r.Snapshot().Steps
	if len(steps) != 2 || !steps[1].Deduped || steps[1].Status != StepDone || steps[1].Body != steps[0].Body {
		t.Fatalf("steps %+v", steps)
	}
}

func TestDedupDoesNotCrossTurnsOrArgs(t *testing.T) {
	inv := &fakeInvoker{}
	c := call("GET /api/history")
	d := Call{Tool: "GET /api/history", Args: json.RawMessage(`{"x":1}`)}
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{c, d}}, {Calls: []Call{c}}}}
	runTask(t, newSup(inv, nil, Policy{}), pl, Task{ID: "t"})
	if inv.count() != 3 {
		t.Fatalf("invoked %d times, want 3 (different args and a later turn are new calls)", inv.count())
	}
}

func TestDedupKeyIsSessionTurnToolArgs(t *testing.T) {
	k := func(s string, turn int, tool, args string) string {
		return dedupKey(s, turn, tool, json.RawMessage(args))
	}
	base := k("s", 1, "t", `{"a":1}`)
	if base != k("s", 1, "t", ` {"a" : 1} `) {
		t.Error("whitespace must not change the key")
	}
	for name, other := range map[string]string{
		"session": k("s2", 1, "t", `{"a":1}`), "turn": k("s", 2, "t", `{"a":1}`),
		"tool": k("s", 1, "u", `{"a":1}`), "args": k("s", 1, "t", `{"a":2}`),
	} {
		if other == base {
			t.Errorf("%s must change the key", name)
		}
	}
	if len(base) != 64 {
		t.Errorf("want hex sha-256, got %q", base)
	}
}

func TestResourcesAttachAndReachThePlanner(t *testing.T) {
	inv := &fakeInvoker{}
	pl := &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("GET /api/history")}}}}
	var seen []Resource
	wrapped := plannerFunc(func(ctx context.Context, tv TaskView) (Proposal, error) {
		seen = tv.Task.Resources
		return pl.Next(ctx, tv)
	})
	task := Task{ID: "t", Resources: []Resource{{Kind: ResourceIssue, Ref: "42", Title: "XSS"}}}
	runTask(t, newSup(inv, nil, Policy{}), wrapped, task)
	if len(seen) != 1 || seen[0].Kind != ResourceIssue || seen[0].Ref != "42" {
		t.Fatalf("planner saw %+v", seen)
	}
}

func TestResourceValidation(t *testing.T) {
	for _, bad := range []Resource{{Kind: "nope", Ref: "1"}, {Kind: ResourceProxy, Ref: " "}, {Kind: ResourceTarget, Ref: strings.Repeat("a", 5000)}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v must be refused", bad)
		}
	}
	if err := (Resource{Kind: ResourceProxy, Ref: "17"}).Validate(); err != nil {
		t.Error(err)
	}
}

func block() (*fakeInvoker, *scriptedPlanner) {
	return &fakeInvoker{block: make(chan struct{})}, &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("GET /api/history")}}}}
}

func TestManagerLifecycle(t *testing.T) {
	inv := &fakeInvoker{}
	m := NewManager(newSup(inv, nil, Policy{}))
	pl := &scriptedPlanner{turns: nil}
	r, err := m.Create(context.Background(), Task{ID: "a", Goal: "g"}, pl)
	if err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if _, err := m.Create(context.Background(), Task{ID: "a"}, pl); err == nil {
		t.Fatal("a duplicate task id must be refused")
	}
	if err := m.Rename("a", "  Recon  "); err != nil {
		t.Fatal(err)
	}
	if err := m.Rename("a", "  "); err == nil {
		t.Fatal("empty name must be refused")
	}
	if m.List(false)[0].Name != "Recon" {
		t.Fatalf("%+v", m.List(false))
	}
	if err := m.Archive("a"); err != nil {
		t.Fatal(err)
	}
	if len(m.List(false)) != 0 || len(m.List(true)) != 1 || !m.List(true)[0].Archived {
		t.Fatal("archived run must leave the default list and stay in the full one")
	}
	if err := m.Restore("a"); err != nil || len(m.List(false)) != 1 {
		t.Fatalf("restore: %v", err)
	}
	if err := m.Archive("zzz"); err == nil {
		t.Fatal("unknown id must error")
	}
}

func TestArchiveRefusedWhileRunning(t *testing.T) {
	inv, pl := block()
	m := NewManager(newSup(inv, nil, Policy{}))
	r, _ := m.Create(context.Background(), Task{ID: "a"}, pl)
	for inv.count() == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if err := m.Archive("a"); err == nil {
		t.Fatal("an active run cannot be archived")
	}
	if err := m.Stop("a"); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if m.Get("a").Snapshot().Status != StatusStopped {
		t.Fatal("Stop must end the run")
	}
	if err := m.Archive("a"); err != nil {
		t.Fatal(err)
	}
}

func TestAttachResourceToLiveRunIsSeenNextTurn(t *testing.T) {
	var turns atomic.Int32
	gate := make(chan struct{})
	var seenLast []Resource
	pl := plannerFunc(func(_ context.Context, tv TaskView) (Proposal, error) {
		if turns.Add(1) == 1 {
			<-gate
			return Proposal{Calls: []Call{call("GET /api/history")}}, nil
		}
		seenLast = tv.Task.Resources
		return Proposal{Done: true}, nil
	})
	m := NewManager(newSup(&fakeInvoker{}, nil, Policy{}))
	r, _ := m.Create(context.Background(), Task{ID: "a"}, pl)
	if err := m.Attach("a", Resource{Kind: ResourceProxy, Ref: "9"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Attach("a", Resource{Kind: ResourceProxy, Ref: "9"}); err != nil {
		t.Fatal(err)
	}
	close(gate)
	r.Wait()
	if len(seenLast) != 1 || seenLast[0].Ref != "9" {
		t.Fatalf("resources %+v (a duplicate attach must be a no-op)", seenLast)
	}
	if err := m.Attach("a", Resource{Kind: "bad", Ref: "1"}); err == nil {
		t.Fatal("invalid resource refused")
	}
}

// ---- sub-tasks (51li) ----

func TestSubtasksRunInParallelWithOwnApprovalState(t *testing.T) {
	inv := &fakeInvoker{}
	asked := make(chan Pending, 4)
	release := make(chan struct{})
	ap := approverFunc(func(ctx context.Context, p Pending) (Decision, error) {
		asked <- p
		select {
		case <-release:
			return Decision{Approved: true, Token: "tok-" + p.RunID}, nil
		case <-ctx.Done():
			return Decision{}, ctx.Err()
		}
	})
	child := func(string) Planner {
		return &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("POST /api/audit")}}}}
	}
	parent := &scriptedPlanner{turns: []Proposal{
		{Spawns: []SpawnRequest{{Goal: "A", Scope: []string{"a.test"}}, {Goal: "B", Scope: []string{"a.test"}}}, AwaitChildren: true},
	}}
	s := newSup(inv, ap, Policy{})
	s.ChildPlanner = func(Task, SpawnRequest) Planner { return child("") }
	r := s.Start(context.Background(), Task{ID: "p", Goal: "split", Scope: []string{"a.test", "b.test"}}, parent)

	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case p := <-asked:
			got[p.RunID] = true
		case <-time.After(3 * time.Second):
			t.Fatal("both children must be asking at once (parallel)")
		}
	}
	if !got["p/1"] || !got["p/2"] {
		t.Fatalf("approvals were not per child run: %v", got)
	}
	// While both wait, the parent view shows them needing a human.
	deadline := time.Now().Add(3 * time.Second)
	for {
		tv := r.view(1)
		if len(tv.Children) == 2 && tv.Children[0].NeedsHuman && tv.Children[1].NeedsHuman {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("children %+v", tv.Children)
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	r.Wait()
	snap := r.Snapshot()
	if snap.Status != StatusDone || len(snap.Children) != 2 {
		t.Fatalf("%s %v %s", snap.Status, snap.Children, snap.Error)
	}
	if inv.count() != 2 {
		t.Fatalf("invoked %d", inv.count())
	}
}

func TestSubtaskCannotWidenScopeOrLoosenPolicy(t *testing.T) {
	inv := &fakeInvoker{}
	ap := &fakeApprover{decide: func(Pending) Decision { return Decision{Approved: true, Token: "x"} }}
	loose := Policy{Mode: ModeAutonomous, Tools: map[string]ToolSetting{"POST /api/repeater": SettingAct, "GET /api/history": SettingAct}}
	parent := &scriptedPlanner{turns: []Proposal{{
		Spawns: []SpawnRequest{
			{Goal: "wide", Scope: []string{"evil.test"}},
			{Goal: "loose", Scope: []string{"a.test"}, Policy: &loose},
		},
		AwaitChildren: true,
	}}}
	s := newSup(inv, ap, Policy{Mode: ModeManual, Tools: map[string]ToolSetting{"GET /api/history": SettingDisabled}})
	s.ChildPlanner = func(Task, SpawnRequest) Planner {
		return &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("POST /api/repeater"), call("GET /api/history")}}}}
	}
	r := runTask(t, s, parent, Task{ID: "p", Scope: []string{"a.test"}})
	snap := r.Snapshot()
	if len(snap.Children) != 1 {
		t.Fatalf("the out-of-scope spawn must be refused: children %v", snap.Children)
	}
	var refused bool
	for _, e := range snap.Transcript {
		if e.Kind == EventRefused && strings.Contains(e.Message, "scope") {
			refused = true
		}
	}
	if !refused {
		t.Fatal("transcript must record the refused spawn and why")
	}
	if len(ap.pending) != 1 || ap.pending[0].Call.Tool != "POST /api/repeater" {
		t.Fatalf("Manual from the parent must still ask in the child: %+v", ap.pending)
	}
	if inv.count() != 1 {
		t.Fatalf("the parent's disabled tool must stay disabled in the child; invoked %d", inv.count())
	}
}

func TestSubtaskDepthAndCountLimits(t *testing.T) {
	var spawn func(Task, SpawnRequest) Planner
	s := newSup(&fakeInvoker{}, nil, Policy{})
	s.MaxDepth, s.MaxChildren = 1, 2
	spawn = func(Task, SpawnRequest) Planner {
		return &scriptedPlanner{turns: []Proposal{{Spawns: []SpawnRequest{{Goal: "grandchild"}}, AwaitChildren: true}}}
	}
	s.ChildPlanner = spawn
	parent := &scriptedPlanner{turns: []Proposal{{Spawns: []SpawnRequest{{Goal: "1"}, {Goal: "2"}, {Goal: "3"}}, AwaitChildren: true}}}
	r := runTask(t, s, parent, Task{ID: "p"})
	snap := r.Snapshot()
	if len(snap.Children) != 2 {
		t.Fatalf("MaxChildren 2: got %v", snap.Children)
	}
	for _, id := range snap.Children {
		_ = id
	}
}

func TestStoppingParentStopsChildren(t *testing.T) {
	inv, _ := block()
	s := newSup(inv, nil, Policy{})
	s.ChildPlanner = func(Task, SpawnRequest) Planner {
		return &scriptedPlanner{turns: []Proposal{{Calls: []Call{call("GET /api/history")}}}}
	}
	parent := &scriptedPlanner{turns: []Proposal{{Spawns: []SpawnRequest{{Goal: "c"}}, AwaitChildren: true}}}
	r := s.Start(context.Background(), Task{ID: "p"}, parent)
	for inv.count() == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	r.Stop()
	r.Wait()
	if r.Snapshot().Status != StatusStopped {
		t.Fatalf("status %s", r.Snapshot().Status)
	}
	for _, c := range r.children {
		if c.Snapshot().Status != StatusStopped {
			t.Fatalf("child status %s", c.Snapshot().Status)
		}
	}
}
