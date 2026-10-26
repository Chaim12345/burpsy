package agent

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	defaultMaxDepth    = 2
	defaultMaxChildren = 4
)

// SpawnRequest asks for a sub-task: a goal split into a child run with its own transcript and its
// own approval state. Scope narrows the parent's, and Policy can only tighten the parent's.
type SpawnRequest struct {
	Goal   string
	Scope  []string
	Policy *Policy
}

// ChildView is what a parent sees of a child between turns. NeedsHuman is true while the child
// waits on an approval ("needs human intervention").
type ChildView struct {
	ID         string `json:"id"`
	Goal       string `json:"goal"`
	Status     Status `json:"status"`
	NeedsHuman bool   `json:"needs_human"`
	Summary    string `json:"summary,omitempty"`
}

func (r *Run) childView() ChildView {
	r.mu.Lock()
	defer r.mu.Unlock()
	return ChildView{ID: r.task.ID, Goal: r.task.Goal, Status: r.status,
		NeedsHuman: r.status == StatusAwaitingApproval, Summary: r.summary}
}

func (s *Supervisor) maxDepth() int {
	if s.MaxDepth > 0 {
		return s.MaxDepth
	}
	return defaultMaxDepth
}

func (s *Supervisor) maxChildren() int {
	if s.MaxChildren > 0 {
		return s.MaxChildren
	}
	return defaultMaxChildren
}

func scopeWithin(child, parent []string) (string, bool) {
	allowed := map[string]bool{}
	for _, p := range parent {
		allowed[strings.ToLower(strings.TrimSpace(p))] = true
	}
	for _, c := range child {
		if !allowed[strings.ToLower(strings.TrimSpace(c))] {
			return c, false
		}
	}
	return "", true
}

// spawn starts one child run. The child's ID is "<parent>/<n>".
func (r *Run) spawn(ctx context.Context, req SpawnRequest, parentPlanner Planner) error {
	if strings.TrimSpace(req.Goal) == "" {
		return fmt.Errorf("a sub-task needs a goal")
	}
	if r.depth+1 > r.sup.maxDepth() {
		return fmt.Errorf("sub-task depth limit %d reached", r.sup.maxDepth())
	}
	scope := req.Scope
	if len(scope) == 0 {
		scope = r.task.Scope
	} else if bad, ok := scopeWithin(scope, r.task.Scope); !ok {
		return fmt.Errorf("scope %q is outside the parent's scope; a sub-task can only narrow it", bad)
	}
	r.mu.Lock()
	if len(r.children) >= r.sup.maxChildren() {
		r.mu.Unlock()
		return fmt.Errorf("sub-task limit %d reached", r.sup.maxChildren())
	}
	id := fmt.Sprintf("%s/%d", r.task.ID, len(r.children)+1)
	r.mu.Unlock()

	base := r.policy
	if req.Policy != nil {
		base = *req.Policy
	}
	pol := base.TightenedBy(r.policy)
	pl := parentPlanner
	if r.sup.ChildPlanner != nil {
		pl = r.sup.ChildPlanner(r.task, req)
	}
	task := Task{ID: id, Goal: req.Goal, Scope: append([]string(nil), scope...), Resources: r.task.Resources}
	child := r.sup.start(ctx, task, pl, pol, r)
	r.mu.Lock()
	r.children = append(r.children, child)
	r.mu.Unlock()
	r.append(Event{Kind: EventSpawn, Tool: id, Message: req.Goal})
	return nil
}

// waitChildren blocks until every child has finished. While ctx is live that wait has no bound: the
// caller asked for AwaitChildren. Once ctx ends the children are being cancelled (their contexts
// derive from the parent's), and the parent gives them StopGrace to finish so it never reports itself
// stopped with a child still running, and never hangs on a child whose Invoker, Planner or Approver
// ignores cancellation: after the grace it stops waiting and the straggler is left to its own
// context, as it was before.
func (r *Run) waitChildren(ctx context.Context) {
	r.mu.Lock()
	kids := append([]*Run(nil), r.children...)
	r.mu.Unlock()
	var grace <-chan time.Time
	for _, k := range kids {
		select {
		case <-k.Done():
			continue
		case <-ctx.Done():
		}
		if grace == nil {
			d := r.sup.StopGrace
			if d <= 0 {
				d = 5 * time.Second
			}
			timer := time.NewTimer(d)
			defer timer.Stop()
			grace = timer.C
		}
		select {
		case <-k.Done():
		case <-grace:
			return
		}
	}
}
