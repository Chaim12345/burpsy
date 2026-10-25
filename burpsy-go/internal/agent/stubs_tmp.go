package agent

import "context"

type Resource struct{}
type SpawnRequest struct{}
type ChildView struct{}

func (r *Run) childView() ChildView                               { return ChildView{} }
func (r *Run) spawn(context.Context, SpawnRequest, Planner) error { return nil }
func (r *Run) waitChildren(context.Context)                       {}
func (r *Run) lookupDedup(int, Call) (int, bool)                  { return 0, false }
func (r *Run) reuse(int, int)                                     {}
func (r *Run) recordDedup(int, Call, int)                         {}
