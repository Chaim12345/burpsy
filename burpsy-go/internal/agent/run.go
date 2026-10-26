package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// MaxTranscriptBody caps the response bytes one transcript event keeps. The cut is flagged on the
// event, never silent.
const MaxTranscriptBody = 64 << 10

// MaxHistoryBody caps the response excerpt a planner sees per past step.
const MaxHistoryBody = 8 << 10

// DefaultMaxSteps bounds a run whose Supervisor does not set MaxSteps.
const DefaultMaxSteps = 50

// Task is what the operator hands over. Scope names the targets the run may touch; the Invoker is
// handed it on every call and enforces it (the console's sender checks scope on the rendered bytes).
type Task struct {
	ID        string
	Goal      string
	Scope     []string
	Resources []Resource
	// Context is untrusted background text (a finding's evidence, say). Planners fence it as data.
	Context string
}

// Call is one proposed or issued tool call. Tool is the manifest key the Classifier knows, such as
// "POST /api/repeater/send". Confirm is filled in by the supervisor from an approval and never
// serialised.
type Call struct {
	Tool      string          `json:"tool"`
	Args      json.RawMessage `json:"args,omitempty"`
	Rationale string          `json:"rationale,omitempty"`
	Confirm   string          `json:"-"`
	Scope     []string        `json:"-"`
}

// Proposal is one planner turn: either a batch of calls, spawn requests, or Done with a summary.
type Proposal struct {
	Done    bool
	Summary string
	// Vectors are further attack vectors the planner names when it finishes (Explore Issue).
	Vectors []string
	Calls   []Call
	// Spawns ask for sub-tasks; AwaitChildren blocks the next turn until every child is finished.
	Spawns        []SpawnRequest
	AwaitChildren bool
}

// Planner proposes the next turn from what has happened so far.
type Planner interface {
	Next(ctx context.Context, tv TaskView) (Proposal, error)
}

// Outcome is a console answer.
type Outcome struct {
	Status int
	Body   []byte
}

// Invoker issues a call against the console. The console's gate is the enforcement: it answers 428
// when a call needs a confirmation it does not carry.
type Invoker interface {
	Invoke(ctx context.Context, c Call) (Outcome, error)
}

// Classifier maps a tool to the risk class of the route it names. ok is false for a tool the
// manifest does not name, which the supervisor refuses.
type Classifier func(tool string) (Risk, bool)

// Pending is what an Approver is asked to decide: the exact call and why it is being asked.
type Pending struct {
	RunID  string `json:"run_id"`
	StepID int    `json:"step_id"`
	Call   Call   `json:"call"`
	Risk   Risk   `json:"risk"`
	Reason string `json:"reason"`
}

// Decision is the human's answer. Token is the console confirmation minted for exactly this call.
type Decision struct {
	Approved bool
	Token    string
	Reason   string
}

// Approver surfaces a Pending to a person and blocks until they decide or ctx ends.
type Approver interface {
	Approve(ctx context.Context, p Pending) (Decision, error)
}

// StepStatus is a step's state.
type StepStatus string

const (
	StepProposed StepStatus = "proposed"
	StepRunning  StepStatus = "running"
	StepDone     StepStatus = "done"
	StepFailed   StepStatus = "failed"
	StepDenied   StepStatus = "denied"
	StepRefused  StepStatus = "refused"
)

// StepView is one step as the planner and the UI see it.
type StepView struct {
	ID         int             `json:"id"`
	Turn       int             `json:"turn"`
	Tool       string          `json:"tool"`
	Args       json.RawMessage `json:"args,omitempty"`
	Risk       Risk            `json:"risk"`
	Status     StepStatus      `json:"status"`
	Reason     string          `json:"reason,omitempty"`
	HTTPStatus int             `json:"http_status,omitempty"`
	Body       string          `json:"body,omitempty"`
	Deduped    bool            `json:"deduped,omitempty"`
}

// TaskView is the planner's input.
type TaskView struct {
	Task     Task
	History  []StepView
	Children []ChildView
	Turn     int
}

// Status is a run's state.
type Status string

const (
	StatusRunning          Status = "running"
	StatusAwaitingApproval Status = "awaiting_approval"
	StatusAwaitingChildren Status = "awaiting_children"
	StatusDone             Status = "done"
	StatusFailed           Status = "failed"
	StatusStopped          Status = "stopped"
	StatusLimit            Status = "limit"
)

func (s Status) finished() bool {
	switch s {
	case StatusDone, StatusFailed, StatusStopped, StatusLimit:
		return true
	}
	return false
}

// EventKind classifies a transcript event.
type EventKind string

const (
	EventTask     EventKind = "task"
	EventProposed EventKind = "proposed"
	EventDecision EventKind = "decision"
	EventResult   EventKind = "result"
	EventRefused  EventKind = "refused"
	EventSpawn    EventKind = "spawn"
	EventDone     EventKind = "done"
	EventError    EventKind = "error"
)

// Event is one append-only transcript entry. Request/response bytes of every issued call are kept
// here (response capped at MaxTranscriptBody), so a finding the run produces is reproducible.
type Event struct {
	Seq       int             `json:"seq"`
	Time      time.Time       `json:"time"`
	Kind      EventKind       `json:"kind"`
	Step      int             `json:"step,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Args      json.RawMessage `json:"args,omitempty"`
	Risk      Risk            `json:"risk,omitempty"`
	Approved  *bool           `json:"approved,omitempty"`
	Message   string          `json:"message,omitempty"`
	Status    int             `json:"status,omitempty"`
	Body      []byte          `json:"body,omitempty"`
	Truncated bool            `json:"truncated,omitempty"`
}

// Supervisor owns the policy and the collaborators a run needs.
type Supervisor struct {
	Classify Classifier
	Invoker  Invoker
	// Approver may be nil: a call that needs approval is then denied.
	Approver Approver
	Policy   Policy
	MaxSteps int
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Limits for sub-tasks; zero values take the defaults in subtask.go.
	MaxDepth int
	// ChildPlanner builds the planner for a sub-task; nil reuses the parent's.
	ChildPlanner func(parent Task, req SpawnRequest) Planner
	MaxChildren  int
}

func (s *Supervisor) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Run is one supervised run. All methods are safe for concurrent use.
type Run struct {
	sup    *Supervisor
	task   Task
	policy Policy

	mu         sync.Mutex
	status     Status
	summary    string
	vectors    []string
	errMsg     string
	steps      []StepView
	events     []Event
	archived   bool
	name       string
	resources  []Resource
	parent     *Run
	depth      int
	children   []*Run
	dedup      map[string]int
	stoppedFlg bool

	cancel context.CancelFunc
	done   chan struct{}
}

// Snapshot is a consistent copy of a run for the UI and for tests.
type Snapshot struct {
	ID         string     `json:"id"`
	ParentID   string     `json:"parent_id,omitempty"`
	Name       string     `json:"name"`
	Goal       string     `json:"goal"`
	Scope      []string   `json:"scope"`
	Resources  []Resource `json:"resources"`
	Status     Status     `json:"status"`
	Archived   bool       `json:"archived"`
	Summary    string     `json:"summary,omitempty"`
	Vectors    []string   `json:"vectors"`
	Error      string     `json:"error,omitempty"`
	Steps      []StepView `json:"steps"`
	Transcript []Event    `json:"transcript"`
	Children   []string   `json:"children"`
}

// Start launches a run and returns at once. ctx bounds it; Stop also ends it.
func (s *Supervisor) Start(ctx context.Context, task Task, pl Planner) *Run {
	return s.start(ctx, task, pl, s.Policy, nil)
}

func (s *Supervisor) start(ctx context.Context, task Task, pl Planner, pol Policy, parent *Run) *Run {
	cctx, cancel := context.WithCancel(ctx)
	r := &Run{
		sup: s, task: task, policy: pol, status: StatusRunning, cancel: cancel,
		done: make(chan struct{}), name: task.Goal, resources: append([]Resource(nil), task.Resources...),
		parent: parent, dedup: map[string]int{},
	}
	if parent != nil {
		r.depth = parent.depth + 1
	}
	r.append(Event{Kind: EventTask, Message: task.Goal})
	go func() {
		defer close(r.done)
		defer cancel()
		r.loop(cctx, pl)
	}()
	return r
}

// Wait blocks until the run is finished.
func (r *Run) Wait() { <-r.done }

// Done is closed when the run is finished.
func (r *Run) Done() <-chan struct{} { return r.done }

// ID is the task ID.
func (r *Run) ID() string { return r.task.ID }

// Stop interrupts the run: the in-flight call's context ends, a pending approval is released, and
// every child run stops with it. Stopping a finished run does nothing.
func (r *Run) Stop() {
	r.mu.Lock()
	if r.status.finished() {
		r.mu.Unlock()
		return
	}
	r.stoppedFlg = true
	kids := append([]*Run(nil), r.children...)
	r.mu.Unlock()
	r.cancel()
	for _, k := range kids {
		k.Stop()
	}
}

// Snapshot copies the run's state.
func (r *Run) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Snapshot{
		ID: r.task.ID, Name: r.name, Goal: r.task.Goal, Scope: append([]string{}, r.task.Scope...),
		Resources: append([]Resource{}, r.resources...), Status: r.status, Archived: r.archived,
		Summary: r.summary, Vectors: append([]string{}, r.vectors...), Error: r.errMsg,
		Steps: append([]StepView{}, r.steps...), Transcript: append([]Event{}, r.events...), Children: []string{},
	}
	if r.parent != nil {
		s.ParentID = r.parent.task.ID
	}
	for _, c := range r.children {
		s.Children = append(s.Children, c.task.ID)
	}
	return s
}

func (r *Run) append(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.Seq = len(r.events) + 1
	e.Time = r.sup.now()
	r.events = append(r.events, e)
}

func (r *Run) setStatus(s Status) {
	r.mu.Lock()
	r.status = s
	r.mu.Unlock()
}

func (r *Run) finish(s Status, errMsg string) {
	r.mu.Lock()
	if r.stoppedFlg && s != StatusDone {
		s = StatusStopped
		errMsg = ""
	}
	r.status = s
	r.errMsg = errMsg
	summary := r.summary
	r.mu.Unlock()
	switch s {
	case StatusDone:
		r.append(Event{Kind: EventDone, Message: summary})
	case StatusStopped:
		r.append(Event{Kind: EventDone, Message: "stopped by the operator"})
	case StatusLimit:
		r.append(Event{Kind: EventDone, Message: "step limit reached"})
	default:
		r.append(Event{Kind: EventError, Message: errMsg})
	}
}

func (r *Run) maxSteps() int {
	if r.sup.MaxSteps > 0 {
		return r.sup.MaxSteps
	}
	return DefaultMaxSteps
}

func (r *Run) view(turn int) TaskView {
	r.mu.Lock()
	defer r.mu.Unlock()
	tv := TaskView{Task: r.task, History: append([]StepView(nil), r.steps...), Turn: turn}
	tv.Task.Resources = append([]Resource(nil), r.resources...)
	for _, c := range r.children {
		tv.Children = append(tv.Children, c.childView())
	}
	return tv
}

func (r *Run) loop(ctx context.Context, pl Planner) {
	for turn := 1; ; turn++ {
		if ctx.Err() != nil {
			r.finish(StatusStopped, "")
			return
		}
		r.mu.Lock()
		n := len(r.steps)
		r.mu.Unlock()
		if n >= r.maxSteps() {
			r.finish(StatusLimit, "")
			return
		}
		prop, err := pl.Next(ctx, r.view(turn))
		if err != nil {
			if ctx.Err() != nil {
				r.finish(StatusStopped, "")
				return
			}
			r.finish(StatusFailed, err.Error())
			return
		}
		for _, sp := range prop.Spawns {
			if err := r.spawn(ctx, sp, pl); err != nil {
				r.append(Event{Kind: EventRefused, Message: "spawn refused: " + err.Error()})
			}
		}
		truncated := false
		for _, c := range prop.Calls {
			if ctx.Err() != nil {
				break
			}
			// MaxSteps binds within a proposal too: a single model reply
			// must not be able to run more calls than the budget allows.
			r.mu.Lock()
			spent := len(r.steps)
			r.mu.Unlock()
			if spent >= r.maxSteps() {
				truncated = true
				break
			}
			r.runCall(ctx, turn, c)
		}
		if truncated {
			r.waitChildren(ctx)
			r.finish(StatusLimit, "")
			return
		}
		if prop.AwaitChildren {
			r.setStatus(StatusAwaitingChildren)
			r.waitChildren(ctx)
			r.setStatus(StatusRunning)
		}
		if prop.Done {
			r.mu.Lock()
			r.summary = prop.Summary
			r.vectors = append([]string(nil), prop.Vectors...)
			r.mu.Unlock()
			r.waitChildren(ctx)
			if ctx.Err() != nil {
				r.finish(StatusStopped, "")
				return
			}
			r.finish(StatusDone, "")
			return
		}
	}
}

func excerpt(b []byte, limit int) (string, bool) {
	if len(b) <= limit {
		return string(b), false
	}
	return string(b[:limit]), true
}

func (r *Run) addStep(turn int, c Call, risk Risk) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := len(r.steps) + 1
	r.steps = append(r.steps, StepView{ID: id, Turn: turn, Tool: c.Tool, Args: c.Args, Risk: risk, Status: StepProposed})
	return id
}

func (r *Run) updateStep(id int, f func(*StepView)) {
	r.mu.Lock()
	f(&r.steps[id-1])
	r.mu.Unlock()
}

func (r *Run) runCall(ctx context.Context, turn int, c Call) {
	c.Scope = r.task.Scope
	risk, known := r.sup.Classify(c.Tool)
	id := r.addStep(turn, c, risk)
	r.append(Event{Kind: EventProposed, Step: id, Tool: c.Tool, Args: c.Args, Risk: risk, Message: c.Rationale})
	refuse := func(reason string) {
		r.updateStep(id, func(s *StepView) { s.Status = StepRefused; s.Reason = reason })
		r.append(Event{Kind: EventRefused, Step: id, Tool: c.Tool, Risk: risk, Message: reason})
	}
	if !known {
		refuse(fmt.Sprintf("tool %q is not in the route manifest", c.Tool))
		return
	}
	if prior, ok := r.lookupDedup(turn, c); ok {
		r.reuse(id, prior)
		return
	}
	v := r.policy.Decide(c.Tool, risk)
	switch v.Action {
	case ActionDeny:
		refuse(v.Reason)
		return
	case ActionAsk:
		d, ok := r.ask(ctx, id, c, risk, v.Reason)
		if !ok {
			return
		}
		c.Confirm = d.Token
	}
	r.issue(ctx, turn, id, c, risk, c.Confirm != "")
}

// ask blocks on the Approver and records the decision. It reports whether the step may run.
func (r *Run) ask(ctx context.Context, id int, c Call, risk Risk, reason string) (Decision, bool) {
	deny := func(why string) (Decision, bool) {
		no := false
		r.updateStep(id, func(s *StepView) { s.Status = StepDenied; s.Reason = why })
		r.append(Event{Kind: EventDecision, Step: id, Tool: c.Tool, Risk: risk, Approved: &no, Message: why})
		return Decision{}, false
	}
	if r.sup.Approver == nil {
		return deny("approval required and no approver is attached")
	}
	prev := func() Status { r.mu.Lock(); defer r.mu.Unlock(); return r.status }()
	r.setStatus(StatusAwaitingApproval)
	d, err := r.sup.Approver.Approve(ctx, Pending{RunID: r.task.ID, StepID: id, Call: c, Risk: risk, Reason: reason})
	r.setStatus(prev)
	if err != nil {
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			r.updateStep(id, func(s *StepView) { s.Status = StepDenied; s.Reason = "run stopped before a decision" })
			return Decision{}, false
		}
		return deny("approver failed: " + err.Error())
	}
	if !d.Approved {
		why := d.Reason
		if why == "" {
			why = "denied by the operator"
		}
		return deny(why)
	}
	yes := true
	r.append(Event{Kind: EventDecision, Step: id, Tool: c.Tool, Risk: risk, Approved: &yes, Message: d.Reason})
	return d, true
}

func (r *Run) issue(ctx context.Context, turn, id int, c Call, risk Risk, asked bool) {
	r.updateStep(id, func(s *StepView) { s.Status = StepRunning })
	out, err := r.sup.Invoker.Invoke(ctx, c)
	if err == nil && out.Status == 428 && !asked {
		// The console's gate wants a confirmation the policy did not ask for. Ask now; never retry blind.
		d, ok := r.ask(ctx, id, c, risk, "the console's gate requires a confirmation for this call")
		if !ok {
			return
		}
		c.Confirm = d.Token
		out, err = r.sup.Invoker.Invoke(ctx, c)
	}
	if err != nil {
		if ctx.Err() != nil {
			r.updateStep(id, func(s *StepView) { s.Status = StepFailed; s.Reason = "interrupted by Stop" })
			r.append(Event{Kind: EventResult, Step: id, Tool: c.Tool, Risk: risk, Message: "interrupted by Stop"})
			return
		}
		r.updateStep(id, func(s *StepView) { s.Status = StepFailed; s.Reason = err.Error() })
		r.append(Event{Kind: EventResult, Step: id, Tool: c.Tool, Risk: risk, Message: err.Error()})
		return
	}
	body, trunc := out.Body, false
	if len(body) > MaxTranscriptBody {
		body, trunc = body[:MaxTranscriptBody], true
	}
	r.append(Event{Kind: EventResult, Step: id, Tool: c.Tool, Risk: risk, Status: out.Status, Body: append([]byte(nil), body...), Truncated: trunc})
	ex, _ := excerpt(out.Body, MaxHistoryBody)
	r.updateStep(id, func(s *StepView) {
		s.HTTPStatus, s.Body = out.Status, ex
		if out.Status >= 400 {
			s.Status = StepFailed
		} else {
			s.Status = StepDone
		}
	})
	r.recordDedup(turn, c, id)
}
