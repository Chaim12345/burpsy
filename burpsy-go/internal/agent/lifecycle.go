package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ResourceKind is what a Resource points at.
type ResourceKind string

const (
	ResourceProxy  ResourceKind = "proxy"  // a Proxy history item (message id)
	ResourceTarget ResourceKind = "target" // a Target / site-map node
	ResourceIssue  ResourceKind = "issue"  // a finding id
)

// Resource is an item attached to a task so the agent starts from it ("Send to agent").
type Resource struct {
	Kind  ResourceKind `json:"kind"`
	Ref   string       `json:"ref"`
	Title string       `json:"title,omitempty"`
}

const maxRefLen = 1024

// Validate refuses an unknown kind, an empty reference, or an oversized one.
func (r Resource) Validate() error {
	switch r.Kind {
	case ResourceProxy, ResourceTarget, ResourceIssue:
	default:
		return fmt.Errorf("resource kind %q is not proxy, target or issue", r.Kind)
	}
	if strings.TrimSpace(r.Ref) == "" {
		return fmt.Errorf("resource reference is empty")
	}
	if len(r.Ref) > maxRefLen {
		return fmt.Errorf("resource reference is %d bytes, over the %d limit", len(r.Ref), maxRefLen)
	}
	return nil
}

// ---- per-turn dedup -----------------------------------------------------------------------------

// canonicalArgs re-marshals JSON arguments with sorted keys and no whitespace, so two spellings of
// one call hash alike. Arguments that are not JSON hash as their raw trimmed bytes.
func canonicalArgs(args json.RawMessage) string {
	t := bytes.TrimSpace(args)
	if len(t) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(t, &v); err != nil {
		return string(t)
	}
	out, err := json.Marshal(v) // map keys marshal sorted
	if err != nil {
		return string(t)
	}
	return string(out)
}

// dedupKey is the SHA-256 of session, turn, tool and canonical args: the same call re-issued in the
// same turn of the same run is one call.
func dedupKey(session string, turn int, tool string, args json.RawMessage) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%d\x00%s\x00%s", session, turn, tool, canonicalArgs(args))
	return hex.EncodeToString(h.Sum(nil))
}

func (r *Run) lookupDedup(turn int, c Call) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.dedup[dedupKey(r.task.ID, turn, c.Tool, c.Args)]
	return id, ok
}

func (r *Run) recordDedup(turn int, c Call, step int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dedup[dedupKey(r.task.ID, turn, c.Tool, c.Args)] = step
}

// reuse answers step id from the recorded outcome of step prior, without a request or an approval.
func (r *Run) reuse(id, prior int) {
	r.mu.Lock()
	p := r.steps[prior-1]
	r.mu.Unlock()
	r.updateStep(id, func(s *StepView) {
		s.Status, s.HTTPStatus, s.Body, s.Deduped = p.Status, p.HTTPStatus, p.Body, true
		s.Reason = fmt.Sprintf("same call as step %d in this turn; not re-sent", prior)
	})
	r.append(Event{Kind: EventResult, Step: id, Tool: p.Tool, Risk: p.Risk, Status: p.HTTPStatus,
		Message: fmt.Sprintf("deduplicated: same call as step %d in this turn", prior)})
}

// ---- manager: rename / archive / restore / stop / attach ----------------------------------------

// Manager keeps the runs of a project and their lifecycle.
type Manager struct {
	sup  *Supervisor
	mu   sync.Mutex
	runs map[string]*Run
	ids  []string
}

// NewManager builds a manager that starts runs with sup.
func NewManager(sup *Supervisor) *Manager { return &Manager{sup: sup, runs: map[string]*Run{}} }

const maxNameLen = 200

// Create starts a run. The task ID must be unused and every resource valid.
func (m *Manager) Create(ctx context.Context, task Task, pl Planner) (*Run, error) {
	if strings.TrimSpace(task.ID) == "" {
		return nil, fmt.Errorf("task id is empty")
	}
	for _, res := range task.Resources {
		if err := res.Validate(); err != nil {
			return nil, err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.runs[task.ID]; dup {
		return nil, fmt.Errorf("task %q already exists", task.ID)
	}
	r := m.sup.Start(ctx, task, pl)
	m.runs[task.ID] = r
	m.ids = append(m.ids, task.ID)
	return r, nil
}

// Get returns a run or nil.
func (m *Manager) Get(id string) *Run {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runs[id]
}

func (m *Manager) must(id string) (*Run, error) {
	if r := m.Get(id); r != nil {
		return r, nil
	}
	return nil, fmt.Errorf("no task %q", id)
}

// List returns snapshots in creation order; archived runs only when includeArchived.
func (m *Manager) List(includeArchived bool) []Snapshot {
	m.mu.Lock()
	ids := append([]string(nil), m.ids...)
	m.mu.Unlock()
	out := []Snapshot{}
	for _, id := range ids {
		s := m.Get(id).Snapshot()
		if s.Archived && !includeArchived {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Rename sets a display name.
func (m *Manager) Rename(id, name string) error {
	r, err := m.must(id)
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxNameLen {
		return fmt.Errorf("a task name must be 1-%d bytes", maxNameLen)
	}
	r.mu.Lock()
	r.name = name
	r.mu.Unlock()
	return nil
}

// Archive hides a finished run. An active run must be stopped first.
func (m *Manager) Archive(id string) error {
	r, err := m.must(id)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.status.finished() {
		return fmt.Errorf("task %q is %s: stop it before archiving", id, r.status)
	}
	r.archived = true
	return nil
}

// Restore un-archives a run.
func (m *Manager) Restore(id string) error {
	r, err := m.must(id)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.archived = false
	r.mu.Unlock()
	return nil
}

// Stop interrupts a run (and its children).
func (m *Manager) Stop(id string) error {
	r, err := m.must(id)
	if err != nil {
		return err
	}
	r.Stop()
	return nil
}

// Attach adds a resource to a run. The planner sees it from its next turn. The same kind and ref
// twice is a no-op.
func (m *Manager) Attach(id string, res Resource) error {
	r, err := m.must(id)
	if err != nil {
		return err
	}
	if err := res.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, have := range r.resources {
		if have.Kind == res.Kind && have.Ref == res.Ref {
			return nil
		}
	}
	r.resources = append(r.resources, res)
	return nil
}

// Names returns the ids of every run, sorted, for tests and listings.
func (m *Manager) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]string(nil), m.ids...)
	sort.Strings(out)
	return out
}
