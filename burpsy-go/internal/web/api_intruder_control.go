package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/intruder"
)

// Pausing, resuming and stopping a running Intruder attack.
//
// # The gap
//
// Only two Intruder routes existed, /points and /run, so a launched attack could not be reached at
// all. Worse, /run registered its dashboard task without calling dash.Handle.WithCancel — while the
// package doc for WithCancel already named "intruder attack stop" as one of its three consumers — so
// Task.Cancellable() was false for every attack and the dashboard rendered no stop button either. A
// cluster bomb bounded at the 200,000-request ceiling and aimed at the wrong host could be halted only
// by killing the process.
//
// # Why the run handler stayed synchronous
//
// intruder.Run is called inside the /run handler and its report is that request's response. Making the
// attack a background job would change /run's contract and every client of it, which is a UI change
// and not this one. So the attack is registered while it runs, and pause/resume/stop act on it from
// another connection. A paused attack holds /run's response open, which is the honest consequence: the
// report does not exist yet.
//
// The remaining half is UI: intruder.tsx needs an AbortController on its run mutation (useRepeaterSend
// in the same file already has one) and controls wired to these routes. The dashboard stop button
// works today, because the task is now cancellable.

// runningAttack is one attack the process is executing, as the control routes see it.
type runningAttack struct {
	taskID  uint64
	kind    string
	target  string
	planned int
	control *intruder.Control
}

// attackRegistry is the live table of attacks that can be controlled.
//
// Keyed by dashboard task id, deliberately: the dashboard is where an operator sees a running attack,
// so the handle they already have is the handle these routes take. Inventing a second id space would
// mean the stop button on the dashboard and the stop button in Intruder addressed the same attack by
// different names.
type attackRegistry struct {
	mu sync.RWMutex
	m  map[uint64]*runningAttack
}

func newAttackRegistry() *attackRegistry { return &attackRegistry{m: map[uint64]*runningAttack{}} }

func (r *attackRegistry) add(a *runningAttack) {
	if r == nil || a == nil || a.taskID == 0 {
		return
	}
	r.mu.Lock()
	r.m[a.taskID] = a
	r.mu.Unlock()
}

// remove drops an attack that has ended. Called from the run handler's defer, so an attack that
// panicked is still removed — a table entry whose attack is gone would offer a stop button that
// silently does nothing, which is the failure the dash registry's Cancellable() exists to prevent.
func (r *attackRegistry) remove(taskID uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.m, taskID)
	r.mu.Unlock()
}

func (r *attackRegistry) get(taskID uint64) *runningAttack {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.m[taskID]
}

func (r *attackRegistry) snapshot() []*runningAttack {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]*runningAttack, 0, len(r.m))
	for _, a := range r.m {
		out = append(out, a)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].taskID < out[j].taskID })
	return out
}

// intruderAttackView is one running attack on the wire.
type intruderAttackView struct {
	// TaskID is the dashboard task id, which is also the id the control routes take.
	TaskID  uint64 `json:"task_id"`
	Kind    string `json:"kind"`
	Target  string `json:"target"`
	Planned int    `json:"planned"`
	// Status is "running", "paused" or "stopped". A stopped attack can still appear here briefly,
	// while its in-flight sends land and its report is assembled: reporting it as running would be a
	// state the operator can no longer act on, and dropping it early would make a stop look like it
	// had not happened.
	Status string `json:"status"`
	// StopReason is why it was stopped, empty when it was not.
	StopReason string `json:"stop_reason,omitempty"`
	// Sent and Failed are the sends that have settled so far — the live answer to "is it doing
	// anything", and the same totals the eventual report carries. planned bounds sent+failed only
	// loosely: a stop lets in-flight sends land, so an ended attack's counts can still move.
	Sent   int `json:"sent"`
	Failed int `json:"failed"`
}

func attackView(a *runningAttack) intruderAttackView {
	sent, failed := a.control.Progress()
	return intruderAttackView{
		TaskID: a.taskID, Kind: a.kind, Target: a.target, Planned: a.planned,
		Status:     string(a.control.Status()),
		StopReason: a.control.StopReason(),
		Sent:       sent,
		Failed:     failed,
	}
}

// intruderAttacksResp is the list shape. Attacks is never null, so a client cannot read "the field is
// missing" as "there are none".
type intruderAttacksResp struct {
	Attacks []intruderAttackView `json:"attacks"`
}

// handleIntruderAttacks serves GET /api/intruder/attacks: every attack this process is running and
// can be controlled.
func (s *Server) handleIntruderAttacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	running := s.attacks.snapshot()
	out := make([]intruderAttackView, 0, len(running))
	for _, a := range running {
		out = append(out, attackView(a))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(intruderAttacksResp{Attacks: out})
}

// handleIntruderAttackAction serves POST /api/intruder/attacks/{task_id}/{pause|resume|stop}.
//
// The three failure answers are kept distinct, for the reason dash.Registry.Cancel keeps its three
// apart: "no such attack" (404) means the id is wrong or the attack has finished, while "the attack is
// already over" (409) means the id was right and the action cannot apply. Collapsing them into one
// success — the shape /api/sequencer/stop used to have before it grew a real loop to stop — is how a
// stop button that does nothing reads as a stop button that worked.
func (s *Server) handleIntruderAttackAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/intruder/attacks/")
	idStr, action, ok := strings.Cut(rest, "/")
	if !ok {
		http.Error(w, "Expected /api/intruder/attacks/{task_id}/{pause|resume|stop}", http.StatusNotFound)
		return
	}
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid task id", http.StatusNotFound)
		return
	}
	attack := s.attacks.get(id)
	if attack == nil {
		http.Error(w, "No running attack with that task id", http.StatusNotFound)
		return
	}

	var changed bool
	switch action {
	case "pause":
		changed = attack.control.Pause()
	case "resume":
		changed = attack.control.Resume()
	case "stop":
		changed = attack.control.Stop("stopped by the operator")
	default:
		http.Error(w, "Unknown action "+strconv.Quote(action)+": expected pause, resume or stop",
			http.StatusNotFound)
		return
	}
	if !changed {
		// The attack exists and the action cannot apply: it has already stopped, or its plan is
		// exhausted and its report is being assembled. Named as a conflict rather than reported as a
		// success on a state that did not change.
		writeJSON(w, http.StatusConflict, map[string]any{
			"task_id": id,
			"action":  action,
			"applied": false,
			"status":  string(attack.control.Status()),
			"reason":  "the attack is no longer in a state this action can change",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"task_id": id,
		"action":  action,
		"applied": true,
		"status":  string(attack.control.Status()),
	})
}
