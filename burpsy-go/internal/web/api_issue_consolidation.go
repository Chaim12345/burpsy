package web

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// ---- Issue consolidation (burpsy-react-ui-oorl) --------------------------------------------------
//
// When a new finding is the same catalog row at the same dedup key as an existing one, the store
// resolves the collision one of three ways — Burp's ConsolidationAction: keep the existing finding
// (merge into it, the default and the behaviour before this existed), keep both, or keep the new
// one. The operator picks one action for every issue type and may override it per type: Burp's
// merge dialog pairs each choice with "apply to all", and an action applied to all issue types with
// per-type exceptions is that pairing made durable, since a scan does not stop to ask.
//
// The answer also carries what consolidation did — collisions resolved, in total and per run — so a
// scan that folded forty duplicates into one issue is distinguishable from one that found it once.

type consolidationTaskView struct {
	TaskID uint64 `json:"task_id"`
	core.ConsolidationTally
}

type consolidationView struct {
	Default core.ConsolidationAction            `json:"default"`
	PerRow  map[string]core.ConsolidationAction `json:"per_row"`
	Tally   core.ConsolidationTally             `json:"tally"`
	ByTask  []consolidationTaskView             `json:"by_task"`
	// NeverMerge names the rows the store never merges, whatever the action — an override on one of
	// them is inert, and the console says so instead of offering it.
	NeverMerge []string `json:"never_merge"`
}

func (s *Server) viewConsolidation() consolidationView {
	policy := s.findings.Consolidation()
	total, byTask := s.findings.ConsolidationTallies()
	tasks := make([]consolidationTaskView, 0, len(byTask))
	for id, t := range byTask {
		tasks = append(tasks, consolidationTaskView{TaskID: id, ConsolidationTally: t})
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].TaskID < tasks[j].TaskID })
	return consolidationView{
		Default:    policy.Default,
		PerRow:     policy.PerRow,
		Tally:      total,
		ByTask:     tasks,
		NeverMerge: s.findings.NeverMergeRows(),
	}
}

// applyConsolidation installs a policy on the current finding store and remembers it, so a store
// swapped in later (WithFindings) gets the same policy from followLive.
func (s *Server) applyConsolidation(p core.ConsolidationPolicy) {
	s.consolidationMu.Lock()
	s.consolidation = &p
	s.consolidationMu.Unlock()
	s.findings.SetConsolidation(p)
}

// reapplyConsolidation is followLive's half: re-install the remembered policy, if any, on a store
// that may have just been swapped in.
func (s *Server) reapplyConsolidation() {
	s.consolidationMu.Lock()
	p := s.consolidation
	s.consolidationMu.Unlock()
	if p != nil {
		s.findings.SetConsolidation(*p)
	}
}

// restoreFindingConsolidation loads the project's policy from WithPersist, so it follows a project
// switch. A project that never saved one, or whose stored policy does not parse, gets the default —
// keep_existing, the direction that never silently stops merging.
func (s *Server) restoreFindingConsolidation(p *persist.Store) {
	var policy core.ConsolidationPolicy
	raw, err := p.LoadFindingConsolidation()
	if err != nil {
		s.logger.Warn("failed to restore the issue consolidation policy", zap.Error(err))
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &policy); err != nil {
			s.logger.Warn("stored issue consolidation policy does not parse; merging as before", zap.Error(err))
			policy = core.ConsolidationPolicy{}
		}
	}
	s.applyConsolidation(policy)
}

// issueConsolidationReq is the request body handleIssueConsolidation decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type issueConsolidationReq struct {
	Default string            `json:"default"`
	PerRow  map[string]string `json:"per_row"`
}

// handleIssueConsolidation serves GET/PUT /api/issues/consolidation. riskLocal: it writes burpsy's
// own intake policy and sends nothing; a policy change applies to findings filed after it — a merge
// already made is not reversible from what the store keeps.
func (s *Server) handleIssueConsolidation(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.viewConsolidation())
	case http.MethodPut:
		var body issueConsolidationReq
		if err := requestJSON(w, r, io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, `the body must be {"default":"keep_existing|keep_both|keep_new","per_row":{...}}`, http.StatusBadRequest)
			return
		}
		def, err := core.ParseConsolidationAction(body.Default)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		policy := core.ConsolidationPolicy{Default: def, PerRow: make(map[string]core.ConsolidationAction, len(body.PerRow))}
		for name, action := range body.PerRow {
			if name == "" {
				http.Error(w, "a per-type override needs an issue name", http.StatusBadRequest)
				return
			}
			a, err := core.ParseConsolidationAction(action)
			if err != nil {
				http.Error(w, name+": "+err.Error(), http.StatusBadRequest)
				return
			}
			policy.PerRow[name] = a
		}
		s.applyConsolidation(policy)
		if s.persist != nil {
			if blob, err := json.Marshal(policy); err == nil {
				if err := s.persist.SaveFindingConsolidation(blob); err != nil {
					s.logger.Warn("issue consolidation policy persist failed", zap.Error(err))
				}
			}
		}
		writeJSON(w, http.StatusOK, s.viewConsolidation())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
