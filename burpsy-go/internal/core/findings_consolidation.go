package core

import (
	"fmt"
	"sort"
)

// ConsolidationAction is what the store does when a new finding collides with an existing one — the
// same catalog row at the same dedup key (burpsy-react-ui-oorl).
//
// Burp's consolidation engine applies one of three (ConsolidationAction.java:15-20: KEEP_EXISTING,
// KEEP_BOTH, KEEP_NEW). Its integer mapping makes KEEP_BOTH the zero value; this one does not, on
// purpose: every producer in the tree builds a NewFinding without saying anything about
// consolidation, and a zero value meaning "keep both" would silently switch merging off for all of
// them. The zero value here means "no opinion — use the store's policy", and the store's own default
// is ConsolidateKeepExisting, which is the merge this store has always done.
type ConsolidationAction string

const (
	// ConsolidationDefault is the zero value: defer to the per-row override, then the store default.
	ConsolidationDefault ConsolidationAction = ""
	// ConsolidateKeepExisting folds the new observation into the existing finding — occurrences
	// appended, severity raised, parameters unioned (see FindingStore.mergeLocked). The store's
	// behaviour before this type existed, and still its default.
	ConsolidateKeepExisting ConsolidationAction = "keep_existing"
	// ConsolidateKeepBoth files the new observation as its own finding. The dedup index keeps
	// pointing at the oldest finding for the key, so later observations under keep_existing still
	// land there.
	ConsolidateKeepBoth ConsolidationAction = "keep_both"
	// ConsolidateKeepNew replaces the existing finding's content with the new observation, in place
	// and under the same id. Severity and confidence are the new observation's too — that is what
	// "keep new" means, so a Low replacing a High lowers the finding — except where the operator set
	// an override, which outlives the engine's opinion here as it does on a merge. The triage note
	// is cleared: it described content that is gone.
	ConsolidateKeepNew ConsolidationAction = "keep_new"
)

// ParseConsolidationAction validates an action as an operator or a stored setting spells it. The
// empty string is not accepted here — a setting has to name an action.
func ParseConsolidationAction(s string) (ConsolidationAction, error) {
	switch a := ConsolidationAction(s); a {
	case ConsolidateKeepExisting, ConsolidateKeepBoth, ConsolidateKeepNew:
		return a, nil
	}
	return "", fmt.Errorf("unknown consolidation action %q: want keep_existing, keep_both or keep_new", s)
}

// ConsolidationPolicy is the operator's choice of action: one for every issue type ("apply to all"),
// and per-catalog-row overrides on top of it.
type ConsolidationPolicy struct {
	Default ConsolidationAction            `json:"default"`
	PerRow  map[string]ConsolidationAction `json:"per_row"`
}

// ConsolidationTally counts what the store did with colliding findings. A collision is a new
// finding whose dedup key already had an owner; each is resolved exactly one way, so
// Collisions == Merged + Replaced + KeptBoth.
type ConsolidationTally struct {
	Collisions int `json:"collisions"`
	Merged     int `json:"merged"`
	Replaced   int `json:"replaced"`
	KeptBoth   int `json:"kept_both"`
}

func (t *ConsolidationTally) note(a ConsolidationAction) {
	t.Collisions++
	switch a {
	case ConsolidateKeepBoth:
		t.KeptBoth++
	case ConsolidateKeepNew:
		t.Replaced++
	default:
		t.Merged++
	}
}

// SetConsolidation installs the operator's policy. An empty or unknown default reads as
// keep_existing — the direction that never silently stops merging — and so does an override that
// does not name an action.
func (fs *FindingStore) SetConsolidation(p ConsolidationPolicy) {
	clean := ConsolidationPolicy{Default: ConsolidateKeepExisting, PerRow: map[string]ConsolidationAction{}}
	if a, err := ParseConsolidationAction(string(p.Default)); err == nil {
		clean.Default = a
	}
	for name, action := range p.PerRow {
		if a, err := ParseConsolidationAction(string(action)); err == nil && name != "" {
			clean.PerRow[name] = a
		}
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.consolidation = clean
}

// Consolidation returns the installed policy, with the keep_existing default filled in for a store
// that never had one installed. PerRow is never nil, so it marshals as {} rather than null.
func (fs *FindingStore) Consolidation() ConsolidationPolicy {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	out := ConsolidationPolicy{Default: fs.consolidation.Default, PerRow: make(map[string]ConsolidationAction, len(fs.consolidation.PerRow))}
	if out.Default == ConsolidationDefault {
		out.Default = ConsolidateKeepExisting
	}
	for k, v := range fs.consolidation.PerRow {
		out.PerRow[k] = v
	}
	return out
}

// ConsolidationTallies returns the totals since the store was created or cleared, and the same
// counts per run (the TaskID of the INCOMING finding), so a scan that merged forty duplicates is
// distinguishable from one that found one issue once. Run-scoped: the per-finding MergedCount is
// what survives a restart.
func (fs *FindingStore) ConsolidationTallies() (ConsolidationTally, map[uint64]ConsolidationTally) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	byTask := make(map[uint64]ConsolidationTally, len(fs.tallyByTask))
	for k, v := range fs.tallyByTask {
		byTask[k] = *v
	}
	return fs.tally, byTask
}

// actionForLocked resolves the action for one incoming finding: the per-row override, then the
// default. Called with the lock held.
func (fs *FindingStore) actionForLocked(name string) ConsolidationAction {
	if a, ok := fs.consolidation.PerRow[name]; ok {
		return a
	}
	if fs.consolidation.Default != ConsolidationDefault {
		return fs.consolidation.Default
	}
	return ConsolidateKeepExisting
}

// noteCollisionLocked records one resolved collision in the totals and under the incoming run.
func (fs *FindingStore) noteCollisionLocked(task uint64, a ConsolidationAction) {
	fs.tally.note(a)
	if fs.tallyByTask == nil {
		fs.tallyByTask = make(map[uint64]*ConsolidationTally)
	}
	t := fs.tallyByTask[task]
	if t == nil {
		t = &ConsolidationTally{}
		fs.tallyByTask[task] = t
	}
	t.note(a)
}

// replaceLocked is keep_new: the existing finding takes the incoming observation's content. The id,
// the dedup slot and the operator's own triage (overrides, false-positive mark, comment) stay —
// those are facts about the issue the operator is tracking, not about one observation of it.
func (fs *FindingStore) replaceLocked(existing *Finding, incoming NewFinding) {
	if existing.SeverityOverride == nil {
		existing.Severity = incoming.Severity
	}
	if existing.ConfidenceOverride == nil {
		existing.Confidence = incoming.Confidence
	}
	existing.Description = incoming.Description
	existing.Remediation = incoming.Remediation
	existing.Evidence = incoming.Evidence
	existing.Occurrences = append([]Occurrence(nil), incoming.Occurrences...)
	existing.Inserted = incoming.Inserted
	existing.TaskID = incoming.TaskID
	existing.Confirm = incoming.Confirm
	existing.Timestamp = uint64(getTimestamp())
	existing.Param = incoming.Param
	existing.Params = nil
	if incoming.Param != "" {
		existing.Params = []string{incoming.Param}
	}
	existing.Triage = nil
	existing.MergedCount = 0
}

// NeverMergeRows lists the catalog rows that never merge — the built-in exemptions plus the
// installed policy's — so a consolidation surface can say an override on them is inert rather than
// offer a choice that does nothing.
func (fs *FindingStore) NeverMergeRows() []string {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	seen := map[string]bool{}
	out := []string{}
	for name := range dedupExemptRows {
		seen[name] = true
		out = append(out, name)
	}
	if fs.policy != nil {
		for name := range fs.policy.Exempt {
			if !seen[name] {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}
