package core

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Severity represents the severity of a finding.
type Severity int

const (
	SeverityInformational Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInformational:
		return "Informational"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// Confidence represents the confidence level of a finding.
type Confidence int

const (
	ConfidenceCertain Confidence = iota
	ConfidenceFirm
	ConfidenceTentative
	// ConfidenceSuppressedNegative is the DOM dynamic tier's retired verdict
	// (burpsy-react-ui-m97j): the static candidate is still named, and a real browser loaded
	// the page with a canary in the flow's source and no instrumented sink received it. It is
	// a weaker grade than Tentative — tentative says "we do not know", suppressed-negative says
	// "we looked once and saw nothing", and one load is evidence against reachability, not
	// proof of safety. Kept as a confidence grade rather than a boolean on the finding because
	// the store, the issues API and the exports all grade confidence already; a second axis
	// would have to be threaded through each of them to say one thing.
	ConfidenceSuppressedNegative
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceCertain:
		return "Certain"
	case ConfidenceFirm:
		return "Firm"
	case ConfidenceTentative:
		return "Tentative"
	case ConfidenceSuppressedNegative:
		return "Suppressed-negative"
	default:
		return "Unknown"
	}
}

// ParseSeverity maps a scanner-style severity string ("high", "medium",
// "low", "info", "critical") to the Severity enum. Unknown values map to
// SeverityInformational.
func ParseSeverity(v string) Severity {
	switch strings.ToLower(v) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityInformational
	}
}

// ParseConfidence maps a scanner-style confidence string ("certain",
// "firm", "tentative") to the Confidence enum. Unknown values map to
// ConfidenceTentative.
func ParseConfidence(v string) Confidence {
	switch strings.ToLower(v) {
	case "certain":
		return ConfidenceCertain
	case "firm":
		return ConfidenceFirm
	case "suppressed-negative":
		return ConfidenceSuppressedNegative
	default:
		return ConfidenceTentative
	}
}

// Occurrence represents where a finding was observed.
//
// ExchangeID records the exchange directly rather than leaving a reader to re-derive it from
// Request. The producer always knows it, and re-deriving it downstream is what went wrong before:
// message ids and exchange ids are both dense counters from zero, so the wrong lookup returns a
// real but unrelated exchange and the finding is reported against a URL it was never seen at.
//
// Zero is ambiguous — it is also a valid exchange id — so it is not a reliable "unset" marker on its
// own. Readers cross-check against Request via TrafficStore.ExchangeByRequest, which is exact; that
// is also what keeps findings persisted before this field existed resolving correctly.
type Occurrence struct {
	ExchangeID ExchangeID
	Request    MsgId
	Response   *MsgId
	Span       Span
}

// FindingTarget is the logical location a finding is about — the thing two findings must agree on
// before they can be considered the same issue seen twice.
//
// # Why the producer supplies this rather than the store resolving it
//
// A finding's occurrences carry message ids, and only TrafficStore can turn one into a host and a
// path. There were two ways to close that gap: install a resolver callback on FindingStore (there is
// precedent — SetPersistenceSink and OnChange are both installed-callback slots), or have the caller
// pass the target it already holds. This is the second, for three reasons.
//
//   - Lock discipline. Anything installed on this store runs under its write lock, under the same
//     contract onAdd carries: it must not call back into a store. A resolver would do exactly that,
//     reaching into TrafficStore's own RWMutex from inside FindingStore's. Findings are already
//     produced from the proxy's response path, which is where the traffic store's observers run, and
//     an RWMutex is not reentrant — so that is a latent deadlock, not a hypothetical one.
//   - The producer already has it. Every site that builds a NewFinding is holding the *Exchange the
//     finding came from (internal/scanner/capture.go, Server.activeFinding, the CLI audit command).
//     There is no lookup to do, only a value to carry.
//   - It survives capture rollover. An exchange can leave the traffic store; a resolver would then
//     return nothing and the finding would silently fall into the "unknown target" bucket, where it
//     would either merge with unrelated findings or stop merging with its own siblings. A target
//     recorded at production time stays true.
//
// A zero value means "the producer did not say", and such a finding is never merged: merging on name
// alone across unknown targets would collapse genuinely distinct issues, which is strictly worse than
// the duplication this whole mechanism exists to remove.
type FindingTarget struct {
	Host string
	Port uint16
	TLS  bool
	Path string
}

// Origin is the scheme/host/port triple, without the path. Port is always written out: a target is
// compared as a string, and "app.test" on 80 and on 8080 are different targets.
func (t FindingTarget) Origin() string {
	scheme := "http"
	if t.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, t.Host, t.Port)
}

// dedupExemptRows are the catalog rows that never merge, mirroring Burp's burp.Zbvp.Zd
// (out/clean/jdt_src/burp/Zbvp.java:62-64), which exempts CROSS_DOMAIN_POST and
// SERIALIZED_OBJECT_IN_HTTP_MESSAGE from the intake gate entirely.
//
// Both rows describe a property of one specific message rather than of an endpoint: a page's
// cross-domain form posts somewhere in particular, and a serialized blob is in one particular
// request or response. Collapsing five of them into one occurrence list would hide four distinct
// facts behind a count, which is why Burp exempts them and why the exemption is reproduced here.
//
// These are the two Burp names, and both exist verbatim as burpsy-go catalog rows
// (internal/scanner/catalog_data.go:2083 and :2147) and as live check names, so neither needed a
// substitute. The list lives in core rather than being installed alongside the granularity policy
// because it is a correctness rule: a build that forgot to wire a policy must still not merge these.
var dedupExemptRows = map[string]bool{
	"Cross-domain POST":                 true,
	"Serialized object in HTTP message": true,
}

// DedupPolicy is the per-catalog-row tuning the store cannot derive on its own.
//
// Granularity is the part that needs it. Most rows are about an endpoint — reflected XSS on /search
// is not the same issue as reflected XSS on /login — so the default target is origin+path. But a row
// like "Strict transport security not enforced" or a cookie-scope finding is a property of the host,
// and a passive check re-fires it on every response, so at path granularity one host yields one
// finding per URL ever captured. Which rows are which is knowledge the scanner's check registry
// already holds as DispatchScopePerHost, and internal/scanner exports it as ScannerDedupPolicy();
// core cannot import scanner, so the set is handed in rather than looked up.
//
// With no policy installed everything is path-scoped. That is the safe direction: path granularity
// only ever under-merges, and under-merging is the behaviour that exists today.
type DedupPolicy struct {
	// HostScoped names the catalog rows whose target is the origin alone, ignoring the path.
	HostScoped map[string]bool
	// Exempt names additional rows that never merge. Added to the built-in set above, never
	// replacing it — a caller cannot switch the built-in exemptions off.
	Exempt map[string]bool
}

// TriageNote is the LLM post-scan second look's verdict on one finding (ei0v). The engine
// copies the scanner package's verdict vocabulary; the reasoning is carried verbatim.
type TriageNote struct {
	Verdict        string    `json:"verdict"`
	Reasoning      string    `json:"reasoning"`
	Model          string    `json:"model"`
	InvestigatedAt time.Time `json:"investigated_at"`
}

// SetTriage attaches (or, with nil, clears) the second-look note on one finding. The note
// is written under the store lock so a re-audit merging into the same finding cannot lose
// it, and it never touches the severity or confidence fields — advice rides beside grades.
func (fs *FindingStore) SetTriage(id uint64, note *TriageNote) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for _, f := range fs.findings {
		if f.ID == id {
			f.Triage = note
			fs.signalChangeLocked()
			return true
		}
	}
	return false
}

// Inserted represents inserted payload information.
type Inserted struct {
	Original string
	Payload  string
	Encoded  string
}

// NewFinding represents a new finding to be added.
type NewFinding struct {
	Name        string
	Severity    Severity
	Confidence  Confidence
	Description string
	Remediation string
	Occurrences []Occurrence
	Inserted    *Inserted
	// TaskID is the run that produced this finding, or 0 when nothing tracked it. Without it a
	// coverage summary and a finding count cannot be tied together: the dashboard can say an audit
	// swept 200 exchanges and that 12 findings exist, and nothing relates the two.
	TaskID uint64
	// Confirm is the DOM dynamic tier's machine verdict for a static-pass finding
	// (burpsy-react-ui-m97j): promoted / retired / unavailable / unsupported-source, "" for every
	// finding the tier never saw. Carried beside Confidence because they answer different
	// questions: Confidence is a graded belief a human filters on, Confirm is what one browser
	// load actually observed about one finding.
	Confirm string `json:"confirm,omitempty"`
	// Param is the name of the parameter, header or cookie the finding was observed at, empty when
	// the finding is about a resource rather than one of its inputs — a DOM sink's source
	// expression, or an insertion point a BCheck fired at.
	Param string
	// Target is the logical location this finding is about, and the second half of the dedup key
	// (the first is Name). Zero means the producer did not resolve one, which disables merging for
	// this finding. See FindingTarget.
	Target FindingTarget
}

// Finding represents a security finding.
type Finding struct {
	ID          uint64
	Name        string
	Severity    Severity
	Confidence  Confidence
	Description string
	Remediation string
	Occurrences []Occurrence
	Inserted    *Inserted
	// TaskID is the run that produced this finding, or 0 when nothing tracked it. See NewFinding.
	TaskID    uint64
	Timestamp uint64
	// Confirm is the DOM dynamic tier's machine verdict for a static-pass finding. See
	// NewFinding.Confirm — empty for every finding the tier never saw, which is every finding
	// except the DOM pass's own.
	Confirm string `json:"confirm,omitempty"`
	// Triage is the LLM second look's note (ei0v): verdict + reasoning + model. ADVICE never
	// promotion — it is carried beside Confidence/ConfidenceOverride and moves neither, the
	// same rule SeverityOverride already obeys. Nil = not investigated.
	Triage *TriageNote `json:"triage,omitempty"`
	// Param names the parameter the finding was observed at, empty when it is about a resource.
	// See NewFinding.Param. On a merged finding this is the *first* param observed; Params below is
	// the full set and is what a reader should use.
	Param string
	// Params is every distinct parameter this finding was observed at, in first-seen order, empty
	// for a resource-level finding.
	//
	// This field is the reason merging is safe. Five reflected-XSS findings on /search differ only in
	// which parameter was vulnerable, and folding them into one finding with five occurrences would
	// destroy exactly the fact the operator needs — the occurrences record *where* each hit was, not
	// *what* was injected. Keeping the set here means the merged finding still answers "which
	// parameters", so the merge loses nothing.
	Params []string
	// Target is the logical location this finding is about. See NewFinding.Target.
	Target FindingTarget

	// SeverityOverride is the operator's severity for this finding, nil while the engine's own
	// severity stands. An override beats both the engine's report and a later merge that would
	// raise it (see mergeLocked) — the operator looked at this finding and overruled the scanner;
	// an automated re-observation is not a rebuttal.
	SeverityOverride *Severity
	// ConfidenceOverride is the operator's confidence, same contract as SeverityOverride.
	ConfidenceOverride *Confidence
	// FalsePositive marks a finding the operator has dismissed as not an issue. It stays in the
	// store — deleting is a separate, destructive act — but the UI dims it and the severity
	// counts exclude it.
	FalsePositive bool
	// Comment is the operator's note on this finding, empty when none was left.
	Comment string
}

// EffectiveSeverity is the severity the finding should be reported at: the operator's override
// when one exists, the engine's severity otherwise.
func (f *Finding) EffectiveSeverity() Severity {
	if f.SeverityOverride != nil {
		return *f.SeverityOverride
	}
	return f.Severity
}

// EffectiveConfidence is the confidence the finding should be reported at, same rule as
// EffectiveSeverity.
func (f *Finding) EffectiveConfidence() Confidence {
	if f.ConfidenceOverride != nil {
		return *f.ConfidenceOverride
	}
	return f.Confidence
}

// HasParam reports whether the finding was observed at the named parameter.
func (f *Finding) HasParam(name string) bool {
	for _, p := range f.Params {
		if p == name {
			return true
		}
	}
	return false
}

// FindingStore stores security findings.
type FindingStore struct {
	mu       sync.RWMutex
	findings []*Finding
	nextID   uint64

	// onAdd is an optional write-through hook (see SetPersistenceSink). It runs
	// under the store lock, must not call back into the store, and must not fail
	// the in-memory add — memory is authoritative, SQLite is durable backup.
	onAdd func(f *Finding)
	// onChange is an optional signal that the set of findings changed at all (see
	// OnChange). Separate from onAdd because it has a different owner and a
	// different arity: onAdd is the durable mirror's single slot and only cares
	// about arrivals, this one is the live-update stream and also fires for a
	// delete and a clear, which the UI has to hear about too.
	onChange func()

	// policy tunes the dedup key per catalog row; nil means "everything path-scoped, built-in
	// exemptions only". See DedupPolicy.
	policy *DedupPolicy
	// byKey maps a dedup key to the finding that owns it, so Add is O(1) rather than a scan of every
	// finding on every intake — the passive path adds a finding per response, and an engagement's
	// store runs to thousands. Rebuilt wholesale by Restore, maintained by Delete and Clear.
	byKey map[string]*Finding
	// onDelete is an optional write-through hook (see SetDeleteSink). It runs under the store lock
	// with the finding's id, must not call back into the store, and must not fail the in-memory
	// delete — memory is authoritative, SQLite is durable backup.
	onDelete func(id uint64)
}

// NewFindingStore creates a new finding store.
func NewFindingStore() *FindingStore {
	return &FindingStore{
		findings: make([]*Finding, 0),
		byKey:    make(map[string]*Finding),
	}
}

// SetDedupPolicy installs the per-row dedup tuning (see DedupPolicy). Single slot, so re-installing
// replaces rather than merges.
//
// The index is rebuilt against the new policy rather than left as it is, because the realistic
// ordering is policy-after-restore: the durable layer loads a session's findings into the store and
// the server installs the policy when it adopts that store. Keeping keys computed under the old rule
// would leave every host-scoped row indexed by a path key it will never be looked up by, so a
// restored session would quietly stop merging exactly the rows the policy exists for. Findings
// already merged are not re-split — a merge is not reversible from what is kept — so a policy change
// mid-session narrows or widens future intake only.
func (fs *FindingStore) SetDedupPolicy(p *DedupPolicy) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.policy = p
	fs.rebuildIndexLocked()
}

// rebuildIndexLocked recomputes byKey from the current findings under the current policy. Called
// with the write lock held. Where several findings share a key — possible after a policy change
// widened one — the first wins, so new occurrences land on the oldest finding of that class rather
// than on whichever happened to be last.
func (fs *FindingStore) rebuildIndexLocked() {
	fs.byKey = make(map[string]*Finding, len(fs.findings))
	for _, f := range fs.findings {
		if key, ok := fs.dedupKeyLocked(f.Name, f.Target); ok {
			if _, clash := fs.byKey[key]; !clash {
				fs.byKey[key] = f
			}
		}
	}
}

// dedupKeyLocked returns the key a finding merges on, and whether it may merge at all.
//
// The key is the catalog row name plus the target, which is this port's reading of Burp's intake
// gate: burp.Zbvp.ZE collects candidates with findIssuesOfSameType — a filter on the issue-type
// enum (Zbvp.java:74-76) — over a list that is already scoped to one target, so "same issue" there
// is (type, target) too. Name stands in for the type enum because Name *is* the catalog row here;
// every producer sets it from the catalog and the advisory resolver already keys on it.
//
// Query strings are deliberately not in the key. /search?q=a and /search?q=b are the same endpoint,
// and merging across them is precisely the behaviour that turns five parameter hits into one issue.
func (fs *FindingStore) dedupKeyLocked(name string, t FindingTarget) (string, bool) {
	if name == "" || t.Host == "" {
		return "", false
	}
	if dedupExemptRows[name] {
		return "", false
	}
	if fs.policy != nil {
		if fs.policy.Exempt[name] {
			return "", false
		}
		if fs.policy.HostScoped[name] {
			return name + "\x00" + t.Origin(), true
		}
	}
	return name + "\x00" + t.Origin() + t.Path, true
}

// Add takes in a new finding, merging it into an existing one when it is the same catalog row seen
// at the same target, and returns the id of the finding that now holds it.
//
// On a merge that is the *existing* finding's id, not a freshly minted one — the caller asked for
// this observation to be recorded and the return value says where it landed, which is the only
// answer that stays useful. No caller in the tree treats the result as "an id that did not exist
// before"; they either ignore it or hand it straight to a lookup.
//
// # What escalates on a merge, and what does not
//
// Severity takes the maximum and confidence takes the best (Certain beats Firm beats Tentative). A
// merged issue is as bad as its worst occurrence and as certain as its most certain one: an operator
// triaging by severity must not have a High hidden because a Low arrived at that endpoint first.
//
// This is a design decision, not a port. Burp's shouldMergeIssues (Zbvp.java:53-60) has a
// JWT-specific branch comparing secret values and a generic branch counting matches through an
// obfuscated fingerprint that does not survive decompilation, and it decides *whether* to merge
// rather than what the merged issue looks like. Nothing about escalation is recoverable from it.
//
// Description, remediation, timestamp, TaskID and Inserted stay with the first observation. They
// describe the issue class and the moment it was first seen, and rewriting them on each merge would
// make a finding's text depend on scan order.
func (fs *FindingStore) Add(finding NewFinding) uint64 {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	key, mergeable := fs.dedupKeyLocked(finding.Name, finding.Target)
	if mergeable {
		if existing, ok := fs.byKey[key]; ok {
			fs.mergeLocked(existing, finding)
			// onAdd, not a separate update hook: the sink is a write-through mirror of a finding's
			// current state, and persist.Store.SaveFinding is an INSERT OR REPLACE keyed on the id,
			// so re-offering the merged finding rewrites its row rather than inserting a second
			// one. SQLite therefore does not drift from memory across a merge.
			if fs.onAdd != nil {
				fs.onAdd(existing)
			}
			// The set of findings did not grow, but one of them changed — the UI's list is stale
			// either way, and the live stream's only job is to say so.
			fs.signalChangeLocked()
			return existing.ID
		}
	}

	id := fs.nextID
	fs.nextID++

	f := &Finding{
		ID:          id,
		Name:        finding.Name,
		Severity:    finding.Severity,
		Confidence:  finding.Confidence,
		Description: finding.Description,
		Remediation: finding.Remediation,
		Occurrences: append([]Occurrence(nil), finding.Occurrences...),
		Inserted:    finding.Inserted,
		TaskID:      finding.TaskID,
		Confirm:     finding.Confirm,
		Timestamp:   uint64(getTimestamp()),
		Param:       finding.Param,
		Target:      finding.Target,
	}
	if finding.Param != "" {
		f.Params = []string{finding.Param}
	}

	// Copied rather than aliased above, because a merge appends to this slice later. Aliasing the
	// caller's slice was harmless while it was only ever read; appending to one whose backing array
	// the caller still holds is how a later merge would scribble into somebody else's memory.
	fs.findings = append(fs.findings, f)
	if mergeable {
		// Guarded because a zero-value FindingStore is usable everywhere else in this file, and a
		// write to a nil map panics where a read from one does not.
		if fs.byKey == nil {
			fs.byKey = make(map[string]*Finding)
		}
		fs.byKey[key] = f
	}
	if fs.onAdd != nil {
		fs.onAdd(f)
	}
	fs.signalChangeLocked()
	return id
}

// mergeLocked folds one new observation into an existing finding. Called with the write lock held.
func (fs *FindingStore) mergeLocked(existing *Finding, incoming NewFinding) {
	existing.Occurrences = append(existing.Occurrences, incoming.Occurrences...)
	if incoming.Param != "" && !existing.HasParam(incoming.Param) {
		existing.Params = append(existing.Params, incoming.Param)
		if existing.Param == "" {
			// The first observation was resource-level and this one names a parameter. Param is the
			// legacy single-value view of Params, so it takes the first one that exists.
			existing.Param = incoming.Param
		}
	}
	// An operator override outlives the engine's opinion (see Finding.SeverityOverride): the raise
	// and the lowering below run only while no override stands. Re-raising a severity the operator
	// already overruled would turn the override off on the next re-audit — exactly the
	// "suppressed false positive that comes back" the triage feature must not do.
	if existing.SeverityOverride == nil && incoming.Severity > existing.Severity {
		existing.Severity = incoming.Severity
	}
	if existing.ConfidenceOverride == nil && incoming.Confidence < existing.Confidence {
		existing.Confidence = incoming.Confidence
	}
	if existing.Inserted == nil && incoming.Inserted != nil {
		existing.Inserted = incoming.Inserted
	}
}

// OnChange installs the signal called after the findings change, or nil to remove
// it. Single slot, so re-installing replaces rather than doubling.
//
// It carries no finding: its consumer is the live-update stream, which tells the
// browser that /api/issues is stale and lets that handler render the finding — so
// there stays exactly one place that serialises one. It runs under the store's
// write lock, so it is held to the same cheapness contract as the traffic store's
// observers (see TrafficStore.ObserveExchanges): passive scanning adds findings
// from the proxy's own response path.
func (fs *FindingStore) OnChange(fn func()) {
	if fs == nil {
		return
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.onChange = fn
}

// signalChangeLocked fires the change signal, if one is installed. Called with the
// write lock held, from every mutation.
func (fs *FindingStore) signalChangeLocked() {
	if fs.onChange != nil {
		fs.onChange()
	}
}

// SetPersistenceSink installs an optional write-through hook (see the onAdd
// field doc). Call before any findings are added.
func (fs *FindingStore) SetPersistenceSink(onAdd func(f *Finding)) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.onAdd = onAdd
}

// SetDeleteSink installs the hook called after a finding is removed, or nil to remove it. Single
// slot, like SetPersistenceSink. The durable mirror needs this to drop the row — without it a
// deleted finding walks back in on the next restart, reading its row out of SQLite.
func (fs *FindingStore) SetDeleteSink(onDelete func(id uint64)) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.onDelete = onDelete
}

// Triage applies an operator decision to one finding under the write lock and mirrors the result
// through the persistence sink. The mutation function must not call back into the store. Returns
// false when no finding carries that id — a stale row on the operator's screen, which the API
// surfaces as 404 rather than silently writing nothing.
func (fs *FindingStore) Triage(id uint64, mutate func(f *Finding)) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f := fs.byIDLocked(id)
	if f == nil {
		return false
	}
	mutate(f)
	// onAdd, not a separate update hook: the sink is a write-through mirror of a finding's current
	// state, and SaveFinding is an INSERT OR REPLACE keyed on the id, so re-offering the triaged
	// finding rewrites its row rather than inserting a second one.
	if fs.onAdd != nil {
		fs.onAdd(f)
	}
	fs.signalChangeLocked()
	return true
}

// byIDLocked finds a finding by id. Linear because triage is an operator action, not an intake
// path; the byKey index answers a different question (dedup) and does not map ids.
func (fs *FindingStore) byIDLocked(id uint64) *Finding {
	for _, f := range fs.findings {
		if f.ID == id {
			return f
		}
	}
	return nil
}

// Restore replaces the store's contents with a previously persisted snapshot.
// This is the load path for the SQLite write-through store.
func (fs *FindingStore) Restore(findings []*Finding) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.findings = findings
	var max uint64
	for _, f := range findings {
		if f.ID >= max {
			max = f.ID + 1
		}
	}
	fs.nextID = max
	// The dedup index is rebuilt from the snapshot rather than left empty, so a finding added after a
	// restart merges into the finding it belongs with instead of starting a second one beside it. A
	// row persisted before Target existed reads back with a zero target and simply does not
	// participate — it stays exactly as durable as it was, it just cannot attract new occurrences.
	fs.rebuildIndexLocked()
}

// Get retrieves a finding by ID.
func (fs *FindingStore) Get(id uint64) (*Finding, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	for _, f := range fs.findings {
		if f.ID == id {
			return f, nil
		}
	}

	return nil, fmt.Errorf("finding not found: %d", id)
}

// All returns all findings.
func (fs *FindingStore) All() []*Finding {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	result := make([]*Finding, len(fs.findings))
	copy(result, fs.findings)
	return result
}

// Count returns the number of findings.
func (fs *FindingStore) Count() int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return len(fs.findings)
}

// Delete removes a finding by ID.
func (fs *FindingStore) Delete(id uint64) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	for i, f := range fs.findings {
		if f.ID == id {
			fs.findings = append(fs.findings[:i], fs.findings[i+1:]...)
			// Drop the index entry too, and only if it still points at *this* finding: leaving it
			// behind would make the next matching finding merge into a deleted one, which would
			// vanish from the store's own list.
			if key, ok := fs.dedupKeyLocked(f.Name, f.Target); ok && fs.byKey[key] == f {
				delete(fs.byKey, key)
			}
			if fs.onDelete != nil {
				fs.onDelete(id)
			}
			fs.signalChangeLocked()
			return true
		}
	}

	return false
}

// Clear removes all findings.
// Clear removes all findings. Each removed id goes through the delete sink so the durable mirror
// empties with the memory — the sink is nil-able because a zero-value store is usable without one.
func (fs *FindingStore) Clear() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.onDelete != nil {
		for _, f := range fs.findings {
			fs.onDelete(f.ID)
		}
	}
	fs.findings = fs.findings[:0]
	fs.byKey = make(map[string]*Finding)
	fs.nextID = 0
	fs.signalChangeLocked()
}

// getTimestamp returns the current Unix time in milliseconds.
func getTimestamp() uint64 {
	return uint64(time.Now().UnixMilli())
}
