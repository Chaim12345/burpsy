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
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceCertain:
		return "Certain"
	case ConfidenceFirm:
		return "Firm"
	case ConfidenceTentative:
		return "Tentative"
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
	default:
		return ConfidenceTentative
	}
}

// Occurrence represents where a finding was observed.
type Occurrence struct {
	Request  MsgId
	Response *MsgId
	Span     Span
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
	Timestamp   uint64
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
}

// NewFindingStore creates a new finding store.
func NewFindingStore() *FindingStore {
	return &FindingStore{
		findings: make([]*Finding, 0),
	}
}

// Add adds a new finding to the store.
func (fs *FindingStore) Add(finding NewFinding) uint64 {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	id := fs.nextID
	fs.nextID++

	f := &Finding{
		ID:          id,
		Name:        finding.Name,
		Severity:    finding.Severity,
		Confidence:  finding.Confidence,
		Description: finding.Description,
		Remediation: finding.Remediation,
		Occurrences: finding.Occurrences,
		Inserted:    finding.Inserted,
		Timestamp:   uint64(getTimestamp()),
	}

	fs.findings = append(fs.findings, f)
	if fs.onAdd != nil {
		fs.onAdd(f)
	}
	fs.signalChangeLocked()
	return id
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
			fs.signalChangeLocked()
			return true
		}
	}

	return false
}

// Clear removes all findings.
func (fs *FindingStore) Clear() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.findings = fs.findings[:0]
	fs.nextID = 0
	fs.signalChangeLocked()
}

// getTimestamp returns the current Unix time in milliseconds.
func getTimestamp() uint64 {
	return uint64(time.Now().UnixMilli())
}
