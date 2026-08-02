package core

import (
	"fmt"
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
	return id
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
}

// getTimestamp returns the current Unix time in milliseconds.
func getTimestamp() uint64 {
	return uint64(time.Now().UnixMilli())
}
