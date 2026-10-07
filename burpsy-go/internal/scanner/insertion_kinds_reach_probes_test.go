package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The insertion-point configuration has to reach the checks, not just the queue row
// (burpsy-react-ui-povm).
//
// `scanner/insertion_point_types/*` was threaded into exactly one consumer — auditItemPoints, which
// fills the audit-queue row — while all 19 probe sites passed the DefaultProbeInsertionKinds
// literal. There is no path from AuditConfig into CheckContext.Config, which is a *ScanConfig and
// deliberately unmerged, so an operator who turned cookie insertion off changed what the queue
// displayed and not one byte of what burpsy sent.
//
// That is the wrong direction to be wrong in. Every other parity gap on this board costs the
// operator a capability; this one sent payloads into positions they had excluded while reporting
// that it had not.

func TestAConfiguredInsertionKindReachesTheProbeSites(t *testing.T) {
	s := NewActiveScanner(nil, nil)
	s.WithAuditConfig(AuditConfig{InsertionKinds: []string{"query"}})

	cc := NewCheckContext(s, nil, nil)
	got := cc.ProbeInsertionKinds()

	if len(got) != 1 || got[0] != "query" {
		t.Fatalf("ProbeInsertionKinds() = %v, want [query] — the operator's choice must reach the probe, not stop at the queue row", got)
	}
}

// The "none" sentinel a fully-disabled overlay writes must survive to the probe, where it matches
// no kind. Collapsing it to the default is how "insert nowhere" would become "insert everywhere".
func TestTheNoneSentinelSurvivesToTheProbeSites(t *testing.T) {
	s := NewActiveScanner(nil, nil)
	s.WithAuditConfig(AuditConfig{InsertionKinds: []string{"none"}})

	got := NewCheckContext(s, nil, nil).ProbeInsertionKinds()
	if len(got) != 1 || got[0] != "none" {
		t.Fatalf("ProbeInsertionKinds() = %v, want [none] — a run configured to insert nowhere must probe nowhere", got)
	}
}

// An unconfigured run keeps the engine default, so every caller that never touched the setting —
// the CLI, the MCP surface, every existing test — behaves exactly as before.
func TestAnUnconfiguredRunKeepsTheEngineDefault(t *testing.T) {
	s := NewActiveScanner(nil, nil)

	got := NewCheckContext(s, nil, nil).ProbeInsertionKinds()
	if len(got) != len(DefaultProbeInsertionKinds) {
		t.Fatalf("ProbeInsertionKinds() = %v, want the engine default %v", got, DefaultProbeInsertionKinds)
	}
	for i := range got {
		if got[i] != DefaultProbeInsertionKinds[i] {
			t.Fatalf("ProbeInsertionKinds() = %v, want the engine default %v", got, DefaultProbeInsertionKinds)
		}
	}
}

// A nil context must not panic and must not silently probe nowhere: the default is the safe answer
// for a caller that supplied no configuration at all.
func TestANilContextFallsBackToTheDefault(t *testing.T) {
	var cc *CheckContext
	if got := cc.ProbeInsertionKinds(); len(got) != len(DefaultProbeInsertionKinds) {
		t.Fatalf("nil context gave %v, want the engine default", got)
	}
}

// The guard that keeps this fixed: no probe site may name the literal again. The defect was not
// that the default was wrong — it is the right default — but that it was hardcoded at the call
// site, where the configuration could never override it.
func TestNoCheckSiteHardcodesTheInsertionKinds(t *testing.T) {
	// Kept as a source check rather than a behavioural one because that is the actual failure
	// mode: a new check copied from an old one reintroduces the literal, builds, passes every
	// behavioural test, and silently ignores the operator's configuration.
	matches := grepCheckSources(t, "DefaultProbeInsertionKinds")
	for _, m := range matches {
		t.Errorf("%s names DefaultProbeInsertionKinds directly; use cc.ProbeInsertionKinds() so the audit configuration can reach it", m)
	}
}

// grepCheckSources returns "file:line" for every occurrence in the checks_*.go sources.
func grepCheckSources(t *testing.T, needle string) []string {
	t.Helper()
	files, err := filepath.Glob("checks_*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			if strings.Contains(line, needle) {
				out = append(out, fmt.Sprintf("%s:%d", f, i+1))
			}
		}
	}
	return out
}
