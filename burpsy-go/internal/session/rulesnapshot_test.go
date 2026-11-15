package session

import (
	"testing"

	"go.uber.org/zap"
)

// RuleSnapshot: the copy is deep (mutating it never reaches the live rule), the digest is the
// live rule's own, and the JSON round-trip rebuilds extraction matchers like the persistence
// loader - the ui2 gate merges on this copy, so these are its load-bearing properties.
func TestRuleSnapshotDeepCopyDigestAndRecompile(t *testing.T) {
	c := NewCoordinator(zap.NewNop())
	ex, err := NewExtraction("tok", "body", `token=(\w+)`, 1)
	if err != nil {
		t.Fatalf("NewExtraction: %v", err)
	}
	rule := &SessionRule{
		Name:    "snap",
		Enabled: true,
		Actions: []*Action{{
			Kind:    ActionCheckValidity,
			Enabled: true,
			Else:    []*Action{{Kind: ActionRunMacro, Enabled: true, ExtensionSession: "ext-state"}},
		}},
		Steps:       []MacroStep{{Method: "GET", URL: "https://fixture.test/login"}},
		MaxAttempts: 3,
		Extractions: []*Extraction{ex},
	}
	id, err := c.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	live := c.Rule(id)
	digest := RuleDigest(live)

	snap, snapDigest, ok := c.RuleSnapshot(id)
	if !ok {
		t.Fatal("snapshot of a stored rule not ok")
	}
	if snapDigest != digest {
		t.Errorf("snapshot digest %s != live digest %s", snapDigest, digest)
	}
	// The round-trip drops compiled extraction state; the snapshot must rebuild it like the
	// persistence loader does - an extraction that cannot match is a silent login failure.
	if got := snap.Extractions[0].Run(nil, []byte("token=abc123")); got != "abc123" {
		t.Errorf("snapshot extraction does not match after the round-trip: %q", got)
	}
	// Mutate the copy everywhere: nothing may reach the stored rule.
	snap.Enabled = false
	snap.Actions[0].Else[0].ExtensionSession = "mutated"
	snap.Extractions[0].Pattern = "mutated=(\\w+)"
	snap.Steps[0].URL = "https://fixture.test/mutated"
	if after := RuleDigest(c.Rule(id)); after != digest {
		t.Errorf("mutating the snapshot reached the live rule: %s -> %s", digest, after)
	}
	if _, _, ok := c.RuleSnapshot(9999); ok {
		t.Error("snapshot of a missing rule reported ok")
	}
}
