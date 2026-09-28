package web

import (
	"strings"
	"testing"
)

// The agent tool registry (burpsy-react-ui-acdv).
//
// The point of these tests is the acceptance criterion that the GENERATION and the GATE are one
// change: a generated table nothing enforces is the same defect the route manifest test exists to
// prevent, one layer up. So each test below checks a property that would fail if the two were
// allowed to drift — a tool whose safety disagrees with its route's risk class, or a class that
// needs confirming and is reachable without it.

// Every tool in the registry must correspond to a real route, and carry a safety string derived
// from that route's risk class. A hand-written safety string that drifted from the risk class is
// exactly the duplication the derivation exists to remove.
func TestEveryAgentToolSafetyIsDerivedFromItsRouteRiskClass(t *testing.T) {
	tools := generateAgentTools()
	if len(tools) != len(manifest) {
		t.Fatalf("generated %d tools for %d routes — the registry and the manifest must be the same set, "+
			"or a route is reachable with no tool describing its safety", len(tools), len(manifest))
	}
	for _, tool := range tools {
		risk, ok := riskClassOf(tool.Name)
		if !ok {
			t.Errorf("tool %q has no manifest entry, so its risk class cannot be derived", tool.Name)
			continue
		}
		if want := toolSafety(risk); tool.Safety != want {
			t.Errorf("tool %q (risk %s) carries safety %q, want %q — a tool's safety string is DERIVED from "+
				"its route's risk class, so the two cannot be allowed to disagree", tool.Name, risk, tool.Safety, want)
		}
		if want := toolTier(risk); tool.Tier != want {
			t.Errorf("tool %q (risk %s) carries tier %q, want %q", tool.Name, risk, tool.Tier, want)
		}
	}
}

// A read-only tool is ALWAYS_ALLOW; anything that can change state, send traffic, read a secret or
// run code is ALWAYS_ESCALATE. This is the deterministic half of the tier, and it is checked per
// class rather than per tool so a new tool cannot opt itself out of escalation.
func TestAgentToolTierIsDeterministicFromTheRiskClass(t *testing.T) {
	for _, risk := range []riskClass{
		riskRead, riskLocal, riskEgress, riskAttack,
		riskScope, riskCredential, riskDestructive, riskAsset, riskExecute,
	} {
		tier := toolTier(risk)
		switch risk {
		case riskRead, riskAsset:
			if tier != "ALWAYS_ALLOW" {
				t.Errorf("risk %s yields tier %q, want ALWAYS_ALLOW — a read-only tool cannot change anything", risk, tier)
			}
		default:
			if tier != "ALWAYS_ESCALATE" {
				t.Errorf("risk %s yields tier %q, want ALWAYS_ESCALATE — every class that can change state, "+
					"send traffic, read a secret or run code escalates", risk, tier)
			}
		}
	}
}

// The gate is the reason the tier is not decoration: a confirmation-worthy class must be REFUSED
// without an explicit per-call human confirmation, and allowed with one.
func TestTheConfirmationGateRefusesEveryConfirmationWorthyClass(t *testing.T) {
	confirmWorthy := []riskClass{riskScope, riskAttack, riskCredential, riskDestructive}
	for _, risk := range confirmWorthy {
		if !needsConfirmation(risk) {
			t.Errorf("risk %s does not require confirmation, but it is in the confirmation-worthy set — "+
				"an unattended caller would be able to invoke it silently", risk)
		}
		gate := newConfirmationGate()
		if err := gate.allow(risk, "call-1"); err == nil {
			t.Errorf("the gate allowed an unconfirmed %s call — this is the exact bypass the gate exists to close", risk)
		}
		// A confirmed call is allowed: the gate is a per-call human decision, not a blanket refusal.
		gate.confirm("call-1")
		if err := gate.allow(risk, "call-1"); err != nil {
			t.Errorf("the gate refused a CONFIRMED %s call: %v — a human said yes and was still refused", risk, err)
		}
		// And the confirmation is per-call, not sticky: a second call needs its own yes.
		if err := gate.allow(risk, "call-2"); err == nil {
			t.Errorf("confirming call-1 also allowed call-2 on a %s route — confirmation is per-call, or one "+
				"yes authorises every later call the model decides to make", risk)
		}
	}
}

// The classes that need no confirmation must not be gated: a read-only tool an agent cannot read
// with is not a tool.
func TestTheConfirmationGateDoesNotRefuseReadOnlyClasses(t *testing.T) {
	for _, risk := range []riskClass{riskRead, riskAsset, riskLocal, riskEgress, riskExecute} {
		if needsConfirmation(risk) {
			t.Errorf("risk %s requires confirmation; the acceptance set is scope/attack/credential/destructive", risk)
		}
		if err := newConfirmationGate().allow(risk, ""); err != nil {
			t.Errorf("the gate refused a %s call with no confirmation: %v", risk, err)
		}
	}
}

// riskExecute is deliberately outside the confirmation-worthy set: the operator already authorised
// the binary on the command line, so the gate there is the allowlist rather than a dialog. This
// test exists because that is a judgement call, and a judgement call should be written down where
// a later change to the set will break it loudly.
func TestRiskExecuteIsExcludedFromTheConfirmationSetWithItsReason(t *testing.T) {
	if needsConfirmation(riskExecute) {
		t.Error("riskExecute now requires confirmation. That is a defensible change — a plugin runs until " +
			"something stops it — but it is a change of policy, not a bug fix. Reconsider it deliberately " +
			"and update the comment on riskExecute in route_manifest.go to say why.")
	}
}

// The gate's refusal must name the class and what it can do, so a caller refused by it can tell an
// operator what to confirm rather than being handed a bare 403.
func TestTheConfirmationGateRefusalNamesTheClassAndItsEffect(t *testing.T) {
	err := newConfirmationGate().allow(riskDestructive, "call-9")
	if err == nil {
		t.Fatal("an unconfirmed destructive call was allowed")
	}
	msg := err.Error()
	if !strings.Contains(msg, string(riskDestructive)) {
		t.Errorf("the refusal does not name the risk class: %q", msg)
	}
	if !strings.Contains(msg, "call-9") {
		t.Errorf("the refusal does not name the call it refused: %q", msg)
	}
	if !strings.Contains(msg, "destructive") {
		t.Errorf("the refusal does not say what the class can do: %q", msg)
	}
}
