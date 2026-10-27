package web

import (
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

// The confirmation set is exactly scope/attack/credential/destructive. The gate that enforces it is
// confirm_gate.go (pinned by its own tests); this pins the set itself.
func TestTheConfirmationSetIsScopeAttackCredentialDestructive(t *testing.T) {
	for _, risk := range []riskClass{riskScope, riskAttack, riskCredential, riskDestructive} {
		if !needsConfirmation(risk) {
			t.Errorf("risk %s does not require confirmation — an unattended caller could invoke it silently", risk)
		}
	}
	for _, risk := range []riskClass{riskRead, riskAsset, riskLocal, riskEgress, riskExecute} {
		if needsConfirmation(risk) {
			t.Errorf("risk %s requires confirmation; the set is scope/attack/credential/destructive", risk)
		}
	}
}

// The published contract says a confirmation is needed exactly where the gate asks for one: a client
// reading the OpenAPI document must not be told an ungated route is gated, or the reverse.
func TestTheOpenAPIConfirmationNoteMatchesTheGate(t *testing.T) {
	for pattern, spec := range manifest {
		op := openAPIOperation("POST", pattern, pattern, spec)
		_, says := op["description"].(string)
		if says != needsConfirmation(spec.risk) {
			t.Errorf("%s (%s): OpenAPI says confirmation needed=%v, gate needsConfirmation=%v", pattern, spec.risk, says, needsConfirmation(spec.risk))
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
