package web

import (
	"fmt"
	"strings"
)

// AgentTool is one tool an MCP-capable agent can call, derived from the route
// manifest. The safety string and escalation tier are DERIVED from the route's
// riskClass, not written twice — a tool whose safety disagrees with its route's
// risk class is the defect this generation exists to prevent.
type AgentTool struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Safety      string   `json:"safety"`
	Tier        string   `json:"tier"`
	Group       string   `json:"group"`
	Hints       []string `json:"hints"`
}

// toolSafety derives the safety string from a riskClass. ONE mapping, not one
// per tool, so a new risk class cannot be added without deciding what it means
// for every tool that carries it.
func toolSafety(r riskClass) string {
	switch r {
	case riskRead:
		return "read-only: reads state, sends nothing outbound"
	case riskLocal:
		return "local-write: mutates burpsy's own state without sending traffic"
	case riskEgress:
		return "egress: sends bounded traffic to the engagement target"
	case riskAttack:
		return "attack: sends unbounded traffic — an attack, audit, crawl, or capture"
	case riskScope:
		return "scope-widening: changes what the engagement is allowed to touch"
	case riskCredential:
		return "credential-access: reads or replays credentials"
	case riskDestructive:
		return "destructive: irreversibly discards evidence"
	case riskAsset:
		return "asset: serves a static asset"
	case riskExecute:
		return "code-execution: runs operator-supplied code in this process's privileges"
	default:
		return "unknown: risk class not recognised"
	}
}

// toolTier derives the escalation tier from a riskClass. ALWAYS_ALLOW for
// read-only tools, ALWAYS_ESCALATE for anything that can change state or send
// traffic.
func toolTier(r riskClass) string {
	switch r {
	case riskRead, riskAsset:
		return "ALWAYS_ALLOW"
	default:
		return "ALWAYS_ESCALATE"
	}
}

// toolGroup derives the tool group from a riskClass.
func toolGroup(r riskClass) string {
	switch r {
	case riskRead, riskAsset:
		return "DATASETS"
	case riskLocal, riskScope:
		return "CONFIGURATION"
	case riskEgress, riskAttack, riskCredential, riskDestructive, riskExecute:
		return "SCAN_CHECKS"
	default:
		return "CONFIGURATION"
	}
}

// toolHints derives the hints from a riskClass.
func toolHints(r riskClass) []string {
	var hints []string
	switch r {
	case riskRead, riskAsset:
		hints = append(hints, "READ_ONLY", "IDEMPOTENT")
	case riskLocal:
		hints = append(hints, "IDEMPOTENT")
	case riskEgress:
		hints = append(hints, "OPEN_WORLD")
	case riskAttack:
		hints = append(hints, "OPEN_WORLD", "DESTRUCTIVE")
	case riskScope:
		hints = append(hints, "DESTRUCTIVE")
	case riskCredential:
		hints = append(hints, "READ_ONLY")
	case riskDestructive:
		hints = append(hints, "DESTRUCTIVE")
	case riskExecute:
		hints = append(hints, "OPEN_WORLD")
	}
	return hints
}

// generateAgentTools builds the tool list from the route manifest. Each tool's
// safety, tier, group and hints are DERIVED from its route's riskClass.
func generateAgentTools() []AgentTool {
	tools := make([]AgentTool, 0, len(manifest))
	for pattern, r := range manifest {
		tools = append(tools, AgentTool{
			Name:        pattern,
			Description: r.summary,
			Safety:      toolSafety(r.risk),
			Tier:        toolTier(r.risk),
			Group:       toolGroup(r.risk),
			Hints:       toolHints(r.risk),
		})
	}
	return tools
}

// confirmationGate is the shared gate that refuses scope/attack/credential/
// destructive classes without an explicit per-call human confirmation.
type confirmationGate struct {
	confirmed map[string]bool
}

func newConfirmationGate() *confirmationGate {
	return &confirmationGate{confirmed: make(map[string]bool)}
}

// needsConfirmation reports whether a risk class requires explicit human
// confirmation before an unattended caller can use it.
func needsConfirmation(r riskClass) bool {
	switch r {
	case riskScope, riskAttack, riskCredential, riskDestructive:
		return true
	default:
		return false
	}
}

// allow reports whether a call to a route with the given risk class is allowed.
// If the class requires confirmation, the caller must have explicitly confirmed
// this specific call.
func (g *confirmationGate) allow(r riskClass, callID string) error {
	if !needsConfirmation(r) {
		return nil
	}
	if callID == "" {
		return fmt.Errorf("call to %s route requires explicit human confirmation: this route can %s", r, toolSafety(r))
	}
	if !g.confirmed[callID] {
		return fmt.Errorf("call %q to %s route has not been confirmed by a human", callID, r)
	}
	return nil
}

// confirm marks a call ID as human-confirmed.
func (g *confirmationGate) confirm(callID string) {
	g.confirmed[callID] = true
}

// riskClassOf returns the risk class for a route pattern.
func riskClassOf(pattern string) (riskClass, bool) {
	r, ok := manifest[pattern]
	if !ok {
		return "", false
	}
	return r.risk, true
}

// toolForPattern returns the agent tool for a route pattern.
func toolForPattern(pattern string) (AgentTool, bool) {
	r, ok := manifest[pattern]
	if !ok {
		return AgentTool{}, false
	}
	return AgentTool{
		Name:        pattern,
		Description: r.summary,
		Safety:      toolSafety(r.risk),
		Tier:        toolTier(r.risk),
		Group:       toolGroup(r.risk),
		Hints:       toolHints(r.risk),
	}, true
}

// toolsByGroup returns the tools grouped by their derived group.
func toolsByGroup() map[string][]AgentTool {
	tools := generateAgentTools()
	groups := make(map[string][]AgentTool)
	for _, t := range tools {
		groups[t.Group] = append(groups[t.Group], t)
	}
	return groups
}

// toolsByTier returns the tools grouped by their derived tier.
func toolsByTier() map[string][]AgentTool {
	tools := generateAgentTools()
	tiers := make(map[string][]AgentTool)
	for _, t := range tools {
		tiers[t.Tier] = append(tiers[t.Tier], t)
	}
	return tiers
}

// describeTools returns a human-readable summary of all tools.
func describeTools() string {
	tools := generateAgentTools()
	var b strings.Builder
	for _, t := range tools {
		fmt.Fprintf(&b, "%s: %s [%s]\n", t.Name, t.Safety, t.Tier)
	}
	return b.String()
}
