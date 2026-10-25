package mcp

import (
	"fmt"
	"path"
	"strings"

	"github.com/burpsy-go/burpsy/internal/agent"
)

// The MCP side of the per-project agent policy (burpsy-react-ui-2jig).
//
// The policy is enforced by the console's gate, which answers an agent-marked call. This layer does
// two things the gate cannot do for the model's benefit: it keeps a disabled tool out of tools/list
// and refuses a call to one before any request is built, and it advertises requiresConfirmation
// truthfully so a client prompts the right calls. Both only ever tighten: a policy setting can raise
// requiresConfirmation but never lower the manifest's own answer.
//
// The policy route is not a tool. Whatever the manifest says about it, this transport refuses any
// call that resolves to it, so a model cannot read or rewrite the rules that bind it.

// policyPath is the console's agent-policy route.
const policyPath = "/api/settings/agent-policy"

// isPolicyPath reports whether a request path (query allowed) names the policy route, however it is
// spelled: case, doubled or trailing slashes and dot segments are normalised first.
func isPolicyPath(p string) bool {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = path.Clean("/" + strings.ToLower(strings.TrimSpace(p)))
	return p == policyPath || strings.HasPrefix(p, policyPath+"/")
}

func (s *Server) currentPolicy() agent.Policy {
	if s.policy == nil {
		return agent.Policy{}
	}
	return s.policy()
}

// policyExempt are the transport's own tools, which are not routes and carry no policy.
func policyExempt(name string) bool { return name == confirmToolName || name == taskStatusToolName }

// refusedByPolicy returns the refusal text for a disabled tool, or "".
func (s *Server) refusedByPolicy(name string) string {
	if s.policy == nil || policyExempt(name) {
		return ""
	}
	if !s.currentPolicy().Visible(name) {
		return fmt.Sprintf("tool %s is disabled by the project's agent policy", name)
	}
	return ""
}

// visibleTools applies the policy to the descriptor list: disabled tools are dropped, and a tool the
// policy says must ask advertises requiresConfirmation. The stored descriptors are never mutated.
func (s *Server) visibleTools() []tool {
	if s.policy == nil {
		return s.tools
	}
	p := s.currentPolicy()
	out := make([]tool, 0, len(s.tools))
	for _, t := range s.tools {
		if policyExempt(t.Name) {
			out = append(out, t)
			continue
		}
		if !p.Visible(t.Name) {
			continue
		}
		set := p.Tools[t.Name]
		readOnly, _ := t.Annotations["readOnlyHint"].(bool)
		already, _ := t.Annotations["requiresConfirmation"].(bool)
		want := already || set == agent.SettingAsk ||
			(p.Mode == agent.ModeManual && !readOnly && set != agent.SettingAct)
		if want && !already {
			ann := make(map[string]any, len(t.Annotations))
			for k, v := range t.Annotations {
				ann[k] = v
			}
			ann["requiresConfirmation"] = true
			t.Annotations = ann
		}
		out = append(out, t)
	}
	return out
}
