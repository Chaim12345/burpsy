package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/agent"
	"github.com/burpsy-go/burpsy/internal/web"
)

// The MCP side of burpsy-react-ui-2jig: a tool the project's agent policy disables is not listed and
// is refused before any request; Ask raises requiresConfirmation; the policy route is never reachable
// over this transport. The policy itself is enforced by the console's gate (the web half); this
// layer only keeps a disabled tool out of the model's sight and the policy route out of its reach.

func policyFn(p agent.Policy) func() agent.Policy { return func() agent.Policy { return p } }

func listWith(t *testing.T, opts Options) []groupedTool {
	t.Helper()
	opts.BaseURL = "http://127.0.0.1:1"
	replies := askWith(t, opts, rpcRequest(t, 1, "tools/list", nil))
	var lst struct {
		Tools []groupedTool `json:"tools"`
	}
	if err := json.Unmarshal(replies[0].Result, &lst); err != nil {
		t.Fatal(err)
	}
	return lst.Tools
}

func TestDisabledToolIsNotListed(t *testing.T) {
	all := listWith(t, Options{})
	if len(all) < 3 {
		t.Fatalf("surface too small: %d", len(all))
	}
	victim := all[0].Name
	got := listWith(t, Options{Policy: policyFn(agent.Policy{Tools: map[string]agent.ToolSetting{victim: agent.SettingDisabled}})})
	if len(got) != len(all)-1 {
		t.Fatalf("listed %d, want %d", len(got), len(all)-1)
	}
	for _, g := range got {
		if g.Name == victim {
			t.Fatalf("%s is disabled and still listed", victim)
		}
	}
}

func TestDisabledToolIsRefusedBeforeAnyRequest(t *testing.T) {
	all := listWith(t, Options{})
	var victim groupedTool
	for _, g := range all {
		if len(g.Annotations.Operations) > 0 {
			victim = g
			break
		}
	}
	opts := Options{BaseURL: "http://127.0.0.1:1", Policy: policyFn(agent.Policy{Tools: map[string]agent.ToolSetting{victim.Name: agent.SettingDisabled}})}
	replies := askWith(t, opts, rpcRequest(t, 1, "tools/call", map[string]any{"name": victim.Name, "arguments": map[string]any{"op": victim.Annotations.Operations[0]}}))
	var res callResult
	if err := json.Unmarshal(replies[0].Result, &res); err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(textOf(res), "disabled by the project's agent policy") {
		t.Fatalf("got %q", textOf(res))
	}
	if strings.Contains(textOf(res), "could not reach") {
		t.Fatal("a request was attempted for a disabled tool")
	}
	// The confirm step is refused for it too: no token is minted for a tool the policy removed.
	replies = askWith(t, opts, rpcRequest(t, 2, "tools/call", map[string]any{"name": confirmToolName, "arguments": map[string]any{"tool": victim.Name, "arguments": map[string]any{"op": victim.Annotations.Operations[0]}}}))
	if err := json.Unmarshal(replies[0].Result, &res); err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(textOf(res), "disabled by the project's agent policy") || strings.Contains(textOf(res), "could not reach") {
		t.Fatalf("confirm for a disabled tool: %q", textOf(res))
	}
}

func TestAskSettingRaisesRequiresConfirmationAndNeverLowersIt(t *testing.T) {
	base := listWith(t, Options{})
	var read, gated groupedTool
	for _, g := range base {
		if !g.Annotations.RequiresConfirmation && read.Name == "" {
			read = g
		}
		if g.Annotations.RequiresConfirmation && gated.Name == "" {
			gated = g
		}
	}
	if read.Name == "" || gated.Name == "" {
		t.Skip("surface lacks both a plain and a gated tool")
	}
	got := listWith(t, Options{Policy: policyFn(agent.Policy{Tools: map[string]agent.ToolSetting{read.Name: agent.SettingAsk, gated.Name: agent.SettingAct}})})
	for _, g := range got {
		switch g.Name {
		case read.Name:
			if !g.Annotations.RequiresConfirmation {
				t.Errorf("%s is set to Ask and must advertise requiresConfirmation", g.Name)
			}
		case gated.Name:
			if !g.Annotations.RequiresConfirmation {
				t.Errorf("%s is in the floor: Act must not lower requiresConfirmation", g.Name)
			}
		}
	}
	for _, g := range base {
		if g.Name == read.Name && g.Annotations.RequiresConfirmation {
			t.Fatal("the base descriptor was mutated")
		}
	}
}

func TestManualModeMarksEveryNonReadToolAsRequiringConfirmation(t *testing.T) {
	got := listWith(t, Options{Policy: policyFn(agent.Policy{Mode: agent.ModeManual})})
	for _, g := range got {
		if !policyExempt(g.Name) && !g.Annotations.ReadOnly && !g.Annotations.RequiresConfirmation {
			t.Errorf("%s writes but does not require confirmation in Manual mode", g.Name)
		}
	}
}

func TestThePolicyRouteIsUnreachableOverTheTransport(t *testing.T) {
	routes := []web.MCPRouteInfo{
		{Pattern: "/api/history", Methods: []string{"GET"}, Summary: "history", Risk: "read", Hints: []string{"READ_ONLY"}},
		{Pattern: "/api/settings/agent-policy", Methods: []string{"GET", "PUT"}, Summary: "agent policy", Risk: "scope", NeedsConfirm: true},
		{Pattern: "/api/settings/", Methods: []string{"GET"}, Summary: "subtree", Risk: "read", SubPath: "/api/settings/x", Hints: []string{"READ_ONLY"}},
	}
	opts := Options{BaseURL: "http://127.0.0.1:1", Routes: routes, Surface: SurfaceRoutes}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"api_settings_agent_policy", map[string]any{}},
		{"api_settings", map[string]any{"path": "/api/settings/agent-policy"}},
		{"api_settings", map[string]any{"path": "/api/settings/Agent-Policy"}},
		{"api_settings", map[string]any{"path": "/api/settings/./agent-policy"}},
		{"api_settings", map[string]any{"path": "/api/settings/agent-policy/"}},
	} {
		replies := askWith(t, opts, rpcRequest(t, 1, "tools/call", map[string]any{"name": tc.name, "arguments": tc.args}))
		var res callResult
		if replies[0].Error != nil {
			t.Fatalf("%s: protocol error %s (tool names: %v)", tc.name, replies[0].Error.Message, toolNamesOf(t, opts))
		}
		if err := json.Unmarshal(replies[0].Result, &res); err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(textOf(res), "agent policy") || strings.Contains(textOf(res), "could not reach") {
			t.Errorf("%s %v: got %q", tc.name, tc.args, textOf(res))
		}
	}
}

func toolNamesOf(t *testing.T, opts Options) []string {
	t.Helper()
	opts.In, opts.Out = strings.NewReader(""), &strings.Builder{}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s.ToolNames()
}

func TestIsPolicyPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/api/settings/agent-policy": true, "/api/settings/agent-policy/": true, "/API/Settings/Agent-Policy": true,
		"/api/settings//agent-policy": true, "/api/settings/x/../agent-policy": true,
		"/api/settings/agent-policy?x=1": true,
		"/api/settings/triage":           false, "/api/history": false,
	} {
		if got := isPolicyPath(p); got != want {
			t.Errorf("%q: got %v want %v", p, got, want)
		}
	}
}
