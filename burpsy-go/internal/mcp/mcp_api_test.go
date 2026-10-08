package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// MCP-level tests for the API additions of 2jrr.1 phase 2, through the real stdio session against a
// real gated console.

// z5z3: "is this URL in scope" through the scope_check tool.
func TestScopeCheckThroughTheMCPTool(t *testing.T) {
	srv, base := newConsole(t)
	_ = srv
	res := callGrouped(t, base, "scope_check", map[string]any{
		"op":   "POST /api/scope/check",
		"body": map[string]any{"urls": []string{"https://app.test/x", "gopher://app.test/"}},
	})
	if res.IsError {
		t.Fatalf("scope_check failed: %s", textOf(res))
	}
	var view struct {
		Results []struct {
			InScope     bool            `json:"in_scope"`
			Reason      string          `json:"reason"`
			Error       string          `json:"error"`
			MatchedRule json.RawMessage `json:"matched_rule"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(bodyLine(t, textOf(res))), &view); err != nil {
		t.Fatalf("%v\n%s", err, textOf(res))
	}
	if len(view.Results) != 2 || !view.Results[0].InScope || view.Results[0].Reason != "no_include_rules" ||
		string(view.Results[0].MatchedRule) != "null" || view.Results[1].Error == "" {
		t.Fatalf("unexpected verdicts: %+v", view.Results)
	}
	// GET with the url query parameter.
	res = callGrouped(t, base, "scope_check", map[string]any{"op": "GET /api/scope/check", "query": map[string]string{"url": "http://app.test/"}})
	if res.IsError || !strings.Contains(textOf(res), `"in_scope":true`) {
		t.Fatalf("GET scope_check: %s", textOf(res))
	}
}
