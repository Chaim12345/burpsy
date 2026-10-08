package mcp

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/web"
)

// consoleOver starts a real gated console over a store the test can write to.
func consoleOver(t *testing.T, store *core.TrafficStore) string {
	t.Helper()
	srv := web.NewServer(store, core.NewScope())
	ts := httptest.NewServer(srv.MCPGuarded())
	t.Cleanup(ts.Close)
	return ts.URL
}

// putExchange records one GET exchange the way the proxy would and returns its id.
func putExchange(t *testing.T, store *core.TrafficStore, host, path string) core.ExchangeID {
	t.Helper()
	id, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	status := uint16(200)
	store.AddExchange(&core.Exchange{Request: core.MsgPtr(id), Host: host, Port: 80, Method: "GET", Path: path, Status: &status})
	all := store.Exchanges()
	return all[len(all)-1].ID
}

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

// 4bfp: record a captured exchange into the site map through the sitemap_record tool.
func TestSitemapRecordThroughTheMCPTool(t *testing.T) {
	store := core.NewTrafficStore()
	base := consoleOver(t, store)
	id := putExchange(t, store, "rec.test", "/r")
	res := callGrouped(t, base, "sitemap_record", map[string]any{"body": map[string]any{"exchange_id": id}})
	if res.IsError || !strings.Contains(textOf(res), `"already_on_map":true`) || !strings.Contains(textOf(res), `"exchange_id":`) {
		t.Fatalf("sitemap_record: %s", textOf(res))
	}
	res = callGrouped(t, base, "sitemap_record", map[string]any{"body": map[string]any{"exchange_id": 4242}})
	if !res.IsError || !strings.Contains(textOf(res), "HTTP 404") {
		t.Fatalf("an unknown id was not a 404: %s", textOf(res))
	}
}
