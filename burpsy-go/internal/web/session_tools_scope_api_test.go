package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// requestIdentityFor is one request identity attributed to `tool`, for the match assertions below.
// The host and path are the same in every call, so a difference in the answer can only come from the
// tool — which is the whole point of the axis.
// postRuleIntoSrv posts a rule and returns the status code. postJSONInto insists on a non-nil
// destination, and this test only ever asserts on the code, so it decodes into a struct it ignores.
func postRuleIntoSrv(t *testing.T, srv *Server, body map[string]any) int {
	t.Helper()
	var out map[string]any
	return postJSONInto(t, srv, "/api/session/rules", body, &out)
}

func requestIdentityFor(host, tool string) session.RequestIdentity {
	return session.RequestIdentity{Host: host, Path: "/account", Port: 443, TLS: true, Tool: tool}
}

// /api/session's tools scope (burpsy-react-ui-so3), pinned over HTTP.
//
// Three things are checked here and nowhere else, because all three are wire facts: the vocabulary
// the editor's checklist is built from is the one the API enforces, an unrecognised tool name is
// refused rather than stored as a restriction that can never match, and a rule's tools scope
// survives the round trip through the DTO.

// The rules response carries the tool vocabulary, and it is toollog's — the same resolver the
// tool-log capture filter uses. This is what makes the editor's checklist impossible to drift: the
// UI renders what this response lists, and a tool added to toollog appears in the rule editor
// without a second edit.
func TestTheRulesResponseServesTheToolVocabulary(t *testing.T) {
	srv := sessionTestServer()
	rec := get(t, srv, "/api/session/rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET rules = %d, want 200", rec.Code)
	}
	var body struct {
		Tools []string `json:"tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode rules response: %v", err)
	}
	if len(body.Tools) != len(toollog.ToolAll) {
		t.Fatalf("the response lists %d tools, toollog has %d: the editor would offer a set the API "+
			"does not enforce", len(body.Tools), len(toollog.ToolAll))
	}
	for i, tool := range toollog.ToolAll {
		if body.Tools[i] != tool.String() {
			t.Errorf("tools[%d] = %q, want %q", i, body.Tools[i], tool.String())
		}
	}
	// Never omitted, even when there are no rules: an absent field and an empty list are the same
	// JSON, and "this server knows of no tools" must not be readable from a response that simply
	// had nothing to say.
	if !strings.Contains(rec.Body.String(), `"tools"`) {
		t.Error(`the rules response has no "tools" key at all; a client cannot tell that from a server with no tools`)
	}
}

// A rule's tools scope survives the round trip: submitted, matched, and handed back.
//
// The second half is the half that gets lost. ruleToDto is what the editor reads the rule back
// from, so a scope that reaches the coordinator but not the DTO is a restriction that vanishes the
// next time the operator opens the rule and saves it — the same restore-drops-a-field failure this
// file's scope block already names.
func TestARulesToolsScopeSurvivesTheRoundTrip(t *testing.T) {
	srv := sessionTestServer()
	code := postRuleIntoSrv(t, srv, map[string]any{
		"name":        "crawl re-login",
		"enabled":     true,
		"scope":       map[string]any{"allow_all": true, "rules": []any{}},
		"scope_tools": []string{"crawler"},
		"steps":       []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
		"validity":    map[string]any{"status_is": 200},
	})
	if code != http.StatusOK {
		t.Fatalf("POST rules = %d, want 200", code)
	}

	// The matcher honours it: this is the behaviour the wire round trip exists to carry.
	req := requestIdentityFor("target.test", "crawler")
	if got := srv.sessionCoordinator.MatchingRuleForRequest(req, nil, nil); got == nil {
		t.Fatal("a rule submitted with scope_tools [crawler] did not match crawler traffic")
	}
	other := requestIdentityFor("target.test", "intruder")
	if got := srv.sessionCoordinator.MatchingRuleForRequest(other, nil, nil); got != nil {
		t.Fatal("a rule submitted with scope_tools [crawler] matched Intruder traffic; the tools scope " +
			"was accepted by the wire and then ignored by the matcher")
	}

	// And it comes back on the DTO, so the editor does not silently widen it on the next save.
	rec := get(t, srv, "/api/session/rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET rules = %d, want 200", rec.Code)
	}
	var listed struct {
		Rules []wireSessionRuleWithTools `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	if len(listed.Rules) != 1 {
		t.Fatalf("listed %d rules, want 1", len(listed.Rules))
	}
	got := listed.Rules[0].ScopeTools
	if got == nil || len(*got) != 1 || (*got)[0] != "crawler" {
		t.Fatalf("the rule came back with scope_tools %v; want [crawler], or the editor reopens on "+
			"\"every tool\" and the next save writes that over the restriction", got)
	}
}

// An unrecognised tool name is refused with the alternatives named, rather than stored.
//
// A stored near-miss is the silently-dead restriction this whole axis is exposed to: the rule is
// listed, looks scoped, and matches nothing — or, if the comparison were fuzzy, matches the wrong
// tool. toollog.ToolFromName is the same resolver the tool log's own wire round-trip uses, so the
// rule editor and the Logger's capture filter cannot disagree about what "crawler" means.
func TestARuleNamingAnUnknownToolIsRefused(t *testing.T) {
	srv := sessionTestServer()
	rec := postJSON(t, srv, "/api/session/rules", map[string]any{
		"name":        "typo tool",
		"enabled":     true,
		"scope":       map[string]any{"allow_all": true, "rules": []any{}},
		"scope_tools": []string{"crawlr"},
		"steps":       []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
		"validity":    map[string]any{"status_is": 200},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST rules naming an unknown tool = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "crawlr") {
		t.Errorf("body = %q, want it to name the tool it refused", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "crawler") {
		t.Errorf("body = %q, want it to list the tools burpsy does have, so the operator can fix the spelling",
			rec.Body.String())
	}
	if n := len(srv.sessionCoordinator.AllRules()); n != 0 {
		t.Errorf("%d rules were installed by a refused request, want 0", n)
	}
}

// A tools scope that names nothing is refused rather than read as "every tool".
//
// Both readings are defensible in the abstract and only one is defensible here: a rule whose editor
// showed every tool unchecked and which then applied to every tool would be doing the opposite of
// what its own form said, and the operator has no way to tell. Refusing costs them one click.
func TestARuleWithAnEmptyStatedToolsScopeIsRefused(t *testing.T) {
	srv := sessionTestServer()
	rec := postJSON(t, srv, "/api/session/rules", map[string]any{
		"name":        "scoped to no tool",
		"enabled":     true,
		"scope":       map[string]any{"allow_all": true, "rules": []any{}},
		"scope_tools": []string{},
		"steps":       []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
		"validity":    map[string]any{"status_is": 200},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST rules with an empty stated tools scope = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no tools") {
		t.Fatalf("body = %q, want it to say the tools scope names no tools", rec.Body.String())
	}

	// The control, without which the refusal above could be satisfied by rejecting every rule: the
	// same rule with no scope_tools at all is accepted and applies to every tool.
	ok := postJSON(t, srv, "/api/session/rules", map[string]any{
		"name":     "every tool",
		"enabled":  true,
		"scope":    map[string]any{"allow_all": true, "rules": []any{}},
		"steps":    []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	})
	if ok.Code != http.StatusOK {
		t.Fatalf("POST rules with no tools scope = %d, want 200; body %s", ok.Code, ok.Body.String())
	}
	for _, tool := range []string{"crawler", "intruder", ""} {
		if got := srv.sessionCoordinator.MatchingRuleForRequest(requestIdentityFor("target.test", tool), nil, nil); got == nil {
			t.Errorf("a rule with no tools scope failed to match traffic from %q; silence is not a restriction", tool)
		}
	}
}

// wireSessionRuleWithTools is wireSessionRule plus the tools scope, kept separate so the shared
// session-wire fixture keeps saying exactly what it said before.
type wireSessionRuleWithTools struct {
	wireSessionRule
	ScopeTools *[]string `json:"scope_tools"`
}
