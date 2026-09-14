package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- "Only apply to in-scope items" is a set-wide switch, and it round-trips ---------------------
//
// Burp has no per-rule scope: a rule's persisted fields are rule_type, enabled, category, string_match,
// string_replace and comment (Zejh.ZY), and the table has no scope column (CoreComponent5002). The one
// control is the panel checkbox, persisted as `proxy.match_replace_disable_out_of_scope`. These tests
// pin both halves of that: the switch survives a save/read, and a rule carrying the Rust-era per-rule
// `scope`/`query` is refused rather than saved without the condition.

func putRules(t *testing.T, ts *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/tools/rules", strings.NewReader(body))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	return rec
}

func getRules(t *testing.T, ts *Server) matchReplaceGetBody {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/tools/rules", nil)
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tools/rules = %d: %s", rec.Code, rec.Body.String())
	}
	var out matchReplaceGetBody
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the GET response: %v (%s)", err, rec.Body.String())
	}
	return out
}

// matchReplaceGetBody is the response shape the UI reads, declared here rather than reusing the
// server's own struct so a field renamed in one place and not the other fails this test instead of
// passing silently while the page shows nothing.
type matchReplaceGetBody struct {
	AffectsRequests  bool   `json:"affects_requests"`
	AffectsResponses bool   `json:"affects_responses"`
	ScopeSkipped     uint64 `json:"scope_skipped"`
	Config           struct {
		Rules []struct {
			RuleType string `json:"rule_type"`
		} `json:"rules"`
		UpdateContentLength bool `json:"update_content_length"`
		InScopeOnly         bool `json:"in_scope_only"`
	} `json:"config"`
}

// TestInScopeOnlyRoundTripsThroughTheRulesEndpoint is the wire half of the feature: the switch is set
// by the same endpoint that sets the rules, and read back by the same GET that reads them, because an
// operator edits both on one page and one object cannot be half-persisted.
func TestInScopeOnlyRoundTripsThroughTheRulesEndpoint(t *testing.T) {
	ts := newTestServer()

	body := `{"rules":[{"rule_type":"response_body","enabled":true,"string_match":"a","string_replace":"b"}],` +
		`"update_content_length":false,"in_scope_only":true}`
	if rec := putRules(t, ts, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}

	got := getRules(t, ts)
	if !got.Config.InScopeOnly {
		t.Error("in_scope_only did not survive the round trip; the switch would appear off after a reload")
	}
	// And the engine agrees with the wire, which is the part that matters: the proxy reads the engine.
	if !ts.matchReplace.InScopeOnly() {
		t.Error("the engine's rule set reports the restriction off after a PUT that turned it on")
	}
	// The other switch must not have been toggled by this one. Two booleans on one wire object is
	// exactly the shape where a swapped pair compiles and ships.
	if got.Config.UpdateContentLength {
		t.Error("update_content_length came back on; the two switches were written to the wrong fields")
	}
}

// TestInScopeOnlyDefaultsOffAndIsReportedOff states the default and the evidence the page renders: a
// fresh server reports the restriction off, and it reports that nothing was excluded, rather than
// leaving a field absent for the UI to guess at.
func TestInScopeOnlyDefaultsOffAndIsReportedOff(t *testing.T) {
	ts := newTestServer()
	got := getRules(t, ts)
	if got.Config.InScopeOnly {
		t.Error("a fresh server reports in_scope_only on; the default is off, as Burp's is")
	}
	if got.ScopeSkipped != 0 {
		t.Errorf("scope_skipped = %d on a fresh server, want 0", got.ScopeSkipped)
	}
	// Present in the payload even when zero: the page only shows the badge when it is non-zero, and
	// an absent field and a zero field are the same to that check, so this asserts the field exists.
	if !strings.Contains(bodyOfGet(t, ts), `"scope_skipped"`) {
		t.Error("the GET response does not carry scope_skipped at all; the page cannot report what the " +
			"restriction turned away")
	}
}

func bodyOfGet(t *testing.T, ts *Server) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/tools/rules", nil)
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	return rec.Body.String()
}

// TestAPerRuleScopeIsRefusedRatherThanDropped is the second half of the issue, and it is a refusal on
// purpose. The old behaviour accepted `scope`, saved the rule without it, and warned in the UI: a rule
// that survives one save and not the next is a rule whose behaviour changed without anyone editing it,
// and a dropped *scope* is worse than a dropped comment because it silently widens what the rule
// touches.
func TestAPerRuleScopeIsRefusedRatherThanDropped(t *testing.T) {
	ts := newTestServer()

	body := `{"rules":[{"rule_type":"request_header","enabled":true,"string_match":"a","string_replace":"b",` +
		`"scope":{"host":"only.example"}}]}`
	rec := putRules(t, ts, body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT carrying a per-rule scope = %d, want 400 — accepting it would store a rule whose "+
			"scope is gone by the next read", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Only apply to in-scope items") {
		t.Errorf("the refusal does not name the control that does exist, so an operator who wanted "+
			"this has nowhere to go: %q", rec.Body.String())
	}
	if got := len(ts.matchReplace.Rules()); got != 0 {
		t.Fatalf("the refused PUT installed %d rules; a whole-list PUT is all-or-nothing", got)
	}
}

// TestAPerRuleQueryIsRefusedAsWell — the same reasoning for the other Rust-era field. Separate test
// because they are separate fields with separate messages, and one shared refusal would leave the
// second field unchecked if the first were removed.
func TestAPerRuleQueryIsRefusedAsWell(t *testing.T) {
	ts := newTestServer()

	body := `{"rules":[{"rule_type":"request_header","enabled":true,"string_match":"a","string_replace":"b",` +
		`"query":"if in scope"}]}`
	rec := putRules(t, ts, body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT carrying a per-rule query = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "query") {
		t.Errorf("the refusal does not name the field it refused: %q", rec.Body.String())
	}
}

// An explicit null is not a value. A client that serialises an absent optional as `null` must not be
// told its rule is unrepresentable — the JSON encoders of several languages do exactly this, and a
// refusal here would be a 400 for a request that set nothing.
func TestANullScopeIsNotARefusal(t *testing.T) {
	ts := newTestServer()

	body := `{"rules":[{"rule_type":"response_body","enabled":true,"string_match":"a","string_replace":"b",` +
		`"scope":null,"query":null}]}`
	rec := putRules(t, ts, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT with an explicit null scope/query = %d, want 200: a null is an unset field, not a "+
			"condition this build cannot honour (%s)", rec.Code, rec.Body.String())
	}
}

// The dry run refuses what the live path refuses — the rule this endpoint has always held itself to,
// because a preview that demonstrated behaviour the operator can never install would be the one thing a
// dry run must not be.
func TestTheDryRunRefusesAPerRuleScopeToo(t *testing.T) {
	ts := newTestServer()

	body := `{"input":"HTTP/1.1 200 OK\r\n\r\nx","direction":"response","draft_rules":` +
		`[{"rule_type":"response_body","enabled":true,"string_match":"x","string_replace":"y",` +
		`"scope":{"host":"only.example"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tools/rules/test", strings.NewReader(body))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/tools/rules/test with a per-rule scope = %d, want 400", rec.Code)
	}
}
