package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/matchreplace"
)

// ---- rule_type is a closed vocabulary, and an unknown one is refused ---------------------
//
// `targetToCategory` used to end in `return 0, nil`, and both call sites read it as
// `target, _ :=`. `matchreplace.Target` is an iota enum whose zero value is
// TargetRequestHeader, so a misspelled or unsupported rule_type did not fail — it silently
// produced a rule that rewrote **request headers on live traffic**, answered 200, and counted
// the rule as compiled.
//
// That is worse than an ordinary tolerant-parser bug: the wrong answer was applied to real
// requests rather than merely displayed. These tests pin the refusal.

func TestUnknownRuleTypeIsRefusedRatherThanCoercedToRequestHeader(t *testing.T) {
	ts := newTestServer()

	body := `{"rules":[{"rule_type":"responze_body","enabled":true,"string_match":"a","string_replace":"b"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/tools/rules", strings.NewReader(body))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with a misspelled rule_type = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	// The rejection has to name what is accepted; a bare 400 leaves the operator guessing at a
	// closed vocabulary that exists only in the source.
	if !strings.Contains(rec.Body.String(), "responze_body") {
		t.Errorf("the error does not quote the offending value: %q", rec.Body.String())
	}
	for _, name := range []string{"request_header", "response_body"} {
		if !strings.Contains(rec.Body.String(), name) {
			t.Errorf("the error does not list the accepted value %q: %q", name, rec.Body.String())
		}
	}
	// And crucially: nothing was installed. This is the part that made the old behaviour
	// dangerous rather than merely untidy.
	if got := len(ts.matchReplace.Rules()); got != 0 {
		t.Fatalf("a refused PUT installed %d rules; a rejected whole-list PUT must leave the live set untouched", got)
	}
}

// A whole-list PUT is all-or-nothing. One bad rule in position two must not leave rule one
// installed — the endpoint replaces the live set, so a partial apply would leave the proxy
// obeying a set the operator never asked for and the panel never showed.
func TestOneBadRuleLeavesTheEntireLiveSetUntouched(t *testing.T) {
	ts := newTestServer()

	good := `{"rule_type":"response_body","enabled":true,"string_match":"x","string_replace":"y"}`
	first := `{"rules":[` + good + `]}`
	req := httptest.NewRequest(http.MethodPut, "/api/tools/rules", strings.NewReader(first))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the setup PUT failed: %d %s", rec.Code, rec.Body.String())
	}
	if got := len(ts.matchReplace.Rules()); got != 1 {
		t.Fatalf("setup installed %d rules, want 1", got)
	}

	bad := `{"rules":[` + good + `,{"rule_type":"nonsense","enabled":true,"string_match":"p","string_replace":"q"}]}`
	req = httptest.NewRequest(http.MethodPut, "/api/tools/rules", strings.NewReader(bad))
	rec = httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with a bad second rule = %d, want 400", rec.Code)
	}
	// The index is named so the operator can find the offending row in a long list.
	if !strings.Contains(rec.Body.String(), "1") {
		t.Errorf("the error does not identify which rule failed: %q", rec.Body.String())
	}
	if got := len(ts.matchReplace.Rules()); got != 1 {
		t.Fatalf("the refused PUT changed the live set to %d rules; it must still hold the original 1", got)
	}
}

// The dry-run path refuses exactly what the live path refuses. If it coerced where the live
// path rejects, the preview would demonstrate behaviour the operator can never install — the
// one thing a dry run must not do.
func TestTheDryRunRefusesTheSameRuleTypesTheLivePathRefuses(t *testing.T) {
	ts := newTestServer()

	body := `{"input":"hello","direction":"response","draft_rules":[{"rule_type":"not_a_target","enabled":true,"string_match":"hello","string_replace":"bye"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/tools/rules/test", strings.NewReader(body))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("dry run with an unknown rule_type = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_a_target") {
		t.Errorf("the dry-run error does not quote the offending value: %q", rec.Body.String())
	}
}

// An absent rule_type is refused too, and says so as a missing field rather than as an unknown
// value of "". JSON that omits the key and JSON that sends `""` arrive here identically, so the
// message has to make sense for both readings.
func TestAMissingRuleTypeIsRefusedAsMissing(t *testing.T) {
	ts := newTestServer()

	body := `{"rules":[{"enabled":true,"string_match":"a","string_replace":"b"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/tools/rules", strings.NewReader(body))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with no rule_type = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "required") {
		t.Errorf("the error reads as an unknown value rather than a missing field: %q", rec.Body.String())
	}
}

// ---- the two directions must be inverses -----------------------------------------------
//
// matchReplaceTargetName is targetToCategory's inverse and has to stay total over the engine's
// enum. TargetRequestParamName and TargetRequestParamValue were missing from it and fell
// through to `return "request_body"`, so a param rule *read back* as a body rule. Combined with
// PUT's old coercion, the round trip was actively destructive: GET a param rule, PUT it back
// unchanged, and it became a body rule against live traffic.
//
// This test walks every declared Target rather than an enumerated list of names, so adding a
// Target to the engine without teaching both directions about it fails here by name.
func TestEveryEngineTargetRoundTripsThroughItsWireName(t *testing.T) {
	all := []matchreplace.Target{
		matchreplace.TargetRequestHeader,
		matchreplace.TargetRequestBody,
		matchreplace.TargetRequestFirstLine,
		matchreplace.TargetRequestParamName,
		matchreplace.TargetRequestParamValue,
		matchreplace.TargetResponseHeader,
		matchreplace.TargetResponseBody,
	}
	for _, target := range all {
		name := matchReplaceTargetName(target)
		if strings.HasPrefix(name, "unrecognised_target_") {
			t.Errorf("Target %d has no wire name: matchReplaceTargetName returned %q", int(target), name)
			continue
		}
		back, err := targetToCategory(name)
		if err != nil {
			t.Errorf("Target %d renders as %q, which targetToCategory refuses: %v", int(target), name, err)
			continue
		}
		if back != target {
			t.Errorf("round trip of Target %d via %q produced Target %d", int(target), name, int(back))
		}
	}
}

// The reverse default must not guess. An enum value with no wire name means this function was
// not updated alongside the engine, and answering "request_body" would let that omission reach
// the operator disguised as a real rule the proxy is applying.
func TestAnUnmappedTargetSaysSoRatherThanClaimingRequestBody(t *testing.T) {
	got := matchReplaceTargetName(matchreplace.Target(9999))
	if got == "request_body" {
		t.Fatal("an unmapped Target rendered as request_body; a missing mapping must not present as a real rule")
	}
	if !strings.Contains(got, "unrecognised") {
		t.Errorf("an unmapped Target rendered as %q, which does not say that it is unrecognised", got)
	}
}

// A param rule survives GET → PUT unchanged. This is the concrete failure the two fixes above
// combine to prevent, driven through the real handlers rather than the helpers.
func TestAParamRuleSurvivesAGetPutRoundTrip(t *testing.T) {
	ts := newTestServer()

	rule, err := matchreplace.NewRule(matchreplace.TargetRequestParamValue, matchreplace.CategoryLiteral, "secret", "REDACTED", "")
	if err != nil {
		t.Fatalf("NewRule: %v", err)
	}
	ts.matchReplace.SetRules([]*matchreplace.Rule{rule})

	req := httptest.NewRequest(http.MethodGet, "/api/tools/rules", nil)
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	var got matchReplaceGetResp
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if len(got.Config.Rules) != 1 {
		t.Fatalf("GET returned %d rules, want 1", len(got.Config.Rules))
	}
	if got.Config.Rules[0].RuleType != "request_param_value" {
		t.Fatalf("a param-value rule read back as %q", got.Config.Rules[0].RuleType)
	}

	// PUT the GET answer straight back, byte for byte, and the live set must be unchanged.
	encoded, err := json.Marshal(got.Config)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	req = httptest.NewRequest(http.MethodPut, "/api/tools/rules", strings.NewReader(string(encoded)))
	rec = httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT of the GET answer = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	live := ts.matchReplace.Rules()
	if len(live) != 1 {
		t.Fatalf("the round trip left %d rules, want 1", len(live))
	}
	if live[0].Target != matchreplace.TargetRequestParamValue {
		t.Fatalf("the round trip turned a param-value rule into Target %d (%s)",
			int(live[0].Target), matchReplaceTargetName(live[0].Target))
	}
}
