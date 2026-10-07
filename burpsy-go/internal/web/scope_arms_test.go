package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// ---- Regular-expression and IP-range scope arms (burpsy-react-ui-c09) ----------------------------
//
// A scope rule could name a host only as a literal glob and a path only as a literal prefix. Burp
// takes a regular expression per URL component and an IP range. The new arms are opt-in per rule and
// ride inside the existing pattern and path strings, tagged — which is what makes them survive the
// round trip these tests are about: the same two strings are the rule's wire shape, its stored shape
// and its identity on remove, toggle and edit.

// The whole round trip in one claim: what the UI posts is what the engine matches on and what the
// next GET hands back, so a rule written once does not have to be written twice.
func TestScopeRegexAndRangeArmsRoundTripThroughTheWire(t *testing.T) {
	s := newTestServer()
	post := func(body map[string]any) {
		t.Helper()
		if rec := postJSON(t, s, "/api/scope", body); rec.Code != http.StatusOK {
			t.Fatalf("POST /api/scope %v: status = %d (%s)", body, rec.Code, rec.Body.String())
		}
	}
	post(map[string]any{"action": "include", "pattern": `regex:api[0-9]+\.example\.test`})
	post(map[string]any{"action": "include", "pattern": "range:10.0.0.0/24"})
	post(map[string]any{"action": "exclude", "pattern": "*", "path": `regex:/internal/.*`})

	// The engine matches on the arms, not on the strings.
	if !s.scope.Contains("api3.example.test", 443, "/", true) {
		t.Error("a host the regex arm describes is out of scope; the arm reached the store but not " +
			"the decision, which is a rule the operator can see and the proxy ignores")
	}
	if !s.scope.Contains("10.0.0.9", 80, "/", false) {
		t.Error("an address inside the IP range is out of scope; the range arm is not being applied")
	}
	if s.scope.Contains("10.0.0.9", 80, "/internal/keys", false) {
		t.Error("a path the regex exclude names is still in scope; a path arm that reached the store " +
			"without reaching the matcher is an exclude that does nothing")
	}

	// And the GET hands the arms back verbatim, which is the half the UI needs to show a rule and to
	// name it again on remove.
	rules := getScopeRules(t, s)
	want := map[string]bool{`regex:api[0-9]+\.example\.test`: false, "range:10.0.0.0/24": false}
	var sawPathArm bool
	for _, rule := range rules {
		if rule.Host != nil {
			if _, ok := want[*rule.Host]; ok {
				want[*rule.Host] = true
			}
		}
		if rule.Path != nil && *rule.Path == `regex:/internal/.*` {
			sawPathArm = true
		}
	}
	for pattern, seen := range want {
		if !seen {
			t.Errorf("GET /api/scope did not report the rule %q; a rule the table cannot show is a "+
				"rule the operator cannot remove or edit, because the identity it sends back is the "+
				"string it was given", pattern)
		}
	}
	if !sawPathArm {
		t.Error("GET /api/scope did not report the regex path arm; the table would show the rule as " +
			"covering the whole host, which is not what it covers")
	}
}

// An arm that cannot be read is refused where the operator can still fix it, and nothing is stored.
func TestScopeRefusesAnArmItCannotInterpretAndStoresNothing(t *testing.T) {
	s := newTestServer()
	for _, bad := range []map[string]any{
		{"action": "include", "pattern": `regex:api[0-9`},
		{"action": "include", "pattern": "regex:"},
		{"action": "include", "pattern": "range:10.0.0.0/33"},
		{"action": "include", "pattern": "range:10.0.0.5/8"},
		{"action": "exclude", "pattern": "app.test", "path": "regex:("},
	} {
		rec := postJSON(t, s, "/api/scope", bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %v: status = %d, want 400 — an uninterpretable arm that is accepted is "+
				"stored, and a stored rule the engine cannot read makes the whole scope refuse", bad, rec.Code)
		}
		if body := rec.Body.String(); !strings.Contains(body, "regex") && !strings.Contains(body, "range") && !strings.Contains(body, "IP") {
			t.Errorf("POST %v was refused with %q, which does not say which arm was wrong", bad, strings.TrimSpace(body))
		}
	}
	if rules := getScopeRules(t, s); len(rules) != 0 {
		t.Fatalf("the scope holds %d rules after only refusals; a 400 that still stores the rule is "+
			"worse than accepting it, because the operator believes nothing was written", len(rules))
	}
	// The refusals left the engine exactly as it was: nothing narrowed, nothing widened.
	if !s.scope.Contains("anything.test", 443, "/", true) {
		t.Error("an empty scope stopped authorising after five refused rules; a refusal must cost " +
			"the caller nothing")
	}
}

// The identity half: a tagged arm is normalised the same way on the way in and on the way out, or a
// rule can be created and never removed.
func TestAScopeRuleWithTaggedArmsCanBeRemovedByTheTupleItWasCreatedWith(t *testing.T) {
	s := newTestServer()
	create := map[string]any{"action": "exclude", "pattern": "range:192.168.0.0/16", "path": `regex:/admin.*`}
	if rec := postJSON(t, s, "/api/scope", create); rec.Code != http.StatusOK {
		t.Fatalf("create: status = %d (%s)", rec.Code, rec.Body.String())
	}
	remove := map[string]any{"action": "remove", "kind": "exclude", "pattern": "range:192.168.0.0/16", "path": `regex:/admin.*`}
	if rec := postJSON(t, s, "/api/scope", remove); rec.Code != http.StatusOK {
		t.Fatalf("remove: status = %d (%s) — the rule's identity changed between creation and "+
			"removal, so the operator has a rule they cannot delete from the table", rec.Code, rec.Body.String())
	}
	if rules := getScopeRules(t, s); len(rules) != 0 {
		t.Errorf("%d rules remain after removing the only one", len(rules))
	}
}

// Edit is the one action that names a tagged rule twice — once as the identity being replaced and
// once as the replacement — so it is the one where a normalisation that differs by a character turns
// into a 404 on a rule the operator can see.
func TestATaggedScopeRuleCanBeEditedInPlace(t *testing.T) {
	s := newTestServer()
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": `regex:api[0-9]\.test`, "path": `regex:/v1/.*`}); rec.Code != http.StatusOK {
		t.Fatalf("create: status = %d (%s)", rec.Code, rec.Body.String())
	}
	edit := map[string]any{
		"action":      "edit",
		"old_kind":    "include",
		"old_pattern": `regex:api[0-9]\.test`,
		"old_path":    `regex:/v1/.*`,
		"kind":        "include",
		"pattern":     `regex:api[0-9]+\.test`,
		"path":        `regex:/v[12]/.*`,
	}
	if rec := postJSON(t, s, "/api/scope", edit); rec.Code != http.StatusOK {
		t.Fatalf("edit: status = %d (%s) — the rule was named with exactly the strings the table "+
			"reported, so a refusal here means a tagged rule can be created and never corrected", rec.Code, rec.Body.String())
	}
	if !s.scope.Contains("api12.test", 443, "/v2/orders", true) {
		t.Error("the edited rule does not authorise what its new arms describe; the replacement was " +
			"stored without being compiled")
	}
	if s.scope.Contains("api1.test", 443, "/v3/orders", true) {
		t.Error("a path the new arm excludes is still in scope; the old rule is still in the list, so " +
			"the edit appended rather than replacing")
	}
	if rules := getScopeRules(t, s); len(rules) != 1 {
		t.Fatalf("the scope holds %d rules after an in-place edit; an edit that appends is an edit "+
			"that leaves the rule it was meant to replace still deciding", len(rules))
	}
}

// Import is the other door into the rule list, and it has to refuse on the same terms: a bundle
// carrying an unreadable arm must not land, and it must not land halfway.
func TestConfigImportRefusesABundleWhoseScopeArmCannotBeRead(t *testing.T) {
	s := newTestServer()
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "keep.test"}); rec.Code != http.StatusOK {
		t.Fatalf("seed rule: status = %d", rec.Code)
	}
	bundle := map[string]any{
		"version": 1,
		"scope": map[string]any{
			"rules": []map[string]any{
				{"kind": "Include", "host": "good.test"},
				{"kind": "Exclude", "host": `regex:admin(`},
			},
		},
	}
	rec := postJSON(t, s, "/api/config/import", bundle)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("import: status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	rules := getScopeRules(t, s)
	if len(rules) != 1 || rules[0].Host == nil || *rules[0].Host != "keep.test" {
		t.Fatalf("the recipient's scope is %v after a refused import; phase one converts before it "+
			"mutates precisely so a bad bundle costs the recipient nothing", rules)
	}
}

// An exported bundle carries the arms, so a scope written on one machine means the same thing on the
// next one. Exercised through export→import rather than by reading the JSON, because the claim is
// about what the recipient ends up enforcing.
func TestAnExportedScopeCarriesItsTaggedArmsToTheMachineThatImportsIt(t *testing.T) {
	donor := newTestServer()
	for _, rule := range []map[string]any{
		{"action": "include", "pattern": `regex:(www\.)?example\.test`},
		{"action": "exclude", "pattern": "range:10.1.0.0/16"},
	} {
		if rec := postJSON(t, donor, "/api/scope", rule); rec.Code != http.StatusOK {
			t.Fatalf("seed %v: status = %d (%s)", rule, rec.Code, rec.Body.String())
		}
	}
	exported := get(t, donor, "/api/config/export")
	if exported.Code != http.StatusOK {
		t.Fatalf("export: status = %d", exported.Code)
	}
	var bundle map[string]any
	if err := json.Unmarshal(exported.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}

	recipient := newTestServer()
	if rec := postJSON(t, recipient, "/api/config/import", bundle); rec.Code != http.StatusOK {
		t.Fatalf("import: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if !recipient.scope.Contains("www.example.test", 443, "/", true) {
		t.Error("the imported regex include does not authorise the host it describes; the arm was " +
			"flattened somewhere in the round trip, and the recipient is running a narrower scope " +
			"than the one they were handed")
	}
	if recipient.scope.Contains("10.1.2.3", 443, "/", true) {
		t.Error("the imported IP-range exclude does not exclude. This is the failure direction that " +
			"matters: the recipient believes a network is out of bounds and the proxy will send to it")
	}
}
