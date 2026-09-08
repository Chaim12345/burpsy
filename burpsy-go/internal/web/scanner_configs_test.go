// SCAN-03's tests. Two claims, and they are different claims: that the listing is the table rather than
// a copy of it, and that a named configuration is *applied* rather than accepted and dropped.
package web

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// distinctiveBase is an AuditConfig whose every value is one no shipped preset uses, so an overlaid
// field and an inherited one can never look the same. This is what turns "the reply mentions the
// configuration" into "the reply could only have come from applying it".
func distinctiveBase() scanner.AuditConfig {
	return scanner.AuditConfig{
		TimeBudget:                            7 * time.Second,
		ConsecutiveCheckFailuresToAbandonUnit: 91,
		ConsecutiveUnitFailuresToFailItem:     92,
		PauseSessionAfterFailedItems:          93,
		PauseSessionAtFailedItemPercentage:    94,
	}
}

// configuredScannerServer is a server whose audit endpoint runs under a stated base configuration —
// what -scan-config does at startup.
func configuredScannerServer(t *testing.T, base scanner.AuditConfig) (*Server, core.ExchangeID) {
	t.Helper()
	s := newTestServer()
	s.WithScanner(scanner.NewActiveScanner(s.store, zap.NewNop()).
		WithScope(s.scope).
		WithAuditConfig(base))
	reqID, err := s.store.Put([]byte("GET /shop HTTP/1.1\r\nHost: h.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\n\r\n<html>hello</html>"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	// Exchange id 0 is not addressable through the audit route (it has always rejected id 0), so seed a
	// throwaway first.
	s.store.AddExchange(&core.Exchange{Request: reqID, Response: &respID, Host: "h.test", Port: 80, Method: "GET", Path: "/first"})
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: "h.test", Port: 80, Method: "GET", Path: "/shop"}
	s.store.AddExchange(ex)
	return s, ex.ID
}

// wireConfigsResp is the GET /api/scanner/configs body.
type wireConfigsResp struct {
	Configs []struct {
		Name string `json:"name"`
		Keys []struct {
			Name    string `json:"name"`
			BurpKey string `json:"burp_key"`
			What    string `json:"what"`
			Value   uint32 `json:"value"`
			Set     bool   `json:"set"`
		} `json:"keys"`
		Resolved auditConfigView `json:"resolved"`
	} `json:"configs"`
	Default         auditConfigView `json:"default"`
	ShippedByBurp   int             `json:"shipped_by_burp"`
	ImplementedHere int             `json:"implemented_here"`
}

// The configuration bodies decode into auditConfigView itself rather than into a parallel struct: a
// second copy of the wire shape here could drift from the one the server emits and the tests would
// still pass. What is checked independently is the *values*, which are recomputed from
// scanner.BuiltInConfig.Apply.

// The listing must *be* scanner.BuiltInConfigs, not a copy of it: same configurations, same order, same
// keys, same set/unset for each. A hand-written listing that dropped a configuration or a key would
// render perfectly and fail here.
func Test_the_listed_scan_configurations_are_generated_from_the_table(t *testing.T) {
	s, _ := configuredScannerServer(t, distinctiveBase())

	rec := get(t, s, "/api/scanner/configs")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/scanner/configs: %d", rec.Code)
	}
	var body wireConfigsResp
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}

	if len(body.Configs) != len(scanner.BuiltInConfigs) {
		t.Fatalf("listed %d configuration(s), want %d", len(body.Configs), len(scanner.BuiltInConfigs))
	}
	for i, want := range scanner.BuiltInConfigs {
		got := body.Configs[i]
		if got.Name != want.Name {
			t.Errorf("configs[%d] = %q, want %q", i, got.Name, want.Name)
		}
		wantKeys := want.Keys()
		if len(got.Keys) != len(wantKeys) {
			t.Fatalf("%s listed %d key(s), want %d — every key must appear, set or not", want.Name, len(got.Keys), len(wantKeys))
		}
		for j, wk := range wantKeys {
			gk := got.Keys[j]
			if gk.Name != wk.Name || gk.BurpKey != wk.BurpKey || gk.Set != wk.Set {
				t.Errorf("%s key %d = {%s %s set=%v}, want {%s %s set=%v}",
					want.Name, j, gk.Name, gk.BurpKey, gk.Set, wk.Name, wk.BurpKey, wk.Set)
			}
			if wk.Set && gk.Value != wk.Value {
				t.Errorf("%s %s = %d, want %d", want.Name, gk.Name, gk.Value, wk.Value)
			}
			if gk.What == "" {
				t.Errorf("%s %s has no description, so an operator cannot tell what choosing it changes", want.Name, gk.Name)
			}
		}
		// Resolved must be the overlay on the server's own default, independently recomputed here.
		wantResolved := want.Apply(distinctiveBase())
		if got.Resolved.TimeBudgetMs != wantResolved.TimeBudget.Milliseconds() {
			t.Errorf("%s resolved time budget = %dms, want %dms", want.Name, got.Resolved.TimeBudgetMs, wantResolved.TimeBudget.Milliseconds())
		}
		if got.Resolved.ConsecutiveCheckFailuresToAbandonUnit != wantResolved.ConsecutiveCheckFailuresToAbandonUnit {
			t.Errorf("%s resolved abandon-unit = %d, want %d", want.Name,
				got.Resolved.ConsecutiveCheckFailuresToAbandonUnit, wantResolved.ConsecutiveCheckFailuresToAbandonUnit)
		}
	}

	// The six implemented here are a subset of Burp's 29, and the response says so rather than letting
	// "6 configurations" read as Burp shipping six.
	if body.ImplementedHere != len(scanner.BuiltInConfigs) {
		t.Errorf("implemented_here = %d, want %d", body.ImplementedHere, len(scanner.BuiltInConfigs))
	}
	if body.ShippedByBurp <= body.ImplementedHere {
		t.Errorf("shipped_by_burp = %d, want more than the %d implemented here", body.ShippedByBurp, body.ImplementedHere)
	}
	// The default is what an audit with no name runs under, so a preset's numbers have something to be
	// compared against.
	if body.Default.ConsecutiveCheckFailuresToAbandonUnit != distinctiveBase().ConsecutiveCheckFailuresToAbandonUnit {
		t.Errorf("default abandon-unit = %d, want the server's own %d",
			body.Default.ConsecutiveCheckFailuresToAbandonUnit, distinctiveBase().ConsecutiveCheckFailuresToAbandonUnit)
	}
}

// wireAuditResp is the part of the audit reply SCAN-03 adds.
type wireAuditResp struct {
	Started    bool            `json:"started"`
	ExchangeID core.ExchangeID `json:"exchange_id"`
	ConfigName string          `json:"config_name"`
	Config     auditConfigView `json:"config"`
}

func runAuditUnder(t *testing.T, s *Server, id core.ExchangeID, body any) (int, wireAuditResp) {
	t.Helper()
	rec := postJSON(t, s, "/api/audit/"+strconv.FormatUint(uint64(id), 10), body)
	var out wireAuditResp
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, out
}

// The claim that matters: naming a configuration changes what the audit runs under. The base here sets
// every value to something no preset uses, so a reply carrying the preset's 2 could not have come from
// echoing the name back — only from applying the overlay. The keys the preset leaves alone must still
// show the base's values, which is the other half: an overlay is not a replacement.
func Test_running_an_audit_under_a_named_configuration_applies_its_overlay(t *testing.T) {
	s, id := configuredScannerServer(t, distinctiveBase())
	const name = "Crawl and Audit - Balanced"
	preset, ok := scanner.BuiltInConfigByName(name)
	if !ok {
		t.Fatalf("%s is missing from the table", name)
	}

	code, got := runAuditUnder(t, s, id, map[string]any{"config": name})
	if code != http.StatusOK {
		t.Fatalf("POST /api/audit/%d: %d", id, code)
	}
	if got.ConfigName != name {
		t.Errorf("config_name = %q, want %q", got.ConfigName, name)
	}
	// Balanced sets these two to 2. The base says 91 and 92.
	if got.Config.ConsecutiveCheckFailuresToAbandonUnit != 2 {
		t.Errorf("abandon-unit = %d, want the preset's 2 (the base says %d, so this is the overlay or nothing)",
			got.Config.ConsecutiveCheckFailuresToAbandonUnit, distinctiveBase().ConsecutiveCheckFailuresToAbandonUnit)
	}
	if got.Config.ConsecutiveUnitFailuresToFailItem != 2 {
		t.Errorf("fail-item = %d, want the preset's 2", got.Config.ConsecutiveUnitFailuresToFailItem)
	}
	// Balanced sets neither of these, so they must survive from the base. An overlay that replaced the
	// whole configuration would zero them, and a zero here is a *disabled breaker* — the opposite
	// instruction.
	if got.Config.PauseSessionAfterFailedItems != distinctiveBase().PauseSessionAfterFailedItems {
		t.Errorf("pause-after = %d, want the base's %d: an unset key inherits, it does not zero",
			got.Config.PauseSessionAfterFailedItems, distinctiveBase().PauseSessionAfterFailedItems)
	}
	if got.Config.TimeBudgetMs != distinctiveBase().TimeBudget.Milliseconds() {
		t.Errorf("time budget = %dms, want the base's %dms: Balanced sets no time limit",
			got.Config.TimeBudgetMs, distinctiveBase().TimeBudget.Milliseconds())
	}
	// And the whole reply must equal an independently computed overlay, so no field is left unchecked.
	want := preset.Apply(distinctiveBase())
	if !reflect.DeepEqual(got.Config, newAuditConfigView(want)) {
		t.Errorf("config = %+v, want %+v", got.Config, newAuditConfigView(want))
	}
}

// A preset that changes the time budget, so the overlay is proven for the one key whose unit is
// translated (minutes on the wire, a Duration in the engine) rather than copied.
func Test_a_configuration_that_sets_a_time_limit_changes_the_runs_budget(t *testing.T) {
	s, id := configuredScannerServer(t, distinctiveBase())
	const name = "Crawl and Audit - CICD Optimized"

	code, got := runAuditUnder(t, s, id, map[string]any{"config": name})
	if code != http.StatusOK {
		t.Fatalf("POST /api/audit/%d: %d", id, code)
	}
	if want := (15 * time.Minute).Milliseconds(); got.Config.TimeBudgetMs != want {
		t.Errorf("time budget = %dms, want %dms from maximum_crawl_and_audit_time = 15", got.Config.TimeBudgetMs, want)
	}
	// The default run must not have that budget, or the assertion above proves nothing.
	_, plain := runAuditUnder(t, s, id, nil)
	if plain.Config.TimeBudgetMs == got.Config.TimeBudgetMs {
		t.Error("the default run has the same budget as the preset run, so the preset changed nothing")
	}
}

// An audit with no configuration named runs under the server's default and says so with an empty name —
// not with a preset name it did not use.
func Test_an_audit_with_no_named_configuration_runs_under_the_server_default(t *testing.T) {
	s, id := configuredScannerServer(t, distinctiveBase())

	code, got := runAuditUnder(t, s, id, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /api/audit/%d: %d", id, code)
	}
	if got.ConfigName != "" {
		t.Errorf("config_name = %q, want empty: no preset was named", got.ConfigName)
	}
	if !reflect.DeepEqual(got.Config, newAuditConfigView(distinctiveBase())) {
		t.Errorf("config = %+v, want the server default %+v", got.Config, newAuditConfigView(distinctiveBase()))
	}
	if !got.Started || got.ExchangeID != id {
		t.Errorf("started/exchange_id = %v/%d, want true/%d: the pre-SCAN-03 keys must survive", got.Started, got.ExchangeID, id)
	}
}

// A name that does not resolve is refused, with the real names in the message. Auditing under the
// default instead would run a configuration the operator did not ask for and report success — the same
// class of lie as a skipped check reporting as a pass.
func Test_an_unknown_scan_configuration_is_refused_and_names_the_real_ones(t *testing.T) {
	s, id := configuredScannerServer(t, distinctiveBase())

	rec := postJSON(t, s, "/api/audit/"+strconv.FormatUint(uint64(id), 10), map[string]any{"config": "Crawl and Audit - Balnaced"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: an unknown configuration must not fall back to the default", rec.Code)
	}
	for _, name := range scanner.BuiltInConfigNames() {
		if !strings.Contains(rec.Body.String(), name) {
			t.Errorf("the refusal does not list %q, so an operator cannot retype it", name)
		}
	}

	// The legacy alias refuses identically; one gate, two doors.
	rec = postJSON(t, s, "/api/scanner/audit", map[string]any{"exchange_id": id, "config": "nope"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("legacy alias status = %d, want 400", rec.Code)
	}
}

// The legacy /api/scanner/audit alias takes the same configuration name, so a caller does not have to
// know which of the two routes it is on to use SCAN-03.
func Test_the_legacy_audit_alias_also_runs_under_a_named_configuration(t *testing.T) {
	s, id := configuredScannerServer(t, distinctiveBase())
	const name = "Never stop audit due to application errors"

	rec := postJSON(t, s, "/api/scanner/audit", map[string]any{"exchange_id": id, "config": name})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/scanner/audit: %d (%s)", rec.Code, rec.Body.String())
	}
	var got wireAuditResp
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if got.ConfigName != name {
		t.Errorf("config_name = %q, want %q", got.ConfigName, name)
	}
	preset, _ := scanner.BuiltInConfigByName(name)
	if !reflect.DeepEqual(got.Config, newAuditConfigView(preset.Apply(distinctiveBase()))) {
		t.Errorf("config = %+v, want the overlay", got.Config)
	}
}
