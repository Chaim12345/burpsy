// Ported from the test module of crates/scanner/src/audit.rs, one test per Rust test and in the same
// order. This module is all edge semantics — does a breaker trip at the boundary or past it, does the
// ledger count a re-admitted unit twice — so the tests are as much the specification as the code is.
//
// The three tests at the end have no Rust counterpart: they cover what the Go port had to add. The
// ledger's mutex (Rust gets exclusivity from `&mut self`), the label-not-ordinal wire form (Rust gets
// it from serde), and OptUint32 standing in for `Option<u32>`.
package scanner

import (
	"encoding/json"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// auditTestExchange builds one exchange record the way the Rust test helper does: no store, no
// messages, just the fields a dispatch unit key is derived from.
func auditTestExchange(id uint64, host, path string, tls bool) *core.Exchange {
	port := uint16(80)
	if tls {
		port = 443
	}
	return &core.Exchange{
		ID:     id,
		Host:   host,
		Port:   port,
		TLS:    tls,
		Method: "GET",
		Path:   path,
	}
}

func Test_bcheck_given_clauses_reach_four_of_the_seven_dispatch_scopes(t *testing.T) {
	cases := []struct {
		given string
		want  DispatchScope
	}{
		{"host", DispatchScopePerHost},
		{"path", DispatchScopePerPath},
		{"request", DispatchScopePerRequest},
		{"insertion point", DispatchScopePerInsertionPoint},
	}
	for _, c := range cases {
		got, ok := DispatchScopeForGiven(c.given)
		if !ok {
			t.Fatalf("given %q: no dispatch scope", c.given)
		}
		if got != c.want {
			t.Errorf("given %q = %s, want %s", c.given, got.Label(), c.want.Label())
		}
	}
	// `given response` is passive; it is not an active dispatch scope at all.
	if _, ok := DispatchScopeForGiven("response"); ok {
		t.Error("given response must not map to an active dispatch scope")
	}
}

func Test_the_three_unreachable_scopes_yield_no_dispatch_unit(t *testing.T) {
	ex := auditTestExchange(1, "a.test", "/x", true)
	reachable := 0
	for _, s := range DispatchScopeAll {
		if s.IsReachable() {
			reachable++
		}
	}
	if reachable != 4 {
		t.Errorf("reachable scopes = %d, want 4 of seven wired up", reachable)
	}
	for _, s := range DispatchScopeAll {
		// Nothing can be admitted to a scope with no key, so an unreachable scope cannot quietly
		// appear to have been audited.
		_, ok := s.UnitKey(ex)
		if ok != s.IsReachable() {
			t.Errorf("%s disagrees with its own reachability: unit key present = %v, reachable = %v",
				s.Label(), ok, s.IsReachable())
		}
	}
}

func Test_dispatch_unit_keys_nest_from_host_down_to_request(t *testing.T) {
	a := auditTestExchange(1, "a.test", "/shop/item?id=1", true)
	b := auditTestExchange(2, "a.test", "/shop/item?id=2", true)
	key := func(s DispatchScope, ex *core.Exchange) string {
		k, ok := s.UnitKey(ex)
		if !ok {
			t.Fatalf("%s has no unit key", s.Label())
		}
		return k
	}

	// Same host, same path, different query, different request.
	if key(DispatchScopePerHost, a) != key(DispatchScopePerHost, b) {
		t.Error("one host must be one per-host unit")
	}
	if key(DispatchScopePerPath, a) != key(DispatchScopePerPath, b) {
		t.Error("the query string must not split a per-path unit")
	}
	if key(DispatchScopePerUrl, a) == key(DispatchScopePerUrl, b) {
		t.Error("a different query is a different URL")
	}
	if key(DispatchScopePerRequest, a) == key(DispatchScopePerRequest, b) {
		t.Error("a different capture is a different request")
	}

	if got, want := key(DispatchScopePerHost, a), "https://a.test:443"; got != want {
		t.Errorf("per-host key = %q, want %q", got, want)
	}
	if got, want := key(DispatchScopePerPath, a), "https://a.test:443/shop/item"; got != want {
		t.Errorf("per-path key = %q, want %q", got, want)
	}
	if got, want := key(DispatchScopePerUrl, a), "https://a.test:443/shop/item?id=1"; got != want {
		t.Errorf("per-URL key = %q, want %q", got, want)
	}
}

func Test_plaintext_and_tls_on_one_hostname_are_different_dispatch_units(t *testing.T) {
	// Different origins can serve different applications, so auditing one must not mark the other as
	// covered.
	plain, _ := DispatchScopePerHost.UnitKey(auditTestExchange(1, "a.test", "/", false))
	tls, _ := DispatchScopePerHost.UnitKey(auditTestExchange(2, "a.test", "/", true))
	if plain == tls {
		t.Errorf("http and https on one hostname share the unit key %q", plain)
	}
}

func Test_the_ledger_admits_a_pair_once_and_refuses_the_repeat(t *testing.T) {
	l := NewAuditLedger()
	if !l.Admit("https://a.test:443", 0) {
		t.Fatal("a new pair must be admitted")
	}
	if l.Admit("https://a.test:443", 0) {
		t.Error("the same pair must not be admitted twice")
	}
	if !l.Admit("https://a.test:443", 1) {
		t.Error("a different check is a different pair")
	}
	if !l.Admit("https://b.test:443", 0) {
		t.Error("a different unit is a different pair")
	}
	if l.Units() != 2 {
		t.Errorf("units = %d, want 2", l.Units())
	}
	if l.Admitted() != 3 {
		t.Errorf("admitted = %d, want 3", l.Admitted())
	}
}

func Test_the_ledger_tracks_check_indices_beyond_one_bitmap_word(t *testing.T) {
	l := NewAuditLedger()
	for _, i := range []int{0, 63, 64, 126, 127} {
		if !l.Admit("u", i) {
			t.Errorf("check %d should be new", i)
		}
	}
	for _, i := range []int{0, 63, 64, 126, 127} {
		if l.Admit("u", i) {
			t.Errorf("check %d should be a repeat", i)
		}
	}
	if l.Admitted() != 5 {
		t.Errorf("admitted = %d, want 5", l.Admitted())
	}
	if l.Units() != 1 {
		t.Errorf("units = %d, want 1", l.Units())
	}
}

func Test_two_consecutive_check_failures_abandon_the_unit_and_two_units_fail_the_item(t *testing.T) {
	b := newItemBreaker(DefaultAuditConfig())
	if b.checkFailed() {
		t.Error("one failure is not enough")
	}
	if !b.checkFailed() {
		t.Error("the second consecutive failure abandons the unit")
	}
	if b.unitFinished(true) {
		t.Error("one abandoned unit is not enough to fail the item")
	}
	if b.checkFailed() {
		t.Error("the streak restarted with the unit, so this is failure one again")
	}
	if !b.checkFailed() {
		t.Error("the second consecutive failure abandons the unit again")
	}
	if !b.unitFinished(true) {
		t.Error("the second abandoned unit fails the item")
	}
	if !b.failed() {
		t.Error("the item breaker should stay tripped")
	}
}

func Test_a_success_between_failures_resets_the_unit_breaker(t *testing.T) {
	b := newItemBreaker(DefaultAuditConfig())
	if b.checkFailed() {
		t.Error("one failure is not enough")
	}
	b.checkSucceeded()
	if b.checkFailed() {
		t.Error("the streak restarted, so this is failure one again")
	}
	if !b.checkFailed() {
		t.Error("the second consecutive failure abandons the unit")
	}
}

func Test_a_healthy_unit_resets_the_item_breaker(t *testing.T) {
	b := newItemBreaker(DefaultAuditConfig())
	if b.unitFinished(true) {
		t.Error("one abandoned unit is not enough")
	}
	if b.unitFinished(false) {
		t.Error("a good unit clears the streak")
	}
	if b.unitFinished(true) {
		t.Error("so this is abandoned unit one again")
	}
	if !b.unitFinished(true) {
		t.Error("the second consecutive abandoned unit fails the item")
	}
}

func Test_zero_disables_a_breaker_as_the_shipped_never_stop_preset_does(t *testing.T) {
	b := newItemBreaker(AuditConfigWithoutBreakers())
	for i := 0; i < 50; i++ {
		if b.checkFailed() {
			t.Fatalf("with the breaker off no failure count abandons the unit (failure %d)", i+1)
		}
	}
	for i := 0; i < 50; i++ {
		if b.unitFinished(true) {
			t.Fatalf("with the breaker off no abandoned unit count fails the item (unit %d)", i+1)
		}
	}
	if b.failed() {
		t.Error("the item must not be failed with every breaker off")
	}
}

func Test_the_session_breaker_is_off_by_default_and_trips_on_a_count_when_armed(t *testing.T) {
	off := newSessionBreaker(DefaultAuditConfig())
	for i := 0; i < 100; i++ {
		if off.itemFinished(true) {
			t.Fatalf("pausing a run must be opted into (item %d)", i+1)
		}
	}
	if off.failed() != 100 {
		t.Errorf("failed items = %d, want 100 counted even with the breaker off", off.failed())
	}

	cfg := DefaultAuditConfig()
	cfg.PauseSessionAfterFailedItems = 3
	armed := newSessionBreaker(cfg)
	if armed.itemFinished(true) {
		t.Error("one failed item is not enough")
	}
	if armed.itemFinished(false) {
		t.Error("a good item must not trip a count breaker")
	}
	if armed.itemFinished(true) {
		t.Error("two failed items are not enough")
	}
	if !armed.itemFinished(true) {
		t.Error("the third failed item trips the count breaker")
	}
}

func Test_the_session_breaker_trips_on_a_percentage_when_armed(t *testing.T) {
	cfg := DefaultAuditConfig()
	cfg.PauseSessionAtFailedItemPercentage = 50

	b := newSessionBreaker(cfg)
	if !b.itemFinished(true) {
		t.Error("1 of 1 failed is 100%")
	}

	b = newSessionBreaker(cfg)
	for i := 0; i < 3; i++ {
		if b.itemFinished(false) {
			t.Fatalf("no failures yet (item %d)", i+1)
		}
	}
	if b.itemFinished(true) {
		t.Error("1 of 4 is 25%")
	}
	if b.itemFinished(false) {
		t.Error("1 of 5 is 20%")
	}
	if b.itemFinished(true) {
		t.Error("2 of 6 is 33%")
	}
	if b.itemFinished(true) {
		t.Error("3 of 7 is 42%")
	}
	if !b.itemFinished(true) {
		t.Error("4 of 8 is 50%, which trips at the boundary")
	}
}

func Test_built_in_presets_overlay_only_the_keys_their_source_file_sets(t *testing.T) {
	lightweight, ok := BuiltInConfigByName("Crawl and Audit - Lightweight")
	if !ok {
		t.Fatal("the Lightweight preset is missing")
	}
	cfg := lightweight.Apply(DefaultAuditConfig())
	if cfg.TimeBudget != 15*time.Minute {
		t.Errorf("time budget = %s, want 15m from maximum_crawl_and_audit_time", cfg.TimeBudget)
	}
	if cfg.ConsecutiveCheckFailuresToAbandonUnit != 2 {
		t.Errorf("abandon-unit = %d, want 2", cfg.ConsecutiveCheckFailuresToAbandonUnit)
	}
	if cfg.PauseSessionAfterFailedItems != 0 {
		t.Errorf("pause-after = %d, want 0 (set to zero, i.e. disabled)", cfg.PauseSessionAfterFailedItems)
	}

	// Balanced sets neither the pause count nor a time limit, so both keep the default — an absent key
	// is not a zero.
	balanced, ok := BuiltInConfigByName("Crawl and Audit - Balanced")
	if !ok {
		t.Fatal("the Balanced preset is missing")
	}
	cfg = balanced.Apply(DefaultAuditConfig())
	if cfg.TimeBudget != DefaultAuditBudget {
		t.Errorf("time budget = %s, want the default: an absent key must not become zero", cfg.TimeBudget)
	}
	if cfg.ConsecutiveUnitFailuresToFailItem != 2 {
		t.Errorf("fail-item = %d, want 2", cfg.ConsecutiveUnitFailuresToFailItem)
	}

	if len(BuiltInConfigs) != 6 {
		t.Errorf("built-in configs = %d, want 6 of Burp's 29 shipped configurations", len(BuiltInConfigs))
	}
	if _, ok := BuiltInConfigByName("Crawl and Audit - Nonexistent"); ok {
		t.Error("an unknown preset name must not resolve")
	}
}

func Test_every_disposition_is_either_evidence_or_an_admitted_reason_to_distrust_a_clean_result(t *testing.T) {
	// Only Ran is a trustworthy negative result. Everything else either did not reach the target or
	// did not prove anything, and says so.
	looked, dispatched := 0, 0
	for _, d := range DispositionAll {
		if !d.StoppedLooking() {
			looked++
		}
		if d.IsDispatched() {
			dispatched++
		}
		if d.Explanation() == "" {
			t.Errorf("%s has no explanation", d)
		}
		if d.String() == "unknown disposition" {
			t.Errorf("disposition %d has no name", int(d))
		}
	}
	if looked != 3 {
		t.Errorf("dispositions that did not stop looking = %d, want 3", looked)
	}
	if dispatched != 2 {
		t.Errorf("dispatched dispositions = %d, want 2", dispatched)
	}
	if !DispositionAlreadyCovered.StoppedLooking() {
		t.Error("scope collapse is still the engine deciding not to look")
	}
	if DispositionRan.StoppedLooking() {
		t.Error("a check that ran did not stop looking")
	}
}

func Test_only_a_fully_audited_item_counts_as_completed(t *testing.T) {
	if !ItemStateAudited.CompletedAudit() {
		t.Error("an audited item is a completed audit")
	}
	// A bounded, failed or paused item is finished but not audited. Counting any of them as audited is
	// how a coverage number stops meaning anything.
	for _, s := range []ItemState{
		ItemStateBounded,
		ItemStateFailed,
		ItemStatePaused,
		ItemStateOutOfScope,
		ItemStateUnauditable,
	} {
		if !s.IsTerminal() {
			t.Errorf("%s should be terminal", s.Label())
		}
		if s.CompletedAudit() {
			t.Errorf("%s must not count as audited", s.Label())
		}
	}
	if ItemStatePending.IsTerminal() {
		t.Error("pending is not terminal")
	}
	if ItemStateAuditing.IsTerminal() {
		t.Error("auditing is not terminal")
	}
	// Dispatched states are the ones whose disposition counts must cover the whole check set.
	for _, s := range []ItemState{ItemStateAudited, ItemStateBounded, ItemStateFailed} {
		if !s.Dispatched() {
			t.Errorf("%s dispatched checks", s.Label())
		}
	}
	for _, s := range []ItemState{ItemStateOutOfScope, ItemStatePaused, ItemStateUnauditable} {
		if s.Dispatched() {
			t.Errorf("%s dispatched nothing", s.Label())
		}
	}
}

// The Rust ledger takes `&mut self`, so this cannot be written there: exclusivity is a compile-time
// fact. Go's AuditSession admits concurrently, so the resident set has to stay exact under contention
// or the bound is not a bound — two goroutines racing on one pair must produce exactly one admission.
func Test_the_ledger_admits_one_pair_exactly_once_under_concurrent_admission(t *testing.T) {
	l := NewAuditLedger()
	const racers = 64
	var wg sync.WaitGroup
	admitted := make(chan bool, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			admitted <- l.Admit("https://a.test:443", 7)
		}()
	}
	wg.Wait()
	close(admitted)
	wins := 0
	for ok := range admitted {
		if ok {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("admissions = %d, want exactly 1 of %d racers", wins, racers)
	}
	if l.Admitted() != 1 {
		t.Errorf("ledger admitted count = %d, want 1", l.Admitted())
	}
}

// Rust gets the wire form from serde, which writes variant names. A Go enum would serialise as an
// ordinal, so a state or disposition inserted into the middle of the list would silently renumber
// everything a stored report had already recorded.
func Test_states_and_dispositions_serialise_as_names_not_ordinals(t *testing.T) {
	b, err := json.Marshal(ItemStateBounded)
	if err != nil {
		t.Fatalf("marshal item state: %v", err)
	}
	if string(b) != `"bounded"` {
		t.Errorf("ItemStateBounded = %s, want \"bounded\"", b)
	}
	if b, err = json.Marshal(DispositionAlreadyCovered); err != nil {
		t.Fatalf("marshal disposition: %v", err)
	}
	if string(b) != `"already covered"` {
		t.Errorf("DispositionAlreadyCovered = %s, want \"already covered\"", b)
	}
	if b, err = json.Marshal(DispatchScopePerUrl); err != nil {
		t.Fatalf("marshal dispatch scope: %v", err)
	}
	if string(b) != `"per URL"` {
		t.Errorf("DispatchScopePerUrl = %s, want \"per URL\"", b)
	}
}

// OptUint32 stands in for Rust's `Option<u32>`, and the distinction it preserves is load-bearing:
// BuiltInConfig's whole doc comment turns on "absent inherits the default, zero disables the
// breaker". A uint32 with a zero sentinel could not express the shipped presets.
func Test_an_absent_option_and_an_option_set_to_zero_are_different_answers(t *testing.T) {
	absent := BuiltInConfig{Name: "absent"}
	zeroed := BuiltInConfig{Name: "zeroed", PauseSessionAfterFailedItems: SomeUint32(0)}

	base := DefaultAuditConfig()
	base.PauseSessionAfterFailedItems = 5

	if got := absent.Apply(base).PauseSessionAfterFailedItems; got != 5 {
		t.Errorf("absent key overlaid %d, want the base's 5 left alone", got)
	}
	if got := zeroed.Apply(base).PauseSessionAfterFailedItems; got != 0 {
		t.Errorf("a key set to zero overlaid %d, want 0 — zero disables the breaker", got)
	}
	if !SomeUint32(0).Set {
		t.Error("SomeUint32(0) is set; it is a zero, not an absence")
	}
	if (OptUint32{}).Set {
		t.Error("the zero value of OptUint32 is absent, not a set zero")
	}
}

// SCAN-03 asks an operator to be able to *choose* a built-in configuration, and a chooser has to be
// told what each one does. The listing an operator reads and the overlay the engine performs are
// therefore generated from the same table (builtInConfigKeys), and these two tests are what makes
// "generated" mean something: the first fails if a field is added to BuiltInConfig without a row, and
// the second re-derives every preset's effect independently of the table.

// Every OptUint32 on BuiltInConfig must have a row in builtInConfigKeys. Without this, a key added to
// the struct would be silently unreportable *and* silently not applied — Apply would skip it and the
// listing would omit it, and nothing would fail.
func Test_every_built_in_config_field_has_a_key_row(t *testing.T) {
	typ := reflect.TypeOf(BuiltInConfig{})
	optFields := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type == reflect.TypeOf(OptUint32{}) {
			optFields = append(optFields, typ.Field(i).Name)
		}
	}
	if len(optFields) != len(builtInConfigKeys) {
		t.Fatalf("BuiltInConfig has %d overlayable field(s) %v but builtInConfigKeys has %d row(s): a field with no row is neither applied nor listed",
			len(optFields), optFields, len(builtInConfigKeys))
	}
	// Keys() must report all of them, every time, set or not: an operator has to be able to tell "this
	// preset leaves the time budget alone" from "this engine has no time budget".
	for _, c := range BuiltInConfigs {
		if got := len(c.Keys()); got != len(optFields) {
			t.Errorf("%s reported %d key(s), want all %d", c.Name, got, len(optFields))
		}
	}
	seen := map[string]bool{}
	for _, k := range builtInConfigKeys {
		if k.name == "" || k.burpKey == "" || k.what == "" {
			t.Errorf("key row %q is missing a name, a Burp key or a description", k.name)
		}
		if seen[k.name] {
			t.Errorf("two rows are named %q", k.name)
		}
		seen[k.name] = true
	}
}

// Keys() and Apply() must agree, and the oracle is a switch written out by hand here: this test's copy
// of "which AuditConfig field does this key land in" is independent of the table's, so a row whose
// apply function writes the wrong field fails rather than agreeing with itself.
func Test_a_configs_reported_keys_are_exactly_what_apply_overlays(t *testing.T) {
	// A base with nothing in common with any preset's values, so an inherited field and an overlaid one
	// can never coincide by accident.
	base := AuditConfig{
		TimeBudget:                            7 * time.Second,
		ConsecutiveCheckFailuresToAbandonUnit: 91,
		ConsecutiveUnitFailuresToFailItem:     92,
		PauseSessionAfterFailedItems:          93,
		PauseSessionAtFailedItemPercentage:    94,
	}
	for _, c := range BuiltInConfigs {
		applied := c.Apply(base)
		for _, k := range c.Keys() {
			var got, wantSet, wantUnset uint64
			switch k.Name {
			case "consecutive_check_failures_to_abandon_unit":
				got, wantSet, wantUnset = uint64(applied.ConsecutiveCheckFailuresToAbandonUnit), uint64(k.Value), uint64(base.ConsecutiveCheckFailuresToAbandonUnit)
			case "consecutive_unit_failures_to_fail_item":
				got, wantSet, wantUnset = uint64(applied.ConsecutiveUnitFailuresToFailItem), uint64(k.Value), uint64(base.ConsecutiveUnitFailuresToFailItem)
			case "pause_session_after_failed_items":
				got, wantSet, wantUnset = uint64(applied.PauseSessionAfterFailedItems), uint64(k.Value), uint64(base.PauseSessionAfterFailedItems)
			case "maximum_audit_time_minutes":
				got = uint64(applied.TimeBudget)
				wantSet = uint64(time.Duration(k.Value) * time.Minute)
				wantUnset = uint64(base.TimeBudget)
			default:
				t.Fatalf("%s reports key %q, which this test does not know how to check — add it here rather than letting it go unverified", c.Name, k.Name)
			}
			if k.Set && got != wantSet {
				t.Errorf("%s sets %s to %d but the applied config holds %d", c.Name, k.Name, wantSet, got)
			}
			if !k.Set && got != wantUnset {
				t.Errorf("%s does not set %s, but the applied config holds %d instead of the base's %d", c.Name, k.Name, got, wantUnset)
			}
		}
		// The keys a preset does not set must not be reported as zeroes: that is the absent/zero
		// distinction OptUint32 exists for, one layer up.
		if c.Name == "Crawl and Audit - Balanced" {
			for _, k := range c.Keys() {
				if k.Name == "maximum_audit_time_minutes" && k.Set {
					t.Error("Balanced does not set a time limit; reporting it as set would be a fabricated key")
				}
			}
		}
	}
}

// The name list a refusal quotes has to be the real one, in table order, or an operator retyping from
// it gets refused again.
func Test_the_config_name_list_is_the_table(t *testing.T) {
	names := BuiltInConfigNames()
	if len(names) != len(BuiltInConfigs) {
		t.Fatalf("names = %d, want %d", len(names), len(BuiltInConfigs))
	}
	for i, n := range names {
		if n != BuiltInConfigs[i].Name {
			t.Errorf("names[%d] = %q, want %q", i, n, BuiltInConfigs[i].Name)
		}
		if _, ok := BuiltInConfigByName(n); !ok {
			t.Errorf("%q is listed but does not resolve", n)
		}
	}
}
