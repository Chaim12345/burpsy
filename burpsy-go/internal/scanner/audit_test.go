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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// auditTestExchange builds one exchange record the way the Rust test helper does: no store, no
// messages, just the fields a dispatch unit key is derived from.
func auditTestExchange(id core.ExchangeID, host, path string, tls bool) *core.Exchange {
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

func Test_the_one_unreachable_scope_yields_no_dispatch_unit(t *testing.T) {
	ex := auditTestExchange(1, "a.test", "/x", true)
	reachable := 0
	for _, s := range DispatchScopeAll {
		if s.IsReachable() {
			reachable++
		}
	}
	// Six of seven. Per-insertion-point became reachable when the corpus's active checks were
	// wired in; stored-per-insertion-point became reachable when StoredCheckDescriptors bound ten
	// native checks to it, and leaving it unreachable after that made all ten permanently
	// unsupported while still counting as runnable coverage. In-session-per-request has no bound
	// check and stays unreachable, which is the state this assertion protects.
	if reachable != 6 {
		t.Errorf("reachable scopes = %d, want 6 of seven wired up", reachable)
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
	// A per-insertion-point unit keys on the request itself: one request's point set is one unit,
	// because the check's run covers every point of it internally. Two captures of one request are
	// identical work; two captures of different requests are different point sets.
	if key(DispatchScopePerInsertionPoint, a) == key(DispatchScopePerInsertionPoint, b) {
		t.Error("a different capture is a different insertion-point unit")
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
	if b.checkFailed("u", "c") {
		t.Error("one failure is not enough")
	}
	if !b.checkFailed("u", "c") {
		t.Error("the second consecutive failure abandons the unit")
	}
	if b.unitFinished(true) {
		t.Error("one abandoned unit is not enough to fail the item")
	}
	if b.checkFailed("u", "c") {
		t.Error("the streak restarted with the unit, so this is failure one again")
	}
	if !b.checkFailed("u", "c") {
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
	if b.checkFailed("u", "c") {
		t.Error("one failure is not enough")
	}
	b.checkSucceeded()
	if b.checkFailed("u", "c") {
		t.Error("the streak restarted, so this is failure one again")
	}
	if !b.checkFailed("u", "c") {
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
		if b.checkFailed("u", "c") {
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
//
// Rows without a read (the per-issue selection keys this engine cannot apply) are exempt from the
// field side of the count but not from the reporting side: Keys() must still list them, with
// Applies false.
func Test_every_built_in_config_field_has_a_key_row(t *testing.T) {
	typ := reflect.TypeOf(BuiltInConfig{})
	optFields := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type == reflect.TypeOf(OptUint32{}) {
			optFields = append(optFields, typ.Field(i).Name)
		}
	}
	fieldRows := 0
	for _, k := range builtInConfigKeys {
		if k.read != nil {
			fieldRows++
		}
	}
	if len(optFields) != fieldRows {
		t.Fatalf("BuiltInConfig has %d overlayable field(s) %v but builtInConfigKeys has %d field-backed row(s): a field with no row is neither applied nor listed",
			len(optFields), optFields, fieldRows)
	}
	// Keys() must report all of them, every time, set or not: an operator has to be able to tell "this
	// preset leaves the time budget alone" from "this engine has no time budget".
	for _, c := range BuiltInConfigs {
		if got := len(c.Keys()); got != len(builtInConfigKeys) {
			t.Errorf("%s reported %d key(s), want all %d", c.Name, got, len(builtInConfigKeys))
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
		// Three states, and the rule is that a row's claim must match how it is applied:
		//
		//   applies && read != nil  -- a scalar key this engine overlays
		//   applies && read == nil  -- LIST-shaped: honoured through a different path entirely
		//   !applies && read == nil -- genuinely unrepresentable
		//   !applies && read != nil -- the impossible one, and a silent-state lie
		//
		// The third is what burpsy-react-ui-86le was: the row claimed NOT applied while the engine
		// honoured the control through a list-valued field this oracle cannot see. So a row with no
		// scalar read must not silently claim the plain two-state answer.
		if k.read == nil && k.applies && !k.listShaped {
			t.Errorf("key row %q has no read and is not list-shaped but claims to apply: an "+
				"unrepresentable key must be honest about it", k.name)
		}
		if k.read == nil && k.listShaped && !strings.HasPrefix(k.what, "partly applied: ") {
			t.Errorf("key row %q is list-shaped but its description does not say so: %q", k.name, k.what)
		}
	}
}

// Every insertion_point_types key must map to at least one bcheck kind, and every kind it maps to
// must be one bcheck.Enumerate understands — a kind string that drifted would silently stop
// selecting points rather than failing.
func Test_every_insertion_point_key_maps_to_a_bcheck_kind(t *testing.T) {
	known := map[string]bool{}
	for _, k := range DefaultProbeInsertionKinds {
		known[k] = true
	}
	// The full class list the enumerator supports, spelled independently of the overlay: kinds the
	// engine default does not enable but a shipped configuration may ask for.
	for _, kind := range []string{"query", "header", "cookie", "body", "param_name_url", "param_name_body", "url_path_filename", "url_path_folder", "entire_body"} {
		known[kind] = true
	}
	for _, k := range builtInConfigKeys {
		if !strings.HasPrefix(k.burpKey, "scanner/insertion_point_types/") {
			continue
		}
		kinds, ok := insertionPointKindFor[k.name]
		if !ok || len(kinds) == 0 {
			t.Errorf("insertion key %q has no bcheck kind mapping", k.name)
			continue
		}
		for _, kind := range kinds {
			if !known[kind] {
				t.Errorf("insertion key %q maps to unknown kind %q", k.name, kind)
			}
		}
	}
}

// A preset that names the insertion_point_types section must build the run's point set from the full
// Burp-shaped default, then apply each set key — so disabling one class leaves the others on
// (including the finer ones the engine default does not enumerate), and enabling entire body alone
// adds exactly that.
func Test_insertion_point_overlay_adds_and_removes_kinds(t *testing.T) {
	base := DefaultAuditConfig()

	off := BuiltInConfig{Name: "off", InsertCookies: SomeUint32(0), InsertParamName: SomeUint32(0)}
	applied := off.Apply(base)
	want := map[string]bool{"query": true, "header": true, "cookie": false, "body": true,
		"param_name_url": false, "param_name_body": false, "url_path_filename": true, "url_path_folder": true}
	for kind, wantOn := range want {
		if containsKind(applied.InsertionKinds, kind) != wantOn {
			t.Errorf("cookies+param-name off: kind %q present = %v, want %v", kind, containsKind(applied.InsertionKinds, kind), wantOn)
		}
	}

	on := BuiltInConfig{Name: "on", InsertEntireBody: SomeUint32(1)}
	applied = on.Apply(base)
	if !containsKind(applied.InsertionKinds, "entire_body") {
		t.Error("entire body on: entire_body missing from the run's point classes")
	}
	if containsKind(applied.InsertionKinds, "relocate_body_to_query") {
		t.Error("relocation kinds belong to a different Burp section and must not join the point set")
	}

	all := BuiltInConfig{Name: "all", InsertURLParams: SomeUint32(0), InsertBodyParams: SomeUint32(0),
		InsertCookies: SomeUint32(0), InsertHTTPHeaders: SomeUint32(0), InsertParamName: SomeUint32(0),
		InsertURLPathFilename: SomeUint32(0), InsertURLPathFolders: SomeUint32(0), InsertEntireBody: SomeUint32(0)}
	applied = all.Apply(base)
	if len(applied.InsertionKinds) != 1 || applied.InsertionKinds[0] != "none" {
		t.Errorf("every class disabled should pin the none sentinel, got %v", applied.InsertionKinds)
	}

	// No insertion key set: the engine default stands, untouched.
	untouched := BuiltInConfig{Name: "untouched"}.Apply(base)
	if len(untouched.InsertionKinds) != 0 {
		t.Errorf("a preset that never names the section must leave the engine default, got %v", untouched.InsertionKinds)
	}
}

// optField is the value side of an OptUint32 the oracle compares. An unset key's "inherited"
// comparison compares the field to itself; only a set key's value is actually asserted.
func optField(v OptUint32) uint64 {
	return uint64(v.Value)
}

func containsKind(kinds []string, kind string) bool {
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// The issues_reported overlay must narrow the check set exactly as documented: passive off drops
// the passive families, each active tier selects the checks carrying that rank, JavaScript off
// drops the DOM family, and a key that was never set inherits the base switches.
//
// The three active keys are INDEPENDENT. That is the whole point of the tier ranking: before it,
// "any tier true" left every base switch alone, so a preset that enabled only the light checks and
// refused the intrusive ones still ran the intrusive ones. Each key now selects its own rank.
func Test_issues_reported_gate_narrows_the_check_set(t *testing.T) {
	allOn := &ScanConfig{
		MaxConcurrency: 1,
		Timeout:        5 * time.Second,
		CheckSqli:      true, CheckXss: true, CheckPathTraversal: true, CheckSSRF: true,
		CheckXXE: true, CheckJwtWeak: true, CheckJSVulns: true,
		CheckPassiveAnalysis: true, CheckPassivePosture: true, CheckHeaders: true,
		CheckHostDiscovery: true, CheckExtendedCoverage: true, CheckReflectionProbes: true,
		CheckResponseDependence: true, CheckActiveInjection: true, CheckDOM: true,
		CheckExtendedActive: true, CheckOutOfBand: true, CheckStored: true, CheckCorpus: true,
	}
	s := NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).WithConfig(allOn)
	baseCount := len(s.enabledChecks())
	if baseCount == 0 {
		t.Fatal("the scanner has no checks enabled, so the gate has nothing to narrow")
	}

	passive := s.enabledChecksUnder(AuditConfig{PassiveChecks: SomeUint32(0)})
	if len(passive) >= baseCount {
		t.Errorf("passive off left %d checks, want fewer than the base %d", len(passive), baseCount)
	}

	allTiersOff := s.enabledChecksUnder(AuditConfig{LightActiveChecks: SomeUint32(0), MediumActiveChecks: SomeUint32(0), IntrusiveActiveChecks: SomeUint32(0)})
	if len(allTiersOff) >= baseCount {
		t.Errorf("all active tiers off left %d checks, want fewer than the base %d", len(allTiersOff), baseCount)
	}
	if len(allTiersOff) == 0 {
		t.Error("all active tiers off should leave the passive families running, not nothing")
	}

	// The three keys select independent sets. Enabling only the light tier must exclude the
	// intrusive checks even though their base switch is on — the assertion the old collapsed gate
	// made impossible to write.
	lightOnly := s.enabledChecksUnder(AuditConfig{LightActiveChecks: SomeUint32(1), MediumActiveChecks: SomeUint32(0), IntrusiveActiveChecks: SomeUint32(0)})
	if len(lightOnly) >= baseCount {
		t.Errorf("light-only left %d checks, want fewer than the base %d: the intrusive checks ran under a preset that disabled them", len(lightOnly), baseCount)
	}
	for _, c := range lightOnly {
		// Passive rows are exempt: they hang from scan_type_passive and send no request, so no
		// active tier selects or excludes them.
		if !c.passive && c.invasiveness != TierLight {
			t.Errorf("light-only admitted %q, which is ranked %s", c.name, c.invasiveness)
		}
	}

	// Enabling only the intrusive tier excludes the light checks: the selection is by rank, not a
	// suffix of the base order.
	intrusiveOnly := s.enabledChecksUnder(AuditConfig{LightActiveChecks: SomeUint32(0), MediumActiveChecks: SomeUint32(0), IntrusiveActiveChecks: SomeUint32(1)})
	if len(intrusiveOnly) >= baseCount {
		t.Errorf("intrusive-only left %d checks, want fewer than the base %d", len(intrusiveOnly), baseCount)
	}
	for _, c := range intrusiveOnly {
		if !c.passive && c.invasiveness != TierIntrusive {
			t.Errorf("intrusive-only admitted %q, which is ranked %s", c.name, c.invasiveness)
		}
	}

	// All three on reproduces the base set: the rank filter admits everything when every tier is
	// enabled, so a full preset is not a narrower run than no preset.
	allTiersOn := s.enabledChecksUnder(AuditConfig{LightActiveChecks: SomeUint32(1), MediumActiveChecks: SomeUint32(1), IntrusiveActiveChecks: SomeUint32(1)})
	if len(allTiersOn) < baseCount {
		t.Errorf("all tiers on left %d checks, want at least the base %d", len(allTiersOn), baseCount)
	}

	noGate := s.enabledChecksUnder(AuditConfig{})
	if len(noGate) != baseCount {
		t.Errorf("no gate keys set must equal the base set: %d, want %d", len(noGate), baseCount)
	}
}

// A run whose configuration names explicit point classes must enumerate those classes in its queue
// rows, not the engine default.
func Test_run_insertion_kinds_come_from_the_configuration(t *testing.T) {
	cfg := AuditConfig{InsertionKinds: []string{"query", "entire_body"}}
	if got := cfg.insertionKinds(); len(got) != 2 || got[0] != "query" || got[1] != "entire_body" {
		t.Errorf("explicit kinds = %v, want the configuration's own list", got)
	}
	if got := (AuditConfig{}).insertionKinds(); len(got) != len(DefaultProbeInsertionKinds) {
		t.Errorf("default kinds = %v, want the engine default", got)
	}
}

// insertionKindsByName and relocationKindsByName are this test's own copy of which point class each
// key governs, written out here so the oracle is independent of the table's apply functions. It is
// the one place a row pointed at the wrong class can be caught by a test that does not read the
// table it is checking.
var (
	insertionKindsByName = map[string][]string{
		"insert_url_params":        {"query"},
		"insert_body_params":       {"body"},
		"insert_cookies":           {"cookie"},
		"insert_http_headers":      {"header"},
		"insert_param_name":        {"param_name_url", "param_name_body"},
		"insert_url_path_filename": {"url_path_filename"},
		"insert_url_path_folders":  {"url_path_folder"},
		"insert_entire_body":       {"entire_body"},
	}
	relocationKindsByName = map[string]string{
		"relocate_body_to_url":    "relocate_body_to_query",
		"relocate_body_to_cookie": "relocate_body_to_cookie",
		"relocate_url_to_body":    "relocate_query_to_body",
		"relocate_url_to_cookie":  "relocate_query_to_cookie",
		"relocate_cookie_to_body": "relocate_cookie_to_body",
		"relocate_cookie_to_url":  "relocate_cookie_to_query",
	}
)

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
			case "quick_scan_url_params", "quick_scan_body_params", "quick_scan_cookies",
				"quick_scan_http_headers", "quick_scan_param_name",
				"quick_scan_url_path_filename", "quick_scan_url_path_folders",
				"quick_scan_entire_body":
				// The eight per-kind light-tier keys, checked through the DERIVED set rather than
				// the scalar: the claim is about which point classes reach the light pass, and a
				// test that read the OptUint32 would pass while the derived set was wrong -- which is
				// the shape of bug burpsy-react-ui-iueb is the precedent for.
				//
				// A preset that sets none of them leaves LightAuditKinds.Set false, and every kind is
				// in the light pass. That IS the assertion for a preset that does not mention them.
				if k.Set {
					if !applied.LightAuditKinds.Set {
						t.Errorf("%s sets %s but the derived light-audit set says nothing was configured; "+
							"the key was applied and then ignored, which is the failure this exists to catch",
							c.Name, k.Name)
						break
					}
				} else if applied.LightAuditKinds.Set {
					t.Errorf("%s does not set %s but the derived set is configured; an unset key must say "+
						"nothing, or a preset that never mentions quick scans narrows the light pass",
						c.Name, k.Name)
					break
				}
			case "number_of_follow_up_passes":
				// Set and NOT set both resolve through followUpPasses rather than the raw OptUint32,
				// so the overlay oracle checks the resolved count: a preset that sets 2 must leave the
				// run on 2, and a preset that does not set it must leave the base's (burpsy-react-ui-5efx).
				if k.Set {
					got = uint64(applied.followUpPasses())
					wantSet = uint64(k.Value)
				} else {
					got, wantUnset = uint64(applied.followUpPasses()), uint64(base.followUpPasses())
				}
			case "consecutive_check_failures_to_abandon_unit":
				got, wantSet, wantUnset = uint64(applied.ConsecutiveCheckFailuresToAbandonUnit), uint64(k.Value), uint64(base.ConsecutiveCheckFailuresToAbandonUnit)
			case "consecutive_unit_failures_to_fail_item":
				got, wantSet, wantUnset = uint64(applied.ConsecutiveUnitFailuresToFailItem), uint64(k.Value), uint64(base.ConsecutiveUnitFailuresToFailItem)
			case "pause_session_after_failed_items":
				got, wantSet, wantUnset = uint64(applied.PauseSessionAfterFailedItems), uint64(k.Value), uint64(base.PauseSessionAfterFailedItems)
			case "pause_session_at_failed_item_percentage":
				got, wantSet, wantUnset = uint64(applied.PauseSessionAtFailedItemPercentage), uint64(k.Value), uint64(base.PauseSessionAtFailedItemPercentage)
			case "maximum_audit_time_minutes":
				got = uint64(applied.TimeBudget)
				wantSet = uint64(time.Duration(k.Value) * time.Minute)
				wantUnset = uint64(base.TimeBudget)
			case "scan_type_passive":
				got, wantSet, wantUnset = optField(applied.PassiveChecks), uint64(k.Value), optField(base.PassiveChecks)
			case "scan_type_light_active":
				got, wantSet, wantUnset = optField(applied.LightActiveChecks), uint64(k.Value), optField(base.LightActiveChecks)
			case "scan_type_medium_active":
				got, wantSet, wantUnset = optField(applied.MediumActiveChecks), uint64(k.Value), optField(base.MediumActiveChecks)
			case "scan_type_intrusive_active":
				got, wantSet, wantUnset = optField(applied.IntrusiveActiveChecks), uint64(k.Value), optField(base.IntrusiveActiveChecks)
			case "scan_type_javascript_analysis":
				got, wantSet, wantUnset = optField(applied.JavaScriptAnalysis), uint64(k.Value), optField(base.JavaScriptAnalysis)
			case "store_issues_within_queue_items":
				got, wantSet, wantUnset = optField(applied.StoreQueueItems), uint64(k.Value), optField(base.StoreQueueItems)
			case "use_nested_insertion_points":
				// A switch carried as OptUint32, so what is checked is the VALUE (1 on, 0 off), not
				// whether the option is present. 0 is the meaningful setting here — it is what stops
				// the enumerator expanding a point inside an already-spliced value — so a check that
				// only asked "is it set?" would pass while the preset turned the feature the wrong
				// way (burpsy-react-ui-iueb).
				got, wantSet, wantUnset = optField(applied.NestedInsertionPoints), uint64(k.Value), optField(base.NestedInsertionPoints)
			case "max_insertion_points_per_base_request":
				// A cap, not a flag: the value itself is what must land on the field, so this checks
				// the number rather than a presence bit. An unset key must leave the base's value
				// alone — the enumerator falls back to bcheck.DefaultMaxInsertionPoints only when the
				// field is unset, and a preset silently overwriting that default with 0 would turn
				// "no cap stated" into "admit nothing", which is the one reading that is certainly
				// wrong (burpsy-react-ui-iueb).
				got, wantSet, wantUnset = optField(applied.MaxInsertionPointsPerRequest), uint64(k.Value), optField(base.MaxInsertionPointsPerRequest)
			case "follow_redirections", "audit_connect_timeout", "audit_normal_timeout":
				// The per-run overrides (burpsy-react-ui-o2p3). Each overlays a scalar the applied
				// config holds as an OptUint32, checked the use_nested_insertion_points way: the
				// VALUE lands, and an unset key leaves the base's own value alone.
				field := map[string]func(a AuditConfig) uint64{
					"follow_redirections":   func(a AuditConfig) uint64 { return optField(a.FollowRedirects) },
					"audit_connect_timeout": func(a AuditConfig) uint64 { return optField(a.ConnectTimeout) },
					"audit_normal_timeout":  func(a AuditConfig) uint64 { return optField(a.NormalTimeout) },
				}[k.Name]
				got = field(applied)
				wantSet = uint64(k.Value)
				wantUnset = uint64(field(base))
			case "skip_ineffective_checks":
				// A boolean-shaped gate (y4om), so the overlay is a scalar. Checked through the
				// Set/Value pair rather than a resolved boolean because that is what the row writes,
				// and because "unset means Burp's default (on)" cannot be observed on the field —
				// a preset that does not set the key must leave the field UNSET rather than write a
				// 1, or the operator's "inherit" would become an explicit decision on every preset.
				got = optField(applied.SkipIneffectiveChecks)
				if !k.Set {
					wantSet, wantUnset = 0, 0
				} else {
					wantSet, wantUnset = uint64(k.Value), 0
				}
			case "max_items_in_progress":
				// The admission cap (3ymo). Checked through the RUN's resolved value rather than
				// the config field, because a preset value of 0 means the engine's own
				// smallest-real-cap clamp rather than "unbounded" — resolvedMaxItemsInProgress
				// turns it into 1, and asserting the raw field would demand 0 be preserved, which
				// is precisely the deadlock the clamp exists to prevent.
				//
				// Unset means the shipped default, so a preset that does not set the key holds
				// DefaultMaxItemsInProgress rather than zero.
				if !k.Set {
					// Unset is a no-op overlay, so the applied config holds what the BASE held —
					// which is the zero value unless the base also set it. Asserting the shipped
					// default here would be wrong: Apply does not resolve defaults, and the run's
					// newAuditRun does that later.
					got, wantSet, wantUnset = optField(applied.MaxItemsInProgress), 0, 0
					break
				}
				want := uint64(k.Value)
				if k.Value == 0 {
					want = 1 // set-and-zero is the smallest real cap, not "unbounded"
				}
				got, wantSet, wantUnset = uint64(applied.resolvedMaxItemsInProgress()), want, 0
			case "scan_only_selected_issues", "select_individual_issues", "selected_issues":
				// The booleans choose Burp's mode and carry no value of their own onto the run
				// (applyIssueSelection reads them; issue_selection_test.go covers what each mode
				// does). Nothing on the applied config to compare to a scalar here.
				got, wantSet, wantUnset = 1, 1, 1
			case "relocate_body_to_url", "relocate_body_to_cookie", "relocate_url_to_body",
				"relocate_url_to_cookie", "relocate_cookie_to_body", "relocate_cookie_to_url":
				// A relocation key adds or removes one point class. The class is spelled here, by
				// hand, so a row pointed at the wrong one fails rather than agreeing with itself.
				// (Burp spells the query string "url".)
				present := uint64(0)
				if containsKind(applied.InsertionKinds, relocationKindsByName[k.Name]) {
					present = 1
				}
				got = present
				wantSet = uint64(k.Value) // 1 adds the class, 0 removes it
				wantUnset = 0             // the base holds no relocation class
			case "insert_url_params", "insert_body_params", "insert_cookies", "insert_http_headers",
				"insert_param_name", "insert_url_path_filename", "insert_url_path_folders", "insert_entire_body":
				// Insertion keys land in the point-class list, not a scalar field, and a preset that
				// sets any of them materialises the full Burp-shaped set before applying each. So the
				// contract checked here is per class: every class this key governs is present when the
				// key is 1 and absent when it is 0, and an unset key leaves the class absent (the base
				// holds no point classes at all).
				present := uint64(0)
				for _, kind := range insertionKindsByName[k.Name] {
					if containsKind(applied.InsertionKinds, kind) {
						present = 1
					}
				}
				got = present
				wantSet = uint64(k.Value)
				wantUnset = 0
			case "skip_all_tests_for_parameters":
				// A LIST-shaped key: applied through a path this oracle cannot see, and named here
				// rather than left in the default arm precisely because the guard below refuses an
				// applying key it cannot check. What is checked is the half that matters: the control
				// does not reach a scalar, and a PRESET cannot carry a list-valued key at all -- the
				// value is set on the run (burpsy-react-ui-86le).
				if len(applied.SkipAllTestsForParameters) != 0 {
					t.Errorf("preset %q reported %s as applied but a preset cannot carry a "+
						"list-valued key; the value is set on the run, not the preset", c.Name, k.Name)
				}
				got, wantSet, wantUnset = 0, 0, 0
			case "skip_server_side_injection_for_parameters":
				// The same list shape as the skip-all key (burpsy-react-ui-gmdk), checked the same way.
				if len(applied.SkipServerSideInjectionForParameters) != 0 {
					t.Errorf("preset %q reported %s as applied but a preset cannot carry a "+
						"list-valued key; the value is set on the run, not the preset", c.Name, k.Name)
				}
				got, wantSet, wantUnset = 0, 0, 0
			case "scan_speed":
				// The per-check mutation-set selector (burpsy-react-ui-ev7y). Named here because the
				// guard below refuses an applying key this oracle cannot check, and the check is the
				// ordinary one: the row's value reaches its own field.
				got = uint64(applied.ScanSpeed.Value)
				wantSet = uint64(k.Value)
				wantUnset = 0
			case "scan_accuracy":
				// The mutation-token count (4/8/10). Same contract as scan_speed above.
				got = uint64(applied.ScanAccuracy.Value)
				wantSet = uint64(k.Value)
				wantUnset = 0
			default:
				// A key with no field and no apply path can only be reported, never overlaid, so the
				// contract this test checks for it is that it did not reach a scalar. Naming all of
				// them here would verify nothing more and would need editing every time Burp adds a
				// key this engine does not implement. A key that *applies* must be named above: that
				// is the half of this oracle worth keeping, because it is where a row can be pointed
				// at the wrong field.
				if k.Applies {
					t.Fatalf("%s reports key %q as applying, which this test does not know how to check — add it here rather than letting it go unverified", c.Name, k.Name)
				}
				got, wantSet, wantUnset = 1, 1, 1
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
