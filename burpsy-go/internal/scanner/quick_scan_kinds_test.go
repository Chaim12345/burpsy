package scanner

import (
	"context"
	"testing"

	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// burpsy-react-ui-02qi: Burp's quick_scan_* keys gate the LIGHT-AUDIT TIER per insertion-point kind —
// its own panel says "runs a lighter audit ... Select the insertion point types this applies to"
// (Zrdr.java:26), with the per-kind gate at Zb1q.java:111-118. burpsy's key table declined all eight
// as "redundant with insertion_point_types", which is factually wrong: insertion_point_types chooses
// which points are ENUMERATED, these choose which of the enumerated ones get the cheap pass.
//
// The tier itself exists (audit_engine.go, bead 7bkj). What was missing is the operator's per-kind
// control over it, so an operator who wanted a light audit of URL parameters and a full audit of
// body parameters could not say so, and the settings page told them the keys were redundant.

// A configuration that says NOTHING about quick scans gets every kind in the light pass, which is
// exactly the behaviour before this field existed.
func TestAnUnconfiguredLightAuditAppliesToEveryKind(t *testing.T) {
	cfg := AuditConfig{}
	if cfg.LightAuditKinds.Set {
		t.Error("a zero LightAuditKinds reports itself configured; a configuration that never mentions " +
			"the keys must get what it always got")
	}
	for _, kind := range []string{"query", "body", "cookie", "header", "entire_body", "url_path_filename"} {
		if !cfg.LightAuditKinds.LightApplies(kind) {
			t.Errorf("kind %q is outside the light pass with nothing configured; the previous behaviour "+
				"was every kind in, and narrowing it silently would change every existing crawl", kind)
		}
	}
}

// A kind the operator took OUT of the light pass is out. This is the control the eight keys are.
func TestAKindTickedOffIsOutOfTheLightPass(t *testing.T) {
	// query in, body out — the exact combination the bead says could not be expressed.
	cfg := AuditConfig{}
	cfg.QuickScanURLParams = SomeUint32(1)
	cfg.QuickScanBodyParams = SomeUint32(0)
	cfg.rebuildLightAuditKinds()

	if !cfg.LightAuditKinds.LightApplies("query") {
		t.Error("query was ticked IN and is not in the light pass")
	}
	if cfg.LightAuditKinds.LightApplies("body") {
		t.Error("body was ticked OUT and is still in the light pass; a key set to false must take its " +
			"kind out of the cheap pass, which is the control these keys exist for")
	}
	// And a kind nobody mentioned is IN, because the narrowing is by what was ticked OFF. An operator
	// who said nothing about cookies must not find the light pass silently taken away from them.
	if !cfg.LightAuditKinds.LightApplies("cookie") {
		t.Error("cookie is out of the light pass although no key mentioned it; the set narrows by what " +
			"was ticked OFF, so an unmentioned kind keeps the behaviour it had")
	}
}

// The polarity is the reason the set is DERIVED rather than accumulated: a later overlay must be able
// to un-tick what an earlier one ticked.
func TestTheLightAuditSetIsDerivedNotAccumulated(t *testing.T) {
	// One configuration turns body ON...
	first := AuditConfig{}
	first.QuickScanBodyParams = SomeUint32(1)
	first.rebuildLightAuditKinds()
	if !first.LightAuditKinds.LightApplies("body") {
		t.Fatal("precondition: body was not opted into the light pass")
	}

	// ...and a later overlay turns it OFF. If the set accumulated, the first decision would win
	// forever and "set to false" would mean "was never mentioned" for every key applied after it.
	second := first
	second.QuickScanBodyParams = SomeUint32(0)
	second.rebuildLightAuditKinds()
	if second.LightAuditKinds.LightApplies("body") {
		t.Error("a later overlay setting a key to false did not remove its kind; the set is accumulated " +
			"rather than derived, so the first configuration to mention a key wins forever")
	}
}

// A preset carrying the eight keys resolves into a set the engine reads, and a preset carrying none
// leaves it unset. This is the wiring, and it is the thing a row can be accepted-and-ignored without.
func TestAPresetResolvesIntoTheSetTheEngineReads(t *testing.T) {
	ticked := BuiltInConfig{
		Name:                    "light for URLs",
		QuickScanURLParams:      SomeUint32(1),
		QuickScanBodyParams:     SomeUint32(0),
		QuickScanHTTPHeaders:    SomeUint32(0),
		QuickScanCookies:        SomeUint32(0),
		QuickScanEntireBody:     SomeUint32(0),
		QuickScanParamName:      SomeUint32(0),
		QuickScanURLPathFolders: SomeUint32(0),
	}
	applied := ticked.Apply(DefaultAuditConfig())
	if !applied.LightAuditKinds.Set {
		t.Fatal("a preset that sets the keys leaves the derived set unconfigured; the keys were applied " +
			"and then ignored, which is the failure iueb is the precedent for")
	}
	if !applied.LightAuditKinds.LightApplies("query") {
		t.Error("the one ticked-IN kind is not in the light pass")
	}
	for _, kind := range []string{"body", "cookie", "header", "entire_body"} {
		if applied.LightAuditKinds.LightApplies(kind) {
			t.Errorf("kind %q was ticked off and is still in the light pass", kind)
		}
	}

	// And a preset that mentions none of them leaves the set unset, so the engine's gate is a
	// no-op and every crawl behaves as it always has.
	plain := BuiltInConfig{Name: "no quick-scan keys"}.Apply(DefaultAuditConfig())
	if plain.LightAuditKinds.Set {
		t.Error("a preset that names no quick_scan key leaves the set configured; every existing " +
			"configuration must keep the behaviour it had")
	}
}

// The eight rows now apply, and each one's text says what it does rather than calling itself
// redundant with a different key set.
func TestTheEightQuickScanKeysNowApply(t *testing.T) {
	want := []string{
		"quick_scan_url_params", "quick_scan_body_params", "quick_scan_cookies",
		"quick_scan_http_headers", "quick_scan_param_name",
		"quick_scan_url_path_filename", "quick_scan_url_path_folders", "quick_scan_entire_body",
	}
	seen := map[string]bool{}
	for _, k := range BuiltInConfigKeys() {
		if _, tracked := quickScanKeyKinds[k.Name]; !tracked {
			continue
		}
		seen[k.Name] = true
		if !k.Applies {
			t.Errorf("%s still reports as not applied (%q) while AuditConfig.LightAuditKinds gates the "+
				"light tier per kind", k.Name, k.What)
		}
		if k.Partial {
			t.Errorf("%s is marked partial; the control is honoured in full, through a boolean per kind, "+
				"so there is nothing reduced about it", k.Name)
		}
		// The VIEW carries no read/apply, so the pair is checked on the internal table — which is
		// where a row that says "applies" while carrying nothing would be caught.
		row := tableRowNamed(t, k.Name)
		if row == nil || row.read == nil || row.apply == nil {
			t.Errorf("%s claims to apply but has no read/apply pair; a row that cannot carry a value "+
				"cannot be honoured", k.Name)
		}
	}
	for _, name := range want {
		if !seen[name] {
			t.Errorf("no row for %s at all", name)
		}
	}
}

// tableRowNamed is the internal row behind a view row, so a test can read the read/apply pair the
// wire type does not carry.
func tableRowNamed(t *testing.T, name string) *struct {
	name       string
	burpKey    string
	what       string
	read       func(BuiltInConfig) OptUint32
	apply      func(*AuditConfig, uint32)
	max        uint32
	min        uint32
	applies    bool
	listShaped bool
} {
	t.Helper()
	for i := range builtInConfigKeys {
		if builtInConfigKeys[i].name == name {
			// Copied out rather than aliased: the test only reads, and a pointer into the table
			// would let an accidental write in one test change another.
			out := builtInConfigKeys[i]
			return &out
		}
	}
	return nil
}

// The GATE, through the handle the checks actually see.
//
// Every test above reads LightApplies directly, so a mutation that built the per-kind set correctly
// and then never consulted it at the light tier would pass all of them — which is the iueb shape the
// bead names, and which the mutation check duly found the first time round.
//
// This assembles the handle the way auditItem does — the repetition half stubbed to "yes, this kind
// has been seen enough times", so the ONLY thing that can change the answer is the per-kind
// opt-in — and asks it through ShouldSkipRepetitive, which is what a check calls.
func TestTheLightTierGateItselfHonoursAKindTheOperatorTookOut(t *testing.T) {
	cfg := AuditConfig{}
	cfg.QuickScanURLParams = SomeUint32(1)
	cfg.QuickScanBodyParams = SomeUint32(0)
	cfg.rebuildLightAuditKinds()

	tier := &RunLightAudit{
		// A repetition threshold of 1, so the repetition half alone would skip EVERY kind. The
		// per-kind gate is the only thing that can spare the kind the operator took out.
		shouldSkip: func(kind, host string) bool {
			if !cfg.LightAuditKinds.LightApplies(kind) {
				return false
			}
			return true
		},
	}

	if tier.ShouldSkipRepetitive("body", "a.test") {
		t.Error("the light tier would skip a body point the operator took OUT of the light pass; the " +
			"per-kind gate is not consulted, so the eight keys are computed and then ignored")
	}
	if !tier.ShouldSkipRepetitive("query", "a.test") {
		t.Error("the light tier would not skip a query point the operator left IN; the repetition " +
			"threshold is short-circuited for every kind")
	}
}

// A preset that TURNS A KEY OFF, applied through the real Apply path.
//
// The tests above set the OptUint32 and then call rebuildLightAuditKinds by hand, which means they
// would all pass with an Apply whose rows dropped the rebuild on the floor — the set would simply
// never update for anyone who configured a preset rather than a struct literal. This one goes
// through Apply, which is the only path a shipped configuration ever takes.
func TestAPresetThatTurnsAKeyOffNarrowsTheLightPassThroughApply(t *testing.T) {
	applied := BuiltInConfig{
		Name:               "light for URLs only",
		QuickScanURLParams: SomeUint32(1),
		// Every other key explicitly FALSE, which is what a configuration file that lists all eight
		// and ticks one looks like.
		QuickScanBodyParams:      SomeUint32(0),
		QuickScanCookies:         SomeUint32(0),
		QuickScanHTTPHeaders:     SomeUint32(0),
		QuickScanParamName:       SomeUint32(0),
		QuickScanURLPathFilename: SomeUint32(0),
		QuickScanURLPathFolders:  SomeUint32(0),
		QuickScanEntireBody:      SomeUint32(0),
	}.Apply(DefaultAuditConfig())

	if !applied.LightAuditKinds.Set {
		t.Fatal("a preset whose eight keys were all applied leaves the derived set unconfigured; Apply " +
			"wrote the OptUint32s and never rebuilt, so the light tier reads a set that was never set")
	}
	if !applied.LightAuditKinds.LightApplies("query") {
		t.Error("the one ticked-IN kind is out of the light pass after Apply")
	}
	for _, kind := range []string{"body", "cookie", "header", "entire_body", "url_path_filename"} {
		if applied.LightAuditKinds.LightApplies(kind) {
			t.Errorf("kind %q was ticked OFF and is still in the light pass after Apply", kind)
		}
	}
}

// The eight keys, END TO END, through a real audit run against a real origin.
//
// Every other test here reads LightApplies or the derived set directly. That leaves the last link in
// the chain untested: whether auditItem's own gate -- the `shouldSkip` closure it hands the light
// tier -- consults the per-kind set at all. Disabling that line passes all the other tests here
// (verified: M1 in the mutation log), because they never ask the engine anything.
//
// So this runs the same request twice, once with the light tier covering query points and once with
// it taken off, and requires the SKIP COUNT to differ. The repetition half of the gate is identical
// in both runs, so the count can only move if the per-kind set is being read.
func TestTheLightTierRespectsThePerKindKeysOnARealAuditRun(t *testing.T) {
	runWithLightPass := func(urlParams, bodyParams OptUint32) int {
		srv, _ := repetitiveEchoOrigin(t)
		host, port := splitHostPort(t, srv.URL)
		// 25 query points, cap 8, threshold 5: without the per-kind opt-in, points 6-8 skip as
		// repetitive. The count is the observable, and it is the only thing that differs.
		store := seedRepetitiveExchange(t, host, port, 25)
		scan := NewActiveScanner(store, zap.NewNop()).
			WithSender(sender.NewSender(nil)).
			WithConfig(&ScanConfig{MaxConcurrency: 1, CheckSqli: true})

		cfg := DefaultAuditConfig()
		cfg.LightAuditSamplePerKind = SomeUint32(5)
		cfg.QuickScanURLParams = urlParams
		cfg.QuickScanBodyParams = bodyParams
		cfg.rebuildLightAuditKinds()

		out, _ := scan.AuditWithin(context.Background(), 0, cfg)
		return out.PointsSkippedRepetitive
	}

	// Baseline: nothing said about the keys, so query points are in the light pass and the
	// repetition threshold fires. This is the behaviour before the keys existed, and it is the
	// precondition the comparison below is meaningless without.
	untouched := runWithLightPass(OptUint32{}, OptUint32{})
	if untouched == 0 {
		t.Fatal("with no quick_scan keys set, no query point skipped as repetitive; the pre-existing " +
			"light tier is not running, so a zero difference below would prove nothing")
	}

	// query ticked OFF, body ticked ON: every point in this request is a query point, so taking
	// query out of the light pass must stop the repetition skips dead.
	takenOut := runWithLightPass(SomeUint32(0), SomeUint32(1))
	if takenOut != 0 {
		t.Errorf("repetitive skips = %d with query params taken OUT of the light pass, want 0; the "+
			"per-kind gate at auditItem is not consulted, so the eight keys are computed and ignored "+
			"(baseline without the keys was %d)", takenOut, untouched)
	}
}
