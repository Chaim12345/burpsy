package scanner

// The two `scanner/misc_insertion_point_options/*` keys, tested at the level where they either
// change what the audit does or they are a lie: the probe harness that enumerates the points a
// payload is placed in, the queue row that reports what the run ran under, and the dispatch path
// that carries a named configuration from the API to a check.
//
// Deliberately NOT a round-trip test. bcheck's own tests already pin that EnumerateWith honours a
// cap, and internal/web's already pin that a configuration survives save and load. Neither of those
// would fail if AuditConfig grew a field that no probe site ever read — which is exactly the defect
// burpsy-react-ui-iueb was filed about, and the only one worth writing a test for here.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// manyParamPath is a request with more query parameters than any ceiling under test, so a capped
// enumeration is distinguishable from a request that simply had fewer places to inject.
func manyParamPath(n int) string {
	var b strings.Builder
	b.WriteString("/search?")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte('&')
		}
		fmt.Fprintf(&b, "p%d=v%d", i, i)
	}
	return b.String()
}

func okHandler(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }

// The ceiling an operator configured must bound what the harness actually enumerates. Before this,
// AuditConfig had no such field at all and every probe site enumerated bcheck's default of 30, so a
// configuration naming a smaller number changed the queue row's caveat and not one probe.
func Test_a_runs_insertion_point_ceiling_bounds_what_the_probe_harness_enumerates(t *testing.T) {
	const params, ceiling = 12, 5
	cc := harnessAgainst(t, okHandler, manyParamPath(params))
	cfg := DefaultAuditConfig()
	cfg.MaxInsertionPointsPerRequest = SomeUint32(ceiling)
	cc.EnumerateOptions = cfg.enumerateOptions()

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	if got := len(h.Points()); got != ceiling {
		t.Errorf("the run was configured to audit at most %d insertion points per request and the harness enumerated %d "+
			"for a request with %d parameters: the ceiling reached the configuration but not the enumerator, so every "+
			"probe this check sends ignores the operator's setting", ceiling, got, params)
	}
	// The points it gave up have to be on the record. A truncation nobody can see is the silent
	// false negative bcheck.Declined exists to prevent.
	var said bool
	for _, d := range h.DeclinedPoints() {
		if strings.HasPrefix(d.What, bcheck.DeclinedPastLimitWhat) && strings.Contains(d.Reason, fmt.Sprint(ceiling)) {
			said = true
		}
	}
	if !said {
		t.Errorf("the harness dropped %d of %d insertion points and recorded no decline naming the ceiling of %d; "+
			"a capped enumeration that says nothing is indistinguishable from an endpoint with fewer parameters: %+v",
			params-ceiling, params, ceiling, h.DeclinedPoints())
	}
}

// Turning nested points off must remove the points inside a decoded parameter value, and must say
// how many it removed. Before this, expandNested ran unconditionally: the key could be set and the
// enumerator would expand anyway.
func Test_a_run_can_turn_nested_insertion_points_off_and_reports_what_it_gave_up(t *testing.T) {
	// A query parameter whose value is JSON, which is what expandNested reaches into.
	path := `/api?payload={"user":"alice","role":"guest"}&other=1`

	countPoints := func(t *testing.T, nested bool) (*ProbeHarness, int) {
		t.Helper()
		cc := harnessAgainst(t, okHandler, path)
		cfg := DefaultAuditConfig()
		cfg.NestedInsertionPoints = SomeUint32(b2u(nested))
		cc.EnumerateOptions = cfg.enumerateOptions()
		h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
		if err != nil {
			t.Fatalf("NewProbeHarness (nested=%v): %v", nested, err)
		}
		return h, len(h.Points())
	}

	on, withNested := countPoints(t, true)
	off, withoutNested := countPoints(t, false)

	if withNested <= withoutNested {
		t.Fatalf("enumerating the same request with nested insertion points on gave %d point(s) and with them off gave %d: "+
			"the switch changed nothing, so use_nested_insertion_points is a control that stores a value the enumerator "+
			"never reads (on: %v)", withNested, withoutNested, on.Points())
	}
	var said bool
	for _, d := range off.DeclinedPoints() {
		if strings.HasPrefix(d.What, bcheck.DeclinedNestedDisabledWhat) {
			said = true
		}
	}
	if !said {
		t.Errorf("%d nested insertion point(s) were not enumerated because the run turned them off, and nothing on the "+
			"run's record says so; a run that probed only the outer parameter of a JSON value has not tested that value: %+v",
			withNested-withoutNested, off.DeclinedPoints())
	}
}

// The queue row must report the ceiling THIS run used. Reporting bcheck's constant while the run
// enumerated under something else is the mismatch the issue names: an operator who lowered the
// ceiling and read 30 on the row is reading about a run that never happened.
func Test_the_audit_queue_row_reports_the_runs_own_insertion_point_settings(t *testing.T) {
	cfg := DefaultAuditConfig()
	cfg.MaxInsertionPointsPerRequest = SomeUint32(7)
	cfg.NestedInsertionPoints = SomeUint32(0)

	b := newAuditItemBreakers(cfg)
	if b.MaxInsertionPointsPerRequest != 7 {
		t.Errorf("the run enumerated at most 7 insertion points per request and its queue row reports %d; "+
			"the row is the only place the threshold behind a skipped-past-the-limit point is recorded",
			b.MaxInsertionPointsPerRequest)
	}
	if b.NestedInsertionPoints {
		t.Error("the run had nested insertion points turned off and its queue row reports them as enabled, " +
			"so nothing explains the points that are missing from the row")
	}

	// A configuration that sets neither key inherits Burp's own shipped default, and the row must
	// say that rather than 0 — which would read as "no insertion points were audited".
	base := newAuditItemBreakers(DefaultAuditConfig())
	if base.MaxInsertionPointsPerRequest != bcheck.DefaultMaxInsertionPoints {
		t.Errorf("a run that set no ceiling reports %d on its queue row, want Burp's shipped default of %d",
			base.MaxInsertionPointsPerRequest, bcheck.DefaultMaxInsertionPoints)
	}
	if !base.NestedInsertionPoints {
		t.Error("a run that set no nested-points key reports them off; Burp ships use_nested_insertion_points true")
	}

	// The wire shape, not the struct: a Go bool is fine but the console reads JSON.
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal breakers: %v", err)
	}
	for _, want := range []string{`"max_insertion_points_per_request":7`, `"nested_insertion_points":false`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the queue row's JSON does not carry %s, so the console cannot show what the run ran under: %s", want, raw)
		}
	}
}

// The plumbing this all rests on: a configuration passed to AuditWithin/AuditSession must reach the
// check, not just the run's budgets and the queue row.
//
// This is the defect that made the two keys worth wiring at all. NewCheckContext read
// ActiveScanner.AuditConfig() — the server-wide default from -scan-config — so `{"config": "<name>"}`
// on /api/audit/{id} resolved a configuration, recorded its name on the reply, and dispatched every
// check under the server's own settings.
func Test_the_configuration_an_audit_was_launched_under_reaches_its_checks(t *testing.T) {
	cc := harnessAgainst(t, okHandler, manyParamPath(12))
	s, ex := cc.Scanner, cc.Exchange

	// The server-wide default, which is what the old code would hand every check.
	serverCfg := DefaultAuditConfig()
	serverCfg.MaxInsertionPointsPerRequest = SomeUint32(30)
	serverCfg.InsertionKinds = []string{"query", "body", "cookie", "header"}
	s.WithAuditConfig(serverCfg)

	// The configuration this one run was launched under — a different answer to both questions.
	runCfg := DefaultAuditConfig()
	runCfg.MaxInsertionPointsPerRequest = SomeUint32(4)
	runCfg.NestedInsertionPoints = SomeUint32(0)
	runCfg.InsertionKinds = []string{"query"}

	var seen *CheckContext
	d := CheckDescriptor{
		TypeIndex:      1,
		Name:           "records the context it was dispatched with",
		Implementation: ImplementationNative,
		Run: func(_ context.Context, cc *CheckContext) ([]*Finding, error) {
			seen = cc
			return nil, nil
		},
	}
	ctx := withRunConfig(context.Background(), runCfg)
	if _, err := wrapDescriptor(d)(s, ctx, ex); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if seen == nil {
		t.Fatal("the descriptor never ran, so nothing was observed")
	}
	if got := seen.ProbeEnumerateOptions().Max; got != 4 {
		t.Errorf("the audit was launched under a configuration capping insertion points at 4 and the dispatched check "+
			"enumerates at %d (the server-wide default is 30): a named configuration reaches the run's budgets and the "+
			"queue row but not the wire, so the reply names a configuration the probes did not use", got)
	}
	if !seen.ProbeEnumerateOptions().NoNested {
		t.Error("the audit was launched with nested insertion points off and the dispatched check still expands them")
	}
	if got := seen.ProbeInsertionKinds(); len(got) != 1 || got[0] != "query" {
		t.Errorf("the audit was launched to insert only into query parameters and the dispatched check enumerates %v; "+
			"this is the same defect for the insertion_point_types keys, which were wired to the queue row only", got)
	}

	// And a context with no run on it still falls back to the scanner's own configuration, which is
	// what a direct evaluator test — every existing caller of NewCheckContext — depends on.
	plain := newCheckContextForRun(context.Background(), s, ex, nil)
	if got := plain.ProbeEnumerateOptions().Max; got != 30 {
		t.Errorf("a check context built outside a dispatched audit enumerates at %d, want the scanner's own 30", got)
	}
}

// A ceiling of zero is refused by name rather than clamped. It would enumerate nothing, so the run
// would audit nothing and report a completed audit — the one outcome this project treats as worse
// than refusing the operator's file.
func Test_an_insertion_point_ceiling_of_zero_is_refused_rather_than_clamped(t *testing.T) {
	doc := []byte(`{"scanner":{"misc_insertion_point_options":{"max_insertion_points_per_base_request":0}}}`)
	_, err := ParseBurpConfig(doc)
	if err == nil {
		t.Fatal("a configuration capping insertion points at zero loaded without complaint; a run under it would " +
			"enumerate nothing, probe nothing, and report a completed audit")
	}
	if !strings.Contains(err.Error(), "max_insertion_points_per_base_request") {
		t.Errorf("the refusal does not name the key that caused it, so the operator cannot find it in their file: %v", err)
	}

	// The same file with a usable ceiling must still load, or the refusal above is just a broken parser.
	cfg, err := ParseBurpConfig([]byte(
		`{"scanner":{"misc_insertion_point_options":{"max_insertion_points_per_base_request":5,"use_nested_insertion_points":false}}}`))
	if err != nil {
		t.Fatalf("a configuration with a usable ceiling failed to load: %v", err)
	}
	applied, unapplied := cfg.ApplyWithReport(DefaultAuditConfig())
	if applied.MaxInsertionPointsPerBaseRequest() != 5 {
		t.Errorf("the parsed ceiling of 5 resolved to %d", applied.MaxInsertionPointsPerBaseRequest())
	}
	if applied.NestedInsertionPointsEnabled() {
		t.Error("the parsed file set use_nested_insertion_points false and the resolved configuration still expands them")
	}
	for _, name := range unapplied {
		if name == "max_insertion_points_per_base_request" || name == "use_nested_insertion_points" {
			t.Errorf("%s parsed and applied but is still reported to the operator as a key this engine did not apply", name)
		}
	}
}
