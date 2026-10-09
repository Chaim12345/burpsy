package scanner

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// burpsy-react-ui-2hze: per-issue detection methods. A method the configuration disabled is never
// sent, and the withholding is a counted record with a reason, never a silent skip.

const sqlInjectionType = uint32(0x00100200)

// harnessFor builds a probe harness against a counting target, under a context whose check is SQL
// injection and whose run disabled the given methods for it.
func harnessFor(t *testing.T, disabled ...string) (*ProbeHarness, *CheckContext, *countingProbeTarget) {
	t.Helper()
	target := newCountingProbeTarget(t)
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, target.host, target.port, "/q?id=1", "<html>seed</html>")
	ex, err := store.GetExchange(id)
	if err != nil {
		t.Fatal(err)
	}
	scan := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(sender.DefaultSenderConfig()))
	cfg := DefaultAuditConfig()
	for _, m := range disabled {
		cfg.DisabledDetectionMethods = append(cfg.DisabledDetectionMethods, IssueDetectionMethod{TypeIndex: sqlInjectionType, Method: m})
	}
	desc, ok := descriptorByName(sqlInjectionIssue)
	if !ok {
		t.Fatal("no SQL injection descriptor")
	}
	ctx := withRunConfig(context.Background(), cfg)
	cc := newCheckContextForCheck(ctx, scan, ex, nil, desc)
	h, err := NewProbeHarness(ctx, cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h, cc, target
}

func descriptorByName(name string) (CheckDescriptor, bool) {
	for _, d := range NativeCheckRegistry() {
		if d.Name == name {
			return d, true
		}
	}
	return CheckDescriptor{}, false
}

// The claim: "Time delays" disabled for SQL injection means ProbeTiming sends nothing, and the
// decline is recorded with the request it withheld.
func TestADisabledTimeDelaysMethodSendsNoTimingProbeAndRecordsTheDecline(t *testing.T) {
	h, cc, target := harnessFor(t, MethodTimeDelays)
	point := h.Points()[0]
	before := target.total()
	probe := h.ProbeTiming(context.Background(), point, "1' AND SLEEP(5)--", 5*time.Second)
	if sent := target.total() - before; sent != 0 {
		t.Fatalf("the target received %d timing probe(s) with Time delays disabled for SQL injection", sent)
	}
	if !probe.Withheld {
		t.Errorf("probe = %+v; a withheld probe must say so, or it reads as a clean one", probe)
	}
	got := cc.MethodDeclines.List()
	if len(got) != 1 || got[0].Method != MethodTimeDelays || got[0].TypeIndex != sqlInjectionType || got[0].ProbesWithheld != 1 {
		t.Fatalf("declines = %+v, want one Time delays record withholding one probe", got)
	}
	if !strings.Contains(got[0].Reason, "disabled") {
		t.Errorf("reason %q does not say the configuration disabled it", got[0].Reason)
	}
}

// Positive control: with the method enabled the same call reaches the target, so the zero above is
// the gate and not a harness that never sends.
func TestAnEnabledTimeDelaysMethodReachesTheTarget(t *testing.T) {
	h, cc, target := harnessFor(t)
	before := target.total()
	h.ProbeTiming(context.Background(), h.Points()[0], "1", time.Millisecond)
	if target.total()-before != 1 {
		t.Fatalf("the target received %d request(s), want 1", target.total()-before)
	}
	if n := len(cc.MethodDeclines.List()); n != 0 {
		t.Errorf("%d decline(s) recorded with nothing disabled", n)
	}
}

// Disabling a method for one type does not touch another type's method of the same name: Burp
// resolves the name inside its type (Zwx_.java:43-61).
func TestAMethodIsDisabledPerIssueTypeNotByName(t *testing.T) {
	h, _, target := harnessFor(t)
	h.disabled = nil
	cfg := AuditConfig{DisabledDetectionMethods: []IssueDetectionMethod{{TypeIndex: 0x00200140, Method: MethodTimeDelays}}}
	h.disabled = cfg.disabledMethodsFor(sqlInjectionType)
	before := target.total()
	h.ProbeTiming(context.Background(), h.Points()[0], "1", time.Millisecond)
	if target.total()-before != 1 {
		t.Fatal("request smuggling's Time delays switch withheld SQL injection's timing probe")
	}
}

// Every gated probe kind withholds its own requests.
func TestEveryGatedProbeKindWithholdsItsRequests(t *testing.T) {
	h, cc, target := harnessFor(t, MethodBooleanConditions, MethodErrorMessages)
	p := h.Points()[0]
	before := target.total()
	if pr := h.ProbeBoolean(context.Background(), p, "1 AND 1=1", "1 AND 1=2"); !pr.Withheld {
		t.Error("ProbeBoolean sent with Boolean conditions disabled")
	}
	for _, pr := range h.ProbeErrorSignatures(context.Background(), p, []string{"'", `"`}, SQLErrorSignatures) {
		if !pr.Withheld {
			t.Error("ProbeErrorSignatures sent with Error messages disabled")
		}
	}
	if target.total() != before {
		t.Fatalf("%d request(s) reached the target", target.total()-before)
	}
	withheld := 0
	for _, d := range cc.MethodDeclines.List() {
		withheld += d.ProbesWithheld
	}
	if withheld != 4 {
		t.Errorf("withheld = %d, want 4 (two boolean, two error)", withheld)
	}
}

// A check that declares a disabled method is not dispatched; one that does not declare it is.
func TestADisabledDeclaredMethodWithholdsTheCheckAndAnUndeclaredOneDoesNot(t *testing.T) {
	scan := everyFamilyScanner(t)
	errorsOff := AuditConfig{DisabledDetectionMethods: []IssueDetectionMethod{{TypeIndex: sqlInjectionType, Method: MethodErrorMessages}}}
	if typesOf(scan.enabledChecksUnder(errorsOff))[sqlInjectionType] != 0 {
		t.Error("SQL injection detects only by error messages; with that method disabled it must not be dispatched")
	}
	timeOff := AuditConfig{DisabledDetectionMethods: []IssueDetectionMethod{{TypeIndex: sqlInjectionType, Method: MethodTimeDelays}}}
	if typesOf(scan.enabledChecksUnder(timeOff))[sqlInjectionType] == 0 {
		t.Error("SQL injection was withheld for a disabled method it does not use")
	}
}

// "Burp Infiltrator" has no counterpart here: an imported configuration that enables it is told so,
// by name and reason, for both types the time-based preset enables it on.
func TestBurpInfiltratorIsDeclinedNotSilentlyIgnored(t *testing.T) {
	cfg, _, err := ApplyBurpConfigFile(DefaultAuditConfig(), readShippedConfig(t, "Audit checks - all except time-based detection methods"))
	if err != nil {
		t.Fatal(err)
	}
	infiltrator := map[uint32]string{}
	for _, d := range cfg.DeclinedDetectionMethods {
		if d.Method == MethodInfiltrator {
			infiltrator[d.TypeIndex] = d.Reason
		}
		if d.Method == MethodTimeDelays {
			t.Errorf("Time delays is disabled in the file and must not also read as declined-but-enabled: %+v", d)
		}
	}
	for _, ty := range []uint32{0x00100100, sqlInjectionType} {
		if !strings.Contains(infiltrator[ty], "no such agent") {
			t.Errorf("type %#08x: Infiltrator decline reason = %q, want the permanent one", ty, infiltrator[ty])
		}
	}
	// And the other SQL injection methods the file enables that burpsy does not run are named too.
	var sqli []string
	for _, d := range cfg.DeclinedDetectionMethods {
		if d.TypeIndex == sqlInjectionType {
			sqli = append(sqli, d.Method)
		}
	}
	for _, want := range []string{MethodBooleanConditions, MethodOracleSpecific, MethodMySQLSpecific, MethodSQLServerSpecific, MethodCollaborator} {
		if !slices.Contains(sqli, want) {
			t.Errorf("SQL injection declines = %v, missing %q, which the file enables and burpsy does not implement", sqli, want)
		}
	}
	if slices.Contains(sqli, MethodErrorMessages) {
		t.Error("Error messages is declined for SQL injection, but it is the method burpsy runs")
	}
}

// The declines reach the item's outcome: an audit under the imported preset says, on the item, which
// methods its SQL injection check did not try.
func TestAnItemOutcomeCarriesTheDeclinedMethodsOfTheChecksItRan(t *testing.T) {
	target := newCountingProbeTarget(t)
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, target.host, target.port, "/q?id=1", "<html>seed</html>")
	scan := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 10 * time.Second, CheckSqli: true})
	cfg, _, err := ApplyBurpConfigFile(DefaultAuditConfig(), readShippedConfig(t, "Audit checks - all except time-based detection methods"))
	if err != nil {
		t.Fatal(err)
	}
	outcome, _ := scan.AuditWithin(context.Background(), id, cfg)
	if outcome.Ran == 0 {
		t.Fatalf("outcome %s: the SQL injection check did not run", outcome.Summary())
	}
	found := false
	for _, d := range outcome.MethodsDeclined {
		if d.TypeIndex == sqlInjectionType && d.Method == MethodInfiltrator {
			found = true
		}
	}
	if !found {
		t.Errorf("methods_declined = %+v; the item ran SQL injection and must say Infiltrator did not run", outcome.MethodsDeclined)
	}
	if !strings.Contains(outcome.Summary(), "detection method(s) declined") {
		t.Errorf("summary %q does not mention the declines", outcome.Summary())
	}
}

// The new lists marshal as [] when empty: a console reading null would show "no declines" for an
// absent list.
func TestTheDeclineListsMarshalAsEmptyArrays(t *testing.T) {
	for name, v := range map[string]any{"outcome": AuditOutcome{}, "config": AuditConfig{}} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{`"methods_declined":[]`, `"DeclinedDetectionMethods":[]`} {
			if name == "outcome" && strings.HasPrefix(key, `"Declined`) || name == "config" && strings.HasPrefix(key, `"methods`) {
				continue
			}
			if !strings.Contains(string(b), key) {
				t.Errorf("%s JSON lacks %s: %s", name, key, b)
			}
		}
	}
}

// Every runnable check whose Burp type defines detection methods declares which of them it uses, or
// is listed as using none with the reason; and every method it declares is one Burp defines for its
// type. Otherwise a configuration could disable the method a check actually uses and the check
// would run anyway.
func TestEveryCheckDeclaresItsDetectionMethodsInBurpsVocabulary(t *testing.T) {
	for _, d := range NativeCheckRegistry() {
		burp := BurpDetectionMethods(d.TypeIndex)
		if !d.Runnable() || len(burp) == 0 {
			if len(d.DetectionMethods) != 0 && len(burp) == 0 {
				t.Errorf("%s declares %v but Burp defines no method for its type", d.Name, d.DetectionMethods)
			}
			continue
		}
		if len(d.DetectionMethods) == 0 {
			if _, exempt := burpsyMethodlessTypes[d.TypeIndex]; !exempt {
				t.Errorf("%s (%#08x): Burp defines %v; the check declares none and has no stated reason", d.Name, d.TypeIndex, burp)
			}
			continue
		}
		for _, m := range d.DetectionMethods {
			if !slices.Contains(burp, m) {
				t.Errorf("%s declares %q, which Burp does not define for its type (%v)", d.Name, m, burp)
			}
		}
	}
}
