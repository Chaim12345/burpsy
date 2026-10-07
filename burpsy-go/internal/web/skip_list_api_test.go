package web

// The operator's parameter skip list (burpsy-react-ui-v9cg) at the configuration API:
// the write door takes the list, trims its names, refuses an empty name rather than dropping
// it, and an explicit empty array clears the list while an absent field leaves it alone.
import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/scanner"
)

func applyConfigOverlay(t *testing.T, base scanner.AuditConfig, body string) (scanner.AuditConfig, error) {
	t.Helper()
	var v auditConfigView
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("decode overlay: %v", err)
	}
	return v.applyTo(base)
}

func TestTheSkipListOverlaysOntoTheRunConfiguration(t *testing.T) {
	cfg, err := applyConfigOverlay(t, scanner.AuditConfig{}, `{"skip_all_tests_for_parameters":["  user  ","token"]}`)
	if err != nil {
		t.Fatalf("applyTo refused a well-formed list: %v", err)
	}
	want := []string{"user", "token"}
	if len(cfg.SkipAllTestsForParameters) != 2 || cfg.SkipAllTestsForParameters[0] != want[0] || cfg.SkipAllTestsForParameters[1] != want[1] {
		t.Fatalf("list = %v, want %v with each name trimmed", cfg.SkipAllTestsForParameters, want)
	}
}

func TestAnEmptyNameInTheSkipListIsRefusedNotDropped(t *testing.T) {
	_, err := applyConfigOverlay(t, scanner.AuditConfig{}, `{"skip_all_tests_for_parameters":["user","   "]}`)
	if err == nil {
		t.Fatal("a whitespace-only name was accepted — a name that silently vanishes is a parameter that silently goes back to being tested")
	}
	if !strings.Contains(err.Error(), "needs a parameter name") {
		t.Errorf("refusal = %q, want it to name what an entry needs", err)
	}
}

func TestAnExplicitEmptyArrayClearsTheListAnAbsentFieldLeavesItAlone(t *testing.T) {
	base := scanner.AuditConfig{}
	base.SkipAllTestsForParameters = []string{"user"}

	// Absent field: the list carries over untouched.
	cfg, err := applyConfigOverlay(t, base, `{"nested_insertion_points":false}`)
	if err != nil {
		t.Fatalf("absent skip field: %v", err)
	}
	if len(cfg.SkipAllTestsForParameters) != 1 || cfg.SkipAllTestsForParameters[0] != "user" {
		t.Fatalf("an absent field cleared the list: %v — partial overlay means untouched, not reset", cfg.SkipAllTestsForParameters)
	}

	// Explicit empty array: the operator cleared their exemptions.
	cfg, err = applyConfigOverlay(t, base, `{"skip_all_tests_for_parameters":[]}`)
	if err != nil {
		t.Fatalf("explicit empty array: %v", err)
	}
	if len(cfg.SkipAllTestsForParameters) != 0 {
		t.Fatalf("explicit [] did not clear the list: %v", cfg.SkipAllTestsForParameters)
	}
}

func TestTheViewCarriesTheListForRoundTrip(t *testing.T) {
	cfg := scanner.AuditConfig{}
	cfg.SkipAllTestsForParameters = []string{"user", "token"}
	v := newAuditConfigView(cfg)
	if len(v.SkipAllTestsForParameters) != 2 {
		t.Fatalf("view list = %v, want it carried", v.SkipAllTestsForParameters)
	}
	// absent stays absent
	if got := newAuditConfigView(scanner.AuditConfig{}).SkipAllTestsForParameters; got != nil {
		t.Errorf("empty config's view carries %v, want nil — absent and empty must not merge", got)
	}
}
