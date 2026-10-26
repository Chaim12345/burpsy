package scanner

// Mass-assignment tests (burpsy-react-ui-0vzb.46 slice 3).

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func massAssignAudit(t *testing.T, path string, mod func(*ScanConfig)) []*Finding {
	t.Helper()
	rt := startRuntimeTarget(t)
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute,
		CheckMassAssignment: true, CheckAPIWrites: true}
	if mod != nil {
		mod(cfg)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	_, findings := scan.AuditWithin(t.Context(), id, scan.AuditConfig())
	return findings
}

// The update persists an injected role, and the re-read shows it: the server binds a field the
// request was never meant to carry.
func TestMassAssignmentReportsAPersistedInjectedRole(t *testing.T) {
	f := bflaFindingIn(massAssignAudit(t, "/api/users/2", nil))
	if f == nil {
		t.Fatal("no Broken access control finding on the vulnerable twin")
	}
	if f.Confidence != "firm" || f.Severity != "high" {
		t.Errorf("confidence/severity = %s/%s, want firm/high", f.Confidence, f.Severity)
	}
	if !strings.Contains(f.Description, "role") {
		t.Errorf("description does not name the injected field: %s", f.Description)
	}
	if strings.Contains(f.Description, `"repeated"`) || strings.Count(f.Description, "burpsy-ma-") != 2 {
		t.Errorf("description does not name both canaries: %s", f.Description)
	}
	if !strings.Contains(f.Evidence, "burpsy-ma-") {
		t.Errorf("evidence does not show the persisted canary: %s", f.Evidence)
	}
}

// The safe twin binds only the declared fields: the injected role is dropped, nothing to report.
func TestMassAssignmentStaysQuietWhenTheBinderIsStrict(t *testing.T) {
	if f := bflaFindingIn(massAssignAudit(t, "/api/safe/users/2", nil)); f != nil {
		t.Fatalf("safe twin reported: %+v", f)
	}
}

// Mass assignment is a write probe: without CheckAPIWrites the pass sends nothing.
func TestMassAssignmentDeclinesWithoutTheWritesOptIn(t *testing.T) {
	if f := bflaFindingIn(massAssignAudit(t, "/api/users/2", func(c *ScanConfig) { c.CheckAPIWrites = false })); f != nil {
		t.Fatalf("reported without CheckAPIWrites: %+v", f)
	}
}

// And without its own switch.
func TestMassAssignmentOffWithoutItsSwitch(t *testing.T) {
	if f := bflaFindingIn(massAssignAudit(t, "/api/users/2", func(c *ScanConfig) { c.CheckMassAssignment = false })); f != nil {
		t.Fatalf("reported with the switch off: %+v", f)
	}
}

// A read-only exchange is not a mass-assignment candidate.
func TestMassAssignmentSkipsARead(t *testing.T) {
	if f := bflaFindingIn(massAssignAudit(t, "/api/admin/users", nil)); f != nil {
		t.Fatalf("GET exchange reported: %+v", f)
	}
}
