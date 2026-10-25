package scanner

// BFLA tests (burpsy-react-ui-0vzb.46 slice 2).

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

func bflaAudit(t *testing.T, path string, mod func(*ScanConfig)) []*Finding {
	t.Helper()
	rt := startRuntimeTarget(t)
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckBFLA: true,
		SecondIdentity: SecondIdentity{CookieHeader: vulnapp.IDORSecondSessionCookie}}
	if mod != nil {
		mod(cfg)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	_, findings := scan.AuditWithin(t.Context(), id, scan.AuditConfig())
	return findings
}

func bflaFindingIn(fs []*Finding) *Finding {
	for _, f := range fs {
		if f != nil && f.Name == "Broken access control" {
			return f
		}
	}
	return nil
}

// bob (ordinary user) is served the admin operation: function-level authorization is broken.
func TestBFLAReportsLowPrivilegeAccessToAnAdminOperation(t *testing.T) {
	f := bflaFindingIn(bflaAudit(t, "/api/admin/users", nil))
	if f == nil {
		t.Fatal("no Broken access control finding on the vulnerable twin")
	}
	if f.Confidence != "firm" || f.Severity != "high" {
		t.Errorf("confidence/severity = %s/%s, want firm/high", f.Confidence, f.Severity)
	}
	if !strings.Contains(f.Description, "second") {
		t.Errorf("description does not name the second identity: %s", f.Description)
	}
}

// The safe twin refuses bob 403: nothing to report.
func TestBFLAStaysQuietWhenTheOperationEnforcesTheRole(t *testing.T) {
	if f := bflaFindingIn(bflaAudit(t, "/api/safe/admin/users", nil)); f != nil {
		t.Fatalf("safe twin reported: %+v", f)
	}
}

// Without the switch the vulnerable twin draws nothing from the BFLA pass.
func TestBFLAOffWithoutItsSwitch(t *testing.T) {
	if f := bflaFindingIn(bflaAudit(t, "/api/admin/users", func(c *ScanConfig) { c.CheckBFLA = false })); f != nil {
		t.Fatalf("reported with the switch off: %+v", f)
	}
}

// A non-admin path is not a BFLA candidate: the pass sends nothing and reports nothing.
func TestBFLASkipsNonAdminPaths(t *testing.T) {
	if f := bflaFindingIn(bflaAudit(t, "/idor/profile?id=1", nil)); f != nil {
		t.Fatalf("non-admin path reported: %+v", f)
	}
}
