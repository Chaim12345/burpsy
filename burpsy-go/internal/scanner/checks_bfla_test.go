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

// Slice 3b: a state-changing admin operation replayed as the low-privilege identity. It changes
// state on the target, so it needs the explicit writes opt-in on top of the BFLA switch.

func bflaWriteAudit(t *testing.T, path string, writes bool) []*Finding {
	t.Helper()
	return bflaAudit(t, path, func(c *ScanConfig) { c.CheckAPIWrites = writes })
}

const bobUID = 2 // the fixture's low-privilege user (vulnapp.IDORSecondSessionCookie)

func TestBFLAWriteReportsLowPrivilegeWriteToAnAdminOperation(t *testing.T) {
	before := vulnapp.APIAuthSettingWritesBy(bobUID)
	f := bflaFindingIn(bflaWriteAudit(t, "/api/admin/settings", true))
	if f == nil {
		t.Fatal("no Broken access control finding on the vulnerable settings write")
	}
	if !strings.Contains(f.Description, "POST /api/admin/settings") {
		t.Errorf("the finding does not name the operation: %s", f.Description)
	}
	if vulnapp.APIAuthSettingWritesBy(bobUID) <= before {
		t.Error("the finding claims a second-identity write but the target recorded none")
	}
}

func TestBFLAWriteStaysQuietWhenTheOperationEnforcesTheRole(t *testing.T) {
	before := vulnapp.APIAuthSettingWritesBy(bobUID)
	if f := bflaFindingIn(bflaWriteAudit(t, "/api/safe/admin/settings", true)); f != nil {
		t.Fatalf("finding on the role-enforcing twin: %s", f.Description)
	}
	if vulnapp.APIAuthSettingWritesBy(bobUID) != before {
		t.Error("the safe twin accepted a write from the low-privilege identity")
	}
}

// Without the writes opt-in the pass must send no write at all: this pins the side effect, not only
// the absence of a finding.
func TestBFLAWriteNeedsTheWritesOptIn(t *testing.T) {
	before := vulnapp.APIAuthSettingWritesBy(bobUID)
	if f := bflaFindingIn(bflaWriteAudit(t, "/api/admin/settings", false)); f != nil {
		t.Fatalf("a write finding without CheckAPIWrites: %s", f.Description)
	}
	if vulnapp.APIAuthSettingWritesBy(bobUID) != before {
		t.Error("a write reached the target as the low-privilege identity without the writes opt-in")
	}
}

// DELETE is never replayed: a destructive probe is not a role check worth the damage.
func TestBFLAWriteMethods(t *testing.T) {
	for m, want := range map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": false, "GET": false, "OPTIONS": false} {
		if got := bflaWriteMethod(m); got != want {
			t.Errorf("bflaWriteMethod(%s) = %v, want %v", m, got, want)
		}
	}
}

// A role-enforcing write that refuses with HTTP 200 and the success envelope's shape
// ({"updated":false,...}) is not a finding: the answer differs from the admin's in value.
func TestBFLAWriteStaysQuietOnA200RefusalEnvelope(t *testing.T) {
	before := vulnapp.APIAuthSettingWritesBy(bobUID)
	if f := bflaFindingIn(bflaWriteAudit(t, "/api/envelope/admin/settings", true)); f != nil {
		t.Fatalf("finding on the 200 refusal envelope: %s", f.Description)
	}
	if vulnapp.APIAuthSettingWritesBy(bobUID) != before {
		t.Error("the envelope twin accepted a write from the low-privilege identity")
	}
}

// Per-call values (a created id, a timestamp, a request id) differ between any two writes; the
// verdict leaves (booleans, status words) must not.
func TestBFLASameAnswerIgnoresPerCallValues(t *testing.T) {
	a := idorShapeOf(`{"updated":true,"id":41,"created_at":"2026-10-27T00:00:01Z","requestId":"9f8e7d6c5b4a39281706f5e4d3c2b1a0","status":"saved"}`)
	b := idorShapeOf(`{"updated":true,"id":42,"created_at":"2026-10-27T00:00:02Z","requestId":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","status":"saved"}`)
	if !bflaSameAnswer(a, b) {
		t.Error("two successful writes differing only in per-call values were judged different")
	}
	for _, refusal := range []string{
		`{"updated":false,"id":42,"created_at":"2026-10-27T00:00:02Z","requestId":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","status":"saved"}`,
		`{"updated":true,"id":42,"created_at":"2026-10-27T00:00:02Z","requestId":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","status":"denied"}`,
	} {
		if bflaSameAnswer(a, idorShapeOf(refusal)) {
			t.Errorf("a refusal judged the same answer: %s", refusal)
		}
	}
}

// The anonymous control is judged by value for a write too: an endpoint that refuses anonymous
// callers with a 200 envelope ({"updated":false}) while accepting B's write is still a finding.
func TestBFLAWriteReportsWhenAnonymousIsRefusedWithA200Envelope(t *testing.T) {
	if f := bflaFindingIn(bflaWriteAudit(t, "/api/anon-envelope/admin/settings", true)); f == nil {
		t.Fatal("no finding: the anonymous 200 refusal envelope was read as an anonymous success")
	}
}
