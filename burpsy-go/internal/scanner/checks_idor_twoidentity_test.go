package scanner

// Two-identity cross-read tests (burpsy-react-ui-0vzb.46 slice 1).

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

func idorTwoIdentityAudit(t *testing.T, path string, mod func(*ScanConfig)) []*Finding {
	t.Helper()
	rt := startRuntimeTarget(t)
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckIDOR: true,
		CheckIDORTwoIdentity: true,
		SecondIdentity:       SecondIdentity{CookieHeader: vulnapp.IDORSecondSessionCookie}}
	if mod != nil {
		mod(cfg)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx := t.Context()
	_, findings := scan.AuditWithin(ctx, id, scan.AuditConfig())
	return findings
}

// bob's session asking for id=1 is served alice's profile: the cross-read proves the object
// belongs to a DIFFERENT user, which the one-account swap cannot show - the finding is firm.
func TestIDORTwoIdentityFirmsTheCrossRead(t *testing.T) {
	f := idorFindingIn(idorTwoIdentityAudit(t, "/idor/profile?id=1", nil))
	if f == nil {
		t.Fatal("no IDOR finding on the vulnerable twin")
	}
	if f.Confidence != "firm" || f.Severity != "high" {
		t.Errorf("confidence/severity = %s/%s, want firm/high", f.Confidence, f.Severity)
	}
	if !strings.Contains(f.Description, "second") {
		t.Errorf("description does not name the second identity: %s", f.Description)
	}
}

// The safe twin checks ownership: bob asking for alice's profile is refused, so nothing fires.
func TestIDORTwoIdentityStaysQuietOnTheSafeTwin(t *testing.T) {
	if f := idorFindingIn(idorTwoIdentityAudit(t, "/idor/safe/profile?id=1", nil)); f != nil {
		t.Fatalf("safe twin reported: %+v", f)
	}
}

// Without the switch the same configuration stays a one-account scan: tentative, and the
// description asks for a second account.
func TestIDORTwoIdentityOffWithoutItsSwitch(t *testing.T) {
	f := idorFindingIn(idorTwoIdentityAudit(t, "/idor/profile?id=1", func(c *ScanConfig) {
		c.CheckIDORTwoIdentity = false
	}))
	if f == nil {
		t.Fatal("no IDOR finding")
	}
	if f.Confidence != "tentative" {
		t.Errorf("confidence = %s, want tentative without the two-identity switch", f.Confidence)
	}
}
