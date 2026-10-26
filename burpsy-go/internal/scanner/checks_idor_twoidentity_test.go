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

// bob's session asking for id=1 is served alice's profile. Cookie sessions carry no user id the
// scanner can read, so nothing ties the profile to alice: a shared, login-only record would answer
// the same way. The cross-read is reported, but tentative, and says what is missing.
func TestIDORTwoIdentityCrossReadWithoutOwnershipIsTentative(t *testing.T) {
	f := idorFindingIn(idorTwoIdentityAudit(t, "/idor/profile?id=1", nil))
	if f == nil {
		t.Fatal("no IDOR finding on the vulnerable twin")
	}
	if f.Confidence != "tentative" || f.Severity != "high" {
		t.Errorf("confidence/severity = %s/%s, want tentative/high without ownership evidence", f.Confidence, f.Severity)
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

// A cookie header whose names B's set does not hold still carries A's session: the replay would be
// A's own request, so it is not a two-identity read at all.
func TestIDORReidentityUncoveredWhenACookieIsNotReplaced(t *testing.T) {
	raw := "GET /x HTTP/1.1\r\nHost: h\r\nCookie: session=alice\r\n\r\n"
	if _, covered := idorReidentity(raw, &SecondIdentity{CookieHeader: "sid=bob"}); covered {
		t.Error("covered with A's session cookie left in place")
	}
	if out, covered := idorReidentity(raw, &SecondIdentity{CookieHeader: "session=bob"}); !covered || !strings.Contains(out, "Cookie: session=bob") {
		t.Errorf("same-name cookie: covered=%v out=%q", covered, out)
	}
}

// A credential header B has no value for (here X-Auth-Token) leaves the request A's.
func TestIDORReidentityUncoveredForAnUnfilledCredentialHeader(t *testing.T) {
	raw := "GET /x HTTP/1.1\r\nHost: h\r\nX-Auth-Token: alice-token\r\n\r\n"
	if _, covered := idorReidentity(raw, &SecondIdentity{CookieHeader: "sid=bob"}); covered {
		t.Error("covered with A's X-Auth-Token left in place")
	}
	raw = "GET /x HTTP/1.1\r\nHost: h\r\nX-API-Key: alice-key\r\n\r\n"
	if _, covered := idorReidentity(raw, &SecondIdentity{APIKeyHeader: "X-API-Key", APIKeyValue: "bob-key"}); !covered {
		t.Error("the configured API-key header was not treated as replaced")
	}
}

// Ownership evidence: an owner-like field naming the session's own user id.
func TestIDOROwnedBySession(t *testing.T) {
	session := map[string]bool{"1": true}
	if path, v, ok := idorOwnedBySession(session, idorShapeOf(`{"order":{"id":7,"userId":1}}`)); !ok || path != "order.userId" || v != "1" {
		t.Errorf("owner field not found: %q %q %v", path, v, ok)
	}
	if _, _, ok := idorOwnedBySession(session, idorShapeOf(`{"name":"widget","price":1}`)); ok {
		t.Error("a non-owner field counted as ownership")
	}
	if _, _, ok := idorOwnedBySession(nil, idorShapeOf(`{"userId":1}`)); ok {
		t.Error("ownership without any session id")
	}
}
