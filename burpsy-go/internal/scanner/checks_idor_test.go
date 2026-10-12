package scanner

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/advisory"
	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
)

// The IDOR check (burpsy-react-ui-0vzb.12) against the live vulnapp IDOR family. Each guard has a
// safe twin that only it stops:
//
//   - the invalid-id control and the echo rule: /idor/safe/echo answers every existing id with the
//     session's own record plus the id repeated (unknown ids are 404);
//   - the credential-less control: /idor/safe/products is a public catalogue;
//   - the swapped response must be the object: /idor/safe/profile checks ownership;
//   - the invalid-id control alone: /idor/safe/generated computes a record for any number;
//   - a raised client role only counts when it changes the answer: /idor/safe/doc ignores its cookie.

// idorAudit audits one seeded vulnapp endpoint with only the IDOR switch on.
func idorAudit(t *testing.T, path string, mod func(*ScanConfig)) ([]*Finding, uint32) {
	t.Helper()
	rt := startRuntimeTarget(t)
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckIDOR: true}
	if mod != nil {
		mod(cfg)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	outcome, findings := scan.AuditWithin(ctx, id, scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", path, outcome.Error)
	}
	return findings, outcome.RequestsSent
}

func idorFindingIn(fs []*Finding) *Finding {
	for _, f := range fs {
		if f != nil && f.Name == idorIssue {
			return f
		}
	}
	return nil
}

func TestIDORFindsAnotherUsersObject(t *testing.T) {
	cases := []struct {
		path, confidence, mustSay string
	}{
		// A session cookie only: no user-identity binding, so tentative.
		{"/idor/profile?id=1", "tentative", `query parameter "id" from "1" to "2"`},
		// A bearer JWT naming sub=1 and an order whose ownerId is 1: the binding is shown.
		{"/idor/orders/1001", "firm", `ownerId`},
		// The id lives in a cookie.
		{"/idor/account", "tentative", `cookie "acct_id"`},
		// Refused as captured; the client-held role cookie raised to admin opens it.
		{"/idor/doc?id=1", "tentative", `raised from "user" to "admin"`},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			fs, _ := idorAudit(t, c.path, nil)
			f := idorFindingIn(fs)
			if f == nil {
				t.Fatalf("%s returns another user's object but %q was not reported", c.path, idorIssue)
			}
			if f.Confidence != c.confidence || f.Severity != "high" {
				t.Errorf("confidence/severity = %s/%s, want %s/high", f.Confidence, f.Severity, c.confidence)
			}
			if !strings.Contains(f.Description, c.mustSay) {
				t.Errorf("description does not say %q: %s", c.mustSay, f.Description)
			}
		})
	}
}

func TestIDORStaysQuietOnTheSafeTwins(t *testing.T) {
	// The check must demonstrably work in this run before silence on a twin means anything.
	if fs, _ := idorAudit(t, "/idor/profile?id=1", nil); idorFindingIn(fs) == nil {
		t.Fatal("the vulnerable profile endpoint did not fire, so the twins' silence proves nothing")
	}
	for path, why := range map[string]string{
		"/idor/safe/profile?id=1":   "checks ownership",
		"/idor/safe/products?id=1":  "is a public catalogue served without credentials",
		"/idor/safe/echo?id=1":      "only echoes the requested id around the session's own record",
		"/idor/safe/doc?id=1":       "ignores its role cookie",
		"/idor/safe/generated?id=1": "computes a record for any number, made up or not",
	} {
		fs, sent := idorAudit(t, path, nil)
		if f := idorFindingIn(fs); f != nil {
			t.Errorf("%s %s but was reported: %s", path, why, f.Description)
		}
		// Baseline, its stable re-send and the invalid-id control at least: silence must be a verdict.
		if sent < 3 {
			t.Errorf("%s: only %d requests sent, so the check never reached its controls", path, sent)
		}
	}
}

func TestIDORIsOffWithoutItsSwitch(t *testing.T) {
	fs, _ := idorAudit(t, "/idor/profile?id=1", func(c *ScanConfig) {
		c.CheckIDOR = false
		c.CheckExtendedActive = true // the descriptor it rides is on; the IDOR half is not
	})
	if f := idorFindingIn(fs); f != nil {
		t.Errorf("reported with CheckIDOR off: %s", f.Description)
	}
}

// Only GET, or a POST naming a read operation, is ever replayed with a swapped id.
func TestIDORNeverReplaysAStateChangingRequest(t *testing.T) {
	for _, raw := range []string{
		"DELETE /api/users/7 HTTP/1.1\r\nHost: h\r\nCookie: sid=x\r\n\r\n",
		"PUT /api/orders/7 HTTP/1.1\r\nHost: h\r\nCookie: sid=x\r\n\r\n",
		"POST /api/user?id=7 HTTP/1.1\r\nHost: h\r\nCookie: sid=x\r\n\r\n",
		"POST /api/updateUser HTTP/1.1\r\nHost: h\r\nCookie: sid=x\r\nContent-Type: application/json\r\n\r\n{\"user_id\":7}",
		"POST /api/getAndDeleteUser HTTP/1.1\r\nHost: h\r\nCookie: sid=x\r\nContent-Type: application/json\r\n\r\n{\"user_id\":7}",
	} {
		if idorReadOnly(raw) {
			t.Errorf("admitted as read-only: %q", strings.SplitN(raw, "\r\n", 2)[0])
		}
	}
	for _, raw := range []string{
		"GET /api/users/7 HTTP/1.1\r\nHost: h\r\n\r\n",
		"POST /api/getUser HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"user_id\":7}",
	} {
		if !idorReadOnly(raw) {
			t.Errorf("refused as read-only: %q", strings.SplitN(raw, "\r\n", 2)[0])
		}
	}
}

// End to end: a DELETE carrying an id and a session is audited and sends nothing.
func TestIDORSendsNothingForADelete(t *testing.T) {
	store := newIDORTestStore(t, "DELETE /idor/profile?id=1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nCookie: sid=x\r\n\r\n")
	cc := &CheckContext{Scanner: NewActiveScanner(store.s, zap.NewNop()).WithSender(runtimeSender()),
		Exchange: store.ex, Config: &ScanConfig{CheckIDOR: true}}
	fs, err := checkIDOR(context.Background(), cc)
	if err != nil || len(fs) != 0 {
		t.Fatalf("checkIDOR on a DELETE = %v, %v; want nothing at all", fs, err)
	}
}

type idorTestStore struct {
	s  *core.TrafficStore
	ex *core.Exchange
}

func newIDORTestStore(t *testing.T, raw string) idorTestStore {
	t.Helper()
	st := core.NewTrafficStore()
	reqID, err := st.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Host: "127.0.0.1", Port: 1, Method: "DELETE", Path: "/idor/profile?id=1"}
	st.AddExchange(ex)
	return idorTestStore{s: st, ex: ex}
}

func TestIDORReferenceNames(t *testing.T) {
	for _, n := range []string{"id", "user_id", "userId", "USERID", "accountId", "account", "order", "orderNo",
		"invoice_number", "acct_id", "doc_id", "filter[owner_id]", "userId_v2"} {
		if !idorIDName(n) {
			t.Errorf("%q not read as an object reference", n)
		}
	}
	for _, n := range []string{"page", "limit", "session_id", "csrf_token", "valid", "paid", "timestamp", "version",
		"api_key", "sort", "size", "id_token", "idempotency_key"} {
		if idorIDName(n) {
			t.Errorf("%q read as an object reference", n)
		}
	}
}

func TestIDORCandidatesInPathQueryCookieAndBody(t *testing.T) {
	raw := "GET /api/v2/users/42/orders/7f1c2a3b-1111-4222-8333-444455556666?page=2&id=9&q=hello HTTP/1.1\r\n" +
		"Host: h\r\nCookie: sid=abc; acct_id=5; _ga=1700000000\r\n\r\n"
	pts, _ := bcheck.EnumerateWith([]byte(raw), idorKinds, bcheck.EnumerateOptions{})
	var got []string
	for _, c := range idorCandidates(pts, raw) {
		got = append(got, string(c.point.Kind)+":"+c.value)
	}
	want := map[string]bool{"query:9": true, "cookie:5": true, "url_path_folder:42": true,
		"url_path_filename:7f1c2a3b-1111-4222-8333-444455556666": true}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected candidate %s (all: %v)", g, got)
		}
		delete(want, g)
	}
	for w := range want {
		t.Errorf("missing candidate %s (all: %v)", w, got)
	}
}

func TestIDORAnonymousStripsEveryCredential(t *testing.T) {
	raw := "GET /x?id=2 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer t\r\nX-Api-Key: k\r\n" +
		"Cookie: sid=s; acct_id=2; role=admin\r\nAccept: */*\r\n\r\n"
	got := idorAnonymous(raw, map[string]bool{"acct_id": true})
	for _, gone := range []string{"Authorization", "X-Api-Key", "sid=s", "role=admin"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q survived: %q", gone, got)
		}
	}
	if !strings.Contains(got, "Cookie: acct_id=2\r\n") || !strings.Contains(got, "Accept: */*") {
		t.Errorf("kept the wrong things: %q", got)
	}
	if idorHasCredentials("GET / HTTP/1.1\r\nHost: h\r\nAccept: */*\r\n\r\n") {
		t.Error("a request with no credential header read as credentialed")
	}
}

func TestIDORShapes(t *testing.T) {
	a := idorShapeOf(`{"content":{"id":1,"name":"a","note":null},"ok":true}`)
	b := idorShapeOf(`{"content":{"id":2,"name":"b","note":"x"},"ok":true}`)
	c := idorShapeOf(`{"content":"not found","ok":false}`)
	if !a.same(b) {
		t.Error("two objects of one structure (one optional field null) read as different shapes")
	}
	if a.same(c) {
		t.Error("an error envelope read as the object's shape")
	}
	if idorShapeOf("plain text") != nil {
		t.Error("plain text has no comparable structure")
	}
	if v := idorRoleVariants([]bcheck.InsertionPoint{{Kind: bcheck.IpCookie, Name: "role_x", BaseValue: "VVNFUg"}}); len(v) != 1 || v[0].raised != "QURNSU4" {
		t.Errorf("base64 role variant = %+v, want ADMIN encoded the same way (QURNSU4)", v)
	}
}

// burpsy's own rows must each have a native advisory definition carrying the same index and CWE, ride
// a real descriptor, and never shadow a Burp row.
func TestBurpsyNativeRowsMatchTheirAdvisories(t *testing.T) {
	cat, err := advisory.Load()
	if err != nil {
		t.Fatal(err)
	}
	descriptors := map[string]bool{}
	for _, d := range NativeCheckRegistry() {
		descriptors[d.Name] = true
	}
	for _, r := range BurpsyNativeRows() {
		if _, ok := ByName(r.Name); ok {
			t.Errorf("%q is in Burp's catalogue; it is not a burpsy row", r.Name)
		}
		if !descriptors[r.Rides] {
			t.Errorf("%q rides %q, which is not a registered descriptor", r.Name, r.Rides)
		}
		d, why := cat.Resolve(r.Name)
		if d == nil {
			t.Errorf("%q has no advisory: %s", r.Name, why)
			continue
		}
		if !d.IsNative() || uint32(d.TypeIndex) != r.TypeIndex {
			t.Errorf("%q resolves to native=%v index %s, want native %08x", r.Name, d.IsNative(), d.HexIndex(), r.TypeIndex)
		}
		cwe := false
		for _, c := range d.Classification {
			cwe = cwe || strings.HasPrefix(c.Title, "CWE-"+strconv.FormatUint(uint64(r.CWE), 10)+":")
		}
		if !cwe {
			t.Errorf("%q advisory lacks CWE-%d: %v", r.Name, r.CWE, d.Classification)
		}
	}
}
