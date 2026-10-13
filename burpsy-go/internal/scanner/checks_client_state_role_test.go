package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// csrAudit audits one request (method, path, extra headers) with ONLY the deserialization switch on,
// which is the switch the forged-role probe runs behind.
func csrAudit(t *testing.T, host string, port uint16, method, path string, headers map[string]string) []*Finding {
	t.Helper()
	store := core.NewTrafficStore()
	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1\r\nHost: " + net.JoinHostPort(host, strconv.Itoa(int(port))) + "\r\n")
	for k, v := range headers {
		b.WriteString(k + ": " + v + "\r\n")
	}
	if method == "POST" {
		b.WriteString("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\n\r\nnote=x")
	} else {
		b.WriteString("\r\n")
	}
	reqID, err := store.Put([]byte(b.String()), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nseed"), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: port, Method: method, Path: path}
	store.AddExchange(ex)
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 60 * time.Second, CheckInsecureDeserialization: true})
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{ex.ID}, DefaultAuditConfig())
	return findings
}

func csrFinding(fs []*Finding) *Finding {
	for _, f := range fs {
		if f.Name == IssueForgedClientRole {
			return f
		}
	}
	return nil
}

func csrCookie(doc string) map[string]string {
	return map[string]string{"Cookie": "session=" + base64.StdEncoding.EncodeToString([]byte(doc))}
}

// Every vulnapp fixture of the row: the two vulnerable ones are reported, each safe twin is quiet.
// The twins are the negative controls of the guards: allowlist (P answered like the control), echo
// (the role echoed upper- and lower-cased, masked), reauth (the privileged answer is a refusal),
// server-role (the cookie's role decides nothing) and signed (a signature beside the JSON, never
// probed).
func TestForgedClientRoleFixtures(t *testing.T) {
	host, port := deserServe(t, vulnapp.Handler())
	seen := 0
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row != IssueForgedClientRole {
			continue
		}
		seen++
		f := csrFinding(csrAudit(t, host, port, "GET", e.Path, e.RequestHeaders))
		if e.Safe {
			if f != nil {
				t.Errorf("safe twin %s reported: %s", e.Path, f.Evidence)
			}
			continue
		}
		if f == nil {
			t.Errorf("%s not reported", e.Path)
			continue
		}
		if f.Severity != "high" || f.Confidence != "firm" {
			t.Errorf("%s: got %s/%s, want high/firm", e.Path, f.Severity, f.Confidence)
		}
		t.Logf("%s: %s", e.Path, f.Evidence)
	}
	if seen != 7 {
		t.Fatalf("exercised %d fixtures, want 7", seen)
	}
}

// The probe re-sends only GET and HEAD: a forged administrator replaying a state-changing request
// would perform an administrative action. Negative control: dropping the method gate makes the
// vulnerable dashboard fire on a POST.
func TestForgedClientRoleNeverReplaysAPost(t *testing.T) {
	host, port := deserServe(t, vulnapp.Handler())
	h := csrCookie(`{"user":"ada","role":"USER","theme":"light"}`)
	if f := csrFinding(csrAudit(t, host, port, "GET", "/client-state/dashboard", h)); f == nil {
		t.Fatal("the GET control was not reported, so the POST's silence would prove nothing")
	}
	if f := csrFinding(csrAudit(t, host, port, "POST", "/client-state/dashboard", h)); f != nil {
		t.Fatalf("a POST was replayed with a forged role: %s", f.Evidence)
	}
}

// A page that drifts by itself must not line up with the forgeries. The target answers the admin
// view to every other request regardless of the cookie. Negative control: dropping the repeat
// comparison makes this fire.
func TestForgedClientRoleDriftingTargetIsNotAFinding(t *testing.T) {
	var n atomic.Int64
	host, port := deserServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1)%2 == 0 {
			_, _ = w.Write([]byte("Administration: pending reports, flagged listings"))
			return
		}
		_, _ = w.Write([]byte("Your tasks: profile"))
	}))
	if f := csrFinding(csrAudit(t, host, port, "GET", "/p", csrCookie(`{"user":"ada","role":"USER"}`))); f != nil {
		t.Fatalf("a drifting target was reported: %s", f.Evidence)
	}
}

// A role mapped to a display label only (USER -> "Member", ADMIN -> "Administrator") changes one
// word: that the server reads the member is shown, that it grants anything is not. Negative control:
// lowering the two-novel-word floor to one makes this fire.
func TestForgedClientRoleLabelOnlyIsNotAFinding(t *testing.T) {
	host, port := deserServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("session")
		var s struct{ User, Role string }
		if c != nil {
			if b, err := base64.StdEncoding.DecodeString(c.Value); err == nil {
				_ = json.Unmarshal(b, &s)
			}
		}
		label := map[string]string{"USER": "Member", "ADMIN": "Administrator"}[s.Role]
		if label == "" {
			label = "Guest"
		}
		_, _ = w.Write([]byte("Signed in as " + s.User + " - " + label + ". Your tasks: profile."))
	}))
	if f := csrFinding(csrAudit(t, host, port, "GET", "/p", csrCookie(`{"user":"ada","role":"USER"}`))); f != nil {
		t.Fatalf("a display label was reported as a privilege: %s", f.Evidence)
	}
}

// Which cookie values are forged, and to what.
func TestForgedClientRoleForgeries(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	cases := []struct {
		value string
		want  []string // privileged member renderings expected, in order
	}{
		{b64(`{"user":"ada","role":"USER"}`), []string{`"role" set to "ADMIN"`, `"role" set to "ADMINISTRATOR"`}},
		{b64(`{"user":"ada","role":"member"}`), []string{`"role" set to "admin"`, `"role" set to "administrator"`}},
		{b64(`{"user":"ada","Group":"Staff"}`), []string{`"Group" set to "Admin"`, `"Group" set to "Administrator"`}},
		{`{"name":"ada","is_admin":false}`, []string{`"is_admin" set to true`}},
		{b64(`{"roles":["user"]}`), []string{`"roles" set to ["user","admin"]`, `"roles" set to ["user","administrator"]`}},
		{b64(`{"user":"ada","role":"ADMIN"}`), nil},                  // already privileged
		{b64(`{"user":"ada","is_admin":true}`), nil},                 // already privileged
		{b64(`{"user":"ada","theme":"dark"}`), nil},                  // no authorization member
		{b64(`{"user":"ada","role":"USER"}`) + ".c2lnbmF0dXJl", nil}, // signed: not one JSON value
		{"eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiVVNFUiJ9.c2ln", nil},      // a JWT
		{"opaque-session-id", nil},
	}
	for _, c := range cases {
		var got []string
		if d, ok := csrParseDoc(c.value); ok {
			for _, f := range csrForgeries(d) {
				got = append(got, f.privNote)
			}
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: got %q, want %q", c.value, got, c.want)
		}
	}
}
