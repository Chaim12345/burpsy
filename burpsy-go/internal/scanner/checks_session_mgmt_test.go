package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// The session-management check (burpsy-react-ui-0vzb wave 5) against the live vulnapp session family.
// Each guard has a safe twin that only it stops:
//
//   - the confirmation of a prediction: /session/mixed/login shows a counter inside an unpredictable token;
//   - the page's random-token control: /session/lax/login's page names the user to anyone;
//   - a logout must expire the cookie: /session/guest has no logout and answers with a new cookie;
//   - and /session/secure/login, which does everything right.

var sessRows = []string{sessionFixationIssue, predictableSessionIssue, logoutInvalidationIssue}

// sessAudit audits one seeded vulnapp endpoint with only the session-management switch on.
func sessAudit(t *testing.T, path string, mod func(*ScanConfig)) ([]*Finding, uint32) {
	t.Helper()
	rt := startRuntimeTarget(t)
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckSessionManagement: true}
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

func sessFindingIn(fs []*Finding, row string) *Finding {
	for _, f := range fs {
		if f != nil && f.Name == row {
			return f
		}
	}
	return nil
}

func TestSessionManagementFindsEachDefect(t *testing.T) {
	cases := []struct {
		path, row, confidence, mustSay string
	}{
		{"/session/fixation/login", sessionFixationIssue, "certain", `the response names "sessuser"`},
		// The page is found only through the site map here.
		{"/session/counter/login", predictableSessionIssue, "certain", "/session/counter/home"},
		{"/session/encoded/login", predictableSessionIssue, "certain", "unpadded base64-encoded"},
		{"/session/clock/login", predictableSessionIssue, "firm", "microseconds"},
		{"/session/keep?action=login", logoutInvalidationIssue, "firm", "query action=logout"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			fs, _ := sessAudit(t, c.path, nil)
			f := sessFindingIn(fs, c.row)
			if f == nil {
				t.Fatalf("%s: %q was not reported (got %v)", c.path, c.row, sessNames(fs))
			}
			if f.Confidence != c.confidence {
				t.Errorf("confidence %s, want %s: %s", f.Confidence, c.confidence, f.Description)
			}
			if !strings.Contains(f.Description, c.mustSay) {
				t.Errorf("description does not say %q: %s", c.mustSay, f.Description)
			}
			for _, other := range sessRows {
				if other != c.row && sessFindingIn(fs, other) != nil {
					t.Errorf("%s also reported %q, which this variant does not have: %s", c.path, other,
						sessFindingIn(fs, other).Description)
				}
			}
		})
	}
}

func sessNames(fs []*Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Name)
	}
	return out
}

func TestSessionManagementStaysQuietOnTheSafeTwins(t *testing.T) {
	// The check must demonstrably work in this run before silence on a twin means anything.
	if fs, _ := sessAudit(t, "/session/keep?action=login", nil); sessFindingIn(fs, logoutInvalidationIssue) == nil {
		t.Fatal("the vulnerable logout did not fire, so the twins' silence proves nothing")
	}
	for path, why := range map[string]string{
		"/session/secure/login":       "rotates, issues random tokens and destroys the session at logout",
		"/session/mixed/login":        "shows a counter inside a token that cannot be predicted as a whole",
		"/session/lax/login":          "has a page that names the last user to anyone, session or not",
		"/session/guest?action=login": "has no logout; its POST without credentials opens a guest session",
	} {
		fs, sent := sessAudit(t, path, nil)
		for _, row := range sessRows {
			if f := sessFindingIn(fs, row); f != nil {
				t.Errorf("%s %s but %q was reported: %s", path, why, row, f.Description)
			}
		}
		// The baseline, two cookie-naming logins and twelve samples at least: silence must be a verdict.
		if sent < 15 {
			t.Errorf("%s: only %d requests sent, so the check never reached its analysis", path, sent)
		}
	}
}

func TestSessionManagementIsOffWithoutItsSwitch(t *testing.T) {
	fs, sent := sessAudit(t, "/session/fixation/login", func(c *ScanConfig) {
		c.CheckSessionManagement = false
		c.CheckIDOR = true // the descriptor it rides is on; this half is not
	})
	for _, row := range sessRows {
		if f := sessFindingIn(fs, row); f != nil {
			t.Errorf("reported with the switch off: %s", f.Description)
		}
	}
	if sent > 2 {
		t.Errorf("%d requests sent with the switch off", sent)
	}
}

func sessSamplesOf(toks ...string) []sessSample {
	now := time.Now()
	var out []sessSample
	for _, t := range toks {
		out = append(out, sessSample{token: t, before: now, after: now})
	}
	return out
}

// The VulnerableApp-style tokens: a plain counter, and a base64-wrapped counter stepping by 100.
func TestSessionTokenModels(t *testing.T) {
	var plain, b64 []string
	for i := 0; i < 12; i++ {
		plain = append(plain, fmt.Sprintf("SESSION-%d", 1001+i))
		b64 = append(b64, base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("SESSION-%d", 19020+100*i))))
	}
	m := sessModel(sessSamplesOf(plain...))
	if m == nil || !m.counter {
		t.Fatal("a plain counter was not modelled")
	}
	if k, ok := m.confirm("SESSION-1013", time.Now(), time.Now()); !ok || k != 1 {
		t.Errorf("SESSION-1013 confirm = %d %v, want step 1", k, ok)
	}
	if _, ok := m.confirm("SESSION-1099", time.Now(), time.Now()); ok {
		t.Error("a value far beyond the predicted steps was accepted")
	}
	m = sessModel(sessSamplesOf(b64...))
	if m == nil || !m.counter || m.codec.name != "base64" || m.step.Int64() != 100 {
		t.Fatalf("base64 counter model = %+v", m)
	}
	next := base64.StdEncoding.EncodeToString([]byte("SESSION-20220"))
	if k, ok := m.confirm(next, time.Now(), time.Now()); !ok || k != 1 {
		t.Errorf("confirm(%s) = %d %v", next, k, ok)
	}
	// Random tokens fit nothing.
	var random []string
	for i := 0; i < 12; i++ {
		random = append(random, sessLookalike("0123456789abcdef0123456789abcdef"))
	}
	if m := sessModel(sessSamplesOf(random...)); m != nil {
		t.Errorf("random tokens were modelled: %+v", m)
	}
}

func TestSessionLogoutWordsAndRewrites(t *testing.T) {
	for in, want := range map[string]string{"login": "logout", "LogIn": "LogOut", "sign_in": "sign_out",
		"logon": "logoff", "SIGNIN": "SIGNOUT"} {
		if got := sessLogoutWord(in); got != want {
			t.Errorf("sessLogoutWord(%q) = %q, want %q", in, got, want)
		}
	}
	login := "POST /a/login?x=1 HTTP/1.1\r\nHost: h\r\nCookie: a=b\r\nAuthorization: Basic eDp5\r\n" +
		"Content-Type: application/json\r\nContent-Length: 30\r\n\r\n{\"username\":\"u\",\"password\":\"p\"}"
	out := sessRewrite(login, "POST", "/a/logout?x=1", "", "")
	if strings.Contains(out, "password") || strings.Contains(out, "Authorization") || strings.Contains(out, "Cookie") {
		t.Errorf("a derived logout carries credentials:\n%s", out)
	}
	if !strings.HasPrefix(out, "POST /a/logout?x=1 HTTP/1.1\r\n") || !strings.Contains(out, "Content-Length: 0\r\n") {
		t.Errorf("rewrite = %q", out)
	}
	if c, ok := sessLoginFields(login); !ok || c.user != "u" {
		t.Errorf("login fields = %+v %v", c, ok)
	}
	if _, ok := sessLoginFields("GET /a?q=1 HTTP/1.1\r\nHost: h\r\n\r\n"); ok {
		t.Error("a request with no password field was taken for a login")
	}
}
