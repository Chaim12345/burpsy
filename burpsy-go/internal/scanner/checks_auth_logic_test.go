package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// The two burpsy-authored authentication rows against the vulnapp auth family. Each claim is
// asserted on a vulnerable endpoint AND denied on a safe twin built to trip one guard, so each guard
// has a test that fails when it is removed:
//
//   - the credential-evaluation control: /auth/static/form has login field names, ignores them, and
//     answers every burst identically;
//   - the throttle / changed-answer rule: /auth/throttled/login (429 + Retry-After after 5 failures)
//     and /auth/otp/capped (a code invalidated after 3 guesses);
//   - the growing-delay rule: /auth/slow/login never refuses but slows each failure;
//   - the enumeration comparison: /auth/login quotes the submitted username and a per-request id in
//     ONE generic message, and a captured username that does not exist answers like invented ones.
//
// The checks run on a target of their own, with only their two switches on, so the target's login
// ledger counts what THESE checks did: no other family replays the captured (real) password.

type authTarget struct {
	rt     *runtimeTarget
	scan   *ActiveScanner
	client *http.Client
}

var (
	authTargetOnce sync.Once
	authTargetVal  *authTarget
	authMemoMu     sync.Mutex
	authMemo       = map[string]map[string]*Finding{}
)

// authOnlyConfig enables only the two authentication checks.
func authOnlyConfig() *ScanConfig {
	return &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckLoginRateLimit: true, CheckUsernameEnumeration: true}
}

func startAuthTarget(t *testing.T) *authTarget {
	t.Helper()
	authTargetOnce.Do(func() {
		srv := httptest.NewServer(vulnapp.Handler())
		host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
		var port uint16
		fmt.Sscanf(portStr, "%d", &port)
		rt := &runtimeTarget{srv: srv, host: host, port: port, store: core.NewTrafficStore(), exchanges: map[string]core.ExchangeID{}}
		client := &http.Client{Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		for _, e := range vulnapp.Vulnerabilities() {
			if strings.HasPrefix(e.Path, "/auth/") {
				if _, seen := rt.exchanges[e.Path]; !seen {
					rt.seed(t, client, e)
				}
			}
		}
		// A captured login for a username that does not exist on the enumerating endpoint: the
		// comparison must find nothing, because there is no known user on either side.
		rt.seed(t, client, vulnapp.Endpoint{Path: "/auth/enum/login?as=stranger", Method: http.MethodPost,
			Body: "username=mallory&password=whatever", ContentType: "application/x-www-form-urlencoded"})
		scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(authOnlyConfig())
		authTargetVal = &authTarget{rt: rt, scan: scan, client: client}
	})
	if authTargetVal == nil {
		t.Fatal("auth target did not start")
	}
	return authTargetVal
}

// findings audits one seeded auth endpoint once and returns the rows reported.
func (a *authTarget) findings(t *testing.T, path string) map[string]*Finding {
	t.Helper()
	authMemoMu.Lock()
	if got, ok := authMemo[path]; ok {
		authMemoMu.Unlock()
		return got
	}
	authMemoMu.Unlock()
	id, ok := a.rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	outcome, fs := a.scan.AuditWithin(ctx, id, a.scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", path, outcome.Error)
	}
	got := map[string]*Finding{}
	for _, f := range fs {
		if f != nil {
			got[f.Name] = f
		}
	}
	authMemoMu.Lock()
	authMemo[path] = got
	authMemoMu.Unlock()
	return got
}

func (a *authTarget) ledger(t *testing.T) map[string]int {
	t.Helper()
	res, err := a.client.Get(a.rt.srv.URL + "/auth/ledger")
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	defer res.Body.Close()
	out := map[string]int{}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode ledger: %v", err)
	}
	return out
}

func TestLoginRateLimitReportsAnUnthrottledLoginAndOTPCheck(t *testing.T) {
	a := startAuthTarget(t)
	for _, path := range []string{"/auth/login", "/auth/otp/verify"} {
		got := a.findings(t, path)
		f := got[IssueLoginRateLimitMissing]
		if f == nil {
			t.Fatalf("%s accepts unlimited wrong guesses but %q was not reported; rows: %s", path, IssueLoginRateLimitMissing, joinRows(got))
		}
		if f.Confidence != "tentative" || !strings.Contains(f.Evidence, "20 consecutive failed attempts") {
			t.Errorf("%s: finding = %s %q; want tentative, naming the 20-attempt burst", path, f.Confidence, f.Evidence)
		}
		if strings.Contains(f.Evidence, vulnapp.AuthUser+`"`) || strings.Contains(f.Evidence, vulnapp.AuthEmail) {
			t.Errorf("%s: the burst must use an invented identity, not the captured one: %q", path, f.Evidence)
		}
	}
	otp := a.findings(t, "/auth/otp/verify")[IssueLoginRateLimitMissing]
	if !strings.Contains(otp.Evidence, "one-time code") {
		t.Errorf("the OTP finding should say a one-time code was guessed: %q", otp.Evidence)
	}
}

func TestLoginRateLimitStaysQuietWhereADefenceEngages(t *testing.T) {
	a := startAuthTarget(t)
	if a.findings(t, "/auth/login")[IssueLoginRateLimitMissing] == nil {
		t.Fatal("the row did not fire on /auth/login in this run, so the twins' silence proves nothing")
	}
	for path, why := range map[string]string{
		"/auth/throttled/login": "answers 429 with Retry-After after 5 failures",
		"/auth/otp/capped":      "invalidates the code after 3 wrong guesses",
		"/auth/slow/login":      "slows each failure by a growing delay",
		"/auth/static/form":     "ignores the fields entirely (no evidence it evaluates credentials)",
	} {
		if f := a.findings(t, path)[IssueLoginRateLimitMissing]; f != nil {
			t.Errorf("%s %s, yet it was reported: %q", path, why, f.Evidence)
		}
	}
}

func TestUsernameEnumerationReportsAConsistentDifference(t *testing.T) {
	a := startAuthTarget(t)
	for path, want := range map[string]string{
		"/auth/enum/login":          "Incorrect password",
		"/auth/enum-redirect/login": "bad-password",
		"/auth/enum-json/login":     "BAD_CREDENTIALS",
	} {
		got := a.findings(t, path)
		f := got[IssueUsernameEnumeration]
		if f == nil {
			t.Errorf("%s answers known and unknown users differently but %q was not reported; rows: %s", path, IssueUsernameEnumeration, joinRows(got))
			continue
		}
		if !strings.Contains(f.Evidence, want) || !strings.Contains(f.Evidence, "2 of 2 identical") ||
			!strings.Contains(f.Evidence, "3 of 3 identical") {
			t.Errorf("%s: evidence should quote the difference (%q) and both repeat counts: %q", path, want, f.Evidence)
		}
	}
}

func TestUsernameEnumerationStaysQuietOnGenericAnswers(t *testing.T) {
	a := startAuthTarget(t)
	if a.findings(t, "/auth/enum/login")[IssueUsernameEnumeration] == nil {
		t.Fatal("the row did not fire on /auth/enum/login in this run, so the twins' silence proves nothing")
	}
	for path, why := range map[string]string{
		"/auth/login":                  "quotes the submitted username and a request id in one generic message",
		"/auth/throttled/login":        "answers every failure with one generic message",
		"/auth/enum/login?as=stranger": "was captured with a username that does not exist, so nothing distinguishes the two sides",
	} {
		if f := a.findings(t, path)[IssueUsernameEnumeration]; f != nil {
			t.Errorf("%s %s, yet enumeration was reported: %q", path, why, f.Evidence)
		}
	}
}

// Never log in, never send the captured password. The ledger counts successful logins per endpoint;
// the seeding logged in once on each endpoint whose captured request carried the real credentials,
// and auditing every auth endpoint must not add a single one.
func TestAuthChecksNeverLogIn(t *testing.T) {
	a := startAuthTarget(t)
	before := a.ledger(t)
	for path := range a.rt.exchanges {
		a.findings(t, path)
	}
	after := a.ledger(t)
	for path, n := range after {
		if n != before[path] {
			t.Errorf("%s: %d successful login(s) during the audit; the checks must only ever send wrong credentials", path, n-before[path])
		}
	}
	if before["/auth/login"] != 1 {
		t.Errorf("the seeded real login should have been counted once on /auth/login, ledger = %v; without it this test proves nothing", before)
	}
}

// The burst size is the configured one, clamped.
func TestLoginRateLimitBurstIsConfigurableAndBounded(t *testing.T) {
	for _, c := range []struct{ set, want int }{{0, 20}, {7, 7}, {1, MinLoginRateLimitAttempts}, {1000, MaxLoginRateLimitAttempts}} {
		if got := loginRateLimitAttempts(&ScanConfig{LoginRateLimitAttempts: c.set}); got != c.want {
			t.Errorf("LoginRateLimitAttempts=%d -> %d, want %d", c.set, got, c.want)
		}
	}
	a := startAuthTarget(t)
	cfg := &ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, CheckLoginRateLimit: true, LoginRateLimitAttempts: 7}
	scan := NewActiveScanner(a.rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	outcome, fs := scan.AuditWithin(ctx, a.rt.exchanges["/auth/login"], scan.AuditConfig())
	var f *Finding
	for _, x := range fs {
		if x != nil && x.Name == IssueLoginRateLimitMissing {
			f = x
		}
	}
	if f == nil || !strings.Contains(f.Evidence, "7 consecutive failed attempts") {
		t.Fatalf("a 7-attempt burst should be reported as 7 attempts; got %v", f)
	}
	if outcome.RequestsSent != 7 {
		t.Errorf("RequestsSent = %d, want exactly the 7-attempt burst (no baseline replay)", outcome.RequestsSent)
	}
}

// Both checks are off unless switched on.
func TestAuthChecksAreOffByDefault(t *testing.T) {
	a := startAuthTarget(t)
	// Every other family on, these two off: what "off" means is that nothing else admits them.
	cfg := runtimeScanConfig()
	cfg.CheckLoginRateLimit, cfg.CheckUsernameEnumeration = false, false
	scan := NewActiveScanner(a.rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, fs := scan.AuditWithin(ctx, a.rt.exchanges["/auth/enum/login"], scan.AuditConfig())
	for _, f := range fs {
		if f != nil && (f.Name == IssueLoginRateLimitMissing || f.Name == IssueUsernameEnumeration) {
			t.Errorf("%q reported with its switch off", f.Name)
		}
	}
	if loginRateLimitEnabled(&ScanConfig{}) || usernameEnumerationEnabled(&ScanConfig{}) {
		t.Error("a zero ScanConfig enables an authentication check")
	}
}

// Which requests count as a login. Registration, password change, reset and identity-only forms are
// never acted on: repeating them creates accounts, changes passwords or sends mail.
func TestFindLoginPointsRecognisesOnlyLogins(t *testing.T) {
	form := func(path, body string) []byte {
		return []byte("POST " + path + " HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n" +
			fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body))
	}
	jsonReq := func(path, body string) []byte {
		return []byte("POST " + path + " HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n" +
			fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body))
	}
	cases := []struct {
		name string
		raw  []byte
		path string
		ok   bool
		kind secretKind
	}{
		{"form login", form("/login", "username=a&password=b"), "/login", true, secretPassword},
		{"json login", jsonReq("/api/session", `{"email":"a@b.c","pass":"x"}`), "/api/session", true, secretPassword},
		{"otp verify", form("/mfa", "user_email=a%40b.c&otp=123456"), "/mfa", true, secretOTP},
		{"registration path", form("/register", "username=a&password=b"), "/register", false, 0},
		{"confirm field", form("/account", "username=a&password=b&password_confirm=b"), "/account", false, 0},
		{"password change", form("/settings", "username=a&current_password=b&new_password=c"), "/settings", false, 0},
		{"identity only", form("/forgot", "email=a%40b.c"), "/forgot", false, 0},
		{"identity only, neutral path", form("/otp/send", "email=a%40b.c"), "/otp/send", false, 0},
		{"no identity", form("/unlock", "password=b"), "/unlock", false, 0},
		{"oauth code is not an OTP", form("/callback", "username=a&code=xyz"), "/callback", false, 0},
	}
	for _, c := range cases {
		lp, ok := findLoginPoints(c.raw, c.path, bcheck.EnumerateOptions{})
		if ok != c.ok || (ok && lp.kind != c.kind) {
			t.Errorf("%s: ok=%v kind=%v, want ok=%v kind=%v", c.name, ok, lp.kind, c.ok, c.kind)
		}
	}
}

// Invented identities keep the captured shape and are never the captured value.
func TestInventedIdentitiesKeepTheShape(t *testing.T) {
	if v := inventIdentity("alice@corp.example"); !strings.HasSuffix(v, "@corp.example") || v == "alice@corp.example" {
		t.Errorf("e-mail identity -> %q", v)
	}
	if v := inventIdentity("1234"); !isAllDigits(v) || len(v) != 10 {
		t.Errorf("numeric identity -> %q", v)
	}
	if a, b := inventIdentity("alice"), inventIdentity("alice"); a == b || a == "alice" {
		t.Errorf("invented names must be fresh: %q %q", a, b)
	}
	if v := inventSecret(secretOTP, "0420"); len(v) != 4 || !isAllDigits(v) {
		t.Errorf("a 4-digit code should be guessed with 4 digits: %q", v)
	}
}

// The fingerprint masks what was submitted and what changes per request, and nothing else.
func TestAuthFingerprintMasksSubmittedValuesAndTokens(t *testing.T) {
	mk := func(body string) ProbeResponse {
		return ProbeResponse{Status: 200, Body: body, Raw: []byte("HTTP/1.1 200 OK\r\n\r\n" + body)}
	}
	a := authFingerprint(mk(`{"msg":"Invalid password for bsyalpha","req":"9f86d081884c7d65"}`), []string{"bsyalpha", "bsybravo"})
	b := authFingerprint(mk(`{"msg":"Invalid password for bsybravo","req":"aa11bb22cc33dd44"}`), []string{"bsyalpha", "bsybravo"})
	if a != b {
		t.Errorf("reflection and request id were not masked:\n%q\n%q", a, b)
	}
	c := authFingerprint(mk(`{"msg":"Unknown user bsybravo","req":"aa11bb22cc33dd44"}`), []string{"bsyalpha", "bsybravo"})
	if a == c {
		t.Error("a different message was masked away")
	}
}
