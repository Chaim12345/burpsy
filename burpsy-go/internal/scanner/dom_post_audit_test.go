package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// burpsy-react-ui-4kmr: with a DOM engine attached, an audit of a POST login lost its
// session-management and login-rate-limit rows.
//
// The browser can only navigate, so a DOM check on a POST seed loads the URL with GET. A framework
// that maps the route to POST alone answers that GET with an error status and no body (Spring's
// 405), which Chrome reports as net::ERR_HTTP_RESPONSE_CODE_FAILURE. The first two DOM checks of the
// unit failed that way, the check-failure breaker (2 consecutive failures by default) abandoned the
// unit, and every check after them - the authentication and session rows among them - was counted
// "unit abandoned" and never ran.
//
// The target here is vulnapp behind exactly that framework behaviour: a request other than POST to a
// path vulnapp declares only as POST answers 405 with an empty body. Everything else is vulnapp.

// methodStrictPaths is the set of vulnapp paths declared only as POST.
func methodStrictPaths() map[string]bool {
	post, other := map[string]bool{}, map[string]bool{}
	for _, e := range vulnapp.Vulnerabilities() {
		p := e.Path
		if i := strings.IndexByte(p, '?'); i >= 0 {
			p = p[:i]
		}
		if e.Method == http.MethodPost {
			post[p] = true
		} else {
			other[p] = true
		}
	}
	for p := range other {
		delete(post, p)
	}
	return post
}

// methodStrict answers a non-POST request to a POST-only path the way a method-mapped framework does.
func methodStrict(next http.Handler) http.Handler {
	strict := methodStrictPaths()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && strict[r.URL.Path] {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func startMethodStrictTarget(t *testing.T, paths ...string) *runtimeTarget {
	t.Helper()
	srv := httptest.NewServer(methodStrict(vulnapp.Handler()))
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	rt := &runtimeTarget{srv: srv, host: host, port: port, store: core.NewTrafficStore(), exchanges: map[string]core.ExchangeID{}}
	client := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	want := map[string]bool{}
	for _, p := range paths {
		want[p] = true
	}
	for _, e := range vulnapp.Vulnerabilities() {
		if want[e.Path] {
			if _, seen := rt.exchanges[e.Path]; !seen {
				rt.seed(t, client, e)
			}
		}
	}
	for _, p := range paths {
		if _, ok := rt.exchanges[p]; !ok {
			t.Fatalf("%s was never seeded", p)
		}
		// The premise: a GET of the seeded POST route is an empty error, which is what the browser trips on.
		res, err := client.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s answered %d, want 405: the test no longer models a POST-only route", p, res.StatusCode)
		}
	}
	return rt
}

// domPostCase is one POST seed and the row its audit must report.
type domPostCase struct {
	path, row string
	cfg       func() *ScanConfig
}

var domPostCases = []domPostCase{
	{"/auth/login", IssueLoginRateLimitMissing, func() *ScanConfig { return &ScanConfig{CheckLoginRateLimit: true} }},
	{"/auth/otp/verify", IssueLoginRateLimitMissing, func() *ScanConfig { return &ScanConfig{CheckLoginRateLimit: true} }},
	{"/session/fixation/login", sessionFixationIssue, func() *ScanConfig { return &ScanConfig{CheckSessionManagement: true} }},
}

// auditWithBrowser audits one seed with only the case's switch on, plus the DOM families the browser
// provider switches on, at one worker - the benchmark's setting.
func auditWithBrowser(t *testing.T, rt *runtimeTarget, c domPostCase, browser BrowserProvider) (AuditOutcome, []*Finding, string) {
	t.Helper()
	cfg := c.cfg()
	cfg.MaxConcurrency, cfg.Timeout = 1, 2*time.Minute
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg).WithBrowserProvider(browser)
	if !scan.ConfigSnapshot().CheckDOM {
		t.Fatal("attaching the browser did not switch the DOM checks on; this test would prove nothing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	outcome, fs := scan.AuditWithin(ctx, rt.exchanges[c.path], scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", c.path, outcome.Error)
	}
	summary := fmt.Sprintf("ran=%d send_failed=%d unit_abandoned=%d units_abandoned=%d skipped=%d unmeasurable=%d",
		outcome.Ran, outcome.SendFailures, outcome.UnitAbandoned, outcome.UnitsAbandoned, outcome.Skipped, outcome.Unmeasurable)
	t.Log(summary)
	if outcome.UnitAbandoned != 0 || outcome.UnitsAbandoned != 0 {
		t.Errorf("%s: browser-side failures abandoned the unit (%s)", c.path, summary)
	}
	if sessFindingIn(fs, c.row) == nil {
		var names []string
		for _, f := range fs {
			names = append(names, f.Name)
		}
		t.Errorf("%s: %q was not reported with a DOM engine attached (%s); rows: %v", c.path, c.row, summary, names)
	}
	return outcome, fs, summary
}

func TestDOMEngineDoesNotAbandonPOSTLoginAudits(t *testing.T) {
	// Skipped only when Chrome is actually missing, and counted: this used to skip whenever
	// BURPSY_ALLOW_NO_CHROME=1 was set, even on a machine whose Chrome would have run it.
	if !chromeOnPath() {
		domexectest.Skip(t, "no Chrome on PATH: the DOM engine this regression needs is not available")
	}
	paths := make([]string, 0, len(domPostCases))
	for _, c := range domPostCases {
		paths = append(paths, c.path)
	}
	rt := startMethodStrictTarget(t, paths...)
	browser := sharedBrowserProvider()
	for _, c := range domPostCases {
		t.Run(strings.TrimPrefix(c.path, "/"), func(t *testing.T) {
			outcome, _, summary := auditWithBrowser(t, rt, c, browser)
			// The 405 page is an answer: the DOM checks ran and are undecided, never a send failure.
			if outcome.SendFailures != 0 {
				t.Errorf("%s: a page the target answered with an error status was counted as a send failure (%s)", c.path, summary)
			}
			// Positive control: the DOM checks really navigated and met the empty 405. Without it a
			// browser that never launched would also leave this test with no abandoned unit to see.
			if outcome.Unmeasurable == 0 {
				t.Errorf("%s: no DOM check reported the error page as undecided; the browser never reached it (%s)", c.path, summary)
			}
		})
	}
}

// failingBrowser is a configured engine that does not work: it cannot launch, or its process died.
type failingBrowser struct{}

func (failingBrowser) Browser(context.Context) (*domexec.Browser, error) {
	return nil, errors.New("browser: the headless browser is no longer available")
}
func (failingBrowser) Close() error { return nil }

// TestBrowserFailuresDoNotAbandonTheUnit: whatever a browser-driven check fails on, it is not evidence
// that the target is failing, so it must not abandon the HTTP checks queued behind it in the unit.
// Needs no Chrome: the engine here is broken on purpose.
func TestBrowserFailuresDoNotAbandonTheUnit(t *testing.T) {
	rt := startMethodStrictTarget(t, "/auth/login", "/session/fixation/login")
	for _, c := range domPostCases {
		if c.path == "/auth/otp/verify" {
			continue
		}
		t.Run(strings.TrimPrefix(c.path, "/"), func(t *testing.T) {
			outcome, _, summary := auditWithBrowser(t, rt, c, failingBrowser{})
			// The failures are still reported as what they are, not hidden.
			if outcome.SendFailures == 0 {
				t.Errorf("%s: the broken engine's checks were not counted as failed (%s)", c.path, summary)
			}
		})
	}
}

// TestJWTHostedRowWithNoFetchIsUndecided: a target that never fetches the jku/x5u material answered
// the forged token, so the row is undecided - not a send failure, and not two of them in a row
// tripping the breaker over every check queued behind.
func TestJWTHostedRowWithNoFetchIsUndecided(t *testing.T) {
	rt := startRuntimeTarget(t)
	for _, path := range []string{"/fn/jwt/jku-safe", "/fn/jwt/x5u-safe"} {
		id, ok := rt.exchanges[path]
		if !ok {
			t.Fatalf("%s was never seeded", path)
		}
		cfg := &ScanConfig{MaxConcurrency: 1, Timeout: 2 * time.Minute, CheckJwtForgery: true}
		scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		outcome, fs := scan.AuditWithin(ctx, id, scan.AuditConfig())
		cancel()
		if outcome.Error != "" {
			t.Fatalf("audit of %s failed: %s", path, outcome.Error)
		}
		summary := fmt.Sprintf("ran=%d send_failed=%d unit_abandoned=%d unmeasurable=%d",
			outcome.Ran, outcome.SendFailures, outcome.UnitAbandoned, outcome.Unmeasurable)
		if outcome.SendFailures != 0 || outcome.UnitAbandoned != 0 {
			t.Errorf("%s: a jku/x5u header the target ignored was counted as a failure (%s)", path, summary)
		}
		if outcome.Unmeasurable == 0 {
			t.Errorf("%s: the unfetched material was not reported undecided (%s)", path, summary)
		}
		for _, f := range fs {
			if strings.HasPrefix(f.Name, "JWT arbitrary") {
				t.Errorf("%s: the safe twin reported %q", path, f.Name)
			}
		}
	}
}
