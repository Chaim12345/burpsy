package scanner

// burpsy-react-ui-o2p3: Burp's per-run project-option overrides —
// scanner/audit_optimization/follow_redirections and
// scanner/audit_project_option_overrides/{connect_timeout,normal_timeout} — imported through the path
// -scan-config uses (ApplyBurpConfigFile, over Burp-shaped JSON) and run through AuditSession against
// vulnapp. Each test also proves the engagement sender came out of the run exactly as it went in.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
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

// overrideTarget is vulnapp with a counter on the redirect fixture's landing page.
type overrideTarget struct {
	srv     *httptest.Server
	host    string
	port    uint16
	landing atomic.Int64
	store   *core.TrafficStore
}

func startOverrideTarget(t *testing.T) *overrideTarget {
	t.Helper()
	ot := &overrideTarget{store: core.NewTrafficStore()}
	inner := vulnapp.Handler()
	ot.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect/xss/landing" {
			ot.landing.Add(1)
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(ot.srv.Close)
	hostPort := strings.TrimPrefix(ot.srv.URL, "http://")
	h, p, _ := strings.Cut(hostPort, ":")
	n, _ := strconv.Atoi(p)
	ot.host, ot.port = h, uint16(n)
	return ot
}

// seed captures path once with a client that does NOT follow redirects — the 302 is the captured
// response, as a proxy would record it.
func (ot *overrideTarget) seed(t *testing.T, path string) core.ExchangeID {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(ot.srv.URL + path)
	if err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
	defer res.Body.Close()
	reqID, _ := ot.store.Put([]byte(buildRawRequest("GET", path, ot.host, ot.port, "", "", nil)), core.DirectionRequest)
	respID, _ := ot.store.Put([]byte(buildRawResponse(t, res)), core.DirectionResponse)
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: ot.host, Port: ot.port, Method: "GET", Path: path}
	ot.store.AddExchange(ex)
	return ex.ID
}

// xssOnlyScanner audits with the reflected-XSS family alone, through eng, inside a scope naming the
// target.
func (ot *overrideTarget) xssOnlyScanner(eng *sender.Sender, scoped bool) *ActiveScanner {
	s := NewActiveScanner(ot.store, zap.NewNop()).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 2 * time.Minute, CheckXss: true}).
		WithSender(eng)
	if scoped {
		scope := core.NewScope()
		scope.AddInclude(ot.host)
		s = s.WithScope(scope)
	}
	return s
}

func importOverride(t *testing.T, doc string) AuditConfig {
	t.Helper()
	cfg, unapplied, err := ApplyBurpConfigFile(DefaultAuditConfig(), []byte(doc))
	if err != nil {
		t.Fatalf("import %s: %v", doc, err)
	}
	if len(unapplied) != 0 {
		t.Fatalf("import %s left keys unapplied: %v", doc, unapplied)
	}
	return cfg
}

func findingNamed(fs []*Finding, name string) *Finding {
	for _, f := range fs {
		if f != nil && f.Name == name {
			return f
		}
	}
	return nil
}

func TestFollowRedirectionsDecidesWhetherTheReflectedXSSProbeFollowsAVulnappRedirect(t *testing.T) {
	for _, scoped := range []bool{true, false} {
		name := "engagement scope configured (in-scope rule)"
		if !scoped {
			name = "no engagement scope (same host and port rule)"
		}
		t.Run(name, func(t *testing.T) {
			ot := startOverrideTarget(t)
			id := ot.seed(t, "/redirect/xss?q=seed")
			eng := runtimeSender()
			before := eng.Network()
			scan := ot.xssOnlyScanner(eng, scoped)

			off := importOverride(t, `{"scanner":{"audit_optimization":{"follow_redirections":false}}}`)
			if !off.FollowRedirects.Set || off.FollowRedirects.Value != 0 {
				t.Fatalf("follow_redirections false did not land on the run: %+v", off.FollowRedirects)
			}
			ot.landing.Store(0)
			offOutcome, offFindings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, off)
			if got := ot.landing.Load(); got != 0 {
				t.Fatalf("follow_redirections false: the landing page was requested %d times — a 302 was followed", got)
			}
			if findingNamed(offFindings, xssReflectedIssue) != nil {
				t.Fatal("follow_redirections false: reflected XSS was reported from a 302 that reflects nothing")
			}

			on := importOverride(t, `{"scanner":{"audit_optimization":{"follow_redirections":true}}}`)
			ot.landing.Store(0)
			onOutcome, onFindings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, on)
			if got := ot.landing.Load(); got == 0 {
				t.Fatal("follow_redirections true: the landing page was never requested — the 302 was not followed")
			}
			f := findingNamed(onFindings, xssReflectedIssue)
			if f == nil {
				t.Fatalf("follow_redirections true: no reflected XSS on the page the redirect lands on (outcome %+v)", onOutcome.Items[0].Outcome)
			}
			if !strings.Contains(f.Description, "/redirect/xss/landing") || !strings.Contains(f.Description, "following the probe's redirect") {
				t.Errorf("the finding does not say it was found after following the redirect: %q", f.Description)
			}
			// The hops are requests the run sent: they are metered and count against the budget. Every
			// landing-page arrival is one hop after one probe, plus the baseline, so a run that metered
			// its probes and not its hops would report fewer than twice the arrivals.
			if hops := ot.landing.Load(); int64(onOutcome.RequestsSent) < 2*hops+1 {
				t.Errorf("following: %d landing-page hops but only %d requests metered — the hops were not counted",
					hops, onOutcome.RequestsSent)
			}
			if offOutcome.RequestsSent == 0 {
				t.Error("follow_redirections false: the run sent nothing, so its silence is not evidence")
			}
			if after := eng.Network(); !reflect.DeepEqual(before, after) {
				t.Errorf("the engagement sender's settings changed under the run:\nbefore %+v\nafter  %+v", before, after)
			}
		})
	}
}

func TestNormalTimeoutBoundsTheRunsProbesAndLeavesTheEngagementSenderAlone(t *testing.T) {
	ot := startOverrideTarget(t)
	id := ot.seed(t, "/slow")
	// The engagement allows ten seconds; /slow answers in one and a half.
	eng := sender.NewSender(&sender.SenderConfig{Timeout: 10 * time.Second})
	before := eng.Network()
	scan := ot.xssOnlyScanner(eng, true)

	// connect_timeout -1 is Burp's own "not overridden" (Zbuj.java:27-28): honoured as asked, not refused.
	tight := importOverride(t, `{"scanner":{"audit_project_option_overrides":{"normal_timeout":1,"connect_timeout":-1}}}`)
	if !tight.NormalTimeout.Set || tight.NormalTimeout.Value != 1 || tight.ConnectTimeout.Set {
		t.Fatalf("the overrides did not land as written: normal %+v connect %+v", tight.NormalTimeout, tight.ConnectTimeout)
	}
	start := time.Now()
	outcome, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, tight)
	took := time.Since(start)
	o := outcome.Items[0].Outcome
	if o.SendFailures == 0 || o.Ran != 0 {
		t.Fatalf("normal_timeout 1: the check against a 1.5 s endpoint was not a send failure (ran %d, send failures %d) — "+
			"the run's timeout did not bound its probes", o.Ran, o.SendFailures)
	}
	if took >= vulnapp.SlowResponseDelay {
		t.Errorf("normal_timeout 1: the run took %s, at least the endpoint's own %s — the probe waited for the answer", took, vulnapp.SlowResponseDelay)
	}
	if len(findings) != 0 {
		t.Errorf("a run whose probes all timed out reported %d finding(s)", len(findings))
	}

	// Control: the same scanner and the same item with no override wait out the 1.5 s and run.
	outcome, _ = scan.AuditSession(context.Background(), []core.ExchangeID{id}, DefaultAuditConfig())
	if c := outcome.Items[0].Outcome; c.Ran == 0 || c.SendFailures != 0 {
		t.Fatalf("control: with no override the check did not run cleanly (ran %d, send failures %d)", c.Ran, c.SendFailures)
	}

	// The engagement sender is the one every other tool shares: same object, same settings, and it
	// still waits out a 1.5 s answer after a run that timed out after 1 s.
	if scan.sender != eng {
		t.Fatal("the scanner's engagement sender was replaced")
	}
	if after := eng.Network(); !reflect.DeepEqual(before, after) {
		t.Errorf("the engagement sender's settings changed under the run:\nbefore %+v\nafter  %+v", before, after)
	}
	raw := []byte("GET /slow HTTP/1.1\r\nHost: " + ot.host + ":" + strconv.Itoa(int(ot.port)) + "\r\n\r\n")
	if _, err := eng.SendRaw(context.Background(), ot.host, ot.port, false, raw); err != nil {
		t.Errorf("after the run, the engagement sender could not wait out a 1.5 s answer: %v", err)
	}
}

// loadShippedConfig parses one of Burp's shipped files by its file name.
func loadShippedConfig(t *testing.T, file string) BuiltInConfig {
	t.Helper()
	parsed, err := ParseBurpConfig(readShippedConfig(t, strings.TrimSuffix(file, ".json")))
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return parsed
}

func TestShippedConfigurationsCarryTheOverridesAsBurpWroteThem(t *testing.T) {
	maximum := loadShippedConfig(t, "Audit coverage - maximum.json")
	if v := maximum.FollowRedirections; !v.Set || v.Value != 1 {
		t.Errorf("Audit coverage - maximum: follow_redirections true parsed as %+v", v)
	}
	cicd := loadShippedConfig(t, "Crawl and Audit - CICD Optimized.json")
	if v := cicd.AuditNormalTimeout; !v.Set || v.Value != 10 {
		t.Errorf("CICD Optimized: normal_timeout 10 parsed as %+v (a boolean read of 10 is 1)", v)
	}
	if v := cicd.AuditConnectTimeout; !v.Set || v.Value != 10 {
		t.Errorf("CICD Optimized: connect_timeout 10 parsed as %+v", v)
	}
	applied, _ := cicd.ApplyWithReport(DefaultAuditConfig())
	if applied.NormalTimeout.Value != 10 || applied.ConnectTimeout.Value != 10 {
		t.Errorf("CICD Optimized: the run carries normal %+v connect %+v, want 10 and 10", applied.NormalTimeout, applied.ConnectTimeout)
	}
}

func TestAnOverrideOfMinusOneIsAppliedAsNoOverrideAndNotLostFromTheReport(t *testing.T) {
	parsed, err := ParseBurpConfig([]byte(`{"scanner":{"audit_project_option_overrides":{"connect_timeout":-1,"normal_timeout":-1}}}`))
	if err != nil {
		t.Fatalf("Burp's own -1 was refused: %v", err)
	}
	cfg, rep := parsed.applyWithAccounting(DefaultAuditConfig())
	if cfg.ConnectTimeout.Set || cfg.NormalTimeout.Set {
		t.Errorf("-1 installed an override: connect %+v normal %+v", cfg.ConnectTimeout, cfg.NormalTimeout)
	}
	for _, want := range []string{"audit_connect_timeout", "audit_normal_timeout"} {
		found := false
		for _, a := range rep.Applied {
			found = found || a == want
		}
		if !found {
			t.Errorf("%s set to -1 is in neither list (applied %v, unapplied %v)", want, rep.Applied, rep.Unapplied)
		}
	}
	if s := (AuditConfig{}).timeoutOverride(); !s.Empty() {
		t.Error("an unset configuration produced a timeout override")
	}
}

func TestAnOverrideAboveTheSenderCeilingIsRefusedAtImport(t *testing.T) {
	_, err := ParseBurpConfig([]byte(`{"scanner":{"audit_project_option_overrides":{"normal_timeout":100000}}}`))
	if err == nil {
		t.Fatal("a normal_timeout above the sender's twenty-minute ceiling was accepted and would be clamped at send time")
	}
}
