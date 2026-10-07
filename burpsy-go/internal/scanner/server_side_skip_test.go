package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// burpsy-react-ui-gmdk: skip_server_side_injection_for_parameters exempts a parameter from the
// server-side injection checks only, using Burp's own split of the check set.

// recordingVulnapp serves vulnapp and records every value a parameter arrived with.
type recordingVulnapp struct {
	mu     sync.Mutex
	values map[string][]string
	host   string
	port   uint16
}

func startRecordingVulnapp(t *testing.T) *recordingVulnapp {
	t.Helper()
	rv := &recordingVulnapp{values: map[string][]string{}}
	inner := vulnapp.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rv.mu.Lock()
		for k, vs := range r.URL.Query() {
			rv.values[k] = append(rv.values[k], vs...)
		}
		rv.mu.Unlock()
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	rv.host, rv.port = host, uint16(port)
	return rv
}

// received returns every value the parameter arrived with that satisfies match.
func (rv *recordingVulnapp) received(param string, match func(string) bool) []string {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	var out []string
	for _, v := range rv.values[param] {
		if match(v) {
			out = append(out, v)
		}
	}
	return out
}

func isSQLiProbe(v string) bool { return slices.Contains(sqlErrorProbePayloads(), v) }
func isXSSProbe(v string) bool  { return strings.HasPrefix(v, "zxss") }
func isRedirectProbe(v string) bool {
	return strings.HasPrefix(v, "http://a") || strings.HasPrefix(v, "//a")
}
func describe(vs []string) string { return strconv.Itoa(len(vs)) + " " + strings.Join(vs, " | ") }
func skipCfg(params ...string) AuditConfig {
	cfg := DefaultAuditConfig()
	cfg.SkipServerSideInjectionForParameters = params
	return cfg
}

// auditProducts audits vulnapp's SQL-injectable /products?sort_col= through AuditSession with SQL
// injection, reflected XSS and the reflection probes (open redirection among them) enabled.
func auditProducts(t *testing.T, cfg AuditConfig) (*recordingVulnapp, []*Finding) {
	t.Helper()
	rv := startRecordingVulnapp(t)
	store := core.NewTrafficStore()
	id := seedAuditExchange(t, store, rv.host, rv.port, "/products?sort_col=seed", "Products sorted by seed")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 30 * time.Second,
			CheckSqli: true, CheckXss: true, CheckReflectionProbes: true})
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, cfg)
	return rv, findings
}

// The parameter on the list is not SQL-injection-probed — and the SQL injection finding it would have
// produced does not appear — while a check Burp does not classify as server-side injection (open
// redirection, Zuag) still probes it. The control run without the list proves both probe sets reach
// the parameter at all.
func TestAServerSideSkippedParameterIsNotSQLiProbedButIsStillProbedByOtherChecks(t *testing.T) {
	control, controlFindings := auditProducts(t, skipCfg())
	if len(control.received("sort_col", isSQLiProbe)) == 0 {
		t.Fatal("control: no SQL injection probe reached sort_col, so the skip below would prove nothing")
	}
	if !hasFinding(controlFindings, sqlInjectionIssue) {
		t.Fatal("control: vulnapp's /products did not yield SQL injection")
	}

	cfg := skipCfg("sort_col")
	cfg.SkipIneffectiveChecks = SomeUint32(0) // isolate the always-skipped class from the gated one
	rv, findings := auditProducts(t, cfg)
	if got := rv.received("sort_col", isSQLiProbe); len(got) != 0 {
		t.Errorf("sort_col is on the server-side-injection skip list and received SQL injection probes: %s", describe(got))
	}
	if hasFinding(findings, sqlInjectionIssue) {
		t.Error("SQL injection was reported on a parameter the operator exempted from server-side injection checks")
	}
	if len(rv.received("sort_col", isRedirectProbe)) == 0 {
		t.Error("open redirection did not probe sort_col; the skip list must exempt the parameter from server-side injection checks only")
	}
	// With the effectiveness gate off, Burp does not ask its XSS-and-template check (Zfhb.java:81-82),
	// so reflected XSS still probes the parameter.
	if len(rv.received("sort_col", isXSSProbe)) == 0 {
		t.Error("with skip_ineffective_checks off, reflected XSS must still probe the listed parameter")
	}
}

// With skip_ineffective_checks on — Burp's default — the XSS-and-template check is also exempted
// (Zi6p.java:128-130), and open redirection still is not.
func TestReflectedXSSHonoursTheServerSideSkipListOnlyWhileTheEffectivenessGateIsOn(t *testing.T) {
	rv, _ := auditProducts(t, skipCfg("sort_col"))
	if got := rv.received("sort_col", isXSSProbe); len(got) != 0 {
		t.Errorf("reflected XSS probed the listed parameter with skip_ineffective_checks on: %s", describe(got))
	}
	if got := rv.received("sort_col", isSQLiProbe); len(got) != 0 {
		t.Errorf("SQL injection probed the listed parameter: %s", describe(got))
	}
	if len(rv.received("sort_col", isRedirectProbe)) == 0 {
		t.Error("open redirection did not probe sort_col")
	}
}

// The exemption rides only a server-side check's enumeration, never the run-wide options the queue
// row and every other check read.
func TestTheServerSideSkipRidesOnlyTheServerSideChecksEnumeration(t *testing.T) {
	cfg := skipCfg("sort_col")
	if got := cfg.enumerateOptions().SkipServerSideInjectionForParameters; len(got) != 0 {
		t.Fatalf("run-wide enumerate options carry the server-side list %v; every check and the queue would drop the parameter", got)
	}
	ctx := withRunConfig(context.Background(), cfg)
	for name, want := range map[string]bool{
		sqlInjectionIssue:                true,
		xssReflectedIssue:                true,
		"XPath injection":                true,
		"OS command injection":           true,
		"Open redirection (reflected)":   false,
		"Link manipulation (reflected)":  false,
		"HTTP response header injection": false,
	} {
		d, ok := descriptorByName(name)
		if !ok {
			t.Fatalf("no descriptor %q", name)
		}
		got := newCheckContextForCheck(ctx, nil, nil, nil, d).ProbeEnumerateOptions().SkipServerSideInjectionForParameters
		if (len(got) > 0) != want {
			t.Errorf("%s: server-side skip list %v, want applied=%v", name, got, want)
		}
	}
	// And the always-class survives the gate being off while the gated class does not.
	cfg.SkipIneffectiveChecks = SomeUint32(0)
	ctx = withRunConfig(context.Background(), cfg)
	for name, want := range map[string]bool{sqlInjectionIssue: true, xssReflectedIssue: false} {
		d, _ := descriptorByName(name)
		got := newCheckContextForCheck(ctx, nil, nil, nil, d).ProbeEnumerateOptions().SkipServerSideInjectionForParameters
		if (len(got) > 0) != want {
			t.Errorf("gate off, %s: server-side skip list %v, want applied=%v", name, got, want)
		}
	}
}

// The enumerator's drop is counted under its own Declined, not folded into the skip-all one.
func TestTheServerSideDropIsItsOwnDeclined(t *testing.T) {
	raw := []byte("GET /products?sort_col=a&q=b HTTP/1.1\r\nHost: h\r\n\r\n")
	pts, declined := bcheck.EnumerateWith(raw, []string{"query"},
		bcheck.EnumerateOptions{SkipServerSideInjectionForParameters: []string{"SORT_COL"}})
	for _, p := range pts {
		if p.Name == "sort_col" {
			t.Error("sort_col survived the server-side skip list (matching is case-insensitive)")
		}
	}
	found := false
	for _, d := range declined {
		if d.What == bcheck.DeclinedSkippedServerSideWhat {
			found = true
		}
	}
	if !found {
		t.Errorf("declined = %+v, want a %q record", declined, bcheck.DeclinedSkippedServerSideWhat)
	}
}

// Every check class is taken from Burp's table, and each classified type has a burpsy check.
func TestEveryServerSideClassifiedTypeIsARealCheck(t *testing.T) {
	byType := map[uint32]CheckDescriptor{}
	for _, d := range NativeCheckRegistry() {
		byType[d.TypeIndex] = d
	}
	for ty, class := range serverSideInjectionByType {
		d, ok := byType[ty]
		if !ok {
			t.Errorf("%#08x is classified but has no descriptor", ty)
			continue
		}
		if d.ServerSideInjection != class {
			t.Errorf("%s: descriptor class %d, table %d", d.Name, d.ServerSideInjection, class)
		}
	}
}

func hasFinding(fs []*Finding, name string) bool {
	for _, f := range fs {
		if f.Name == name {
			return true
		}
	}
	return false
}
