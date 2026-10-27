package scanner

// The 0vzb.3 server-side prototype pollution check against the vulnapp sppj family: the merge
// that keeps __proto__ is found, the twin that drops it stays quiet, and the switch gates both.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

var (
	sppjTargetOnce sync.Once
	sppjTargetVal  *runtimeTarget
)

func startSppjTarget(t *testing.T) *runtimeTarget {
	t.Helper()
	sppjTargetOnce.Do(func() {
		srv := httptest.NewServer(vulnapp.Handler())
		host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
		var port uint16
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			t.Fatalf("test server port %q: %v", portStr, err)
		}
		rt := &runtimeTarget{srv: srv, host: host, port: port, store: core.NewTrafficStore(), exchanges: map[string]core.ExchangeID{}}
		client := &http.Client{Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		for _, e := range vulnapp.Vulnerabilities() {
			if strings.HasPrefix(e.Path, "/sppj/") {
				rt.seed(t, client, e)
			}
		}
		sppjTargetVal = rt
	})
	if sppjTargetVal == nil {
		t.Fatal("sppj target did not start")
	}
	return sppjTargetVal
}

func sppjAudit(t *testing.T, path string, mod func(*ScanConfig)) []*Finding {
	t.Helper()
	rt := startSppjTarget(t)
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckServerSidePrototypePollution: true}
	if mod != nil {
		mod(cfg)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	outcome, findings := scan.AuditWithin(ctx, rt.exchanges[path], scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", path, outcome.Error)
	}
	return findings
}

func TestServerSidePrototypePollutionFindsTheMerge(t *testing.T) {
	fs := sppjAudit(t, "/sppj/json/profile", nil)
	var f *Finding
	for _, x := range fs {
		if x.Name == IssueServerSidePrototypePollution {
			f = x
		}
	}
	if f == nil {
		var got []string
		for _, x := range fs {
			got = append(got, x.Name)
		}
		t.Fatalf("no server-side prototype pollution finding (got %v)", got)
	}
	if f.Confidence != "firm" || f.Severity != "high" {
		t.Errorf("confidence/severity %s/%s, want firm/high", f.Confidence, f.Severity)
	}
	if f.Param != "__proto__.json spaces" && f.Param != "__proto__.status" {
		t.Errorf("param %q, want the polluted property", f.Param)
	}
}

func TestServerSidePrototypePollutionStaysQuietOnTheSafeTwin(t *testing.T) {
	fs := sppjAudit(t, "/sppj/safe/json/profile", nil)
	for _, x := range fs {
		if x.Name == IssueServerSidePrototypePollution {
			t.Fatalf("safe twin reported: %s\n%s", x.Description, x.Evidence)
		}
	}
}

func TestServerSidePrototypePollutionIsOffWithoutItsSwitch(t *testing.T) {
	fs := sppjAudit(t, "/sppj/json/profile", func(c *ScanConfig) { c.CheckServerSidePrototypePollution = false })
	for _, x := range fs {
		if x.Name == IssueServerSidePrototypePollution {
			t.Fatalf("reported with the switch off: %s", x.Description)
		}
	}
}

// sppjWithProto merges only into a JSON object body.
func TestSppjWithProto(t *testing.T) {
	if got := sppjWithProto(`{"a":1}`, `{"json spaces":10}`); got != `{"a":1,"__proto__":{"json spaces":10}}` {
		t.Errorf("merge = %s", got)
	}
	if got := sppjWithProto("not json", `{}`); got != "" {
		t.Errorf("non-object body merged: %q", got)
	}
}
