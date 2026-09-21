package web

// The live sweep's passive pass (burpsy-react-ui-v7fo), driven end-to-end: a captured
// cleartext-password form surfaces as a POSTURE finding the moment the sweep admits the
// traffic — before any audit session runs — and the count on the state and view is the
// honest metric the bead names. What these tests pin:
//
//   - a passive-family capture produces a stored finding through the sweep's own pass, and
//     the passiveFindings counter on the state moves with it;
//   - the active session that follows merges into the SAME stored finding (one finding,
//     both passes' evidence), not a duplicate — the store's identity merge is the contract
//     that keeps the counts single;
//   - the view carries passive_findings beside the active findings.
import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// passiveFormOrigin serves a login form that submits over cleartext http — the capture the
// posture families read.
func passiveFormOrigin(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<form action="http://` + r.Host + `/login" method="POST"><input type="text" name="user"><input type="password" name="password"></form>`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestTheSweepRunsPassiveChecksOnCapturedTraffic(t *testing.T) {
	srv, _ := passiveFormOrigin(t)
	host, port := targetHostPort(t, srv.URL)
	s := auditableServer(t, srv.URL)

	// A completed in-scope proxied capture of the form page.
	reqID, _ := s.store.Put([]byte("GET /login HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	respID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<form action=\"http://"+host+"/login\" method=\"POST\"><input type=\"password\" name=\"password\"></form>"), core.DirectionResponse)
	s.store.AddExchange(&core.Exchange{
		Request: reqID, Response: &respID, Host: host, Port: port, Method: "GET", Path: "/login",
		Source: core.SourceProxy,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && s.liveAudit.PassiveFindings() == 0 {
		time.Sleep(sweepTick)
	}
	if got := s.liveAudit.PassiveFindings(); got == 0 {
		t.Fatal("the sweep's passive pass produced nothing for a cleartext password form — the live passive audit is not running on captured traffic")
	}
	view := s.liveAuditStatus()
	if view.PassiveFindings == 0 {
		t.Error("the view hides the passive count")
	}
}

func TestTheActiveSessionMergesIntoTheSweepPassiveFinding(t *testing.T) {
	// The single-finding contract: the sweep's passive pass adds the finding; a later
	// AuditSession over the same exchange — whose own passive row raises the same finding
	// identity — merges into it. One finding, both passes.
	store := core.NewTrafficStore()
	findingStore := core.NewFindingStore()
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<form action=\"http://app.test/login\" method=\"POST\"><input type=\"password\" name=\"password\"></form>"
	reqID, _ := store.Put([]byte("GET /login HTTP/1.1\r\nHost: app.test\r\n\r\n"), core.DirectionRequest)
	respID, _ := store.Put([]byte(rawResp), core.DirectionResponse)
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: "app.test", Port: 80, Method: "GET", Path: "/login"}
	store.AddExchange(ex)

	scan := scanner.NewActiveScanner(store, zap.NewNop()).WithConfig(&scanner.ScanConfig{MaxConcurrency: 1, CheckPassivePosture: true, CheckPassiveAnalysis: true})
	target := core.FindingTarget{Host: "app.test", Port: 80, TLS: false, Path: "/login"}

	// The sweep's passive pass (the same shape liveaudit.go builds):
	passive := scan.RunPassiveChecks(context.Background(), ex)
	if len(passive) == 0 {
		t.Fatal("control: the passive pass found nothing to add")
	}
	// The sweep's door: the same core.NewFinding shape liveaudit.go builds, with the
	// occurrence citing the captured exchange — the merge key.
	for _, f := range passive {
		findingStore.Add(core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Remediation: f.Solution,
			Param:       f.Param,
			Target:      target,
			Occurrences: []core.Occurrence{{ExchangeID: ex.ID, Request: ex.Request, Response: ex.Response}},
		})
	}
	before := len(findingStore.All())

	// The audit session's own passive row raises the same identity, through the same door:
	_, sessionFindings := scan.AuditSession(context.Background(), []core.ExchangeID{ex.ID}, scanner.DefaultAuditConfig())
	for _, f := range sessionFindings {
		if f == nil {
			continue
		}
		findingStore.Add(core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Remediation: f.Solution,
			Param:       f.Param,
			Target:      target,
			Occurrences: []core.Occurrence{{ExchangeID: ex.ID, Request: ex.Request, Response: ex.Response}},
		})
	}
	after := len(findingStore.All())
	if after != before {
		t.Fatalf("the audit session added %d NEW finding(s) instead of merging into the sweep's passive finding — the count would be double", after-before)
	}
}
