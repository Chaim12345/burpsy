package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// The deferred phase runs under the audit's run configuration (burpsy-react-ui-saq3.3.4), through the real
// audit route with a stored claim registered. Its re-fetch goes out through the run's derived sender,
// and its render pass refuses the browser when the run set use_dynamic_analysis false.

// countingBrowsers records whether anything asked for the browser. It never provides one.
type countingBrowsers struct{ asked atomic.Int64 }

func (b *countingBrowsers) Browser(context.Context) (*domexec.Browser, error) {
	b.asked.Add(1)
	return nil, errors.New("no browser in this test")
}
func (b *countingBrowsers) Close() error { return nil }

type deferredReply struct {
	Deferred struct {
		Refetch struct {
			Candidates, Refetched, Failed int
		}
		RefetchError string
		Render       struct {
			Declined      string
			DeclinedByRun int
		}
		RenderError string
	} `json:"deferred"`
}

// auditWithDeferred seeds the stored-XSS pair, audits the planting exchange under cfg, and returns the
// deferred block. The listing page answers slowly only on its second and later fetches, which are the
// deferred phase's re-fetch, so a run timeout shorter than that delay is visible as a failed re-fetch.
func auditWithDeferred(t *testing.T, override string) (deferredReply, *countingBrowsers) {
	t.Helper()
	var listings atomic.Int64
	app := vulnapp.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/comments" && listings.Add(1) > 1 {
			time.Sleep(2500 * time.Millisecond)
		}
		app.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	host, portStr, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	port, _ := strconv.ParseUint(portStr, 10, 16)

	store := core.NewTrafficStore()
	var commentID core.ExchangeID
	for _, path := range []string{"/comment?comment=hello", "/comments"} {
		res, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()
		reqID, _ := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
		respID, _ := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(raw))+"\r\n\r\n"+string(raw)), core.DirectionResponse)
		ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: uint16(port), Method: "GET", Path: path}
		store.AddExchange(ex)
		if path == "/comment?comment=hello" {
			commentID = ex.ID
		}
	}

	cfg := scanner.DefaultAuditConfig()
	if override != "" {
		var err error
		if cfg, _, err = scanner.ApplyBurpConfigFile(cfg, []byte(override)); err != nil {
			t.Fatal(err)
		}
	}
	// The fake browser fails every DOM check, and Burp's default breaker abandons a dispatch unit after
	// two consecutive failures, which would gate the stored check out before it plants anything.
	cfg.ConsecutiveCheckFailuresToAbandonUnit = 1000
	cfg.ConsecutiveUnitFailuresToFailItem = 1000
	browsers := &countingBrowsers{}
	active := scanner.NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithStoredLedger(scanner.NewStoredLedger()).
		WithBrowserProvider(browsers).
		WithConfig(&scanner.ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, CheckStored: true, CheckDOM: true,
			PendingDeadline: 2 * time.Second}).
		WithAuditConfig(cfg)
	s := NewServer(store, core.NewScope()).WithScanner(active)

	rec := postJSON(t, s, "/api/audit/"+strconv.FormatUint(uint64(commentID), 10), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit = %d: %s", rec.Code, rec.Body.String())
	}
	var out deferredReply
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), `"deferred"`) {
		t.Fatalf("no deferred phase ran: the stored claim was not registered: %s", rec.Body.String())
	}
	return out, browsers
}

func Test_the_deferred_phase_runs_under_the_audits_run_configuration(t *testing.T) {
	// Engagement settings: the slow listing is re-fetched, and the render pass asks for the browser.
	base, baseBrowsers := auditWithDeferred(t, "")
	if base.Deferred.Refetch.Failed != 0 || base.Deferred.Refetch.Refetched == 0 {
		t.Fatalf("control: under the engagement's timeouts the re-fetch should succeed: %+v", base.Deferred.Refetch)
	}
	if baseBrowsers.asked.Load() == 0 {
		t.Fatal("control: with dynamic analysis on, the render pass did not ask for the browser")
	}

	// The run's own normal_timeout (1 s) is shorter than the listing's delay, and its dynamic analysis is off.
	run, runBrowsers := auditWithDeferred(t,
		`{"scanner":{"audit_project_option_overrides":{"normal_timeout":1},"javascript_analysis":{"use_dynamic_analysis":false}}}`)
	if run.Deferred.Refetch.Failed == 0 {
		t.Errorf("the re-fetch ignored the run's 1 s timeout and waited out a 2.5 s page: %+v", run.Deferred.Refetch)
	}
	if n := runBrowsers.asked.Load(); n != 0 {
		t.Errorf("the deferred phase asked for the browser %d time(s) in a run with use_dynamic_analysis false", n)
	}
	if !strings.Contains(run.Deferred.Render.Declined, "use_dynamic_analysis") || run.Deferred.RenderError != "" {
		t.Errorf("render pass not declined by the run: %+v / %q", run.Deferred.Render, run.Deferred.RenderError)
	}
}
