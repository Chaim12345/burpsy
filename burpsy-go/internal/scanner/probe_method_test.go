package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// ---- a path probe must choose its method, not inherit the exchange's ---------------------
//
// `sendTestRequestFull` used to set `Method: exchange.Method`. Seven of its eleven call sites
// probe a *different* path from the captured exchange — /robots.txt, /trace.axd,
// /Default.aspx, backup-file candidates, a .burpsy-control-404 control, and the HTTP-PUT
// check's own read-back — and for those the captured method is irrelevant.
//
// So an API exercised through the proxy with POST produced `POST /robots.txt`, took the 405,
// and the check recorded "clean". A default-ON family reporting a clean result for a probe
// that was never meaningfully sent, which is this project's defining failure mode.
//
// These tests drive the real checks against a real listener and assert on the method the
// server actually observed, because that is the only thing that proves it.

// observedTarget records the method and path of every request it receives.
type observedTarget struct {
	mu   sync.Mutex
	seen []string // "METHOD path"
}

func (o *observedTarget) record(r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, r.Method+" "+r.URL.Path)
}

func (o *observedTarget) methodFor(path string) (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, line := range o.seen {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 && parts[1] == path {
			return parts[0], true
		}
	}
	return "", false
}

func (o *observedTarget) all() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.seen...)
}

// postExchangeAgainst seeds a captured POST exchange pointing at the given listener. POST is the
// point: it is what an operator testing a JSON API through the proxy actually has in history.
func postExchangeAgainst(t *testing.T, store *core.TrafficStore, host string, port uint16, path string) *core.Exchange {
	t.Helper()
	reqID, err := store.Put([]byte("POST "+path+" HTTP/1.1\r\nHost: "+host+"\r\nContent-Type: application/json\r\n\r\n{}"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{
		Request:  reqID,
		Response: &respID,
		Host:     host,
		Port:     port,
		Method:   "POST",
		Path:     path,
	}
	store.AddExchange(ex)
	return ex
}

// scannerAgainst stands up a listener that records what it is asked for, and returns a scanner
// wired to reach it plus a POST exchange to audit from.
func scannerAgainst(t *testing.T, handler func(*observedTarget, http.ResponseWriter, *http.Request)) (*ActiveScanner, *core.Exchange, *observedTarget) {
	t.Helper()
	obs := &observedTarget{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obs.record(r)
		handler(obs, w, r)
	}))
	t.Cleanup(srv.Close)

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	store := core.NewTrafficStore()
	ex := postExchangeAgainst(t, store, host, port, "/api/orders")
	scan := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(nil))
	return scan, ex, obs
}

// The defect, driven end to end. A POST exchange must still probe /robots.txt with GET.
func TestRobotsProbeUsesGETNotTheExchangeMethod(t *testing.T) {
	scan, ex, obs := scannerAgainst(t, func(_ *observedTarget, w http.ResponseWriter, r *http.Request) {
		// A realistic server: the well-known file is readable, but only by GET.
		if r.URL.Path == "/robots.txt" && r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/robots.txt" {
			fmt.Fprint(w, "User-agent: *\nDisallow: /admin\n")
			return
		}
		fmt.Fprint(w, "{}")
	})

	if _, err := checkRobotsTxtFile(context.Background(), NewCheckContext(scan, ex, nil)); err != nil {
		t.Fatalf("checkRobotsTxtFile: %v", err)
	}

	method, sent := obs.methodFor("/robots.txt")
	if !sent {
		t.Fatalf("no probe reached /robots.txt at all; observed: %v", obs.all())
	}
	if method == "POST" {
		t.Fatalf("the probe inherited the exchange's POST — this is the defect. A server that "+
			"serves robots.txt only by GET answers 405 and the check records \"clean\". Observed: %v",
			obs.all())
	}
	if method != "GET" {
		t.Errorf("probe method = %q, want GET; observed: %v", method, obs.all())
	}
}

// The same for the ASP.NET trace handler, which is a second default-ON discovery probe at a
// path unrelated to the exchange. Two independent checks share the primitive, so pinning one
// does not pin the other.
func TestTraceAxdProbeUsesGETNotTheExchangeMethod(t *testing.T) {
	scan, ex, obs := scannerAgainst(t, func(_ *observedTarget, w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		fmt.Fprint(w, "<span>trace</span>")
	})

	if _, err := checkASPTracingEnabled(context.Background(), NewCheckContext(scan, ex, nil)); err != nil {
		t.Fatalf("checkASPTracingEnabled: %v", err)
	}

	method, sent := obs.methodFor("/trace.axd")
	if !sent {
		t.Fatalf("no probe reached /trace.axd; observed: %v", obs.all())
	}
	if method != "GET" {
		t.Fatalf("probe method = %q, want GET — a discovery probe at an unrelated path must "+
			"choose its method; observed: %v", method, obs.all())
	}
}

// The other half of the contract, and the reason this was not a one-line change.
//
// Four call sites re-send *this* request with one header altered — mobile-user-agent content
// differences, Referer handling, code-injection headers. Those must keep the exchange's own
// method, or the probe stops being a comparison against the captured response and the check
// compares a POST body to a GET body.
//
// Without this test, "always GET" would pass every assertion above while silently breaking
// four checks.
func TestSamePathHeaderProbesKeepTheExchangeMethod(t *testing.T) {
	scan, ex, obs := scannerAgainst(t, func(_ *observedTarget, w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>desktop layout</body></html>")
	})

	// checkUserAgentDependentResponse re-requests the exchange's own path with a mobile UA.
	if _, err := checkUserAgentDependentResponse(context.Background(), NewCheckContext(scan, ex, nil)); err != nil {
		t.Fatalf("checkUserAgentDependentResponse: %v", err)
	}

	method, sent := obs.methodFor("/api/orders")
	if !sent {
		t.Skipf("the check did not probe the exchange's own path in this configuration; observed: %v", obs.all())
	}
	if method != "POST" {
		t.Fatalf("same-path header probe used %q, want POST (the exchange's own method). A probe "+
			"that re-sends this request with one header changed must not change the method too, or "+
			"it is comparing two different requests; observed: %v", method, obs.all())
	}
}

// Belt and braces on the split itself: no probe should ever arrive at a well-known discovery
// path using the exchange's method, whatever the check. This is the invariant, stated once.
func TestNoDiscoveryPathIsProbedWithTheExchangeMethod(t *testing.T) {
	scan, ex, obs := scannerAgainst(t, func(_ *observedTarget, w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	ctx := NewCheckContext(scan, ex, nil)

	for name, run := range map[string]func(context.Context, *CheckContext) ([]*Finding, error){
		"robots":     checkRobotsTxtFile,
		"trace.axd":  checkASPTracingEnabled,
		"aspdebug":   checkASPDebuggingEnabled,
		"openapidef": checkOpenAPIDefinitionFound,
	} {
		if _, err := run(context.Background(), ctx); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	for _, line := range obs.all() {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		method, path := parts[0], parts[1]
		if path == ex.Path {
			continue // same-path probes legitimately inherit; covered above
		}
		if method == "POST" {
			t.Errorf("%s was probed with POST, inherited from the exchange; a probe at a path the "+
				"exchange never used must choose its own method", path)
		}
	}
}
