package scanner

// The header-dependence rows compared unlike things and so could never return a negative.
//
// `responseRaw` is the full stored message — status line, headers, body — and the probe side was
// `resp.Body`. `responsesDiffer` was therefore true for every endpoint that has ever been scanned,
// and both rows fired unconditionally. Nothing caught it because a check that always fires looks
// exactly like a check that works, until you point it at something that is not vulnerable.
//
// These tests are the negative case, which is the one that was missing.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// dependenceFixture captures the handler's REAL response into the store.
//
// harnessAgainst cannot be used here. It stores a fixed `HTTP/1.1 200 OK\r\n\r\nseed`, which is fine
// for checks that fetch their own baseline through NewProbeHarness but wrong for these two: they
// read the STORED response as the baseline, so a fixture whose stored body never matches the live
// one makes every response look header-dependent — the fixture would manufacture the very defect
// under test and pass either way.
func dependenceFixture(t *testing.T, handler http.HandlerFunc, path string) *CheckContext {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	res, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatalf("capture baseline: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	_ = res.Body.Close()

	store := core.NewTrafficStore()
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s:%d\r\n\r\n", path, host, port)
	reqID, err := store.Put([]byte(rawReq), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	respID, err := store.Put([]byte(rawResp), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: host, Port: uint16(port),
		TLS: false, Method: "GET", Path: path}
	store.AddExchange(ex)

	s := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(nil))
	return NewCheckContext(s, ex, nil)
}

// A response that ignores the header entirely must not be reported as depending on it.
func TestAnEndpointThatIgnoresTheUserAgentIsNotReportedAsDependingOnIt(t *testing.T) {
	cc := dependenceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		// Byte-identical whatever arrives.
		fmt.Fprint(w, "<html><body>same for everyone</body></html>")
	}, "/page")
	got, err := checkUserAgentDependentResponse(t.Context(), cc)
	if err != nil {
		t.Fatalf("checkUserAgentDependentResponse: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d findings against a response that is identical for every User-Agent, want 0. "+
			"This is the case the row exists to exclude, and it fired anyway: %s", len(got), describeFindings(got))
	}
}

func TestAnEndpointThatIgnoresTheRefererIsNotReportedAsDependingOnIt(t *testing.T) {
	cc := dependenceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>same for everyone</body></html>")
	}, "/page")
	got, err := checkRefererDependentResponse(t.Context(), cc)
	if err != nil {
		t.Fatalf("checkRefererDependentResponse: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d findings against a response that is identical for every Referer, want 0: %s",
			len(got), describeFindings(got))
	}
}

// The positive case, so the fix cannot be "always return nothing".
func TestAnEndpointThatVariesByUserAgentIsReported(t *testing.T) {
	cc := dependenceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != "" && indexFold(ua, "Mobile") >= 0 {
			fmt.Fprint(w, "<html><body>mobile layout</body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>desktop layout</body></html>")
	}, "/page")
	got, err := checkUserAgentDependentResponse(t.Context(), cc)
	if err != nil {
		t.Fatalf("checkUserAgentDependentResponse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings against a server that genuinely serves a different body to a "+
			"mobile User-Agent, want 1", len(got))
	}
}

func TestAnEndpointThatVariesByRefererIsReported(t *testing.T) {
	cc := dependenceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Referer") != "" {
			fmt.Fprint(w, "<html><body>welcome back</body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>hello stranger</body></html>")
	}, "/page")
	got, err := checkRefererDependentResponse(t.Context(), cc)
	if err != nil {
		t.Fatalf("checkRefererDependentResponse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings against a server that genuinely varies on Referer, want 1", len(got))
	}
}
