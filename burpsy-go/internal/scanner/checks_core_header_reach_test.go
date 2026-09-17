package scanner

// The reflected-XSS row must probe header insertion points.
//
// # The defect this pins
//
// The three core rows (SQL injection, reflected XSS, file path traversal) named their own
// insertion-point literal — `[]string{"query","body","cookie"}` — instead of asking the check
// context. Two consequences, both real:
//
//  1. No `header`. A value reflected out of an HTTP header is unreachable by the reflected-XSS
//     row no matter what the target does, because no probe is ever sent into a header.
//     cmd/xsschallenge's `/x/header` case (User-Agent reflected into the body) is exactly this,
//     and it is the `hvez` gap.
//  2. The operator's `scanner/insertion_point_types/*` configuration was ignored by those three
//     rows while every other probe site honoured it — turning cookie insertion off changed what
//     the queue displayed and not one byte of what these rows sent.
//
// The existing source guard (`TestNoCheckSiteHardcodesTheInsertionKinds`) could not catch it: it
// greps for `DefaultProbeInsertionKinds`, and the literal these rows used had a different name.
// So this test is behavioural on purpose — it asserts the OBSERVABLE outcome (a finding) that a
// check ignoring header points cannot produce.
//
// # Why the header is the discriminator
//
// The request below carries no query parameter and no body. Its only insertion point is the
// header. Before the fix the harness enumerated zero points and the row returned no finding; the
// test fails. After the fix the header point is enumerated and the row reports. It is not
// possible to pass this by accident.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// headerOnlyXSSContext seeds an exchange whose only insertion point is a header, against a server
// that reflects that header into the body with no escaping.
func headerOnlyXSSContext(t *testing.T) *CheckContext {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<p>your browser: %s</p>", r.Header.Get("X-Reflect"))
	}))
	t.Cleanup(srv.Close)

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	store := core.NewTrafficStore()
	// No query string, no body. X-Reflect is the only thing a probe can be placed in.
	rawReq := fmt.Sprintf("GET /echo HTTP/1.1\r\nHost: %s:%d\r\nX-Reflect: benign\r\n\r\n", host, port)
	reqID, err := store.Put([]byte(rawReq), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nseed"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: host, Port: port,
		TLS: false, Method: "GET", Path: "/echo"}
	store.AddExchange(ex)

	s := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(nil))
	return NewCheckContext(s, ex, nil)
}

// A reflection that reaches the body through a request header is a reflected XSS, and the row
// must find it. This is the header-reach claim, stated as an outcome.
func TestReflectedXSSFindsAReflectionInARequestHeader(t *testing.T) {
	cc := headerOnlyXSSContext(t)

	findings, err := checkReflectedXSSCore(context.Background(), cc)
	if err != nil {
		t.Fatalf("checkReflectedXSSCore: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("no finding for a value reflected unescaped out of a request header; the row " +
			"did not probe the header insertion point, so a header-borne reflection is unreachable")
	}

	f := findings[0]
	if f.Name != xssReflectedIssue {
		t.Errorf("finding name = %q, want %q", f.Name, xssReflectedIssue)
	}
	// The finding has to say which point it came from, or it is a rumour rather than a finding.
	if !strings.Contains(f.Description, "X-Reflect") {
		t.Errorf("finding does not name the header it came from: %q", f.Description)
	}
}

// The count the row reports must not claim to have tested points it never probed. A request with
// more points than the per-check cap has to say so in the finding text, or the coverage line
// reads as a smaller endpoint than it is.
func TestACappedRowSaysHowManyPointsItDidNotProbe(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<p>nothing reflected</p>")
	}))
	t.Cleanup(srv.Close)

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	// More query parameters than MaxInjectionPointsPerCheck, so the cap bites.
	var q strings.Builder
	for i := 0; i < MaxInjectionPointsPerCheck+4; i++ {
		if i > 0 {
			q.WriteByte('&')
		}
		fmt.Fprintf(&q, "p%d=v", i)
	}
	path := "/many?" + q.String()

	store := core.NewTrafficStore()
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s:%d\r\n\r\n", path, host, port)
	reqID, err := store.Put([]byte(rawReq), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nseed"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: host, Port: port,
		TLS: false, Method: "GET", Path: path}
	store.AddExchange(ex)

	s := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(nil))
	cc := NewCheckContext(s, ex, nil)

	// runInjection is what every injection row uses, so its coverage is the row's coverage.
	res, err := runInjection(context.Background(), cc, cc.ProbeInsertionKinds(),
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe { return nil })
	if err != nil {
		t.Fatalf("runInjection: %v", err)
	}
	if res.coverage.PointsCapped == 0 {
		t.Fatalf("coverage says nothing was capped for a request with %d points and a cap of %d; "+
			"a truncated run must report the truncation", MaxInjectionPointsPerCheck+4,
			MaxInjectionPointsPerCheck)
	}
}
