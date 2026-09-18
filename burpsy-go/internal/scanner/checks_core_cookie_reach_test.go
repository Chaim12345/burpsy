package scanner

// The reflected-XSS row must probe cookie insertion points.
//
// # What this pins, and why it is separate from the header test
//
// cmd/xsschallenge's `cookie-pref` case is one of the two endpoints that still miss. Its seed is a
// bare GET carrying exactly one thing a probe can be placed in: `Cookie: pref=hello`. The handler
// reflects that cookie into a text node with no escaping, so a canary sent in the cookie comes back
// in the body and the row's own text-node payload should confirm it.
//
// The header twin (checks_core_header_reach_test.go) was written for the same reason and found a
// real defect: the three core rows hardcoded `{"query","body","cookie"}` and never probed a
// header. This test exists to answer the matching question for cookies, which is NOT answered by
// that test - a row can enumerate headers correctly and still never send anything into a cookie.
//
// The test reports the enumerated points as well as the outcome, so a failure says which half is
// wrong: enumeration (no cookie point) or confirmation (point probed, no finding).

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// cookieOnlyXSSContext seeds the exchange cmd/xsschallenge's `cookie-pref` case seeds: a GET whose
// only insertion point is a cookie, against a server that reflects that cookie into a text node.
func cookieOnlyXSSContext(t *testing.T) *CheckContext {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := ""
		if c, err := r.Cookie("pref"); err == nil {
			v = c.Value
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<p>preference: %s</p>", v)
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
	// Mirrors cmd/xsschallenge's seedOne for a case with param == "": no query string, no body,
	// one Cookie header. The User-Agent line is present because the challenge writes one on every
	// seed, so the request is not artificially reduced to a single point.
	rawReq := fmt.Sprintf("GET /x/cookie HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: Mozilla/5.0 (challenge)\r\nCookie: pref=hello\r\n\r\n", host, port)
	reqID, err := store.Put([]byte(rawReq), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nseed"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: host, Port: port,
		TLS: false, Method: "GET", Path: "/x/cookie"}
	store.AddExchange(ex)

	s := NewActiveScanner(store, zap.NewNop()).WithSender(sender.NewSender(nil))
	return NewCheckContext(s, ex, nil)
}

// A reflection that reaches the body through a request cookie is a reflected XSS, and the row must
// find it. This is the cookie-reach claim, stated as an outcome.
func TestReflectedXSSFindsAReflectionInARequestCookie(t *testing.T) {
	cc := cookieOnlyXSSContext(t)

	h, err := NewProbeHarness(context.Background(), cc, cc.ProbeInsertionKinds())
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	var names []string
	sawCookie := false
	for _, p := range h.Points() {
		names = append(names, string(p.Kind)+":"+p.Name)
		if string(p.Kind) == "cookie" && p.Name == "pref" {
			sawCookie = true
		}
	}
	t.Logf("enumerated insertion points: %v", names)

	findings, err := checkReflectedXSSCore(context.Background(), cc)
	if err != nil {
		t.Fatalf("checkReflectedXSSCore: %v", err)
	}
	if !sawCookie {
		t.Fatalf("the harness enumerated %v for a request whose only point is `Cookie: pref=hello`; "+
			"the cookie point was not offered, so no cookie-borne reflection is reachable and the "+
			"failure below is an enumeration failure, not a confirmation one", names)
	}
	if len(findings) == 0 {
		t.Fatalf("the cookie point WAS enumerated (%v) but the row reported nothing for a cookie "+
			"reflected unescaped into a text node; the failure is in the probe or the confirm, not "+
			"in enumeration", names)
	}

	f := findings[0]
	if f.Name != xssReflectedIssue {
		t.Errorf("finding name = %q, want %q", f.Name, xssReflectedIssue)
	}
	if !strings.Contains(f.Description, "pref") {
		t.Errorf("finding does not name the cookie it came from: %q", f.Description)
	}
}
