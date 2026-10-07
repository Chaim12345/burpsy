package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"go.uber.org/zap"
)

// mustRule compiles a rule or fails the test — the rules under test are the point, so a compile
// error in one is a test bug, not a runtime condition worth threading through the assertions.
func mustRule(t *testing.T, target matchreplace.Target, cat matchreplace.Category, match, replace string) *matchreplace.Rule {
	t.Helper()
	r, err := matchreplace.NewRule(target, cat, match, replace, "")
	if err != nil {
		t.Fatalf("compiling rule (%v %q->%q): %v", target, match, replace, err)
	}
	return r
}

// TestProxyRewritesRequestAndResponseWireBytesViaMatchReplace proves the wiring this unit adds:
// a request-direction rule and a response-direction rule each rewrite the bytes that actually
// cross the wire, and the bytes recorded in history are those same rewritten bytes.
//
// It fails if any part of the wiring is removed. Drop WithMatchReplace from the proxy config and the
// field stays nil, so no rule fires and every assertion below fails. Delete the DirRequest Apply call
// and the three request-direction rules — first line, header, body — become no-ops again, which is the
// exact defect this unit fixes (only DirResponse was ever applied). The growing body rule also pins the
// Content-Length correction: the origin only reads the whole rewritten body if Content-Length was fixed
// to match it, the same fix the intercept forward path performs after a body edit.
func TestProxyRewritesRequestAndResponseWireBytesViaMatchReplace(t *testing.T) {
	// The origin reports back what it actually received, so the assertions are about the bytes that
	// reached upstream, not merely what the store chose to keep.
	var gotPath, gotSecret, gotBody string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotSecret = r.Header.Get("X-Secret")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		io.WriteString(w, "wrap RESP-ORIG wrap")
	}))
	defer origin.Close()

	thost, tportStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	tport, _ := strconv.Atoi(tportStr)

	rules := matchreplace.NewRuleSet()
	rules.SetRules([]*matchreplace.Rule{
		mustRule(t, matchreplace.TargetRequestFirstLine, matchreplace.CategoryLiteral, "/orig", "/rewritten"),
		mustRule(t, matchreplace.TargetRequestHeader, matchreplace.CategoryLiteral, "hunter2", "scrubbed"),
		mustRule(t, matchreplace.TargetRequestBody, matchreplace.CategoryLiteral, "REQ-IN", "REQ-OUT-GROWN"),
		mustRule(t, matchreplace.TargetResponseBody, matchreplace.CategoryLiteral, "RESP-ORIG", "RESP-PROXY-LONGER"),
	})
	// On, so a body rule that changes the body length has Content-Length recomputed — the operator's
	// "update content length" toggle. Without it the origin would read a truncated body below.
	rules.SetUpdateContentLength(true)

	store := core.NewTrafficStore()
	proxySrv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithMatchReplace(rules).
		WithLogger(zap.NewNop()))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxySrv.handleConnection(conn)
		}
	}()

	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
	}}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s:%d/orig", thost, tport), strings.NewReader("body REQ-IN body"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Secret", "hunter2")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	// Request direction: each of the three scopes reached the origin rewritten.
	if gotPath != "/rewritten" {
		t.Errorf("origin saw path %q, want /rewritten — the request_first_line rule did not reach the wire", gotPath)
	}
	if gotSecret != "scrubbed" {
		t.Errorf("origin saw X-Secret %q, want scrubbed — the request_header rule did not reach the wire", gotSecret)
	}
	if gotBody != "body REQ-OUT-GROWN body" {
		t.Errorf("origin saw body %q, want %q — the request_body rule or its Content-Length fix did not reach the wire",
			gotBody, "body REQ-OUT-GROWN body")
	}

	// Response direction: the client received the rewritten response.
	if !strings.Contains(string(respBody), "RESP-PROXY-LONGER") || strings.Contains(string(respBody), "RESP-ORIG") {
		t.Errorf("client received response body %q, want it to contain RESP-PROXY-LONGER and not RESP-ORIG", respBody)
	}

	// History must record the bytes actually sent, not the client's originals: captured == wire.
	ex := awaitExchange(t, store)
	storedReq, err := store.Get(core.MsgOrZero(ex.Request))
	if err != nil {
		t.Fatalf("stored request id does not resolve: %v", err)
	}
	reqBytes := string(storedReq.Raw())
	for _, want := range []string{"/rewritten", "X-Secret: scrubbed", "REQ-OUT-GROWN", "Content-Length: 23"} {
		if !strings.Contains(reqBytes, want) {
			t.Errorf("stored request is missing %q; it does not match the bytes sent upstream:\n%s", want, reqBytes)
		}
	}
	for _, unwanted := range []string{"/orig ", "hunter2", "body REQ-IN body"} {
		if strings.Contains(reqBytes, unwanted) {
			t.Errorf("stored request still contains the pre-rewrite %q; history disagrees with the wire:\n%s", unwanted, reqBytes)
		}
	}
	if ex.Response == nil {
		t.Fatal("recorded exchange has no response")
	}
	storedResp, err := store.Get(*ex.Response)
	if err != nil {
		t.Fatalf("stored response id does not resolve: %v", err)
	}
	if respBytes := string(storedResp.Raw()); !strings.Contains(respBytes, "RESP-PROXY-LONGER") {
		t.Errorf("stored response is missing the rewritten RESP-PROXY-LONGER; history disagrees with the wire:\n%s", respBytes)
	}
}
