package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"go.uber.org/zap"
)

// History's "Edited" column, end to end through the proxy (burpsy-react-ui-sd0d). The flag is Burp's
// `ProxyHttpRequestResponse.edited()`: the request or response was edited *by the user* — the operator
// at the hold — and by nobody else.
//
// These tests live here rather than in internal/intercept because the defect they guard was not in the
// engine's arithmetic but in what the proxy recorded. An earlier rule derived the column from the
// recorded bytes differing from an earlier stage of themselves, which is a question about *what
// changed*; the column asks *who changed it*. burpsy rewrites traffic after the hold — it strips the
// Proxy-* header family and can force `Connection: close` — so the two questions have different
// answers on ordinary traffic, and every one of those rows used to read "Edited".

// operatorEngine is a hold queue that holds every request, with the operator loop the returned
// function runs: each held request is handed to `edit`, which returns the buffer the operator forwards
// (nil to forward the held bytes untouched).
func operatorEngine(t *testing.T, edit func(raw string) *string) *intercept.Engine {
	t.Helper()
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	// An empty rule list on an active list is Burp's "intercept everything".
	if err := engine.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	go func() {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			for _, held := range engine.Held() {
				if held.Direction != intercept.DirectionRequest {
					continue
				}
				// fixContentLength on, which is the Intercept page's default and the setting that
				// makes the "held buffer versus wire bytes" comparison interesting: it can rewrite a
				// message the operator did not touch.
				_ = engine.Forward(held.ID, edit(string(held.Raw)), true, nil)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	return engine
}

// The operator retypes part of the request. That is the whole of what the column is for, and the row
// must say so.
func TestAnOperatorsHoldEditMarksTheRecordedRowEdited(t *testing.T) {
	var originSaw string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originSaw = r.Header.Get("X-Marker")
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	host, port := originHostPort(t, origin)

	engine := operatorEngine(t, func(raw string) *string {
		edited := strings.Replace(raw, "as-sent", "as-edited", 1)
		return &edited
	})
	store := core.NewTrafficStore()
	proxyAddr := startProxy(t, NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithIntercept(engine).
		WithLogger(zap.NewNop())))

	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
	}}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:%d/one", host, port), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Marker", "as-sent")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if originSaw != "as-edited" {
		t.Fatalf("the origin received X-Marker %q, want the operator's edit; the hold did not take effect", originSaw)
	}
	ex := awaitExchangeFor(t, store, "/one", "proxy")
	if !ex.UserEdited {
		t.Error("the operator edited the request in Intercept and the row does not say so; the history column would never fire")
	}
}

// The row the fix is about, and it is deliberately the *harder* case to get wrong rather than the
// simplest one: the operator forwards the bytes they were shown, unchanged, and burpsy then rewrites
// that request twice on its way out — dropping the Proxy-Connection header the egress option removes
// and adding `Connection: close` because that knob is on.
//
// So this row contains bytes the client never sent and bytes the operator never typed, and it is not
// "Edited". The assertion on the recorded message is what makes that a fact rather than an assumption:
// without it, a version of the proxy that simply stopped rewriting anything would pass.
func TestBurbysOwnRequestRewritesDoNotMarkTheRowEdited(t *testing.T) {
	received := make(chan string, 1)
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	defer origin.Close()
	go func() {
		conn, err := origin.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		_ = conn.Close()
	}()

	// The operator forwards every held request exactly as it arrived: a pointer to the held bytes, so
	// "edited" is false by the engine's own comparison and the only changes left are burpsy's.
	engine := operatorEngine(t, func(raw string) *string { return &raw })

	cfg := NewProxyConfig(core.NewTrafficStore()).WithScope(testScope()).WithIntercept(engine).WithLogger(zap.NewNop())
	if err := cfg.options.Set(OptSetConnectionClose, true); err != nil {
		t.Fatalf("Set %s: %v", OptSetConnectionClose, err)
	}
	store := cfg.store
	proxyAddr := startProxy(t, NewServer(cfg))

	// A raw client, because the two headers this test turns on have to be chosen byte for byte: Go's
	// transport decides its own Connection and Proxy-Connection, and the point is a request that
	// carries a Proxy-* header and no Connection at all.
	const sent = "GET /target HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n"
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, sent, origin.Addr().String()); err != nil {
		t.Fatalf("write request: %v", err)
	}
	buf := make([]byte, 4096)
	_, _ = conn.Read(buf)

	got := <-received
	if strings.Contains(got, "Proxy-Connection") {
		t.Fatal("the origin received the Proxy-Connection header, so the strip option never ran and this test would assert nothing about burpsy's own rewrites")
	}
	if !strings.Contains(strings.ToLower(got), "connection: close") {
		t.Fatalf("the origin's request has no `Connection: close`, so the knob never ran; origin received:\n%s", got)
	}

	ex := awaitExchangeFor(t, store, "/target", "proxy")
	recorded := messageText(t, store, core.MsgOrZero(ex.Request))
	if recorded == fmt.Sprintf(sent, origin.Addr().String()) {
		t.Fatalf("the recorded request is byte-for-byte what the client sent, so nothing was rewritten and the flag assertion below would pass vacuously:\n%s", recorded)
	}
	if ex.UserEdited {
		t.Errorf("burpsy stripped a header and forced Connection: close on a request the operator did not touch, and the row is marked Edited; that is the false badge this flag was fixed to stop producing. Recorded request:\n%s", recorded)
	}
}
