package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
)

// traffic_hook_test.go pins the extension traffic seam (burpsy-react-ui-wiwh):
// unwired is byte-for-byte nothing, a replacement flows, a drop mirrors the
// operator's own, a forced intercept holds and a DoNotIntercept passes, and a
// panicking hook fails open. Each behaviour goes through a real listener, not
// only the seam helper, because the wiring is the feature.

type trafficHookStub func(ctx context.Context, phase string, raw []byte) TrafficHookResult

func (f trafficHookStub) HookTraffic(ctx context.Context, phase string, raw []byte) TrafficHookResult {
	return f(ctx, phase, raw)
}

func hookClient(proxyAddr string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		DisableKeepAlives: true,
	}, Timeout: 8 * time.Second}
}

func TestTrafficHookUnwiredLeavesBytesUntouched(t *testing.T) {
	cfg := NewProxyConfig(core.NewTrafficStore())
	srv := NewServer(cfg)
	raw := []byte("GET /a?b=c HTTP/1.1\r\nHost: example\r\n\r\n")
	res := srv.applyTrafficHook(context.Background(), "request", raw)
	if string(res.Raw) != string(raw) || res.Changed || res.Dropped || res.Intercept != nil {
		t.Fatalf("unwired hook altered the message: %+v", res)
	}
	if c := cfg.TrafficHookCounts(); c != (TrafficHookCounts{}) {
		t.Fatalf("unwired hook counted calls: %+v", c)
	}
}

func TestTrafficHookReplacementFlowsThroughProxy(t *testing.T) {
	var sawHeader atomic.Bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Hook-Added") == "yes" {
			sawHeader.Store(true)
		}
		_, _ = io.WriteString(w, "origin-body")
	}))
	defer origin.Close()

	hook := trafficHookStub(func(_ context.Context, phase string, raw []byte) TrafficHookResult {
		if phase == "request" {
			return TrafficHookResult{
				Raw:     []byte(strings.Replace(string(raw), "\r\n\r\n", "\r\nX-Hook-Added: yes\r\n\r\n", 1)),
				Changed: true, Applied: []string{"stub"},
			}
		}
		return TrafficHookResult{
			Raw:     []byte(strings.Replace(string(raw), "origin-body", "hooked-body", 1)),
			Changed: true, Applied: []string{"stub"},
		}
	})
	cfg := NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithTrafficHook(hook)
	proxyAddr := startProxy(t, NewServer(cfg))

	resp, err := hookClient(proxyAddr).Get(strings.Replace(origin.URL, "http://", "http://", 1))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !sawHeader.Load() {
		t.Fatal("origin never saw the hook-added request header")
	}
	if !strings.Contains(string(body), "hooked-body") {
		t.Fatalf("client did not receive the hook's response bytes: %q", body)
	}
	c := cfg.TrafficHookCounts()
	if c.Calls != 2 || c.Changed != 2 || c.Dropped != 0 || c.Failures != 0 {
		t.Fatalf("counts: %+v", c)
	}
}

func TestTrafficHookDropRequestClosesSilentlyAndReachesNoOrigin(t *testing.T) {
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	hook := trafficHookStub(func(_ context.Context, phase string, raw []byte) TrafficHookResult {
		if phase == "request" {
			return TrafficHookResult{Raw: raw, Dropped: true, Applied: []string{"stub"}}
		}
		return TrafficHookResult{Raw: raw}
	})
	cfg := NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithTrafficHook(hook)
	proxyAddr := startProxy(t, NewServer(cfg))

	resp, err := hookClient(proxyAddr).Get(origin.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("a request drop must close the connection without a byte - Burp drop semantics, the request vanishes; got status %d", resp.StatusCode)
	}
	if originHits.Load() != 0 {
		t.Fatalf("dropped request reached the origin %d times", originHits.Load())
	}
	if c := cfg.TrafficHookCounts(); c.Dropped != 1 {
		t.Fatalf("counts: %+v", c)
	}
}

func TestTrafficHookDropResponseServesNothing(t *testing.T) {
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		_, _ = io.WriteString(w, "origin-body")
	}))
	defer origin.Close()

	hook := trafficHookStub(func(_ context.Context, phase string, raw []byte) TrafficHookResult {
		if phase == "response" {
			return TrafficHookResult{Raw: raw, Dropped: true, Applied: []string{"stub"}}
		}
		return TrafficHookResult{Raw: raw}
	})
	cfg := NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithTrafficHook(hook)
	proxyAddr := startProxy(t, NewServer(cfg))

	resp, err := hookClient(proxyAddr).Get(origin.URL)
	var body []byte
	if err == nil {
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if err == nil && strings.Contains(string(body), "origin-body") {
		t.Fatalf("dropped response reached the client: %q", body)
	}
	if originHits.Load() != 1 {
		t.Fatalf("the request must still reach the origin; only its answer is dropped: %d", originHits.Load())
	}
	if c := cfg.TrafficHookCounts(); c.Dropped != 1 {
		t.Fatalf("counts: %+v", c)
	}
}

func TestTrafficHookForcedInterceptHoldsWithoutRules(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	// The engine is enabled but holds nothing on its own: only the hook's forced
	// decision can produce a hold here.
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	yes := true
	hook := trafficHookStub(func(_ context.Context, phase string, raw []byte) TrafficHookResult {
		if phase == "request" {
			return TrafficHookResult{Raw: raw, Intercept: &yes, Applied: []string{"stub"}}
		}
		return TrafficHookResult{Raw: raw}
	})
	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithIntercept(engine).
		WithTrafficHook(hook))
	proxyAddr := startProxy(t, srv)

	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := hookClient(proxyAddr).Get(origin.URL)
		if err == nil {
			resp.Body.Close()
			done <- result{resp.StatusCode, nil}
			return
		}
		done <- result{0, err}
	}()

	var heldID uint64
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		for _, h := range engine.Held() {
			if h.Direction == intercept.DirectionRequest {
				heldID = h.ID
			}
		}
		if heldID != 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if heldID == 0 {
		t.Fatal("the hook forced an intercept and nothing was held")
	}
	if err := engine.Forward(heldID, nil, false, nil); err != nil {
		t.Fatalf("forward: %v", err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.code != http.StatusOK {
			t.Fatalf("forwarded exchange: %+v", r)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("client never saw the response after the forced hold was forwarded")
	}
}

func TestTrafficHookDoNotInterceptSkipsTheHold(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	// Intercept-everything, which the hook's DoNotIntercept overrules.
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	if err := engine.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	no := false
	hook := trafficHookStub(func(_ context.Context, phase string, raw []byte) TrafficHookResult {
		if phase == "request" {
			return TrafficHookResult{Raw: raw, Intercept: &no, Applied: []string{"stub"}}
		}
		return TrafficHookResult{Raw: raw}
	})
	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithIntercept(engine).
		WithTrafficHook(hook))
	proxyAddr := startProxy(t, srv)

	resp, err := hookClient(proxyAddr).Get(origin.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if held := engine.Held(); len(held) != 0 {
		t.Fatalf("DoNotIntercept still held: %d", len(held))
	}
}

func TestTrafficHookPanicFailsOpen(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	hook := trafficHookStub(func(_ context.Context, phase string, raw []byte) TrafficHookResult {
		panic("plugin exploded")
	})
	cfg := NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithTrafficHook(hook)
	proxyAddr := startProxy(t, NewServer(cfg))

	resp, err := hookClient(proxyAddr).Get(origin.URL)
	if err != nil {
		t.Fatalf("a panicking hook must not wedge the traffic: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "ok") {
		t.Fatalf("body: %q", body)
	}
	if c := cfg.TrafficHookCounts(); c.Failures == 0 {
		t.Fatalf("the panic was not counted: %+v", c)
	}
}

// PR #363 review (W6 confirmed the shape in both the TLS and the plaintext path): a response
// the extension hook dropped was still offered to the intercept hold, and an operator Drop
// there overwrote the note naming the extension as the actor. The hook's drop already decided
// what the client gets: nothing is held, and the recorded exchange keeps the extension's note.
func TestTrafficHookDroppedResponseIsNotHeldForTheOperator(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "origin-body")
	}))
	defer origin.Close()

	hook := trafficHookStub(func(_ context.Context, phase string, raw []byte) TrafficHookResult {
		if phase == "response" {
			return TrafficHookResult{Raw: raw, Dropped: true, Applied: []string{"stub"}}
		}
		return TrafficHookResult{Raw: raw}
	})
	// Response interception on, no rules: Burp's "intercept everything" for the response side.
	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	if err := engine.SetRules(intercept.DirectionResponse, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	store := core.NewTrafficStore()
	cfg := NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithTrafficHook(hook).
		WithIntercept(engine)
	proxyAddr := startProxy(t, NewServer(cfg))

	resp, err := hookClient(proxyAddr).Get(origin.URL)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(body), "origin-body") {
			t.Fatalf("dropped response reached the client: %q", body)
		}
	}
	if held := engine.Held(); len(held) != 0 {
		t.Fatalf("a hook-dropped response was held for the operator: %d items", len(held))
	}
	// The recorded exchange names the extension as the actor. Nobody forwarded or dropped a
	// hold - there was none - so the note can only have survived if the hold was skipped.
	deadline := time.Now().Add(3 * time.Second)
	for {
		exchanges := store.ObserveExchanges(func(*core.Exchange) {})
		if len(exchanges) > 0 {
			if exchanges[0].Notes == nil || !strings.Contains(*exchanges[0].Notes, "an extension dropped this response") {
				t.Fatalf("the recorded note does not name the extension as the actor: %v", exchanges[0].Notes)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the dropped exchange was never recorded")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
