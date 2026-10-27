package extension

// wiwh acceptance: a real plugin process rewrites traffic that crosses the
// real proxy listener, wired with the composition root's adapter shape (the
// HTTP kind first, the proxy kind second on whatever it produced — Burp's
// order for proxied traffic). Every earlier test pins one half of that —
// Host.Hook's chain, the proxy's seam with a stub — and this one refuses to
// call the wiring done until a plugin's bytes survive the whole path:
// process -> host -> adapter -> listener -> upstream, and back.

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/proxy"
)

// acceptTrafficHook is main.go's adapter, kept in shape deliberately: if the
// two ever disagree, one of them is lying about the order plugins see traffic.
type acceptTrafficHook struct{ h *Host }

func (a acceptTrafficHook) HookTraffic(ctx context.Context, phase string, raw []byte) proxy.TrafficHookResult {
	httpRes := a.h.Hook(ctx, HookCall{Kind: KindHTTPHandler, Phase: phase, Raw: raw})
	proxyRes := a.h.Hook(ctx, HookCall{Kind: KindProxyHandler, Phase: phase, Raw: httpRes.Raw})
	return proxy.TrafficHookResult{
		Raw:       proxyRes.Raw,
		Changed:   httpRes.Changed || proxyRes.Changed,
		Dropped:   proxyRes.Dropped,
		Intercept: proxyRes.Intercept,
		Applied:   append(httpRes.Applied, proxyRes.Applied...),
		Failures:  len(httpRes.Failures) + len(proxyRes.Failures),
	}
}

func Test_a_plugin_rewrites_traffic_through_the_real_proxy(t *testing.T) {
	h := hookHost(t) // plugins a and b, "hooks" behaviour, both granted hook.traffic

	var originHits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		w.Header().Set("Content-Length", "5")
		_, _ = io.WriteString(w, "hello")
	}))
	defer origin.Close()
	host, _, err := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	if err != nil {
		t.Fatalf("origin authority: %v", err)
	}

	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.AddInclude(host)
	srv := proxy.NewServer(proxy.NewProxyConfig(store).
		WithScope(scope).
		WithLogger(zap.NewNop()).
		WithTrafficHook(acceptTrafficHook{h}))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.ListenAndServe(ctx, "127.0.0.1:0") }()
	addr := ""
	for deadline := time.Now().Add(5 * time.Second); addr == "" && time.Now().Before(deadline); {
		addr = srv.ListenerAddr()
		if addr == "" {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if addr == "" {
		t.Fatal("proxy never bound")
	}

	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
		DisableKeepAlives: true,
	}, Timeout: 15 * time.Second}
	resp, err := client.Get(origin.URL + "/wiwh")
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "hello" {
		t.Fatalf("status %d body %q: the hooked path must not break plain traffic", resp.StatusCode, body)
	}
	if originHits.Load() != 1 {
		t.Fatalf("origin hits = %d", originHits.Load())
	}

	// The helper appends "[name:phase]" to the bytes it is handed. On a GET those
	// markers land after the head, where no Content-Length carries them to the
	// origin's parser — so the store is the honest witness: the proxy records the
	// bytes it forwarded, and the hooked bytes are what must be there. The doubled
	// marker per plugin is the Burp order pinned in bytes: the HTTP kind chains
	// a then b, then the proxy kind chains a then b over that result.
	wantReq := "[a:request][b:request][a:request][b:request]"
	wantResp := "[a:response][b:response][a:response][b:response]"
	deadline := time.Now().Add(5 * time.Second)
	for {
		found := false
		for _, ex := range store.Exchanges() {
			if ex.Path != "/wiwh" || ex.Response == nil {
				continue
			}
			req, rerr := store.Get(core.MsgOrZero(ex.Request))
			rsp, serr := store.Get(*ex.Response)
			if rerr != nil || serr != nil {
				continue
			}
			if !strings.Contains(string(req.Raw()), wantReq) {
				t.Fatalf("recorded request lacks the plugin chain %q:\n%s", wantReq, req.Raw())
			}
			if !strings.Contains(string(rsp.Raw()), wantResp) {
				t.Fatalf("recorded response lacks the plugin chain %q:\n%s", wantResp, rsp.Raw())
			}
			found = true
		}
		if found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the /wiwh exchange was never recorded with its response")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
