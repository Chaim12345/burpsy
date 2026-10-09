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

// A held request says which client sent it (burpsy-react-ui-3bkn), Burp's
// InterceptedHttpMessage.sourceIpAddress(). The client dials from 127.0.0.2 so its address cannot be
// confused with the listener's or the origin's 127.0.0.1.
func TestAHeldRequestCarriesTheClientsAddress(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer origin.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	if err := engine.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithIntercept(engine))
	proxyAddr := startProxy(t, srv)

	got := make(chan string, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			for _, held := range engine.Held() {
				if held.Direction == intercept.DirectionRequest {
					got <- held.ClientIP
					_ = engine.Drop(held.ID, "test")
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		got <- "never held"
	}()

	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}).DialContext,
	}}
	if resp, err := client.Get(fmt.Sprintf("http://%s:%s/held", host, portStr)); err == nil {
		resp.Body.Close()
	}
	if ip := <-got; ip != "127.0.0.2" {
		t.Errorf("held request ClientIP = %q, want 127.0.0.2", ip)
	}
}
