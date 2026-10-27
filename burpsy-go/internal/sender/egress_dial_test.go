package sender

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/upstream/upstreamtest"
)

// EgressDialContext is what the browser's gating proxy and the extscan forward proxy dial through
// (burpsy-react-ui-browser-render-unscoped, burpsy-react-ui-extscan-egress): it must traverse the
// configured upstream proxy, not go direct.
func TestEgressDialContextTraversesTheConfiguredUpstreamProxy(t *testing.T) {
	host, port := originAuthority(t)
	proxy := upstreamtest.StartConnect(t, "", "")
	snd := senderThrough(t, "http://"+proxy.Addr())

	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := snd.EgressDialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("EgressDialContext: %v", err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+addr+"\r\nConnection: close\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(conn)
	if !strings.Contains(string(got), "reached the origin") {
		t.Errorf("the origin's body did not come back over the egress dial; got %q", got)
	}
	if !proxy.Saw(addr) {
		t.Errorf("the upstream proxy was asked for %v, not %q — the egress dial went out direct", proxy.Requests(), addr)
	}
}

func TestEgressDialContextRefusesNonTCPAndBadAddresses(t *testing.T) {
	snd := NewSender(DefaultSenderConfig())
	for _, c := range []struct{ network, addr string }{{"udp", "127.0.0.1:1"}, {"tcp", "nohostport"}, {"tcp", "127.0.0.1:0"}} {
		if conn, err := snd.EgressDialContext(context.Background(), c.network, c.addr); err == nil {
			conn.Close()
			t.Errorf("EgressDialContext(%q, %q) succeeded", c.network, c.addr)
		}
	}
}
