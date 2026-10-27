package sender

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/upstream"
	"github.com/burpsy-go/burpsy/internal/upstream/upstreamtest"
)

// burpsy-react-ui-socks-tls-bypass, sender half: the typed path's DialTLSContext — installed only
// when a client-certificate source is attached — set alpn.Dialer.Carry only when an upstream POLICY
// was configured, and built the upstream.Dialer without the carrier even then. With only a SOCKS
// carrier configured, a typed TLS send from a sender holding client certificates went straight to
// the origin. The raw path's rule (dialTLS: carry when a policy OR a carrier is configured) is the
// one this path now follows.

// declineAllCerts is a client-certificate source that binds nothing. Its presence is what installs
// the typed path's DialTLSContext; what it returns is irrelevant to the egress route.
type declineAllCerts struct{}

func (declineAllCerts) For(string) *tls.Certificate { return nil }

func TestATypedClientCertSendGoesThroughACarrierWithNoUpstreamPolicy(t *testing.T) {
	origin := startConnCounting(t, true, []string{"http/1.1"}, okHandler)
	socks := upstreamtest.StartSOCKS5(t, "", "")
	carrier := upstream.NewCarrier()
	if err := carrier.SetSocks("socks5://"+socks.Addr(), nil, false); err != nil {
		t.Fatal(err)
	}

	config := DefaultSenderConfig()
	config.TLSVerify = false
	config.Timeout = 5 * time.Second
	config.ClientCerts = declineAllCerts{}
	// No Upstream policy: the carrier is the only egress setting.
	snd := NewSender(config).WithUpstreamCarrier(carrier)

	authority := net.JoinHostPort(origin.host, strconv.Itoa(int(origin.port)))
	resp, err := snd.Send(context.Background(), &Request{Method: http.MethodGet, URL: "https://" + authority + "/"})
	if err != nil {
		t.Fatalf("typed Send through the carrier: %v (socks errors: %v)", err, socks.Errors())
	}
	if string(resp.Body) != "ok" {
		t.Errorf("body = %q, want ok", resp.Body)
	}
	if errs := socks.Errors(); len(errs) > 0 {
		t.Fatalf("the SOCKS server could not parse the client: %v", errs)
	}
	connects := len(socks.Requests())
	if !socks.Saw(authority) || connects == 0 {
		t.Fatalf("SOCKS CONNECTs = %v, want one for %s: the typed client-cert send bypassed the carrier",
			socks.Requests(), authority)
	}
	// Every connection the origin accepted must be one the SOCKS server opened for it.
	if got := origin.conns.Load(); got != int64(connects) {
		t.Errorf("origin accepted %d connections for %d SOCKS CONNECTs; %d came direct", got, connects, got-int64(connects))
	}
}
