package sender

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/upstream"
	"github.com/burpsy-go/burpsy/internal/upstream/upstreamtest"
)

// The typed path keeps idle keep-alive connections in its http.Transport. An operator who sets a
// SOCKS hop in place (/api/network/proxy -> Carrier.SetSocks) must not have the next typed send ride
// a connection dialled direct before the edit (burpsy-react-ui-typed-idle-unstamped).
func TestATypedSendAfterAnInPlaceCarrierEditDoesNotReuseADirectConnection(t *testing.T) {
	origin := startConnCounting(t, false, nil, okHandler)
	socks := upstreamtest.StartSOCKS5(t, "", "")
	carrier := upstream.NewCarrier() // unconfigured: the first send dials direct
	config := DefaultSenderConfig()
	config.Timeout = 5 * time.Second
	snd := NewSender(config).WithUpstreamCarrier(carrier)
	url := "http://" + net.JoinHostPort(origin.host, strconv.Itoa(int(origin.port))) + "/"

	send := func() {
		t.Helper()
		resp, err := snd.Send(context.Background(), &Request{Method: http.MethodGet, URL: url})
		if err != nil {
			t.Fatalf("typed send: %v (socks errors %v)", err, socks.Errors())
		}
		_ = resp
	}
	send()
	send() // control: unchanged route reuses the idle connection
	if got := origin.conns.Load(); got != 1 {
		t.Fatalf("two sends on an unchanged route opened %d connections, want 1 (keep-alive reuse)", got)
	}
	if err := carrier.SetSocks("socks5://"+socks.Addr(), nil, false); err != nil {
		t.Fatal(err)
	}
	send()
	if len(socks.Requests()) != 1 {
		t.Fatalf("SOCKS CONNECTs after the edit = %v, want 1: the send reused the direct connection", socks.Requests())
	}
	if got := origin.conns.Load(); got != 2 {
		t.Errorf("origin accepts = %d, want 2 (one direct before the edit, one through SOCKS after)", got)
	}
}
