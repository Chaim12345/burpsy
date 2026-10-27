package sender

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/upstream"
	"github.com/burpsy-go/burpsy/internal/upstream/upstreamtest"
)

// burpsy-react-ui-newsender-carrier: NewSender handed config.UpstreamCarrier to the typed client and
// nowhere else, so a Sender built from config alone — every embedder that does not also call
// WithUpstreamCarrier — sent raw requests straight to the origin around the carrier the config named.

// configOnlyCarriedSender builds a Sender whose carrier comes from SenderConfig alone.
func configOnlyCarriedSender(t *testing.T, socksAddr string) *Sender {
	t.Helper()
	carrier := upstream.NewCarrier()
	if err := carrier.SetSocks("socks5://"+socksAddr, nil, false); err != nil {
		t.Fatal(err)
	}
	config := DefaultSenderConfig()
	config.TLSVerify = false
	config.Timeout = 5 * time.Second
	config.UpstreamCarrier = carrier
	snd := NewSender(config)
	if snd.UpstreamCarrier() != carrier {
		t.Errorf("NewSender did not hold the config's carrier: UpstreamCarrier() = %p, want %p", snd.UpstreamCarrier(), carrier)
	}
	return snd
}

func TestASenderBuiltFromConfigSendsRawThroughTheCarrier(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "cleartext"
		if useTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			origin := startConnCounting(t, useTLS, []string{"http/1.1"}, okHandler)
			socks := upstreamtest.StartSOCKS5(t, "", "")
			snd := configOnlyCarriedSender(t, socks.Addr())

			authority := net.JoinHostPort(origin.host, strconv.Itoa(int(origin.port)))
			raw := []byte("GET / HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n")
			got, err := snd.SendRaw(context.Background(), origin.host, origin.port, useTLS, raw)
			if err != nil {
				t.Fatalf("SendRaw: %v (socks errors: %v)", err, socks.Errors())
			}
			if !strings.Contains(string(got), "ok") {
				t.Errorf("response = %q, want the origin's body", got)
			}
			if errs := socks.Errors(); len(errs) > 0 {
				t.Fatalf("SOCKS server errors: %v", errs)
			}
			connects := len(socks.Requests())
			if !socks.Saw(authority) {
				t.Fatalf("SOCKS CONNECTs = %v, want one for %s: the raw send went around the config's carrier",
					socks.Requests(), authority)
			}
			if accepted := origin.conns.Load(); accepted != int64(connects) {
				t.Errorf("origin accepted %d connections for %d SOCKS CONNECTs; %d came direct",
					accepted, connects, accepted-int64(connects))
			}
		})
	}
}

// ApplyNetwork rebuilds the typed client from the Sender's carrier field. With the field unset by
// NewSender, a config-only Sender's typed path was carried until the first settings edit and direct
// after it.
func TestAConfigCarrierSurvivesApplyNetworkOnTheTypedPath(t *testing.T) {
	origin := startConnCounting(t, true, []string{"http/1.1"}, okHandler)
	socks := upstreamtest.StartSOCKS5(t, "", "")
	snd := configOnlyCarriedSender(t, socks.Addr())
	if err := snd.ApplyNetwork(snd.Network()); err != nil {
		t.Fatal(err)
	}

	authority := net.JoinHostPort(origin.host, strconv.Itoa(int(origin.port)))
	if _, err := snd.Send(context.Background(), &Request{Method: http.MethodGet, URL: "https://" + authority + "/"}); err != nil {
		t.Fatalf("Send: %v (socks errors: %v)", err, socks.Errors())
	}
	if !socks.Saw(authority) {
		t.Fatalf("SOCKS CONNECTs = %v, want one for %s: ApplyNetwork dropped the config's carrier",
			socks.Requests(), authority)
	}
	if accepted, connects := origin.conns.Load(), int64(len(socks.Requests())); accepted != connects {
		t.Errorf("origin accepted %d connections for %d SOCKS CONNECTs", accepted, connects)
	}
}
