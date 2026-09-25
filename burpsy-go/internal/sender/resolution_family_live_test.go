package sender

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The live pass could not demonstrate this environment's defect and the reason is worth recording
// rather than glossing over.
//
// burpsy-react-ui-mr83 part 2 claims: a dual-stack target behind IPv4-only routing can resolve to an
// AAAA first, and burpsy dials the unreachable address, so the request takes the connect timeout to
// fail on a host that was reachable all along.
//
// On this machine that is not reproducible, and it is not a question of the code:
//
//   - /etc/hosts gave dual.test BOTH families, AAAA first (::1 then 127.0.0.1), against an
//     IPv4-only listener.
//   - A send with resolution.family=system and one with ipv4 both answered 200, and both in
//     under 10ms.
//   - A direct dial to an unroutable AAAA (2001:db8::1) failed in 0.00s, not after a timeout.
//
// The reason is that this host has no IPv6 route at all, so an AAAA dial fails instantly and Go's
// dialer moves straight to the A. The defect needs a host where the AAAA is routed but unroutable —
// a firewall that drops rather than rejects — and that is a network the live pass cannot conjure here.
//
// So the selection is proved where it CAN be proved: through a lookup seam that answers with both
// families, on a machine with a real IPv4 listener. This test is that proof, and it exists so the claim
// is not left resting on a live pass that could not exercise it.

// The preference chooses the A record from an answer that leads with the AAAA, and the dial reaches the
// listener. Without the preference the AAAA is dialled first and nothing is listening there.
func TestThePreferenceChoosesTheReachableFamilyFromARealTwoFamilyAnswer(t *testing.T) {
	// A real IPv4 listener, so success means an address was actually dialled.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port uint16
	for _, c := range portStr {
		port = port*10 + uint16(c-'0')
	}
	reached := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case reached <- struct{}{}:
			default:
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()

	// The answer: the AAAA first, and nothing is listening on it. This is the ordering that makes the
	// preference worth having.
	settings := DefaultNetworkSettings()
	settings.Resolution.Family = FamilyIPv4
	settings.Resolution.Lookup = func(_ context.Context, host string) ([]string, error) {
		if host == "unroutable-v6.test" {
			return []string{"2001:db8::dead", "127.0.0.1"}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	snd := NewSender(DefaultSenderConfig())
	if err := snd.ApplyNetwork(settings); err != nil {
		t.Fatalf("apply: %v", err)
	}
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), snd, "unroutable-v6.test", port, false)
	resp, err := a.SendRequest(context.Background(), &Request{
		Method: "GET",
		URL:    "http://unroutable-v6.test:" + strconv.Itoa(int(port)) + "/",
	})
	if err != nil {
		t.Fatalf("the send failed under the IPv4 preference: %v — the AAAA was dialled rather than "+
			"filtered, which is the defect this setting exists to fix", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	select {
	case <-reached:
	default:
		t.Error("the listener never saw a connection: the send reported success without reaching it")
	}
}
