package sender

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/upstream"
)

// burpsy-react-ui-o388-predial-vs-dial: the global SOCKS carrier is edited IN PLACE. The operator
// path is /api/network/proxy -> Carrier.SetSocks on the one instance every surface holds; nothing
// calls WithUpstreamCarrier again, so the settings generation never moves. A stamp that named the
// carrier only through the generation therefore let a connection dialled direct answer sends made
// after the operator aimed every outbound connection at a SOCKS hop. Each pin below configures an
// unreachable hop (127.0.0.1:1): a send that SUCCEEDS after the edit rode a pooled connection the
// carrier never opened.

const deadHop = "socks5://127.0.0.1:1"

// carriedSender is a sender holding an attached, initially unconfigured carrier, wired exactly as
// cmd/burpsy wires it (config field AND WithUpstreamCarrier), so later edits are in-place SetSocks
// calls on the same instance.
func carriedSender(t *testing.T, mutate func(*SenderConfig)) (*Sender, *upstream.Carrier) {
	t.Helper()
	carrier := upstream.NewCarrier()
	config := DefaultSenderConfig()
	config.UpstreamCarrier = carrier
	if mutate != nil {
		mutate(config)
	}
	return NewSender(config).WithUpstreamCarrier(carrier), carrier
}

// Caller-owned ConnPool (the Intruder run's pool).
func TestCarrierEditInPlaceRetiresCallerPoolConn(t *testing.T) {
	srv := startKeepAliveServer(t, framed, 0)
	pool := NewConnPool(2)
	defer pool.Close()
	s, carrier := carriedSender(t, nil)
	auth := stampAuth(t, s, srv.addr)
	stampSend(t, auth, pool)

	if err := carrier.SetSocks(deadHop, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.SendReusing(context.Background(), pool, []byte(keepAliveReq), ProtocolPreferenceAuto); err == nil {
		t.Fatalf("send succeeded (accepts=%d reused=%d) over a connection dialled direct before the carrier edit",
			srv.accepts.Load(), pool.Reused())
	}
	if got := srv.accepts.Load(); got != 1 {
		t.Fatalf("the refused send still reached the origin: %d accepts", got)
	}
}

// Control for the pin above: an edit that leaves the carrier's configuration as it was (the same
// hop written again) is not an identity change and must not cost the pooled connection. Without it
// the pin could be satisfied by a stamp that changed on every read.
func TestCarrierUnchangedRewriteKeepsCallerPoolConn(t *testing.T) {
	srv := startKeepAliveServer(t, framed, 0)
	pool := NewConnPool(2)
	defer pool.Close()
	s, carrier := carriedSender(t, nil)
	if err := carrier.SetSocks(deadHop, []string{"127.0.0.1"}, false); err != nil {
		t.Fatal(err)
	}
	auth := stampAuth(t, s, srv.addr)
	stampSend(t, auth, pool)
	if err := carrier.SetSocks(deadHop, []string{"127.0.0.1"}, false); err != nil {
		t.Fatal(err)
	}
	stampSend(t, auth, pool)
	if got := srv.accepts.Load(); got != 1 || pool.Reused() != 1 {
		t.Fatalf("accepts=%d reused=%d, want 1 and 1: an identical carrier rewrite retired the connection",
			got, pool.Reused())
	}
}

// The sender's own HTTP/1 keep-alive pool: ApplyNetwork flushes it, a carrier edit does not, so the
// take-time stamp comparison is the only thing that can retire the entry.
func TestCarrierEditInPlaceRetiresKeptAliveConn(t *testing.T) {
	s, carrier := carriedSender(t, func(c *SenderConfig) { c.TLSVerify = false })
	n := s.Network()
	n.HTTP1 = &HTTP1Settings{EnableKeepAlive: true}
	n.HTTP2 = &HTTP2Settings{EnableHTTP2: false}
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}
	target := startConnCounting(t, true, []string{alpn.HTTP11}, okHandler)
	raw := rawGet(target.host, target.port)
	send := func() error {
		resp, _, err := s.SendRawOutcome(context.Background(), target.host, target.port, true, raw, ProtocolPreferenceAuto)
		if err == nil && !strings.HasSuffix(string(resp), "ok") {
			t.Fatalf("send answered %q", resp)
		}
		return err
	}
	for i := 0; i < 2; i++ {
		if err := send(); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if got := target.conns.Load(); got != 1 {
		t.Fatalf("control: two sends opened %d connections, want one kept alive", got)
	}

	if err := carrier.SetSocks(deadHop, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := send(); err == nil {
		t.Fatal("after the in-place carrier edit, the send still rode the kept-alive connection dialled direct")
	}

	// Clearing the carrier is itself an identity change back to direct: the connection stamped
	// "direct, no carrier" was retired above, not resurrected, so the next send dials fresh.
	if err := carrier.SetSocks("", nil, false); err != nil {
		t.Fatal(err)
	}
	if err := send(); err != nil {
		t.Fatalf("the send after clearing the carrier failed: %v", err)
	}
	if got := target.conns.Load(); got != 2 {
		t.Fatalf("clearing the carrier opened %d connections in total, want one fresh dial (2)", got)
	}
}

// Caller-owned h2 sessions, the third pool the stamp guards.
func TestCarrierEditInPlaceRetiresH2Session(t *testing.T) {
	srv := startSNIServer(t, true)
	host, port := srv.hostPort(t)
	s, carrier := carriedSender(t, func(c *SenderConfig) {
		c.TLSVerify = false
		c.Timeout = 500 * time.Millisecond
	})
	pool := NewH2Sessions(4, time.Minute)
	defer pool.Close()

	sendPooled(t, s, pool, "tab", host, port)
	if pool.Opened() != 1 {
		t.Fatalf("opened = %d, want the one session the first send dialled", pool.Opened())
	}
	if err := carrier.SetSocks(deadHop, nil, false); err != nil {
		t.Fatal(err)
	}
	ctx := WithSendOptions(context.Background(), SendOptions{H2Sessions: pool, H2SessionKey: "tab"})
	if resp, _, err := s.SendRawOutcome(ctx, host, port, true, rawGet(host, port), ProtocolPreferenceAuto); err == nil {
		t.Fatalf("after the in-place carrier edit, the send still rode the session dialled direct: %q", resp)
	}
}

// The freeze half: the carrier the dial consumes is the capture's, so an edit landing between the
// capture and the socket open cannot put the connection on a hop its stamp does not name.
func TestDialIdentityFreezesTheCarrierConfigurationAtCapture(t *testing.T) {
	s, carrier := carriedSender(t, nil)
	id := mustCapture(t, s, "example.com", 80, false)
	if !id.wrap {
		t.Fatal("an attached carrier must route the dial through upstream.Dialer")
	}
	if err := carrier.SetSocks(deadHop, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, configured := id.carrier.Configured(); configured {
		t.Error("the frozen carrier picked up an edit made after capture")
	}
	if after := mustCapture(t, s, "example.com", 80, false); after.route == id.route {
		t.Error("an in-place carrier edit left the stamp unchanged")
	}
}

// Residual (2), the in-flight window: a send that already holds a connection finishes on it —
// the documented ApplyNetwork semantics, since its dial happened under the old identity — but the
// connection goes back to the pool with its DIAL-time stamp, so the next take retires it. The
// carrier is edited after the dial (the server has accepted) and before the response (the server
// is holding it), on the caller-owned pool.
func TestACarrierEditDuringAnExchangeRetiresTheConnectionAtTheNextTake(t *testing.T) {
	srv := startKeepAliveServer(t, framed, 300*time.Millisecond)
	pool := NewConnPool(2)
	defer pool.Close()
	s, carrier := carriedSender(t, nil)
	auth := stampAuth(t, s, srv.addr)

	done := make(chan error, 1)
	go func() {
		_, err := auth.SendReusing(context.Background(), pool, []byte(keepAliveReq), ProtocolPreferenceAuto)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for srv.accepts.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first send never dialled")
		}
		time.Sleep(time.Millisecond)
	}
	if err := carrier.SetSocks(deadHop, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the in-flight send must finish on the connection it holds: %v", err)
	}
	if got := srv.served.Load(); got != 1 {
		t.Fatalf("served=%d, want the in-flight exchange answered", got)
	}
	if _, err := auth.SendReusing(context.Background(), pool, []byte(keepAliveReq), ProtocolPreferenceAuto); err == nil {
		t.Fatalf("the send after the edit rode the connection dialled direct (accepts=%d reused=%d)",
			srv.accepts.Load(), pool.Reused())
	}
}
