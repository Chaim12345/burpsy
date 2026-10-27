package proxy

import (
	"errors"
	"io"
	"net"

	"github.com/burpsy-go/burpsy/internal/core"
	"testing"
	"time"
)

func TestASpawnedRelayPanicIsContainedAndClosesTheConnection(t *testing.T) {
	s := NewServer(NewProxyConfig(core.NewTrafficStore()))
	client, clientPeer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	done := make(chan struct{})
	s.spawn(func() {
		defer close(done)
		panic("relay bug")
	}, client, upstream)
	<-done
	for name, peer := range map[string]net.Conn{"client": clientPeer, "upstream": upstreamPeer} {
		_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("%s side: read err = %v, want EOF from a closed connection", name, err)
		}
	}
	if s.ConnectionPanics() != 1 {
		t.Fatalf("ConnectionPanics = %d, want 1", s.ConnectionPanics())
	}
}
