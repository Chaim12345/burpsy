package proxy

import (
	"net"

	"github.com/burpsy-go/burpsy/internal/core"
	"testing"
	"time"
)

func TestASpawnedRelayPanicIsContainedAndClosesTheConnection(t *testing.T) {
	s := NewServer(NewProxyConfig(core.NewTrafficStore()))
	client, peer := net.Pipe()
	defer peer.Close()
	done := make(chan struct{})
	s.spawn(client, func() {
		defer close(done)
		panic("relay bug")
	})
	<-done
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection stayed open after its relay goroutine panicked")
	}
	if s.ConnectionPanics() != 1 {
		t.Fatalf("ConnectionPanics = %d, want 1", s.ConnectionPanics())
	}
}
