package sender

import (
	"context"
	"testing"
	"time"
)

// The pool's bounds (adkx): an idle session past its TTL is not handed out, and a full pool closes the
// least recently used session — the two things that release a connection the server is never told
// it can drop.

func sendPooled(t *testing.T, s *Sender, pool *H2Sessions, key, host string, port uint16) SendOutcome {
	t.Helper()
	ctx := WithSendOptions(context.Background(), SendOptions{H2Sessions: pool, H2SessionKey: key})
	_, out, err := s.SendRawOutcome(ctx, host, port, true, rawGet(host, port), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	return out
}

func TestH2SessionsReuseUntilTheTTLThenDialFresh(t *testing.T) {
	srv := startSNIServer(t, true)
	host, port := srv.hostPort(t)
	s := testSender()
	pool := NewH2Sessions(4, 150*time.Millisecond)
	defer pool.Close()

	if out := sendPooled(t, s, pool, "a", host, port); out.ConnectionReused {
		t.Fatal("the first send cannot have reused a connection")
	}
	if out := sendPooled(t, s, pool, "a", host, port); !out.ConnectionReused {
		t.Fatal("a second send inside the TTL should ride the open session")
	}
	time.Sleep(250 * time.Millisecond)
	if out := sendPooled(t, s, pool, "a", host, port); out.ConnectionReused {
		t.Fatal("a session idle past its TTL was handed out")
	}
	if pool.Opened() != 2 || pool.Reused() != 1 {
		t.Fatalf("opened/reused = %d/%d, want 2/1", pool.Opened(), pool.Reused())
	}
}

func TestH2SessionsCloseTheLeastRecentlyUsedWhenFull(t *testing.T) {
	srv := startSNIServer(t, true)
	host, port := srv.hostPort(t)
	s := testSender()
	pool := NewH2Sessions(1, time.Minute)
	defer pool.Close()

	sendPooled(t, s, pool, "a", host, port)
	sendPooled(t, s, pool, "b", host, port)
	if pool.Idle() != 1 {
		t.Fatalf("idle = %d, want the cap of 1", pool.Idle())
	}
	if out := sendPooled(t, s, pool, "a", host, port); out.ConnectionReused {
		t.Fatal("tab a's session should have been closed to make room for tab b's")
	}
}
