package sender

import (
	"context"
	"testing"
)

// Caller-owned ConnPool reuse identity (o388 residual). Every count is taken on the server side.

func stampSend(t *testing.T, auth *AuthorisedSender, pool *ConnPool) {
	t.Helper()
	if _, err := auth.SendReusing(context.Background(), pool, []byte(keepAliveReq), ProtocolPreferenceAuto); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func stampAuth(t *testing.T, s *Sender, addr string) *AuthorisedSender {
	t.Helper()
	host, port := mustHostPort(t, addr)
	return NewAuthorisedSender(allowAll{}, s, host, port, false)
}

// Control: no change between sends reuses the connection, so the fix does not just disable reuse.
func TestStampControlSameSenderUnchangedReuses(t *testing.T) {
	srv := startKeepAliveServer(t, framed, 0)
	pool := NewConnPool(2)
	defer pool.Close()
	auth := poolSender(t, srv.addr)
	stampSend(t, auth, pool)
	stampSend(t, auth, pool)
	if got := srv.accepts.Load(); got != 1 || pool.Reused() != 1 {
		t.Fatalf("accepts=%d reused=%d, want 1 and 1", got, pool.Reused())
	}
}

// R1: ApplyNetwork between sends must retire the caller pool's idle connection.
func TestStampApplyNetworkRetiresCallerPoolConn(t *testing.T) {
	srv := startKeepAliveServer(t, framed, 0)
	pool := NewConnPool(2)
	defer pool.Close()
	s := NewSender(DefaultSenderConfig())
	auth := stampAuth(t, s, srv.addr)
	stampSend(t, auth, pool)
	if err := s.ApplyNetwork(s.Network()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	stampSend(t, auth, pool)
	if got := srv.accepts.Load(); got != 2 || pool.Reused() != 0 {
		t.Fatalf("accepts=%d reused=%d, want 2 and 0: a connection dialled before ApplyNetwork carried a send after it", got, pool.Reused())
	}
}

// R-shared: two Senders share one pool. Their generations are independent counters and are EQUAL
// here (both 1) while their settings differ, so a generation-only stamp would match. Sender B must
// not take Sender A's connection.
func TestStampSharedPoolDifferentSendersEqualGenerationDoNotShare(t *testing.T) {
	srv := startKeepAliveServer(t, framed, 0)
	pool := NewConnPool(2)
	defer pool.Close()
	a := NewSender(DefaultSenderConfig())
	b := NewSender(DefaultSenderConfig())
	sa := a.Network()
	sb := b.Network()
	sb.Timeouts.ConnectMS = sa.Timeouts.ConnectMS + 1234
	if err := a.ApplyNetwork(sa); err != nil {
		t.Fatal(err)
	}
	if err := b.ApplyNetwork(sb); err != nil {
		t.Fatal(err)
	}
	if a.netGen != b.netGen {
		t.Fatalf("test premise: generations differ (%d vs %d)", a.netGen, b.netGen)
	}
	stampSend(t, stampAuth(t, a, srv.addr), pool)
	stampSend(t, stampAuth(t, b, srv.addr), pool)
	if got := srv.accepts.Load(); got != 2 || pool.Reused() != 0 {
		t.Fatalf("accepts=%d reused=%d, want 2 and 0: Sender B reused Sender A's connection", got, pool.Reused())
	}
}
