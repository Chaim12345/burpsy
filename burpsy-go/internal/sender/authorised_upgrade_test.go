package sender

import (
	"context"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
)

const testUpgrade = "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

// The handshake leaves through the same gate as every other send: refused before the dial.
func TestAnOutOfScopeUpgradeIsRefusedBeforeTheDial(t *testing.T) {
	sc := core.NewScope()
	sc.AddExclude("127.0.0.1")
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), "127.0.0.1", 1, false)
	_, err := a.SendUpgrade(context.Background(), []byte(testUpgrade))
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("want a scope refusal, got %v", err)
	}
	if a.Sent() != 0 || a.Refused() != 1 {
		t.Fatalf("sent/refused = %d/%d, want 0/1", a.Sent(), a.Refused())
	}
}

// A handshake the target answers with something other than 101 is an error that still carries the
// status it was refused with, and no connection.
func TestARefusedUpgradeCarriesTheRefusalsStatus(t *testing.T) {
	addr, _ := localServer(t)
	_, port, err := hostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), NewSender(DefaultSenderConfig()), "127.0.0.1", port, false)
	res, err := a.SendUpgrade(context.Background(), []byte(testUpgrade))
	if err == nil {
		t.Fatal("a 200 answer to a handshake was accepted as an upgrade")
	}
	if res.Conn != nil {
		t.Fatal("a refused handshake handed back a connection")
	}
	if st := httputil.ResponseStatus(res.RawResp); st == nil || *st != 200 {
		t.Fatalf("refusal head = %q, want the 200 it was answered with", res.RawResp)
	}
	if a.Sent() != 1 {
		t.Fatalf("sent = %d, want 1: the handshake reached the target", a.Sent())
	}
}
