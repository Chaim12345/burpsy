package persist

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/burpsy-go/burpsy/internal/upstream"
	"github.com/burpsy-go/burpsy/internal/upstream/upstreamtest"
)

// burpsy-react-ui-carrier-creds-lost: the carrier's snapshot was built from the redacted Display
// form, so a hop saved as socks5://user:pw@host came back from disk as user "***" with no password,
// and nothing said so. The proof here is behavioural: the RESTORED carrier must authenticate to a
// SOCKS5 server that demands the saved credentials.

// carrierOrigin is a loopback listener that accepts and closes, for the carried dial to reach.
func carrierOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return ln.Addr().String()
}

func TestACarrierWithCredentialsRestoresWithThemAndStillAuthenticates(t *testing.T) {
	socks := upstreamtest.StartSOCKS5(t, "operator", "s3cr3t")
	origin := carrierOrigin(t)
	store := newTestStore(t)

	live := upstream.NewCarrier()
	if err := live.SetSocks("socks5://operator:s3cr3t@"+socks.Addr(), nil, false); err != nil {
		t.Fatal(err)
	}
	store.SaveUpstreamCarrier(live)

	restored := upstream.NewCarrier()
	ok, err := store.LoadUpstreamCarrier(restored)
	if err != nil || !ok {
		t.Fatalf("LoadUpstreamCarrier = %v, %v; want restored", ok, err)
	}
	// The panel's view stays redacted: persisting the Raw form must not leak into Configured.
	shown, _, _, _ := restored.Configured()
	if strings.Contains(shown, "s3cr3t") || strings.Contains(shown, "operator") {
		t.Errorf("Configured() = %q exposes the credentials; it must stay redacted", shown)
	}

	conn, err := upstream.Dialer{Carrier: restored}.DialContext(context.Background(), "tcp", origin)
	if err != nil {
		t.Fatalf("a dial through the restored carrier failed: %v (socks errors: %v) — the credentials "+
			"did not survive the restart", err, socks.Errors())
	}
	conn.Close()
	if creds := socks.Credentials(); len(creds) != 1 || creds[0] != "operator" {
		t.Errorf("SOCKS server saw users %v, want [operator]", creds)
	}
	if errs := socks.Errors(); len(errs) > 0 {
		t.Errorf("SOCKS server errors: %v", errs)
	}
}

// A row saved by a build that persisted the redacted form holds "***@" and no password. It must not
// come back as a working-looking credential for a user named "***": the hop is restored without
// credentials and the operator is warned.
func TestALegacyRedactedCarrierRowRestoresWithoutCredentialsAndWarns(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	store, err := Open(filepath.Join(t.TempDir(), "test.db"), zap.New(core))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	socks := upstreamtest.StartSOCKS5(t, "", "")
	origin := carrierOrigin(t)
	legacy := `{"socks":"socks5://***@` + socks.Addr() + `","bypass":[],"remote_resolve":false}`
	if err := store.setSetting("network.carrier", legacy); err != nil {
		t.Fatal(err)
	}

	restored := upstream.NewCarrier()
	ok, err := store.LoadUpstreamCarrier(restored)
	if err != nil || !ok {
		t.Fatalf("LoadUpstreamCarrier = %v, %v; want the hop restored (without credentials)", ok, err)
	}
	if got := logs.FilterMessage("persist read inconsistency").FilterField(zap.String("op", "upstream carrier")).Len(); got != 1 {
		t.Errorf("warnings logged for the dropped credentials = %d, want 1; all logs: %v", got, logs.All())
	}
	// Identity carries the hop's Raw form (credentials included), so it is where an installed "***"
	// user would show. The dial below alone cannot tell: x/net/proxy offers no-auth beside
	// username/password, and a no-auth server picks the former whatever user was configured.
	if id := restored.Identity(); strings.Contains(id, "***") || strings.Contains(id, "@") {
		t.Errorf("restored hop still carries the placeholder as a credential: identity %q", id)
	}
	conn, err := upstream.Dialer{Carrier: restored}.DialContext(context.Background(), "tcp", origin)
	if err != nil {
		t.Fatalf("dial through the restored hop: %v (socks errors: %v)", err, socks.Errors())
	}
	conn.Close()
	if creds := socks.Credentials(); len(creds) != 1 || creds[0] != "" {
		t.Errorf("SOCKS server saw users %q, want one request with no user", creds)
	}
}
