package sender

import (
	"crypto/tls"
	"testing"
)

// burpsy-react-ui-o388-predial-vs-dial close condition: the route fingerprint must cover the
// resolver, the dial-address override and the TLS policy. Those are settings-borne dial inputs —
// captured with the settings value and versioned by the generation every ApplyNetwork bumps —
// so each is changed here, alone, between two sends on the caller-owned ConnPool (the pool
// ApplyNetwork cannot flush), and the second send must open a fresh socket. Counts are taken
// on the server. TestStampControlSameSenderUnchangedReuses is the no-change control.
func TestEachSettingsBorneDialInputRetiresCallerPoolConn(t *testing.T) {
	for name, change := range map[string]func(*NetworkSettings){
		"resolver": func(n *NetworkSettings) {
			n.Resolution.Policy = ResolutionResolver
			n.Resolution.Resolver = "127.0.0.1:1"
		},
		"dial override": func(n *NetworkSettings) {
			// The authority keeps resolving to the same listener, so the send still succeeds:
			// what is pinned is that a changed override table is a changed identity.
			n.Resolution.Overrides = append(n.Resolution.Overrides,
				HostOverride{Host: "other.test", Address: "127.0.0.1", Enabled: true})
		},
		"tls min version": func(n *NetworkSettings) { n.TLS.MinVersion = tls.VersionTLS13 },
		"tls verify":      func(n *NetworkSettings) { n.TLS.Verify = !n.TLS.Verify },
		"tls root ca":     func(n *NetworkSettings) { n.TLS.RootCAPath = "/nonexistent/burpsy-test-ca.pem" },
	} {
		t.Run(name, func(t *testing.T) {
			srv := startKeepAliveServer(t, framed, 0)
			pool := NewConnPool(2)
			defer pool.Close()
			s := NewSender(DefaultSenderConfig())
			auth := stampAuth(t, s, srv.addr)
			stampSend(t, auth, pool)

			n := s.Network()
			change(&n)
			if err := s.ApplyNetwork(n); err != nil {
				t.Fatalf("apply: %v", err)
			}
			stampSend(t, auth, pool)
			if got := srv.accepts.Load(); got != 2 || pool.Reused() != 0 {
				t.Fatalf("accepts=%d reused=%d, want 2 and 0: a connection dialled under the old %s carried a send after the change",
					got, pool.Reused(), name)
			}
		})
	}
}
