package sender

import (
	"context"
	"testing"
)

// j1mk.33: tls.verify=false must reach the active-scan sender, not only the proxy leg.
//
// The bug's shape is that the two raw dial paths — dialTLS (SendRawOutcome and every desync probe)
// and the typed path's DialTLSContext — read SenderConfig.TLSVerify directly, while the operator's
// knob is NetworkSettings.TLS.Verify, applied through ApplyNetwork. A console edit therefore changed
// the proxy leg and left the scanner verifying, so a lab target with a self-signed or expired
// certificate (OWASP Benchmark v1.2, on :8443, cert expired 2015) could be browsed but never audited.
//
// Each direction is its own claim: with verification off the send must succeed, and with it on the
// same untrusted target must be refused. The second half is what stops the fix from being "turn
// verification off everywhere".
func TestApplyNetworkTLSVerifyReachesTheRawAndTypedSendPaths(t *testing.T) {
	srv := startALPNServer(t, []string{"http/1.1"}, false)
	// httptest's certificate is self-signed, so it is never in the system pool: verification on
	// means the handshake fails, verification off means it succeeds. That is the whole oracle.
	raw := rawGet(srv.host, srv.port)

	// Direction 1: an operator turning verification off must reach BOTH paths.
	off := NewSender(DefaultSenderConfig())
	settings := off.Network()
	settings.TLS.Verify = false
	if err := off.ApplyNetwork(settings); err != nil {
		t.Fatalf("ApplyNetwork: %v", err)
	}
	if _, _, err := off.SendRawOutcome(context.Background(), srv.host, srv.port, true, raw, ProtocolPreferenceHTTP1); err != nil {
		t.Fatalf("raw send refused with tls.verify=false: %v — the scan sender must obey the same "+
			"setting the proxy leg does, or a self-signed lab target cannot be audited (j1mk.33)", err)
	}
	if _, err := off.Send(context.Background(), &Request{
		Method: "GET", URL: "https://" + formatHostPort(srv.host, srv.port) + "/typed",
		Host: srv.host, Port: srv.port, TLS: true,
	}); err != nil {
		t.Fatalf("typed send refused with tls.verify=false: %v — the typed path must read the same "+
			"setting as the raw one (j1mk.33)", err)
	}

	// Direction 2: verification is still real. A sender that never saw the setting verifies, and the
	// same untrusted target is refused on both paths.
	on := NewSender(DefaultSenderConfig())
	if _, _, err := on.SendRawOutcome(context.Background(), srv.host, srv.port, true, raw, ProtocolPreferenceHTTP1); err == nil {
		t.Fatal("an untrusted certificate was accepted on the raw path under the default config: the " +
			"settings seed must default verification ON, not off")
	}
	if _, err := on.Send(context.Background(), &Request{
		Method: "GET", URL: "https://" + formatHostPort(srv.host, srv.port) + "/typed",
		Host: srv.host, Port: srv.port, TLS: true,
	}); err == nil {
		t.Fatal("an untrusted certificate was accepted on the typed path under the default config")
	}
}
