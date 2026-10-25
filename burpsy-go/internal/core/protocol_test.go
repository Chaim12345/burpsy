package core

import "testing"

// The outcome record names the protocol that actually carried the bytes, so every protocol the
// sender can negotiate needs a version token an operator recognises.
func TestProtocolVersionTokensNameTheWireProtocol(t *testing.T) {
	cases := map[Protocol]string{
		ProtocolHTTP1: "HTTP/1.1",
		ProtocolHTTP2: "HTTP/2",
		ProtocolHTTP3: "HTTP/3",
	}
	for protocol, want := range cases {
		if got := protocol.VersionToken(); got != want {
			t.Errorf("Protocol(%d).VersionToken() = %q, want %q", protocol, got, want)
		}
	}
}
