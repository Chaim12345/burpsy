package sender

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// EgressDialContext opens one raw TCP connection to addr ("host:port") the way every cleartext send
// in this package does — through dialPlain, so the hostname-resolution table, the upstream proxy
// policy and the global SOCKS carrier all apply, read live at this call.
//
// It exists for egress surfaces that are not HTTP sends but must still leave the machine on the
// operator's configured route: the headless browser's scope-gating session proxy (domexec
// Options.EgressDial) and the external-tool forward proxy (extscan), which splice a tunnel or
// forward a request after their own scope decision. It makes NO scope decision itself; a caller
// dials only what it has already authorised. The connection is raw TCP: TLS, when the payload is
// TLS, is the client's own end to end.
//
// The signature is net.Dialer.DialContext's, so it drops into an http.Transport. network must be a
// TCP network.
func (s *Sender) EgressDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("sender: egress dial supports tcp only, not %q", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("sender: egress dial %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("sender: egress dial %q: bad port", addr)
	}
	id, err := s.captureDialIdentity(ctx, host, uint16(port), false)
	if err != nil {
		return nil, err
	}
	return s.dialPlain(ctx, host, uint16(port), id)
}
