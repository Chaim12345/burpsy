package proxy

import (
	"crypto/tls"
)

// dialUpstreamTLS opens a TLS connection to the origin, offering exactly the ALPN
// list derived from the client's own offer. Returns the negotiated protocol.
func dialUpstreamTLS(serverName, addr string, alpnOffer []string) (*tls.Conn, string, error) {
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}
	if len(alpnOffer) > 0 {
		cfg.NextProtos = alpnOffer
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, "", err
	}
	return conn, conn.ConnectionState().NegotiatedProtocol, nil
}
