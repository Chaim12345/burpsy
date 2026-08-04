package proxy

import (
	"context"
	"crypto/tls"

	"github.com/burpsy-go/burpsy/internal/alpn"
)

// dialUpstreamTLS opens a TLS connection to the origin, offering exactly the ALPN
// list derived from the client's own offer. Returns the negotiated protocol.
//
// Certificate verification is off on this leg deliberately: the proxy exists to reach targets whose
// certificate an operator cannot fix, and the client leg is presented with burpsy's own CA anyway. A
// sender's egress leg follows SenderConfig.TLSVerify instead, which is why the choice is a field on
// alpn.Dialer rather than a constant inside it.
func dialUpstreamTLS(serverName, addr string, alpnOffer []string) (*tls.Conn, string, error) {
	return alpn.Dialer{InsecureSkipVerify: true}.Dial(context.Background(), serverName, addr, alpnOffer)
}
