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
//
// clientCerts is the per-host client-certificate source, or nil. This is the leg that makes TLS
// client authentication work through the proxy at all: the browser's own certificate cannot reach the
// origin, because the browser is talking to burpsy's leaf and burpsy is opening a separate connection
// onward. Before this existed, an app requiring a client certificate could only be reached by putting
// its host on the TLS passthrough list — which is to say by giving up interception entirely, which is
// the one thing the operator was using this tool to do.
func dialUpstreamTLS(serverName, addr string, alpnOffer []string, clientCerts alpn.ClientCertSource) (*tls.Conn, string, error) {
	return alpn.Dialer{InsecureSkipVerify: true, ClientCerts: clientCerts}.
		Dial(context.Background(), serverName, addr, alpnOffer)
}
