package proxy

// The listener's in-browser interface (burpsy-react-ui-beof): Burp's http://burpsuite, which "you can
// access ... by visiting http://burpsuite ... or by entering the URL of your Proxy listener"
// (desktop/external-browser-config/certificate/index.html). An external browser or a mobile device
// that is already pointed at the proxy fetches the CA certificate through it, without reaching the
// console, and a browser that reaches the listener directly gets a page saying what it found, not a
// request the proxy forwards back to itself.
//
// Plain HTTP only. https://burpsuite would need the CONNECT path to mint a certificate for a host
// that resolves nowhere and answer without an upstream. The certificate this page hands out is what
// makes HTTPS through the proxy work at all, so the HTTP page is the one that matters. gaps.md
// records the difference.

import (
	"fmt"
	"html"
	"net"
	"strconv"
	"strings"
)

// webInterfaceHosts are the names that address the interface rather than an origin.
var webInterfaceHosts = map[string]bool{"burpsuite": true, "burpsy": true}

// isWebInterfaceTarget reports whether a request addresses the interface: a magic name on port 80, or
// the listener's own address (the browser was pointed at the listener directly). Forwarding the latter
// would loop the proxy into itself.
//
// The own-address half does not apply on a listener that redirects. There a client that is not
// proxy-aware (a thick client pointed at the listener, invisible proxying on) names the listener
// itself as the authority on every request, because the listener is the only server it knows about,
// and the redirect is what sends those requests on to the real origin. Answering them with this page
// would break exactly the setup "Redirect to host" / "Redirect to port" exist for, and nothing loops:
// the bytes go to the redirect target, not back to the listener. The magic names still reach the
// interface on such a listener, since they name the proxy and no origin.
//
// An invisible listener that does NOT redirect keeps the own-address match: it forwards by the Host
// header, so a request whose Host is the listener would be relayed back into the listener itself.
func (s *Server) isWebInterfaceTarget(host string, port uint16, clientConn net.Conn, spec ListenerSpec) bool {
	if s.config.options.Get(OptDisableWebInterface) {
		return false
	}
	h := strings.ToLower(strings.Trim(host, "[]"))
	if webInterfaceHosts[h] && (port == 80 || port == 0) {
		return true
	}
	if spec.redirects() || clientConn == nil || clientConn.LocalAddr() == nil {
		return false
	}
	lhost, lport, err := net.SplitHostPort(clientConn.LocalAddr().String())
	if err != nil || strconv.Itoa(int(port)) != lport {
		return false
	}
	if h == strings.ToLower(lhost) || h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return net.ParseIP(lhost) != nil && net.ParseIP(lhost).IsLoopback()
	}
	// A listener bound to every interface answers on each of the machine's addresses.
	if lip := net.ParseIP(lhost); lip != nil && lip.IsUnspecified() {
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// serveWebInterface answers one request to the interface. Nothing is forwarded or recorded: this is
// the proxy talking about itself, not traffic.
func (s *Server) serveWebInterface(conn net.Conn, method, path string) {
	if q := strings.IndexAny(path, "?#"); q >= 0 {
		path = path[:q]
	}
	switch {
	case method != "GET" && method != "HEAD":
		writeInterfaceResponse(conn, method, "405 Method Not Allowed", "text/plain; charset=utf-8", nil,
			[]byte("the burpsy proxy interface answers GET only\n"))
	case path == "/cert":
		der := s.caCertDER()
		if der == nil {
			writeInterfaceResponse(conn, method, "503 Service Unavailable", "text/plain; charset=utf-8", nil,
				[]byte("this listener has no CA certificate: TLS interception is not configured, so there is nothing to install\n"))
			return
		}
		writeInterfaceResponse(conn, method, "200 OK", "application/x-x509-ca-cert",
			[]string{`Content-Disposition: attachment; filename="burpsy-ca.der"`}, der)
	case path == "/" || path == "":
		writeInterfaceResponse(conn, method, "200 OK", "text/html; charset=utf-8", nil, []byte(s.interfacePage()))
	default:
		writeInterfaceResponse(conn, method, "404 Not Found", "text/plain; charset=utf-8", nil,
			[]byte(fmt.Sprintf("the burpsy proxy interface has no page at %s; the CA certificate is at /cert\n", path)))
	}
}

func (s *Server) caCertDER() []byte {
	if s.config.tls == nil {
		return nil
	}
	// Engine() and ExportCA() take their locks: interception is switched at runtime and the CA can be
	// replaced (import, regenerate), so neither field is read bare.
	engine := s.config.tls.Engine()
	if engine == nil {
		return nil
	}
	cert, _, ok := engine.ExportCA()
	if !ok || cert == nil {
		return nil
	}
	return cert.Raw
}

func (s *Server) interfacePage() string {
	cert := `<p><a href="/cert">CA Certificate</a>: install it in the browser or device as a trusted ` +
		`certificate authority, and HTTPS through this proxy will no longer warn.</p>`
	if s.caCertDER() == nil {
		cert = `<p>TLS interception is not configured on this listener, so there is no CA certificate to install.</p>`
	}
	return "<!doctype html><html><head><meta charset=\"utf-8\"><title>burpsy</title></head><body>" +
		"<h1>burpsy</h1><p>This browser is talking to the burpsy proxy listener. Traffic sent through it " +
		"reaches the console's HTTP history.</p>" + cert +
		"<p>" + html.EscapeString("Visit http://burpsy or http://burpsuite through the proxy to come back here.") + "</p>" +
		"</body></html>\n"
}

func writeInterfaceResponse(conn net.Conn, method, status, contentType string, extra []string, body []byte) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + status + "\r\n")
	b.WriteString("Content-Type: " + contentType + "\r\n")
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	b.WriteString("Cache-Control: no-store\r\nConnection: close\r\n")
	for _, h := range extra {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	out := []byte(b.String())
	if method != "HEAD" {
		out = append(out, body...)
	}
	_, _ = conn.Write(out)
}

// writeProxyError sends one of burpsy's own explanatory error responses, unless the operator chose
// Burp's "Suppress Burp error messages in browser" (0q9d), in which case nothing is written and the
// caller's close is all the client sees.
func (s *Server) writeProxyError(conn net.Conn, raw []byte) {
	if conn == nil || s.config.options.Get(OptSuppressErrorMessages) {
		return
	}
	_, _ = conn.Write(raw)
}
