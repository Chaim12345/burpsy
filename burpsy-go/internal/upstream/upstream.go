// Package upstream is the one place that decides which upstream proxy an egress connection goes
// through, and the one place that dials it.
//
// # Why this is its own package
//
// burpsy has two egress paths and they had nothing in common. `internal/sender` dials for every
// repeater resend, intruder payload, scanner probe, crawl fetch, sequencer capture and session macro;
// `internal/proxy` dials the origin on the far side of a CONNECT tunnel and on the plain-HTTP forward.
// A settings panel wired into one of those and not the other is worse than no panel at all: the
// operator sets a corporate proxy, watches the scanner's traffic take it, and never learns that
// everything their browser drove through the listener went straight out. So the policy and the dial
// live here, both callers hold the same *Policy, and Attach records which of them actually did — see
// Policy.Attached, which /api/network/proxy reports rather than implying coverage it cannot see.
//
// # What it decides, and what it deliberately does not
//
// It decides *which* proxy carries a connection to a given host, and it opens that connection. It has
// no scope handle and must never grow one: whether a request may be sent at all is
// sender.AuthorisedSender's gate on the outbound bytes (HARD-03), and it runs before any dial reaches
// here. A second place that can say yes to an egress is a second place that can be wrong about it.
//
// # Refuse-by-default on the proxy URL
//
// Parse refuses anything it cannot turn into a scheme, a host and a port. A proxy URL an operator
// asked for and that cannot be used must never silently become a direct connection — "my traffic went
// straight to the target" is the one outcome an operator who configured a proxy did not ask for. That
// is why there is no lenient arm that guesses http:// for a bare host:port, and why the API refuses
// the string rather than storing a rule that will fail later at dial time.
package upstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	xproxy "golang.org/x/net/proxy"
)

// Kind is the wire protocol a proxy speaks. It is a closed set because the dial code switches on it:
// an unrecognised scheme must be refused at Parse, not treated as "probably HTTP" and sent an
// absolute-form request line the peer never expected.
type Kind string

const (
	// KindDirect is no proxy at all. The zero Proxy is direct, so a policy with nothing configured
	// dials origins itself, which is exactly what burpsy did before this package existed.
	KindDirect Kind = "direct"
	// KindHTTP is an HTTP proxy reached in the clear.
	KindHTTP Kind = "http"
	// KindHTTPS is an HTTP proxy reached over TLS. The tunnel inside it is unchanged; only the leg to
	// the proxy is encrypted. Its certificate is verified — it is the operator's own infrastructure,
	// not the engagement target whose certificate an operator cannot fix.
	KindHTTPS Kind = "https"
	// KindSOCKS4 is SOCKS4, or SOCKS4a when the scheme asked for remote name resolution.
	KindSOCKS4 Kind = "socks4"
	// KindSOCKS5 is SOCKS5 (RFC 1928), with username/password auth (RFC 1929) when credentials were
	// given.
	KindSOCKS5 Kind = "socks5"
)

// Proxy is one parsed, validated upstream proxy.
//
// Credentials are unexported and there is no getter for them: String, Display and the JSON view all
// render the redacted form, so a proxy cannot be logged or served with its password by accident. The
// only thing that ever sees them is the dial code below and, for the typed net/http path, URL().
type Proxy struct {
	kind Kind
	// host and port are the proxy's own address, already validated as a numeric port.
	host string
	port uint16
	user string
	pass string
	// remoteResolve is SOCKS4a / socks5h: the proxy resolves the destination name rather than us.
	// Default for both SOCKS kinds, because a proxy that can reach a host we cannot resolve is the
	// usual reason to be using one at all.
	remoteResolve bool
}

// Parse turns a proxy URL into a Proxy, or refuses it.
//
// An empty string and the literal "direct" are the direct proxy, which is how a rule says "do not
// proxy this destination even though the default would" — Burp's per-destination list has the same
// escape and it is the only way to exempt one host from a broad default.
func Parse(raw string) (Proxy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "direct") {
		return Proxy{kind: KindDirect}, nil
	}
	if !strings.Contains(raw, "://") {
		// url.Parse accepts "127.0.0.1:8080" as scheme "127.0.0.1" with opaque "8080", which is how a
		// typo becomes a rule that dials nothing. Named rather than guessed: assuming http:// would
		// route traffic through a protocol the operator did not choose.
		return Proxy{}, fmt.Errorf("proxy %q names no scheme; write one of http://, https://, socks5:// or socks4://", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Proxy{}, fmt.Errorf("proxy %q is not a URL: %w", raw, err)
	}
	p := Proxy{}
	switch strings.ToLower(u.Scheme) {
	case "http":
		p.kind = KindHTTP
	case "https":
		p.kind = KindHTTPS
	case "socks5", "socks5h":
		p.kind = KindSOCKS5
		// socks5h is the curl spelling for "let the proxy resolve the name". We always let it: a
		// SOCKS5 dial carries the hostname, so resolving locally would defeat the point and can leak
		// the target to a resolver the engagement never authorised.
		p.remoteResolve = true
	case "socks4", "socks4a":
		p.kind = KindSOCKS4
		p.remoteResolve = strings.EqualFold(u.Scheme, "socks4a")
	default:
		return Proxy{}, fmt.Errorf("proxy %q uses scheme %q, which this build cannot speak; use http, https, socks5 or socks4",
			redactRaw(raw), u.Scheme)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		// A default port per scheme would be a guess: 8080, 3128 and 1080 are all conventions and none
		// is the answer. An operator who omitted the port gets told to write it.
		return Proxy{}, fmt.Errorf("proxy %q needs an explicit host:port (%v)", redactRaw(raw), err)
	}
	if host == "" {
		return Proxy{}, fmt.Errorf("proxy %q names no host", redactRaw(raw))
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return Proxy{}, fmt.Errorf("proxy %q has port %q, which is not a port number", redactRaw(raw), portStr)
	}
	p.host, p.port = host, uint16(port)
	if u.User != nil {
		p.user = u.User.Username()
		pass, hasPass := u.User.Password()
		p.pass = pass
		if p.kind == KindSOCKS4 && hasPass {
			// SOCKS4 has a USERID field and no password field at all (there is nowhere on the wire to
			// put one). Sending the username and dropping the password would authenticate as something
			// the operator did not configure, so the URL is refused with the fix named.
			return Proxy{}, errors.New("socks4 has no password field; drop the password from the URL or use socks5://")
		}
	}
	if u.Path != "" && u.Path != "/" {
		return Proxy{}, fmt.Errorf("proxy %q carries a path, which a proxy address cannot have", redactRaw(raw))
	}
	return p, nil
}

// Schemes is every URL scheme Parse accepts, in the order a settings panel should offer them.
//
// Exported so the API — and through it the console's hint text — names the accepted set from the
// parser rather than from a second hand-maintained list. A scheme added to Parse and forgotten here
// would be a scheme the panel refuses to suggest; a scheme listed here and not in Parse would be one
// the panel offers and the dial path cannot speak. One source removes both.
func Schemes() []string {
	return []string{"http", "https", "socks5", "socks5h", "socks4", "socks4a"}
}

// redactRaw strips any userinfo out of a raw proxy URL so an error message can quote it.
//
// Errors reach the API response and the log, and a rejected URL is exactly the case where a password
// is most likely to be mistyped into the host field. Everything up to and including the last '@'
// before the first '/' after the scheme goes.
func redactRaw(raw string) string {
	scheme := strings.Index(raw, "://")
	if scheme < 0 {
		return raw
	}
	rest := raw[scheme+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return raw
	}
	return raw[:scheme+3] + "***@" + authority[at+1:] + rest[end:]
}

// IsDirect reports whether this proxy is no proxy.
func (p Proxy) IsDirect() bool { return p.kind == KindDirect || p.kind == "" }

// Kind reports which protocol this proxy speaks.
func (p Proxy) Kind() Kind {
	if p.kind == "" {
		return KindDirect
	}
	return p.kind
}

// Addr is the proxy's own host:port, empty for direct.
func (p Proxy) Addr() string {
	if p.IsDirect() {
		return ""
	}
	return net.JoinHostPort(p.host, strconv.Itoa(int(p.port)))
}

// baseFor is the dialer a SOCKS hop opens its own socket with: the caller's when it supplied one,
// and a fresh timeout-bounded dialer otherwise.
//
// The carrier is NOT applied here. Go's net.Dialer has no dialer-shaped field to override -- Dial and
// DialContext are methods -- so a dialer carrying a carrier would silently ignore it. The carrier is
// applied at the socket open instead, in openSocket, which every connection in this package goes
// through.
func baseFor(base *net.Dialer, timeout time.Duration) *net.Dialer {
	if base == nil {
		base = &net.Dialer{}
	}
	clone := *base
	if timeout > 0 {
		clone.Timeout = timeout
	}
	return &clone
}

// openSocket opens one TCP connection, honouring the carrier.
//
// Every socket in this package is opened here or through baseFor, so the layering is reached by
// construction rather than by a call site remembering to ask for it.
func openSocket(ctx context.Context, base *net.Dialer, carrier *Carrier, network, addr string) (net.Conn, error) {
	if carrier == nil {
		if base == nil {
			base = &net.Dialer{}
		}
		return base.DialContext(ctx, network, addr)
	}
	return carrier.dialTCP(ctx, base, network, addr)
}

// hostOnly and portOnly are the proxy address split, for the carrier's self-exemption. The
// exemption compares BOTH: matching on the host alone would exempt every other service on the same
// interface, which is a carrier that silently does nothing for an operator whose SOCKS server and
// targets share 127.0.0.1 — a dev box, and exactly where a bypass list is most wanted.
func (p Proxy) hostOnly() string { return p.host }

func (p Proxy) portOnly() string { return strconv.Itoa(int(p.port)) }

// dialVia reaches a destination through a SOCKS hop, with the hop's own socket opened by base.
//
// It is the one place the carrier's layering happens, and it exists as a method rather than inline in
// carrier.go so the SOCKS handshake itself stays with the SOCKS code that already knows how to speak
// it. The only difference from dialSocks4/dialSocks5 is the socket: those open the proxy's address
// themselves, and this one is handed a socket that already came through the layer beneath.
func (p Proxy) dialVia(ctx context.Context, network, addr string, base *net.Dialer, remote bool) (net.Conn, error) {
	if remote {
		// The caller's choice wins over the URL scheme's default: a socks4a:// or socks5h:// address
		// says resolve remotely, and the settings panel's checkbox says the same, so they agree. Where
		// they disagree the carrier's explicit flag is the one an operator just set.
		hopped := p
		hopped.remoteResolve = true
		return hopped.dialSocks5(ctx, network, addr, base.Timeout, base, nil)
	}
	// Otherwise the existing path opens the proxy socket itself, which is already the right layering:
	// that dial goes to the SOCKS server's own address, and carrier.carries exempts it above so the
	// recursion cannot form.
	return p.dialSocks5(ctx, network, addr, base.Timeout, base, nil)
}

// HasCredentials reports whether a username (and possibly a password) was configured. Reported
// instead of the values, so an operator can see that authentication is set up without the API ever
// serving the secret.
func (p Proxy) HasCredentials() bool { return p.user != "" }

// Display is the proxy as an operator should see it: scheme, host, port, and "***@" in place of any
// credentials. This is what the API serves, what the log carries, and what String returns — there is
// deliberately no rendering anywhere in this package that includes the password.
func (p Proxy) Display() string {
	if p.IsDirect() {
		return "direct"
	}
	creds := ""
	if p.user != "" {
		creds = "***@"
	}
	return string(p.kind) + "://" + creds + p.Addr()
}

// String is Display. Named so that a Proxy handed to a %v or a zap.Stringer cannot leak.
func (p Proxy) String() string { return p.Display() }

// URL renders this proxy for net/http's Transport.Proxy, credentials included, or nil for anything
// that is not an HTTP-family proxy.
//
// This is the one function that emits the password, and it emits it into a *url.URL net/http turns
// straight into a Proxy-Authorization header. SOCKS returns nil because net/http would treat an
// unrecognised proxy scheme as an HTTP proxy and send it an absolute-form request line — see
// Policy.HTTPProxyForRequest.
func (p Proxy) URL() *url.URL {
	if p.kind != KindHTTP && p.kind != KindHTTPS {
		return nil
	}
	u := &url.URL{Scheme: string(p.kind), Host: p.Addr()}
	if p.user != "" {
		u.User = url.UserPassword(p.user, p.pass)
	}
	return u
}

// DialContext opens a connection to addr — the *destination*, not this proxy — through this proxy.
//
// The returned connection is a byte pipe to the destination: for the HTTP kinds a CONNECT tunnel, for
// the SOCKS kinds a SOCKS-negotiated relay. That uniformity is the point, and it is why the HTTP kinds
// use CONNECT even for a cleartext destination. The alternative — rewriting the request line to
// absolute form — cannot be done on burpsy's raw paths at all: those carry deliberately malformed
// request lines (a duplicated Content-Length, an unparseable start line) whose whole purpose is to
// reach the origin byte for byte, and re-rendering one as `GET http://host/path` would send a
// different probe than the operator wrote. One mechanism that preserves bytes beats two that disagree.
// A proxy configured to refuse CONNECT to port 80 (Squid's shipped default) therefore refuses these,
// visibly, rather than quietly sending something else; a SOCKS proxy has no such restriction.
//
// The typed net/http path is the deliberate exception and does not come through here: net/http applies
// an HTTP proxy itself, in absolute form for cleartext and CONNECT for TLS, which is the ordinary
// client behaviour and involves no operator-authored bytes.
func (p Proxy) DialContext(ctx context.Context, network, addr string, timeout time.Duration, carrier *Carrier) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("upstream proxy %s cannot carry %q connections", p.Display(), network)
	}
	switch p.Kind() {
	case KindDirect:
		// Through the carrier, and this arm is the one that matters most: an operator who configures
		// a SOCKS layer and NO upstream proxy — which is the ordinary case for that setting, and the
		// one the live pass exercised — has a policy whose resolved proxy is Direct, so every
		// connection in the process arrives here. Opening a bare net.Dialer here made the carrier
		// configured, reported as configured, and inert on exactly the path it exists for
		// (burpsy-react-ui-mr83 part 3).
		return openSocket(ctx, baseFor(nil, timeout), carrier, network, addr)
	case KindHTTP, KindHTTPS:
		return p.dialConnect(ctx, network, addr, timeout, carrier)
	case KindSOCKS5:
		return p.dialSocks5(ctx, network, addr, timeout, nil, carrier)
	case KindSOCKS4:
		return p.dialSocks4(ctx, network, addr, timeout, nil, carrier)
	default:
		// Unreachable: Parse is the only constructor and it refuses every other scheme. Named rather
		// than falling through to a direct dial, because "the proxy was ignored" is the one failure
		// this package exists to make impossible.
		return nil, fmt.Errorf("upstream proxy kind %q has no dial path", p.kind)
	}
}

// dialConnect opens the carrier connection to an HTTP-family proxy and tunnels to addr with CONNECT.
// carrier is the global SOCKS layer, applied to the socket opened to reach THIS proxy. That is the
// case the carrier exists for: an HTTP proxy that is itself only reachable through a SOCKS hop is
// the ordinary corporate shape, and opening this socket any other way makes the setting silently
// not apply to the one path an operator most often needs it on (burpsy-react-ui-mr83 part 3).
func (p Proxy) dialConnect(ctx context.Context, network, addr string, timeout time.Duration, globalCarrier *Carrier) (net.Conn, error) {
	dialer := baseFor(nil, timeout)
	var hop net.Conn
	var err error
	if p.kind == KindHTTPS {
		// Verified, deliberately. This leg goes to the operator's own proxy, not to an engagement
		// target whose certificate nobody can fix, so skipping verification here would give away the
		// credentials in the CONNECT below to whoever answered.
		//
		// NOT carried, and the limit is deliberate and stated rather than hidden: crypto/tls calls
		// DialContext on the net.Dialer it is handed, and Go's net.Dialer has no field a carrier can
		// replace, so there is no way to put a SOCKS hop under an HTTPS proxy without reimplementing
		// the TLS dial here. An operator whose upstream is HTTPS gets a carrier that covers every
		// other leg, and this one direct — which is reported rather than left to be discovered as a
		// hang (burpsy-react-ui-mr83 part 3).
		td := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: p.host}}
		hop, err = td.DialContext(ctx, network, p.Addr())
	} else {
		hop, err = openSocket(ctx, dialer, globalCarrier, network, p.Addr())
	}
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %s unreachable: %w", p.Display(), err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		hop.SetDeadline(deadline)
	} else if timeout > 0 {
		hop.SetDeadline(time.Now().Add(timeout))
	}

	var req strings.Builder
	fmt.Fprintf(&req, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if p.user != "" {
		token := base64.StdEncoding.EncodeToString([]byte(p.user + ":" + p.pass))
		fmt.Fprintf(&req, "Proxy-Authorization: Basic %s\r\n", token)
	}
	req.WriteString("\r\n")
	if _, err := hop.Write([]byte(req.String())); err != nil {
		hop.Close()
		return nil, fmt.Errorf("writing CONNECT to %s: %w", p.Display(), err)
	}
	status, err := readConnectReply(hop)
	if err != nil {
		hop.Close()
		return nil, fmt.Errorf("reading CONNECT reply from %s: %w", p.Display(), err)
	}
	if status < 200 || status > 299 {
		hop.Close()
		return nil, fmt.Errorf("upstream proxy %s answered %d to CONNECT %s", p.Display(), status, addr)
	}
	// The handshake's deadline must not become the connection's: the caller sets its own for the
	// exchange it is about to run, and leaving this one armed would kill a long-lived tunnel — a
	// WebSocket relay, an intercepted keep-alive connection — at the dial timeout.
	hop.SetDeadline(time.Time{})
	return hop, nil
}

// readConnectReply reads exactly the CONNECT response head off conn and returns its status code.
//
// One byte at a time until CRLFCRLF, rather than a bufio.Reader and http.ReadResponse. A buffered
// reader may pull the first bytes the *origin* sent into its own buffer, and those bytes are the start
// of the tunnelled conversation: they would be lost when the reader is discarded, or would force this
// function to return a wrapper that replays them. Reading the head exactly is a few hundred single-byte
// reads on a socket during a handshake, which costs nothing, and it hands back a connection positioned
// precisely at the first tunnelled byte.
func readConnectReply(conn net.Conn) (int, error) {
	const maxHead = 8 << 10
	head := make([]byte, 0, 128)
	one := make([]byte, 1)
	for len(head) < maxHead {
		if _, err := io.ReadFull(conn, one); err != nil {
			return 0, err
		}
		head = append(head, one[0])
		if len(head) >= 4 && string(head[len(head)-4:]) == "\r\n\r\n" {
			break
		}
	}
	line := string(head)
	if i := strings.Index(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0, fmt.Errorf("reply is not an HTTP status line: %q", line)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, fmt.Errorf("reply status %q is not a number", fields[1])
	}
	return code, nil
}

// dialSocks5 tunnels to addr through a SOCKS5 proxy, using golang.org/x/net/proxy rather than a
// hand-rolled negotiation.
//
// x/net/proxy is already in this module's dependency graph and its socks5 implementation is the one
// the standard library itself vendors for Transport's socks5 support. Re-implementing RFC 1928's
// method negotiation and RFC 1929's auth sub-negotiation would be a second copy of code that is
// already here and already tested.
// base is the dialer that opens the socket to the SOCKS server itself. Nil opens one bounded only
// by timeout; see dialSocks4's note.
func (p Proxy) dialSocks5(ctx context.Context, network, addr string, timeout time.Duration, base *net.Dialer, carrier *Carrier) (net.Conn, error) {
	var auth *xproxy.Auth
	if p.user != "" {
		auth = &xproxy.Auth{User: p.user, Password: p.pass}
	}
	dialer, err := xproxy.SOCKS5(network, p.Addr(), auth, baseFor(base, timeout))
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %s: %w", p.Display(), err)
	}
	// Every dialer x/net/proxy returns for SOCKS5 implements ContextDialer; the assertion is checked
	// rather than assumed so a future version that stops doing so fails here instead of losing the
	// caller's cancellation.
	ctxDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("upstream proxy %s: socks5 dialer does not honour a context", p.Display())
	}
	conn, err := ctxDialer.DialContext(ctx, network, addr)
	if err != nil {
		// The error from x/net/proxy carries the proxy address but not its scheme, and never the
		// credentials — safe to wrap verbatim.
		return nil, fmt.Errorf("upstream proxy %s could not reach %s: %w", p.Display(), addr, err)
	}
	return conn, nil
}

// socks4 reply codes, RFC-less but universally implemented as in the original SOCKS4 note.
const (
	socks4Granted    = 90
	socks4Rejected   = 91
	socks4NoIdentd   = 92
	socks4IdentdFail = 93
)

// dialSocks4 tunnels to addr through a SOCKS4 (or SOCKS4a) proxy.
//
// Hand-rolled, and stated as such because the rest of this file prefers the library: golang.org/x/net
// implements SOCKS5 only, and there is no SOCKS4 anywhere in the module graph. The protocol is one
// 9-byte-plus-userid request and one 8-byte reply, so the choice is between these forty lines and
// declining SOCKS4 outright — and declining it would leave the settings panel offering a scheme the
// dial path cannot speak, which is the shape of defect this repo treats as a bug.
//
// SOCKS4 addresses the destination by IPv4 literal; SOCKS4a adds a hostname form. A socks4:// URL
// therefore resolves the destination here, locally, and a name that resolves only to IPv6 is refused
// rather than silently dialled somewhere else — socks4a:// is the spelling that hands the name to the
// proxy instead.
// base is the dialer that opens the socket to the SOCKS server itself. Nil opens one bounded only
// by timeout, which is what every caller before the carrier passed; the carrier passes its own
// resolved base so a proxied dial keeps the operator's resolver and connect bound all the way down.
func (p Proxy) dialSocks4(ctx context.Context, network, addr string, timeout time.Duration, base *net.Dialer, carrier *Carrier) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %s: destination %q is not host:port", p.Display(), addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("upstream proxy %s: destination port %q is not a port number", p.Display(), portStr)
	}

	var dst [4]byte
	var remoteName string
	if p.remoteResolve {
		// SOCKS4a: 0.0.0.x with x nonzero is the sentinel that says "the hostname follows".
		dst = [4]byte{0, 0, 0, 1}
		remoteName = host
	} else if ip := net.ParseIP(host); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return nil, fmt.Errorf("upstream proxy %s: socks4 carries IPv4 addresses only, and %s is not one; use socks5://",
				p.Display(), host)
		}
		copy(dst[:], v4)
	} else {
		addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("upstream proxy %s: socks4 needs an IPv4 address for %s and none resolved (use socks4a:// to let the proxy resolve it): %w",
				p.Display(), host, err)
		}
		copy(dst[:], addrs[0].To4())
	}

	conn, err := openSocket(ctx, base, carrier, network, p.Addr())
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %s unreachable: %w", p.Display(), err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
	}

	req := []byte{4, 1, byte(port >> 8), byte(port)}
	req = append(req, dst[:]...)
	req = append(req, []byte(p.user)...) // USERID; empty is legal and usual
	req = append(req, 0)
	if remoteName != "" {
		req = append(req, []byte(remoteName)...)
		req = append(req, 0)
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("writing socks4 request to %s: %w", p.Display(), err)
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading socks4 reply from %s: %w", p.Display(), err)
	}
	if reply[1] != socks4Granted {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy %s refused %s: %s", p.Display(), addr, socks4Reason(reply[1]))
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks4Reason(code byte) string {
	switch code {
	case socks4Rejected:
		return "request rejected or failed (91)"
	case socks4NoIdentd:
		return "proxy could not reach an identd on this client (92)"
	case socks4IdentdFail:
		return "identd reported a different user than the request's USERID (93)"
	default:
		return fmt.Sprintf("unrecognised reply code %d", code)
	}
}

// Rule is one destination pattern and the proxy that carries traffic to it.
type Rule struct {
	// Pattern is a host pattern in exactly the language Scope and -tls-passthrough use: an exact
	// host, `*.example.com` for a domain and its subdomains, or `*` for everything. Shared rather
	// than reinvented — a third wildcard-host dialect in this tree would be one more thing for an
	// operator to be wrong about.
	Pattern string
	Proxy   Proxy
	// match is the compiled pattern. Built once at Add rather than per dial.
	match *core.ScopeRule
}

// Policy is the ordered rule list plus the default, and the dialer that resolves them.
//
// Ordered, first match wins, exactly like Burp's upstream proxy list: an operator writes the specific
// exemptions above the broad rule. The default is what carries a destination no rule matched, and a
// direct default is the state burpsy has always been in.
type Policy struct {
	mu       sync.RWMutex
	rules    []Rule
	def      Proxy
	attached map[string]int
}

// NewPolicy returns an empty policy: no rules, a direct default, nothing attached.
func NewPolicy() *Policy {
	return &Policy{attached: map[string]int{}}
}

// Attach records that one egress surface holds this policy.
//
// The reason this exists rather than being assumed: a rule change reaches exactly the surfaces that
// hold this object, and there is no way for the API to know that from the policy's contents. Reported
// by GET /api/network/proxy so an operator can see whether the proxy listener's own upstream leg is
// covered, instead of reading a settings panel that looks global and is not.
func (p *Policy) Attach(surface string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.attached == nil {
		p.attached = map[string]int{}
	}
	p.attached[surface]++
}

// Attached reports how many holders each surface registered.
func (p *Policy) Attached() map[string]int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]int, len(p.attached))
	for k, v := range p.attached {
		out[k] = v
	}
	return out
}

// AttachedSurfaces is Attached's keys, sorted, for a stable rendering.
func (p *Policy) AttachedSurfaces() []string {
	counts := p.Attached()
	out := make([]string, 0, len(counts))
	for k := range counts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Set installs a rule for pattern, replacing any rule with exactly that pattern in place.
//
// Upsert rather than append, and this is load-bearing for startup: flag-configured rules are applied
// after the persisted ones are restored, so a rule named on the command line that is already in the
// database must not become two entries whose second copy is unreachable. Replacing in place also keeps
// the operator's ordering, which is the rule list's semantics.
//
// Returns whether an existing rule was replaced.
func (p *Policy) Set(pattern, proxyURL string) (bool, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false, errors.New("a rule needs a host pattern; use * for every destination")
	}
	proxy, err := Parse(proxyURL)
	if err != nil {
		return false, err
	}
	rule := Rule{Pattern: pattern, Proxy: proxy, match: core.NewScopeRule(core.ScopeInclude, pattern)}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.rules {
		if p.rules[i].Pattern == pattern {
			p.rules[i] = rule
			return true, nil
		}
	}
	p.rules = append(p.rules, rule)
	return false, nil
}

// Remove deletes the rule whose pattern is exactly pattern, reporting whether one was there.
//
// Exact match, not a pattern that would also match the host: a double-clicked remove must answer "no
// such rule" the second time rather than deleting a second, different rule that happens to cover the
// same hosts. The caller turns false into a 404.
func (p *Policy) Remove(pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.rules {
		if p.rules[i].Pattern == pattern {
			p.rules = append(p.rules[:i], p.rules[i+1:]...)
			return true
		}
	}
	return false
}

// SetDefault installs the proxy for destinations no rule matches. An empty string or "direct" clears
// it back to dialling origins ourselves.
func (p *Policy) SetDefault(proxyURL string) error {
	proxy, err := Parse(proxyURL)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.def = proxy
	return nil
}

// Default is the proxy for destinations no rule matches.
func (p *Policy) Default() Proxy {
	if p == nil {
		return Proxy{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.def
}

// Rules returns the ordered rule list.
func (p *Policy) Rules() []Rule {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Rule, len(p.rules))
	copy(out, p.rules)
	return out
}

// Clear removes every rule and the default, putting the policy back to dialling origins directly.
func (p *Policy) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = nil
	p.def = Proxy{}
}

// Empty reports whether nothing is configured, so a reader can tell "no proxy" from "a proxy that
// resolves to direct for this host".
func (p *Policy) Empty() bool {
	if p == nil {
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.rules) == 0 && p.def.IsDirect()
}

// For resolves the proxy that carries traffic to host. First matching rule wins; the default carries
// what nothing matched.
func (p *Policy) For(host string) Proxy {
	if p == nil {
		return Proxy{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, r := range p.rules {
		if r.match != nil && r.match.Matches(host, 0) {
			return r.Proxy
		}
	}
	return p.def
}

// ForAddr resolves the proxy for a host:port, or for a bare host.
func (p *Policy) ForAddr(addr string) Proxy {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	return p.For(host)
}

// HTTPProxyForRequest is net/http Transport.Proxy: the HTTP-family proxy for this request's host, or
// nil.
//
// Nil for the SOCKS kinds *on purpose*. net/http speaks socks5 natively but has no socks4 at all, and
// its dialConn falls through an unrecognised proxy scheme into the HTTP-proxy arm — so returning a
// socks4:// URL here would send a SOCKS proxy an absolute-form HTTP request line. Both SOCKS kinds are
// therefore applied in the dialer instead (see Dialer.DialContext), which keeps one SOCKS
// implementation for every path in the tree.
func (p *Policy) HTTPProxyForRequest(req *http.Request) (*url.URL, error) {
	if p == nil || req == nil || req.URL == nil {
		return nil, nil
	}
	return p.For(req.URL.Hostname()).URL(), nil
}

// isHTTPProxyAddr reports whether addr is the address of an HTTP-family proxy this policy configures.
//
// Needed because of how net/http composes Transport.Proxy with Transport.DialContext: when Proxy
// returns a URL, the dialer is handed the *proxy's* address rather than the destination's. Without
// this check the dialer would resolve the policy for the proxy's own hostname and, if that matched a
// rule, tunnel the proxy connection through another proxy — a chain nobody asked for, produced by a
// coincidence of names.
func (p *Policy) isHTTPProxyAddr(addr string) bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	candidates := make([]Proxy, 0, len(p.rules)+1)
	candidates = append(candidates, p.def)
	for _, r := range p.rules {
		candidates = append(candidates, r.Proxy)
	}
	for _, c := range candidates {
		if (c.kind == KindHTTP || c.kind == KindHTTPS) && c.Addr() == addr {
			return true
		}
	}
	return false
}

// Dialer dials through a Policy, with a bound on the dial and the proxy handshake.
//
// A struct rather than a method on Policy because the timeout belongs to the caller — a sender has a
// configured per-send timeout, the proxy's relay legs have none of their own — and not to the policy.
type Dialer struct {
	// Policy resolves which proxy carries a connection. Nil dials directly, which is what every
	// caller in this tree does when no policy was configured.
	Policy *Policy
	// Timeout bounds the TCP dial and the proxy handshake. Zero leaves the context as the only bound.
	Timeout time.Duration
	// Base, when set, is the dialer used for every TCP connection this one opens — to the proxy on a
	// proxied dial, to the origin on a direct one.
	//
	// It exists because the resolver is not this package's business and must not be lost by it. The
	// network settings carry a hostname-resolution override and a DNS lookup policy; a proxied dial
	// that constructed its own bare net.Dialer would silently ignore both, so "route through this
	// proxy" would quietly also mean "and stop honouring my resolver". Nil keeps the old behaviour:
	// a fresh dialer bounded only by Timeout.
	Base *net.Dialer
	// Carrier is the global SOCKS layer, applied BENEATH whatever the policy resolved: a connection
	// to an HTTP upstream proxy, to a SOCKS rule proxy, or straight to an origin, is all opened
	// through the carrier when it carries that destination. Nil is no carrier, which is what every
	// caller in this tree passes and what the settings are when no hop is configured.
	//
	// It is a field rather than a global because a process can hold more than one egress surface
	// (the proxy listener, the sender, a scanner), and a carrier is per-surface configuration the
	// operator sets on the panel that owns it.
	Carrier *Carrier
}

// base returns the dialer to open TCP with, honouring Base when the caller supplied one.
//
// Timeout is applied on top rather than trusted from Base, so a caller that set one here still gets
// it even if the base dialer it passed had none.
func (d Dialer) base() *net.Dialer {
	if d.Base == nil {
		return &net.Dialer{Timeout: d.Timeout}
	}
	clone := *d.Base
	if d.Timeout > 0 {
		clone.Timeout = d.Timeout
	}
	return &clone
}

// DialContext opens a connection to addr, through whichever proxy the policy resolves for it.
//
// The HTTP-family proxies are skipped for one specific address: the proxy's own, which is what
// net/http hands this dialer once Transport.Proxy has returned a URL. See Policy.isHTTPProxyAddr.
func (d Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	base := d.base()
	// The carrier is applied on EVERY path, and that is the feature: a destination with no proxy rule
	// goes through the SOCKS hop, a destination behind an HTTP proxy goes through the SOCKS hop to
	// REACH that proxy, and the proxy's own connection is exempt from the carrier so the hop cannot
	// dial itself. Routing the direct path around the carrier would leave the global setting meaning
	// "proxy through SOCKS", which is not what Burp's setting says -- it says every outbound
	// connection (settings/network/connections.html:177-199).
	if d.Policy == nil {
		return openSocket(ctx, base, d.Carrier, network, addr)
	}
	if d.Policy.isHTTPProxyAddr(addr) {
		// The address of a proxy this policy configures. It skips the POLICY, deliberately: the
		// check exists so a proxy connection is not resolved against a rule and tunnelled through
		// another proxy (see isHTTPProxyAddr's comment), and a chain nobody asked for is the failure it
		// prevents.
		//
		// It does NOT skip the CARRIER, and that is the whole feature. An HTTP upstream proxy that is
		// itself only reachable through a SOCKS hop is the ordinary corporate shape, and this is the
		// socket that has to carry the hop — exempting it would leave the global setting applying to
		// nothing that matters (burpsy-react-ui-mr83 part 3).
		return openSocket(ctx, base, d.Carrier, network, addr)
	}
	return d.Policy.ForAddr(addr).DialContext(ctx, network, addr, d.Timeout, d.Carrier)
}

// Dial satisfies the one-shot form some callers want. Equivalent to DialContext with a background
// context.
func (d Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// ---- persistence ------------------------------------------------------------------------------

// Raw renders this proxy back into a URL Parse accepts, credentials included.
//
// The only caller is the durable store, which has to be able to restore a working policy across a
// restart — a persisted rule that came back without its password would silently start failing
// authentication, which is the same class of lie as a rule that silently stopped proxying. It is
// deliberately *not* the String method: String and Display redact, so a Proxy reaching a log line, an
// error message or a JSON encoder cannot take this path by accident. Nothing in internal/web calls it.
func (p Proxy) Raw() string {
	if p.IsDirect() {
		return ""
	}
	u := &url.URL{Scheme: string(p.kind), Host: p.Addr()}
	if p.remoteResolve && p.kind == KindSOCKS4 {
		u.Scheme = "socks4a"
	}
	if p.user != "" {
		if p.pass != "" {
			u.User = url.UserPassword(p.user, p.pass)
		} else {
			u.User = url.User(p.user)
		}
	}
	return u.String()
}

// SnapshotRule is one persisted rule.
type SnapshotRule struct {
	Pattern string `json:"pattern"`
	Proxy   string `json:"proxy"`
}

// Snapshot is a whole policy as a value, for the settings row that persists it and for a test that
// wants to compare two policies without reaching into them.
type Snapshot struct {
	Default string         `json:"default"`
	Rules   []SnapshotRule `json:"rules"`
}

// Snapshot renders the policy, credentials included, for the durable store. See Proxy.Raw.
func (p *Policy) Snapshot() Snapshot {
	if p == nil {
		return Snapshot{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := Snapshot{Default: p.def.Raw(), Rules: make([]SnapshotRule, 0, len(p.rules))}
	for _, r := range p.rules {
		out.Rules = append(out.Rules, SnapshotRule{Pattern: r.Pattern, Proxy: r.Proxy.Raw()})
	}
	return out
}

// Restore replaces the policy's contents with a snapshot.
//
// Every entry is re-parsed rather than trusted, so a hand-edited database row that no longer parses is
// refused here instead of becoming a rule that cannot dial. The first unusable entry stops the restore
// and is returned: a partially restored proxy policy is the one state an operator must not be left
// silently holding.
func (p *Policy) Restore(s Snapshot) error {
	def, err := Parse(s.Default)
	if err != nil {
		return fmt.Errorf("stored default upstream proxy: %w", err)
	}
	rules := make([]Rule, 0, len(s.Rules))
	for _, r := range s.Rules {
		pattern := strings.TrimSpace(r.Pattern)
		if pattern == "" {
			return errors.New("stored upstream proxy rule has no host pattern")
		}
		proxy, err := Parse(r.Proxy)
		if err != nil {
			return fmt.Errorf("stored upstream proxy rule for %q: %w", pattern, err)
		}
		rules = append(rules, Rule{Pattern: pattern, Proxy: proxy, match: core.NewScopeRule(core.ScopeInclude, pattern)})
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.def = def
	p.rules = rules
	return nil
}
