// Package upstreamtest runs real upstream proxies in-process, so a test can prove that egress actually
// traversed one rather than that a configuration field was set.
//
// # Why this is a package rather than a helper in each test file
//
// Three packages need it — internal/upstream for the dial paths themselves, internal/sender for the
// tool's own egress and internal/proxy for the listener's origin-facing leg — and the whole point of
// Unit 9 is that those three must not diverge. Three copies of a fake proxy would be three chances for
// one of them to be lenient in a way that hides a real gap: a copy that answered 200 to a CONNECT it
// never parsed would pass while the client sent nonsense.
//
// Every server here records the destination it was asked for, which is the assertion that matters.
// "The proxy received a CONNECT for example.test:443" is proof of traversal; "the policy has a rule"
// is not.
package upstreamtest

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// Proxy is a running in-process proxy.
type Proxy struct {
	listener net.Listener

	mu sync.Mutex
	// requests is every destination asked for, in order.
	requests []string
	// credentials is the username seen per request, empty when none was offered.
	credentials []string
	// failures is anything the server could not make sense of. Kept and surfaced by Errors() rather
	// than swallowed: a test whose client sent a malformed handshake must fail loudly, not time out.
	failures []string
}

// Addr is the proxy's own host:port, for a proxy URL.
func (p *Proxy) Addr() string { return p.listener.Addr().String() }

// Requests is every destination this proxy was asked to reach, in order.
func (p *Proxy) Requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.requests...)
}

// Credentials is the username offered with each request, parallel to Requests.
func (p *Proxy) Credentials() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.credentials...)
}

// Errors is everything the proxy could not parse.
func (p *Proxy) Errors() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.failures...)
}

// Saw reports whether this proxy was asked to reach dst.
func (p *Proxy) Saw(dst string) bool {
	for _, got := range p.Requests() {
		if got == dst {
			return true
		}
	}
	return false
}

func (p *Proxy) record(dst, user string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, dst)
	p.credentials = append(p.credentials, user)
}

func (p *Proxy) fail(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures = append(p.failures, fmt.Sprintf(format, args...))
}

// serve accepts connections until the listener closes, handing each to handle.
func (p *Proxy) serve(handle func(net.Conn)) {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go handle(conn)
	}
}

// start makes a listener bound to loopback and registers its cleanup.
func start(t *testing.T) *Proxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &Proxy{listener: listener}
	t.Cleanup(func() { listener.Close() })
	return p
}

// pipe joins two connections until either end closes. Both directions must be copied concurrently:
// copying one to completion first deadlocks anything that expects a reply before it finishes sending.
func pipe(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// StartConnect runs an HTTP proxy that answers CONNECT and tunnels to the requested destination.
//
// requireUser, when non-empty, makes the proxy answer 407 unless Proxy-Authorization carries exactly
// that user and password — so a test can prove credentials are actually sent, not merely stored.
func StartConnect(t *testing.T, requireUser, requirePass string) *Proxy {
	t.Helper()
	p := start(t)
	go p.serve(func(conn net.Conn) {
		head, err := readHead(conn)
		if err != nil {
			p.fail("reading request head: %v", err)
			conn.Close()
			return
		}
		lines := strings.Split(head, "\r\n")
		fields := strings.Fields(lines[0])
		if len(fields) < 3 || fields[0] != "CONNECT" {
			// Named rather than tolerated. A proxy that accepted anything here would let a client that
			// forgot to tunnel pass this test.
			p.fail("first line is not a CONNECT: %q", lines[0])
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			conn.Close()
			return
		}
		dst := fields[1]
		user, pass := basicCredentials(lines)
		p.record(dst, user)
		if requireUser != "" && (user != requireUser || pass != requirePass) {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			conn.Close()
			return
		}
		origin, err := net.Dial("tcp", dst)
		if err != nil {
			conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			conn.Close()
			return
		}
		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			origin.Close()
			conn.Close()
			return
		}
		pipe(conn, origin)
	})
	return p
}

// basicCredentials pulls the user and password out of a Proxy-Authorization header, if there is one.
func basicCredentials(lines []string) (user, pass string) {
	for _, line := range lines {
		name, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "Proxy-Authorization") {
			continue
		}
		token := strings.TrimSpace(value)
		token = strings.TrimPrefix(token, "Basic ")
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
		if err != nil {
			return "", ""
		}
		u, p, _ := strings.Cut(string(raw), ":")
		return u, p
	}
	return "", ""
}

// readHead reads up to and including the CRLFCRLF that ends a request head.
func readHead(conn net.Conn) (string, error) {
	const max = 8 << 10
	head := make([]byte, 0, 256)
	one := make([]byte, 1)
	for len(head) < max {
		if _, err := io.ReadFull(conn, one); err != nil {
			return string(head), err
		}
		head = append(head, one[0])
		if len(head) >= 4 && string(head[len(head)-4:]) == "\r\n\r\n" {
			return string(head), nil
		}
	}
	return string(head), fmt.Errorf("request head exceeded %d bytes", max)
}

// StartSOCKS5 runs a SOCKS5 proxy (RFC 1928) with optional username/password auth (RFC 1929).
//
// Enough of the protocol to be a real peer for golang.org/x/net/proxy: method negotiation, the CONNECT
// command with all three address forms, and a reply carrying the bound address. It refuses what it does
// not implement rather than answering success, so a client that sends something unexpected fails the
// test instead of passing it.
func StartSOCKS5(t *testing.T, requireUser, requirePass string) *Proxy {
	t.Helper()
	p := start(t)
	go p.serve(func(conn net.Conn) {
		if err := p.socks5Handshake(conn, requireUser, requirePass); err != nil {
			p.fail("socks5: %v", err)
			conn.Close()
		}
	})
	return p
}

func (p *Proxy) socks5Handshake(conn net.Conn, requireUser, requirePass string) error {
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return fmt.Errorf("reading greeting: %w", err)
	}
	if greeting[0] != 5 {
		return fmt.Errorf("version %d is not socks5", greeting[0])
	}
	methods := make([]byte, greeting[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("reading methods: %w", err)
	}
	wantMethod := byte(0x00) // no auth
	if requireUser != "" {
		wantMethod = 0x02 // username/password
	}
	if !contains(methods, wantMethod) {
		conn.Write([]byte{5, 0xFF})
		return fmt.Errorf("client offered no method %#x", wantMethod)
	}
	if _, err := conn.Write([]byte{5, wantMethod}); err != nil {
		return err
	}

	user := ""
	if wantMethod == 0x02 {
		var err error
		user, err = p.socks5Auth(conn, requireUser, requirePass)
		if err != nil {
			return err
		}
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return fmt.Errorf("reading request: %w", err)
	}
	if request[1] != 1 {
		conn.Write([]byte{5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("command %d is not CONNECT", request[1])
	}
	var host string
	switch request[3] {
	case 1: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		host = net.IP(buf).String()
	case 3: // domain name
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		buf := make([]byte, length[0])
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		host = string(buf)
	case 4: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		host = net.IP(buf).String()
	default:
		return fmt.Errorf("unknown address type %d", request[3])
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return err
	}
	dst := net.JoinHostPort(host, fmt.Sprintf("%d", int(portBuf[0])<<8|int(portBuf[1])))
	p.record(dst, user)

	origin, err := net.Dial("tcp", dst)
	if err != nil {
		conn.Write([]byte{5, 0x05, 0, 1, 0, 0, 0, 0, 0, 0})
		return nil // a refused destination is a real answer, not a protocol fault
	}
	// Success, with a zero bound address: clients in this tree do not read it, and inventing one would
	// be more protocol than the assertion needs.
	if _, err := conn.Write([]byte{5, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		origin.Close()
		return err
	}
	pipe(conn, origin)
	return nil
}

func (p *Proxy) socks5Auth(conn net.Conn, requireUser, requirePass string) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("reading auth header: %w", err)
	}
	userBuf := make([]byte, header[1])
	if _, err := io.ReadFull(conn, userBuf); err != nil {
		return "", err
	}
	passLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLen); err != nil {
		return "", err
	}
	passBuf := make([]byte, passLen[0])
	if _, err := io.ReadFull(conn, passBuf); err != nil {
		return "", err
	}
	user, pass := string(userBuf), string(passBuf)
	if user != requireUser || pass != requirePass {
		conn.Write([]byte{1, 1}) // failure
		return user, fmt.Errorf("credentials %q rejected", user)
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return user, err
	}
	return user, nil
}

// StartSOCKS4 runs a SOCKS4/4a proxy: one request, one 8-byte reply.
//
// Records the destination in the form the client asked for it — the IPv4 literal for socks4, the
// hostname for socks4a — because which of the two was sent is exactly the difference between the two
// schemes and a test asserting the wrong one would not notice a client that ignored the distinction.
func StartSOCKS4(t *testing.T) *Proxy {
	t.Helper()
	p := start(t)
	go p.serve(func(conn net.Conn) {
		if err := p.socks4Handshake(conn); err != nil {
			p.fail("socks4: %v", err)
			conn.Close()
		}
	})
	return p
}

func (p *Proxy) socks4Handshake(conn net.Conn) error {
	head := make([]byte, 8)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("reading request: %w", err)
	}
	if head[0] != 4 {
		return fmt.Errorf("version %d is not socks4", head[0])
	}
	if head[1] != 1 {
		return fmt.Errorf("command %d is not CONNECT", head[1])
	}
	port := int(head[2])<<8 | int(head[3])
	user, err := readCString(conn)
	if err != nil {
		return fmt.Errorf("reading USERID: %w", err)
	}
	// 0.0.0.x with x nonzero is the SOCKS4a sentinel: a hostname follows the USERID.
	host := net.IP(head[4:8]).String()
	if head[4] == 0 && head[5] == 0 && head[6] == 0 && head[7] != 0 {
		name, err := readCString(conn)
		if err != nil {
			return fmt.Errorf("reading socks4a hostname: %w", err)
		}
		host = name
	}
	dst := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	p.record(dst, user)

	origin, err := net.Dial("tcp", dst)
	if err != nil {
		conn.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0}) // request rejected or failed
		return nil
	}
	if _, err := conn.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0}); err != nil { // granted
		origin.Close()
		return err
	}
	pipe(conn, origin)
	return nil
}

// readCString reads bytes up to and including a NUL, returning what preceded it.
func readCString(conn net.Conn) (string, error) {
	out := make([]byte, 0, 32)
	one := make([]byte, 1)
	for len(out) < 512 {
		if _, err := io.ReadFull(conn, one); err != nil {
			return string(out), err
		}
		if one[0] == 0 {
			return string(out), nil
		}
		out = append(out, one[0])
	}
	return string(out), fmt.Errorf("unterminated string")
}

func contains(haystack []byte, needle byte) bool {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}
	return false
}
