package proxy

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// The gap burpsy-react-ui-trcy records: the sender had platform credentials and the proxy did not,
// so an operator who configured Basic or Digest got authenticated Repeater sends and an
// UNAUTHENTICATED browser — which is where most of their traffic is. The panel said the rules were
// stored. These tests drive a real proxy with a real browser-shaped request and read the
// Authorization header the origin actually received, because a rule that is stored and not presented
// is the failure this file exists to make impossible.

// authOrigin is a real HTTP server that records the Authorization header it received and answers 401
// with a Digest challenge until the client has learned one.
type authOrigin struct {
	ln           net.Listener
	srv          *http.Server
	mu           sync.Mutex
	seen         []string
	challenges   int
	requireAfter int
}

func startAuthOrigin(t *testing.T, requireAfter int) *authOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := &authOrigin{ln: ln, requireAfter: requireAfter}
	a.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.seen = append(a.seen, r.Header.Get("Authorization"))
		seen := len(a.seen)
		a.mu.Unlock()

		if a.requireAfter > 0 && seen <= a.requireAfter {
			// Challenge the first request. A Digest credential cannot answer until it has seen this,
			// which is the whole reason the proxy has to learn challenges rather than only present
			// them.
			w.Header().Set("WWW-Authenticate", `Digest realm="test", qop="auth", nonce="abc123", algorithm=MD5`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})}
	go a.srv.Serve(ln)
	t.Cleanup(func() { a.srv.Close(); ln.Close() })
	return a
}

func (a *authOrigin) hostPort(t *testing.T) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(a.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}

func (a *authOrigin) authorizations() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.seen...)
}

func credentialsWith(t *testing.T, host string, scheme netauth.Scheme, user, pass, realm string) *netauth.Credentials {
	t.Helper()
	rule, err := netauth.NewCredential(host, scheme, user, pass, realm)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	store := netauth.NewCredentials()
	store.Add(rule)
	return store
}

// A Basic rule must reach the origin on a request that came from a browser through the proxy. This is
// the bead's central claim, measured at the far end.
func TestAConfiguredCredentialReachesTheOriginOnProxiedBrowserTraffic(t *testing.T) {
	origin := startAuthOrigin(t, 0)
	host, port := origin.hostPort(t)

	creds := credentialsWith(t, host, netauth.SchemeBasic, "operator", "s3cret", "")
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(core.NewScopeAllowEverything()).
		WithPlatformAuth(creds).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))
	proxyAddr := startProxyListener(t, srv)

	sendThroughProxy(t, proxyAddr, host, port, "")

	seen := origin.authorizations()
	if len(seen) != 1 {
		t.Fatalf("the origin saw %d request(s), want 1", len(seen))
	}
	if seen[0] == "" {
		t.Fatal("the origin received no Authorization header: the operator's platform credential is configured, the panel says so, and the browser's traffic went out unauthenticated (burpsy-react-ui-trcy)")
	}
	if !strings.HasPrefix(seen[0], "Basic ") {
		t.Errorf("Authorization = %q, want a Basic credential", seen[0])
	}
}

// The browser's OWN Authorization header always wins. A per-host rule that silently replaced it would
// mean the request the operator can see is not the one that goes out — and a target that can induce a
// browser to send a header is not thereby entitled to have a stored credential substituted for it.
//
// Asserted on the transformed BYTES as well as on what the origin received, because the byte-level
// assertion is the one that fails when the rule is dropped: a version of this that only checked the
// origin would pass under that mutation, since a request carrying two Authorization headers is
// rejected by Go's server before the handler records either.
func TestTheBrowsersOwnAuthorizationHeaderIsNeverReplaced(t *testing.T) {
	creds := credentialsWith(t, "example.test", netauth.SchemeBasic, "stored-rule", "stored-password", "")
	raw := "GET / HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer typed-by-the-browser\r\n\r\n"

	out := string(applyPlatformAuth(creds, []byte(raw), "example.test", "GET", "/"))
	if !strings.Contains(out, "Authorization: Bearer typed-by-the-browser") {
		t.Errorf("the browser's own header was replaced:\n%s", out)
	}
	if strings.Contains(out, "stored-rule") || strings.Contains(out, "Basic ") {
		t.Errorf("a stored rule was presented on a request that already carried Authorization:\n%s", out)
	}
	if strings.Count(out, "Authorization:") != 1 {
		t.Errorf("the request now carries %d Authorization headers, which an origin resolves by its own rules rather than the operator's:\n%s",
			strings.Count(out, "Authorization:"), out)
	}
}

// The same claim, end to end: what the origin receives is the browser's header and not the rule's.
func TestTheBrowsersOwnHeaderReachesTheOriginUnreplaced(t *testing.T) {
	origin := startAuthOrigin(t, 0)
	host, port := origin.hostPort(t)

	creds := credentialsWith(t, host, netauth.SchemeBasic, "stored-rule", "stored-password", "")
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(core.NewScopeAllowEverything()).
		WithPlatformAuth(creds).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))
	proxyAddr := startProxyListener(t, srv)

	sendThroughProxy(t, proxyAddr, host, port, "Bearer typed-by-the-browser")

	seen := origin.authorizations()
	if len(seen) != 1 {
		t.Fatalf("the origin saw %d request(s), want 1", len(seen))
	}
	if seen[0] != "Bearer typed-by-the-browser" {
		t.Errorf("Authorization = %q; the browser's own header was replaced by a stored rule, so the request on screen is not the request that went out", seen[0])
	}
}

// A case-insensitive header name is still the browser's own header. HTTP header names fold (RFC 9110
// §5.1), and a case-sensitive test would let `authorization:` be overwritten.
func TestALowerCaseAuthorizationHeaderIsAlsoLeftAlone(t *testing.T) {
	creds := credentialsWith(t, "example.test", netauth.SchemeBasic, "stored", "pw", "")
	raw := "GET / HTTP/1.1\r\nHost: example.test\r\nauthorization: Bearer lower\r\n\r\n"
	out := applyPlatformAuth(creds, []byte(raw), "example.test", "GET", "/")
	if !strings.Contains(string(out), "authorization: Bearer lower") {
		t.Errorf("a lower-case Authorization header was replaced:\n%s", out)
	}
	if strings.Count(string(out), "Authorization")+strings.Count(string(out), "authorization") != 1 {
		t.Errorf("the request now carries two Authorization headers:\n%s", out)
	}
}

// A rule that does not cover this host must not be applied. A credential sent to a host the operator
// did not name it for is a disclosure the operator never asked for.
func TestARuleForAnotherHostIsNotPresented(t *testing.T) {
	origin := startAuthOrigin(t, 0)
	host, port := origin.hostPort(t)

	// A rule deliberately bound somewhere else.
	creds := credentialsWith(t, "intranet.example.com", netauth.SchemeBasic, "operator", "s3cret", "")
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(core.NewScopeAllowEverything()).
		WithPlatformAuth(creds).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))
	proxyAddr := startProxyListener(t, srv)

	sendThroughProxy(t, proxyAddr, host, port, "")

	if seen := origin.authorizations(); len(seen) != 1 || seen[0] != "" {
		t.Errorf("Authorization = %v; a rule for intranet.example.com was presented to %s", seen, host)
	}
}

// Digest needs a challenge before it can answer, and the proxy cannot retry. So the first request
// goes out unauthenticated and is refused, the challenge is learned, and the SECOND request on the
// connection authenticates. That is the whole reachability story for Digest on this leg, and the test
// states it rather than pretending a preemptive Digest header exists.
func TestADigestChallengeIsLearnedSoTheNextRequestAuthenticates(t *testing.T) {
	origin := startAuthOrigin(t, 1) // challenge the first request only
	host, _ := origin.hostPort(t)

	creds := credentialsWith(t, host, netauth.SchemeDigest, "operator", "s3cret", "test")
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(core.NewScopeAllowEverything()).
		WithPlatformAuth(creds).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))
	proxyAddr := startProxyListener(t, srv)

	// Two SEPARATE client connections, which is the honest shape for this proxy: handleHTTP serves
	// one request per connection and dials a fresh upstream for it, so a keep-alive browser session
	// is a sequence of one-request connections. That is also the stronger claim — the learned nonce
	// has to survive in the credential store rather than in a socket, which is the only way it can
	// reach the next request on a different connection.
	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(conn, "GET /dir/index.html HTTP/1.1\r\nHost: %s\r\n\r\n", origin.ln.Addr())
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		conn.Close()
	}

	seen := origin.authorizations()
	if len(seen) < 2 {
		t.Fatalf("the origin saw %d request(s), want at least 2", len(seen))
	}
	if seen[0] != "" {
		t.Errorf("the first request carried %q; Digest cannot answer before it has seen a challenge, so a preemptive header here would be a fabrication", seen[0])
	}
	if !strings.HasPrefix(seen[1], "Digest ") {
		t.Errorf("the second request carried %q, want a Digest credential: the proxy never learned the challenge, so no amount of configuration would authenticate a browser (burpsy-react-ui-trcy)", seen[1])
	}
}

// The header insert must not disturb the body. Getting the head boundary wrong would splice a header
// into a payload, which is the failure mode of doing this with a text replace instead of a parse.
// The NTLMv2 analogue of the Digest test above: the NEGOTIATE goes out on the first request,
// the 401's CHALLENGE_MESSAGE is learned into the credential store, and the second request on
// a SEPARATE connection carries the AUTHENTICATE leg. That is the stronger claim the store
// keyed state makes: the learned challenge survives in netauth rather than in a socket, which
// is the only way it can reach the next request on a different connection (burpsy-react-ui-noz5).
func TestAnNTLMv2ChallengeIsLearnedSoTheNextRequestAuthenticates(t *testing.T) {
	var mu sync.Mutex
	var n int
	originSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		seen := n
		mu.Unlock()
		if seen == 1 {
			targetInfo := []byte{
				0x02, 0x00, 0x08, 0x00,
				0x43, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x50, 0x00, // "CORP", UTF-16LE
				0x06, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00,
				0x00, 0x00,
			}
			msg := make([]byte, 48+len(targetInfo))
			copy(msg[0:8], "NTLMSSP\x00")
			binary.LittleEndian.PutUint32(msg[8:12], 2)
			copy(msg[24:32], "\x01\x02\x03\x04\x05\x06\x07\x08")
			binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfo)))
			binary.LittleEndian.PutUint32(msg[44:48], 48)
			copy(msg[48:], targetInfo)
			w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(msg))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// The second request carries the AUTHENTICATE (type 3).
		hdr := r.Header.Get("Authorization")
		blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "NTLM "))
		if err != nil || len(blob) < 88 || binary.LittleEndian.Uint32(blob[8:12]) != 3 {
			t.Errorf("the second request carried %q; want an NTLMSSP AUTHENTICATE (type 3) message", hdr)
		}
		w.WriteHeader(http.StatusOK)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go originSrv.Serve(ln)
	t.Cleanup(func() { originSrv.Close(); ln.Close() })

	host, _, _ := net.SplitHostPort(ln.Addr().String())
	creds := credentialsWith(t, host, netauth.SchemeNTLMv2, "operator", "s3cret", "")
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(core.NewScopeAllowEverything()).
		WithPlatformAuth(creds).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())))
	proxyAddr := startProxyListener(t, srv)

	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(conn, "GET /dir/index.html HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr())
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		conn.Close()
	}

	mu.Lock()
	requests := n
	mu.Unlock()
	if requests != 2 {
		t.Fatalf("the origin saw %d request(s), want exactly 2 - negotiate then authenticate", requests)
	}
}

func TestTheCredentialInsertLeavesTheBodyAndEveryOtherHeaderUntouched(t *testing.T) {
	creds := credentialsWith(t, "example.test", netauth.SchemeBasic, "operator", "s3cret", "")
	raw := "POST /submit?a=1 HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 11\r\n" +
		"\r\n" +
		"a=1&b=<2>\r\n"
	out := string(applyPlatformAuth(creds, []byte(raw), "example.test", "POST", "/submit?a=1"))

	if !strings.HasPrefix(out, "POST /submit?a=1 HTTP/1.1\r\n") {
		t.Errorf("the request line changed: %q", out[:40])
	}
	if !strings.HasSuffix(out, "\r\n\r\na=1&b=<2>\r\n") {
		t.Errorf("the body moved or changed: %q", out)
	}
	for _, want := range []string{"Host: example.test", "Content-Type: application/x-www-form-urlencoded", "Content-Length: 11"} {
		if !strings.Contains(out, want) {
			t.Errorf("the header %q was lost: %q", want, out)
		}
	}
	if strings.Count(out, "\r\n\r\n") != 1 {
		t.Errorf("the insert produced a second head boundary: %q", out)
	}
}

// A bare-LF request stays bare-LF. An insert that introduced a CRLF into an LF-only head would give
// the origin a request whose framing its own parser may read differently from the browser's.
func TestABareLFRequestIsNotGivenCRLFRoots(t *testing.T) {
	creds := credentialsWith(t, "example.test", netauth.SchemeBasic, "operator", "s3cret", "")
	raw := "GET / HTTP/1.1\nHost: example.test\n\n"
	out := string(applyPlatformAuth(creds, []byte(raw), "example.test", "GET", "/"))
	if strings.Contains(out, "\r") {
		t.Errorf("a bare-LF request came back with CR bytes: %q", out)
	}
	if !strings.Contains(out, "Authorization: Basic ") {
		t.Errorf("the credential was not inserted: %q", out)
	}
}

// A request with no head terminator is returned untouched rather than guessed at. The proxy refuses
// such a request further up; this function does not get to decide otherwise.
func TestAnUnterminatedRequestIsForwardedUntouched(t *testing.T) {
	creds := credentialsWith(t, "example.test", netauth.SchemeBasic, "operator", "s3cret", "")
	raw := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n")
	out := applyPlatformAuth(creds, raw, "example.test", "GET", "/")
	if string(out) != string(raw) {
		t.Errorf("an unterminated request was edited: %q", out)
	}
}

// A proxy with no credential source is the pre-fix state, and it must forward unauthenticated rather
// than invent something. Nil is a real answer.
func TestAProxyWithNoCredentialSourceForwardsUnauthenticated(t *testing.T) {
	if (&ProxyConfig{}).CarriesPlatformAuth() {
		t.Error("a bare ProxyConfig claims to carry credentials it was never given")
	}
	raw := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	if out := applyPlatformAuth(nil, raw, "example.test", "GET", "/"); string(out) != string(raw) {
		t.Errorf("a nil source changed the request: %q", out)
	}
}

// startProxyListener runs a proxy on a loopback port and returns its address.
func startProxyListener(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()
	return ln.Addr().String()
}

// sendThroughProxy makes one browser-shaped request through the proxy and returns the response status
// line. The request carries no Authorization header unless one is given, which is what an ordinary
// browser's first request looks like.
func sendThroughProxy(t *testing.T, proxyAddr, host string, port uint16, authorization string) string {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := fmt.Sprintf("GET /protected HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n", host, port)
	if authorization != "" {
		req += "Authorization: " + authorization + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the status line: %v", err)
	}
	return strings.TrimSpace(line)
}
