package vulnapp

// HTTP request smuggling: a two-tier target whose hops read request framing differently.
//
// # Why these endpoints are listeners, not routes
//
// Request smuggling is a disagreement between two HTTP parsers about where a request ends, and it is
// per host: every path behind one front end and one back end shares the disagreement. Handler()'s
// routes all sit behind one net/http server, which parses framing exactly once and consistently, so
// no route on it can ever be vulnerable — nor can a "safe twin" route there show anything. Each
// endpoint here is therefore served by a listener of its own (Endpoint.Listener), started by
// StartListener, which is a hand-rolled front end forwarding over an in-process connection to a
// hand-rolled back end. The two hops each apply a framing rule, and the pairing of rules is the
// whole fixture:
//
//   - desync-clte: the front honours only Content-Length; the back is RFC 9112 compliant (chunked wins).
//   - desync-tecl: the front is compliant; the back honours only Content-Length.
//   - desync-clte-obfuscated: the front honours Transfer-Encoding only when spelled exactly
//     "Transfer-Encoding: chunked" and otherwise uses Content-Length; the back accepts any header whose
//     trimmed name is Transfer-Encoding and whose value mentions chunked. The plain spelling is
//     consistent; "Transfer-Encoding : chunked" is not.
//   - desync-compliant (safe): both hops compliant, malformed framing headers refused with 400/501.
//   - desync-normalising (safe): a lenient front that decodes the body by its own rule and forwards it
//     with a Content-Length it computed and no Transfer-Encoding; the back honours only Content-Length.
//     The back end's rule is TE.CL's, but it is never shown a disagreement — the realistic safe proxy.
//   - desync-h2-te, desync-h2-cl, desync-h2-compliant: TLS listeners offering h2 and http/1.1. Their
//     HTTP/1.1 side is the normalising pair. Their HTTP/2 side downgrades to HTTP/1.1 for a compliant
//     back end: -te forwards a transfer-encoding header verbatim (adding a Content-Length of the DATA
//     when the client sent none), -cl strips transfer-encoding but forwards the client's content-length
//     verbatim, and -compliant refuses either mismatch (RFC 9113 §8.2.2, §8.1.1).
//
// A back end left waiting for bytes waits until the front end gives up on it (backWait) and answers
// 504, which is what a real gateway does. Each client connection gets its own back-end connection, so
// nothing a client leaves behind can reach another client's request — the fixture cannot be used to
// demonstrate (or suffer) cross-user poisoning.
//
// Nothing here executes anything: the back end answers a fixed page.

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// framingRule is how one hop decides where a request body ends.
type framingRule int

const (
	// ruleCLOnly ignores Transfer-Encoding entirely.
	ruleCLOnly framingRule = iota
	// ruleCompliant is RFC 9112: malformed header lines are refused, chunked as the final coding wins
	// over Content-Length, any other coding is refused with 501.
	ruleCompliant
	// ruleExactTE honours Transfer-Encoding only when the line is spelled exactly
	// "Transfer-Encoding: chunked" (name case-insensitive); any other spelling is an unknown header.
	ruleExactTE
	// ruleLenient honours any header whose trimmed name is transfer-encoding and whose value mentions
	// chunked, unfolds continuation lines and accepts bare LF line endings.
	ruleLenient
	// ruleIgnoreBody reads no body at all, whatever Content-Length says: the CL.0 front end (and
	// the client-side desync server) that answers the request and leaves the "body" to be parsed
	// as the next request.
	ruleIgnoreBody
	// ruleNoChunkExt reads chunked bodies but refuses a chunk-size line carrying an extension:
	// the strict half of the TE.0/chunk-extension disagreement.
	ruleNoChunkExt
	// ruleExpectSkipBody answers a request carrying an Expect header without reading its
	// declared body (the body bytes are then parsed as the next request): the 0.CL/Expect
	// half of the disagreement. Without an Expect header it reads by Content-Length.
	ruleExpectSkipBody
)

// h2Downgrade is how a TLS listener's HTTP/2 side rewrites a request for its HTTP/1.1 back end.
type h2Downgrade int

const (
	h2None h2Downgrade = iota
	// h2PassTE forwards every header verbatim, adding Content-Length of the DATA when none was sent.
	h2PassTE
	// h2PassCL strips transfer-encoding and forwards the client's content-length verbatim.
	h2PassCL
	// h2Compliant refuses transfer-encoding and a content-length that disagrees with the DATA.
	h2Compliant
)

type desyncSpec struct {
	front, back framingRule
	// reframe makes the front end forward the body it decoded with its own Content-Length.
	reframe bool
	tls     bool
	h2      h2Downgrade
}

var desyncSpecs = map[string]desyncSpec{
	"desync-clte":            {front: ruleCLOnly, back: ruleCompliant},
	"desync-tecl":            {front: ruleCompliant, back: ruleCLOnly},
	"desync-clte-obfuscated": {front: ruleExactTE, back: ruleLenient},
	"desync-compliant":       {front: ruleCompliant, back: ruleCompliant},
	"desync-normalising":     {front: ruleLenient, reframe: true, back: ruleCLOnly},
	"desync-h2-te":           {front: ruleLenient, reframe: true, back: ruleCompliant, tls: true, h2: h2PassTE},
	"desync-h2-cl":           {front: ruleLenient, reframe: true, back: ruleCompliant, tls: true, h2: h2PassCL},
	"desync-h2-compliant":    {front: ruleLenient, reframe: true, back: ruleCompliant, tls: true, h2: h2Compliant},
	// 0vzb.40: CL.0 and client-side desync share one client-observable shape: the server answers
	// the POST without reading its declared body, then parses the body bytes as the next request
	// on the same connection. Both hops read no body, so the leftover is re-parsed as a request
	// and its (canary 404) answer takes the follow-up's response slot. The two endpoints differ
	// in what the fixture teaches, not in the wiring.
	"desync-cl0":         {front: ruleIgnoreBody, back: ruleIgnoreBody},
	"desync-client-side": {front: ruleIgnoreBody, back: ruleIgnoreBody},
	// Safe twins.
	"desync-cl0-safe": {front: ruleCompliant, back: ruleCompliant},
	"desync-csd-safe": {front: ruleCompliant, back: ruleCompliant},
	// 0vzb.40 remainder: TE.0/0.CL-Expect differential fixtures. desync-clcl is the safe
	// twin: both hops read by Content-Length, so no framing leaves anything to re-parse.
	"desync-clcl": {front: ruleCLOnly, back: ruleCLOnly},
	// desync-expect: both hops answer an Expect-bearing request without reading its declared
	// body (the 0.CL/Expect condition), so the body bytes re-parse as the next request - the
	// same both-hops construction as the CL.0 fixture, gated on the Expect header.
	"desync-expect": {front: ruleExpectSkipBody, back: ruleExpectSkipBody},
	// desync-chunkext-refused: the back end refuses an extension-terminated chunk (400,
	// connection closed); the plain zero-chunk terminator still lands.
	"desync-chunkext-refused": {front: ruleCLOnly, back: ruleNoChunkExt},
}

// ListenerNames lists every listener StartListener can start.
func ListenerNames() []string {
	out := make([]string, 0, len(desyncSpecs))
	for k := range desyncSpecs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// backWait is how long a front end waits on its back end before answering 504.
const backWait = 10 * time.Second

// maxDesyncBody bounds a request body either hop will read.
const maxDesyncBody = 1 << 20

// Listener is one running two-tier target.
type Listener struct {
	Name string
	Host string
	Port uint16
	TLS  bool

	spec  desyncSpec
	ln    net.Listener
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	done  bool
}

// URL is the listener's base URL.
func (l *Listener) URL() string {
	scheme := "http"
	if l.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(l.Host, strconv.Itoa(int(l.Port))))
}

// Close stops accepting and closes every open connection.
func (l *Listener) Close() error {
	l.mu.Lock()
	l.done = true
	for c := range l.conns {
		c.Close()
	}
	l.mu.Unlock()
	return l.ln.Close()
}

func (l *Listener) track(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return false
	}
	l.conns[c] = struct{}{}
	return true
}

func (l *Listener) untrack(c net.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
}

// StartListener starts the named two-tier target on a loopback port.
func StartListener(name string) (*Listener, error) {
	spec, ok := desyncSpecs[name]
	if !ok {
		return nil, fmt.Errorf("vulnapp: no listener named %q", name)
	}
	var ln net.Listener
	var err error
	if spec.tls {
		cert, cerr := selfSignedLoopback()
		if cerr != nil {
			return nil, cerr
		}
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		})
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		return nil, err
	}
	l := &Listener{
		Name: name, Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), TLS: spec.tls,
		spec: spec, ln: ln, conns: map[net.Conn]struct{}{},
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if !l.track(c) {
				c.Close()
				return
			}
			go func() {
				defer l.untrack(c)
				defer c.Close()
				l.serve(c)
			}()
		}
	}()
	return l, nil
}

func selfSignedLoopback() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func (l *Listener) serve(c net.Conn) {
	if tc, ok := c.(*tls.Conn); ok {
		tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			return
		}
		tc.SetDeadline(time.Time{})
		if tc.ConnectionState().NegotiatedProtocol == "h2" {
			l.serveH2(tc)
			return
		}
	}
	l.serveH1(c)
}

// ---------------------------------------------------------------------------
// HTTP/1.1 parsing shared by both hops
// ---------------------------------------------------------------------------

type rawHeader struct{ name, value string }

type parsedHead struct {
	method  string
	raw     []byte // the head exactly as read, terminating blank line included
	line    string // the request line
	headers []rawHeader
}

var errMalformed = errors.New("malformed request")

// readHead reads one request head. strict refuses bare LF line endings, obs-fold continuation lines
// and whitespace in a header name; otherwise those are accepted (and, for unfold, folded).
func readHead(br *bufio.Reader, strict, unfold bool) (*parsedHead, error) {
	h := &parsedHead{}
	first := true
	for n := 0; ; n++ {
		if n > 200 || len(h.raw) > 64<<10 {
			return nil, errMalformed
		}
		line, err := br.ReadString('\n')
		if err != nil {
			if first && line == "" {
				return nil, io.EOF
			}
			return nil, err
		}
		h.raw = append(h.raw, line...)
		if strict && !strings.HasSuffix(line, "\r\n") {
			return nil, errMalformed
		}
		text := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if first {
			if text == "" {
				// Tolerate a stray empty line before a request (RFC 9112 §2.2).
				h.raw = h.raw[:0]
				continue
			}
			parts := strings.SplitN(text, " ", 3)
			if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
				return nil, errMalformed
			}
			h.method, h.line, first = parts[0], text, false
			continue
		}
		if text == "" {
			return h, nil
		}
		if text[0] == ' ' || text[0] == '\t' {
			if strict {
				return nil, errMalformed
			}
			if unfold && len(h.headers) > 0 {
				h.headers[len(h.headers)-1].value += " " + strings.TrimSpace(text)
				continue
			}
		}
		name, value, ok := strings.Cut(text, ":")
		if !ok {
			if strict {
				return nil, errMalformed
			}
			continue
		}
		if strict && (name == "" || strings.ContainsAny(name, " \t\v\f")) {
			return nil, errMalformed
		}
		h.headers = append(h.headers, rawHeader{name: name, value: value})
	}
}

// framing is a hop's decision about a request body.
type framing struct {
	chunked bool
	length  int
	status  int // non-zero: refuse the request with this status
	// noExt refuses a chunk-size line carrying an extension (ruleNoChunkExt).
	noExt bool
}

func contentLength(headers []rawHeader) framing {
	var seen string
	for _, h := range headers {
		if !strings.EqualFold(strings.TrimSpace(h.name), "content-length") {
			continue
		}
		v := strings.TrimSpace(h.value)
		if seen != "" && v != seen {
			return framing{status: 400}
		}
		seen = v
	}
	if seen == "" {
		return framing{}
	}
	n, err := strconv.Atoi(seen)
	if err != nil || n < 0 || n > maxDesyncBody {
		return framing{status: 400}
	}
	return framing{length: n}
}

func decideFraming(rule framingRule, headers []rawHeader) framing {
	switch rule {
	case ruleCompliant:
		var codings []string
		for _, h := range headers {
			if strings.EqualFold(h.name, "transfer-encoding") {
				for _, c := range strings.Split(h.value, ",") {
					codings = append(codings, strings.ToLower(strings.Trim(c, " \t")))
				}
			}
		}
		if len(codings) > 0 {
			if codings[len(codings)-1] != "chunked" {
				return framing{status: 501}
			}
			return framing{chunked: true}
		}
		return contentLength(headers)
	case ruleExactTE:
		for _, h := range headers {
			if strings.EqualFold(h.name, "transfer-encoding") && strings.EqualFold(strings.Trim(h.value, " \t"), "chunked") {
				return framing{chunked: true}
			}
		}
		return contentLength(headers)
	case ruleLenient:
		for _, h := range headers {
			if strings.EqualFold(strings.TrimSpace(h.name), "transfer-encoding") &&
				strings.Contains(strings.ToLower(h.value), "chunked") {
				return framing{chunked: true}
			}
		}
		return contentLength(headers)
	case ruleIgnoreBody:
		return framing{length: 0}
	case ruleExpectSkipBody:
		for _, h := range headers {
			if strings.EqualFold(strings.TrimSpace(h.name), "expect") {
				return framing{length: 0}
			}
		}
		return contentLength(headers)
	case ruleNoChunkExt:
		for _, h := range headers {
			if strings.EqualFold(h.name, "transfer-encoding") &&
				strings.Contains(strings.ToLower(h.value), "chunked") {
				return framing{chunked: true, noExt: true}
			}
		}
		return contentLength(headers)
	}
	return contentLength(headers)
}

// readBody reads a body by f, returning the bytes as they arrived and the decoded body.
func readBody(br *bufio.Reader, f framing) (raw, decoded []byte, err error) {
	if !f.chunked {
		buf := make([]byte, f.length)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, nil, err
		}
		return buf, buf, nil
	}
	for {
		line, err := br.ReadString('\n')
		raw = append(raw, line...)
		if err != nil {
			return nil, nil, err
		}
		size := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if i := strings.IndexByte(size, ';'); i >= 0 {
			if f.noExt {
				return nil, nil, errMalformed
			}
			size = size[:i]
		}
		size = strings.Trim(size, " \t")
		n, perr := strconv.ParseUint(size, 16, 31)
		if perr != nil || size == "" || len(size) > 7 {
			return nil, nil, errMalformed
		}
		if n == 0 {
			for {
				tl, err := br.ReadString('\n')
				raw = append(raw, tl...)
				if err != nil {
					return nil, nil, err
				}
				if tl == "\r\n" || tl == "\n" {
					return raw, decoded, nil
				}
			}
		}
		if len(decoded)+int(n) > maxDesyncBody {
			return nil, nil, errMalformed
		}
		chunk := make([]byte, n+2)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return nil, nil, err
		}
		if string(chunk[n:]) != "\r\n" {
			return nil, nil, errMalformed
		}
		raw = append(raw, chunk...)
		decoded = append(decoded, chunk[:n]...)
	}
}

func statusResponse(code int) []byte {
	text := map[int]string{400: "Bad Request", 501: "Not Implemented", 502: "Bad Gateway", 504: "Gateway Timeout"}[code]
	return []byte(fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, text))
}

const desyncPage = "<!doctype html><html><head><title>Two-tier fixture</title></head><body><p>Served by the back end.</p></body></html>"

// serveBack is the back end: it reads requests off its end of the front end's connection by its own
// framing rule and answers each with a fixed page. A body it is still waiting for keeps it waiting.
func serveBack(c net.Conn, rule framingRule) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		head, err := readHead(br, rule == ruleCompliant, rule == ruleLenient)
		if err != nil {
			if errors.Is(err, errMalformed) {
				c.Write(statusResponse(400))
			}
			return
		}
		f := decideFraming(rule, head.headers)
		if f.status != 0 {
			c.Write(statusResponse(f.status))
			return
		}
		if _, _, err := readBody(br, f); err != nil {
			if errors.Is(err, errMalformed) {
				c.Write(statusResponse(400))
			}
			return
		}
		// A smuggled-request canary path answers 404 with a marker body: the CL.0 / client-side
		// desync fixtures need a smuggled request's answer to be distinguishable from the
		// endpoint's own page. No declared endpoint path carries the marker, so nothing else
		// changes.
		if strings.Contains(head.line, "-canary-404") {
			body := "burpsy smuggled canary " + head.line // echo the request line, as 404 pages do
			resp := "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: " +
				strconv.Itoa(len(body)) + "\r\n\r\n" + body
			if _, err := c.Write([]byte(resp)); err != nil {
				return
			}
			continue
		}
		resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " +
			strconv.Itoa(len(desyncPage)) + "\r\n\r\n"
		if head.method != "HEAD" {
			resp += desyncPage
		}
		if _, err := c.Write([]byte(resp)); err != nil {
			return
		}
	}
}

// readBackResponse reads one response from the back end. The back end always frames with
// Content-Length.
func readBackResponse(br *bufio.Reader, head bool) ([]byte, bool, error) {
	var raw []byte
	length, closing := 0, false
	for first := true; ; first = false {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, false, err
		}
		raw = append(raw, line...)
		text := strings.TrimRight(line, "\r\n")
		if text == "" {
			break
		}
		if first {
			continue
		}
		name, value, _ := strings.Cut(text, ":")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length":
			length, _ = strconv.Atoi(strings.TrimSpace(value))
		case "connection":
			closing = strings.EqualFold(strings.TrimSpace(value), "close")
		}
	}
	if head || length == 0 {
		return raw, closing, nil
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, false, err
	}
	return append(raw, body...), closing, nil
}

// backLink is a front end's connection to its back end.
type backLink struct {
	conn net.Conn
	br   *bufio.Reader
}

// The link is a real loopback TCP pair, not net.Pipe: a back end that answers a request
// without reading its body and then answers the re-parsed "body" writes TWO responses for
// the front end's one read so far, and an unbuffered pipe deadlocks that against the front
// end's next write (the 0vzb.40 TE.0/Expect differentials). Kernel buffers are also the
// faithful shape: a real front end talks TCP to its back end. If loopback is unavailable the
// link degrades to the synchronous pipe (the pre-remainder shape) rather than failing.
func newBackLink(rule framingRule) *backLink {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		front, back := net.Pipe()
		go serveBack(back, rule)
		return &backLink{conn: front, br: bufio.NewReader(front)}
	}
	go func() {
		c, err := ln.Accept()
		ln.Close()
		if err == nil {
			serveBack(c, rule)
		}
	}()
	front, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		pf, pb := net.Pipe()
		go serveBack(pb, rule)
		return &backLink{conn: pf, br: bufio.NewReader(pf)}
	}
	return &backLink{conn: front, br: bufio.NewReader(front)}
}

// roundTrip forwards one request to the back end and reads its answer, answering 502 or 504 the way
// a gateway does when the back end hangs up or keeps it waiting.
func (b *backLink) roundTrip(req []byte, head bool) ([]byte, bool) {
	b.conn.SetDeadline(time.Now().Add(backWait))
	if _, err := b.conn.Write(req); err != nil {
		return statusResponse(502), true
	}
	resp, closing, err := readBackResponse(b.br, head)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return statusResponse(504), true
		}
		return statusResponse(502), true
	}
	return resp, closing
}

// serveH1 is the front end's HTTP/1.1 side.
func (l *Listener) serveH1(c net.Conn) {
	br := bufio.NewReader(c)
	var back *backLink
	defer func() {
		if back != nil {
			back.conn.Close()
		}
	}()
	for {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		head, err := readHead(br, l.spec.front == ruleCompliant, l.spec.front == ruleLenient)
		if err != nil {
			if errors.Is(err, errMalformed) {
				c.Write(statusResponse(400))
			}
			return
		}
		f := decideFraming(l.spec.front, head.headers)
		if f.status != 0 {
			c.Write(statusResponse(f.status))
			return
		}
		raw, decoded, err := readBody(br, f)
		if err != nil {
			if errors.Is(err, errMalformed) {
				c.Write(statusResponse(400))
			}
			return
		}
		var out []byte
		if l.spec.reframe {
			var b bytes.Buffer
			b.WriteString(head.line + "\r\n")
			for _, h := range head.headers {
				switch strings.ToLower(strings.TrimSpace(h.name)) {
				case "transfer-encoding", "content-length":
					continue
				}
				b.WriteString(strings.TrimSpace(h.name) + ": " + strings.TrimSpace(h.value) + "\r\n")
			}
			b.WriteString("Content-Length: " + strconv.Itoa(len(decoded)) + "\r\n\r\n")
			b.Write(decoded)
			out = b.Bytes()
		} else {
			out = append(append([]byte(nil), head.raw...), raw...)
		}
		if back == nil {
			back = newBackLink(l.spec.back)
		}
		resp, closing := back.roundTrip(out, head.method == "HEAD")
		if _, err := c.Write(resp); err != nil || closing {
			return
		}
		for _, h := range head.headers {
			if strings.EqualFold(strings.TrimSpace(h.name), "connection") &&
				strings.EqualFold(strings.TrimSpace(h.value), "close") {
				return
			}
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP/2 front end
// ---------------------------------------------------------------------------

type h2Stream struct {
	block     []byte
	fields    []hpack.HeaderField
	body      []byte
	endStream bool
}

// serveH2 is the front end's HTTP/2 side: one goroutine reads frames, and each finished stream is
// downgraded and forwarded on a back-end connection of its own, so a stream left waiting never holds
// up another.
func (l *Listener) serveH2(c net.Conn) {
	preface := make([]byte, len(http2.ClientPreface))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	c.SetReadDeadline(time.Time{})
	fr := http2.NewFramer(c, c)
	var wmu sync.Mutex
	var encBuf bytes.Buffer
	enc := hpack.NewEncoder(&encBuf)
	write := func(fn func() error) {
		wmu.Lock()
		defer wmu.Unlock()
		c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_ = fn()
	}
	write(func() error { return fr.WriteSettings() })

	respond := func(id uint32, resp []byte) {
		status, headers, body := splitH1Response(resp)
		write(func() error {
			encBuf.Reset()
			enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
			for _, h := range headers {
				enc.WriteField(h)
			}
			if err := fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: id, BlockFragment: encBuf.Bytes(), EndHeaders: true, EndStream: len(body) == 0,
			}); err != nil {
				return err
			}
			if len(body) > 0 {
				return fr.WriteData(id, true, body)
			}
			return nil
		})
	}

	dec := hpack.NewDecoder(65536, nil)
	streams := map[uint32]*h2Stream{}
	finish := func(id uint32) {
		st := streams[id]
		delete(streams, id)
		if st == nil {
			return
		}
		go func() {
			req, head, refuse := l.downgrade(st)
			if refuse != 0 {
				respond(id, statusResponse(refuse))
				return
			}
			back := newBackLink(l.spec.back)
			defer back.conn.Close()
			resp, _ := back.roundTrip(req, head)
			respond(id, resp)
		}()
	}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				write(func() error { return fr.WriteSettingsAck() })
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				data := f.Data
				write(func() error { return fr.WritePing(true, data) })
			}
		case *http2.HeadersFrame:
			st := streams[f.StreamID]
			if st == nil {
				st = &h2Stream{}
				streams[f.StreamID] = st
			}
			st.block = append(st.block[:0], f.HeaderBlockFragment()...)
			ended := f.StreamEnded()
			if f.HeadersEnded() {
				if st.fields, err = dec.DecodeFull(st.block); err != nil {
					return
				}
				if ended {
					finish(f.StreamID)
				}
			} else {
				// END_STREAM on a HEADERS frame continued by CONTINUATION: the stream ends with the block.
				st.endStream = ended
			}
		case *http2.ContinuationFrame:
			st := streams[f.StreamID]
			if st == nil {
				return
			}
			st.block = append(st.block, f.HeaderBlockFragment()...)
			if f.HeadersEnded() {
				if st.fields, err = dec.DecodeFull(st.block); err != nil {
					return
				}
				if st.endStream {
					finish(f.StreamID)
				}
			}
		case *http2.DataFrame:
			st := streams[f.StreamID]
			if st == nil {
				continue
			}
			data := f.Data()
			st.body = append(st.body, data...)
			if n := uint32(len(data)); n > 0 {
				id := f.StreamID
				write(func() error {
					if err := fr.WriteWindowUpdate(0, n); err != nil {
						return err
					}
					return fr.WriteWindowUpdate(id, n)
				})
			}
			if f.StreamEnded() {
				finish(f.StreamID)
			}
		case *http2.RSTStreamFrame:
			delete(streams, f.StreamID)
		case *http2.GoAwayFrame:
			return
		}
	}
}

// downgrade renders an HTTP/2 stream as the HTTP/1.1 request this listener's front end forwards.
func (l *Listener) downgrade(st *h2Stream) (req []byte, head bool, refuse int) {
	var method, path, authority string
	var b strings.Builder
	sawCL := false
	var regular []hpack.HeaderField
	for _, f := range st.fields {
		switch f.Name {
		case ":method":
			method = f.Value
		case ":path":
			path = f.Value
		case ":authority":
			authority = f.Value
		case ":scheme":
		default:
			regular = append(regular, f)
		}
	}
	if method == "" || path == "" {
		return nil, false, 400
	}
	b.WriteString(method + " " + path + " HTTP/1.1\r\nHost: " + authority + "\r\n")
	for _, f := range regular {
		switch f.Name {
		case "host":
			continue
		case "transfer-encoding":
			switch l.spec.h2 {
			case h2PassCL:
				continue
			case h2Compliant:
				return nil, false, 400
			}
		case "content-length":
			sawCL = true
			if l.spec.h2 == h2Compliant {
				if n, err := strconv.Atoi(f.Value); err != nil || n != len(st.body) {
					return nil, false, 400
				}
			}
		}
		b.WriteString(f.Name + ": " + f.Value + "\r\n")
	}
	if !sawCL {
		b.WriteString("Content-Length: " + strconv.Itoa(len(st.body)) + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(st.body)
	return []byte(b.String()), method == "HEAD", 0
}

// splitH1Response turns a back-end response into an HTTP/2 status, header list and body, dropping
// the connection-specific headers HTTP/2 forbids.
func splitH1Response(resp []byte) (int, []hpack.HeaderField, []byte) {
	head, body, _ := bytes.Cut(resp, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\r\n")
	status := 502
	if parts := strings.SplitN(lines[0], " ", 3); len(parts) >= 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			status = n
		}
	}
	var out []hpack.HeaderField
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		switch name {
		case "connection", "transfer-encoding", "keep-alive":
			continue
		}
		out = append(out, hpack.HeaderField{Name: name, Value: strings.TrimSpace(value)})
	}
	return status, out, body
}

// desyncEndpoints are the manifest rows served by the listeners above. Only the HTTP/1.1 pairs are
// declared: the HTTP/2 listeners are exercised by internal/scanner's own smuggling tests, because every
// other check in the runtime corpus would otherwise be talking HTTP/2 to this hand-rolled front end.
func desyncEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/desync/clte", Listener: "desync-clte", Row: "HTTP request smuggling",
			Note: "the front end frames by Content-Length and ignores Transfer-Encoding; the back end is RFC 9112 compliant and honours chunked, so a request whose Content-Length stops mid-chunk leaves the back end waiting (CL.TE)"},
		{Path: "/desync/tecl", Listener: "desync-tecl", Row: "HTTP request smuggling",
			Note: "the front end is compliant and forwards a chunked body up to its terminator; the back end frames by Content-Length alone and waits for the bytes the terminator stopped short of (TE.CL)"},
		{Path: "/desync/obfuscated", Listener: "desync-clte-obfuscated", Row: "HTTP request smuggling",
			Note: "the plain Transfer-Encoding header is read the same by both hops, but the front end ignores 'Transfer-Encoding : chunked' (space before the colon) while the lenient back end honours it (CL.TE via an obfuscated header)"},
		{Path: "/desync/safe/compliant", Listener: "desync-compliant", Row: "HTTP request smuggling", Safe: true,
			Note: "both hops are RFC 9112 compliant: chunked wins over Content-Length and a malformed framing header is refused, so they never disagree about where a request ends"},
		{Path: "/desync/safe/normalising", Listener: "desync-normalising", Row: "HTTP request smuggling", Safe: true,
			Note: "a lenient front end decodes the body by its own rule and re-frames it with its own Content-Length before forwarding; the back end honours only Content-Length, which is exactly what it is sent"},
		{Path: "/desync/cl0", Listener: "desync-cl0", Row: "HTTP request smuggling",
			Note: "the endpoint answers a POST without reading its Content-Length body; the body bytes are parsed as the next request on the connection (CL.0)"},
		{Path: "/desync/safe/cl0", Listener: "desync-cl0-safe", Row: "HTTP request smuggling", Safe: true,
			Note: "both hops read the declared body, so nothing is left to be re-parsed"},
		{Path: "/desync/clientside", Listener: "desync-client-side", Row: "Client-side desync",
			Note: "answers a POST without reading its declared body, then parses the body bytes as the next request: a browser-deliverable desync"},
		{Path: "/desync/safe/clientside", Listener: "desync-csd-safe", Row: "Client-side desync", Safe: true,
			Note: "reads the declared body before answering"},
	}
}

// registerDesync keeps familyRegistrars parallel to familyEndpoints. The desync family has no routes on
// the shared server: each of its endpoints is a listener of its own (see the file comment).
func registerDesync(*http.ServeMux) {}
