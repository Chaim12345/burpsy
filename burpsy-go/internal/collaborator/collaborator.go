// Package collaborator is a self-hosted interaction recorder in the mould of
// Burp Collaborator: it hands out unique addresses under an operator-supplied
// base domain and records the DNS, HTTP and SMTP interactions those addresses
// attract. It exists so the corpus's blind checks — SSRF, deserialisation RCE,
// header forwarding, email splitting — can verdict against a live oracle
// instead of being counted as skipped, without depending on PortSwigger's
// hosted service.
//
// The protocol surface is deliberately minimal. DNS is a wildcard A-answer
// responder: a target that resolves an injected hostname gets the HTTP
// listener's address, so its follow-on fetch lands on the recorder and the
// interaction is observable twice, exactly like Burp's Collaborator. HTTP
// answers any request with a plain acknowledgement. SMTP is a
// polite-but-laconic responder that lets a relaying client complete its
// transaction. Interaction attribution is by token: every issued address
// embeds a fresh 12-hex label, and every listener scans its traffic for a
// label that matches a known token. Traffic carrying no known token is
// recorded as unmatched noise, never attributed.
//
// The server is in-process with the audit engine; there is no poll API. The
// evaluator holds the *Server through the bcheck.Collaborator interface and
// asks the store directly, so the honest-counting property is preserved: the
// server only ever reports interactions it actually observed.
package collaborator

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// tokenLen is the hex length of the per-address token (6 random bytes).
const tokenLen = 12

// Config describes the interaction server's listeners. Base is the domain
// every issued address lives under (`<token>.<base>`); HTTP, DNS and SMTP are
// listen addresses, each optional — an empty address disables that protocol,
// and the matching interaction kind can then never fire (reported absent
// rather than pretended).
type Config struct {
	Base string
	HTTP string
	DNS  string
	SMTP string
}

// Observation is one recorded event.
type Observation struct {
	Kind   string // "dns", "http" or "smtp"
	Detail string // qname, request line + Host, or the SMTP session transcript
	Source string // remote address that produced it
	At     time.Time
}

// Interaction is everything the server knows about one address's traffic.
type Interaction struct {
	DNS   bool
	HTTP  bool
	SMTP  bool
	First time.Time
	// Observed is every raw observation in arrival order, kept for forensics
	// and honest reporting — a finding backed by one interaction can name it.
	Observed []Observation
}

// Server is a running interaction recorder.
type Server struct {
	base string

	mu         sync.RWMutex
	interacted map[string]*Interaction
	unmatched  []Observation

	httpLn  net.Listener
	dnsConn *net.UDPConn
	smtpLn  net.Listener
	httpIP  net.IP // DNS A-record answer: where a resolving target's fetch lands

	wg     sync.WaitGroup
	closed atomic.Bool
}

// New binds every configured listener. Binding happens here, at construction,
// so a port that cannot be taken is a startup error the operator sees before a
// single probe is sent — the same refuse-up-front policy as a corpus directory
// that will not load.
func New(cfg Config) (*Server, error) {
	base := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cfg.Base)), ".")
	if base == "" {
		return nil, fmt.Errorf("collaborator: base domain is required")
	}
	s := &Server{
		base:       base,
		interacted: make(map[string]*Interaction),
	}
	if cfg.HTTP != "" {
		ln, err := net.Listen("tcp", cfg.HTTP)
		if err != nil {
			return nil, fmt.Errorf("collaborator http listener: %w", err)
		}
		s.httpLn = ln
		if a, ok := ln.Addr().(*net.TCPAddr); ok {
			s.httpIP = a.IP
		}
	}
	if cfg.DNS != "" {
		conn, err := net.ListenPacket("udp", cfg.DNS)
		if err != nil {
			s.closeListeners()
			return nil, fmt.Errorf("collaborator dns listener: %w", err)
		}
		s.dnsConn = conn.(*net.UDPConn)
	}
	if cfg.SMTP != "" {
		ln, err := net.Listen("tcp", cfg.SMTP)
		if err != nil {
			s.closeListeners()
			return nil, fmt.Errorf("collaborator smtp listener: %w", err)
		}
		s.smtpLn = ln
	}
	// Without an HTTP listener the A answer points at the DNS listener itself:
	// the DNS interaction is still recorded, the fetch just lands nowhere.
	if s.httpIP == nil {
		if a, ok := s.dnsConn.LocalAddr().(*net.UDPAddr); ok {
			s.httpIP = a.IP
		} else {
			s.httpIP = net.IPv4(127, 0, 0, 1)
		}
	}
	s.serve()
	return s, nil
}

// HTTPAddr, DNSAddr and SMTPAddr report the bound listener addresses (empty
// when that protocol is disabled), for tests and operator-facing logs.
func (s *Server) HTTPAddr() string {
	if s.httpLn == nil {
		return ""
	}
	return s.httpLn.Addr().String()
}

func (s *Server) DNSAddr() string {
	if s.dnsConn == nil {
		return ""
	}
	return s.dnsConn.LocalAddr().String()
}

func (s *Server) SMTPAddr() string {
	if s.smtpLn == nil {
		return ""
	}
	return s.smtpLn.Addr().String()
}

// Base returns the domain every issued address lives under.
func (s *Server) Base() string { return s.base }

// NewAddress issues a fresh interaction address under the base domain. Each
// address carries a unique token, so concurrent checks over concurrent targets
// never share attribution.
func (s *Server) NewAddress() string {
	tok := token()
	s.mu.Lock()
	s.interacted[tok] = &Interaction{First: time.Now()}
	s.mu.Unlock()
	return tok + "." + s.base
}

// Interactions reports which interaction kinds any of the given addresses has
// attracted. The addresses are exactly the values NewAddress returned; the
// server extracts each one's token and ORs the per-token observations.
func (s *Server) Interactions(addrs []string) (dns, http, smtp bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range addrs {
		tok := tokenOf(a)
		if tok == "" {
			continue
		}
		if it, ok := s.interacted[tok]; ok {
			dns = dns || it.DNS
			http = http || it.HTTP
			smtp = smtp || it.SMTP
		}
	}
	return dns, http, smtp
}

// Close stops every listener and waits for the handlers to drain.
func (s *Server) Close() error {
	s.closed.Store(true)
	s.closeListeners()
	s.wg.Wait()
	return nil
}

func (s *Server) closeListeners() {
	if s.httpLn != nil {
		_ = s.httpLn.Close()
	}
	if s.dnsConn != nil {
		_ = s.dnsConn.Close()
	}
	if s.smtpLn != nil {
		_ = s.smtpLn.Close()
	}
}

// token returns a fresh 12-hex token. crypto/rand failing is nearly impossible
// on Linux; the fallback folds an atomic counter into the timestamp so tokens
// stay unique within the process either way.
func token() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%011x%x", time.Now().UnixNano(), atomic.AddUint64(&tokenFallback, 1)&0xf)
}

var tokenFallback uint64

// tokenOf extracts the token label from an address NewAddress issued. Issued
// addresses are `<token>.<base>`, so the token is the first label; the guard
// on length and the dot keeps a malformed address from matching anything.
func tokenOf(addr string) string {
	addr = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(addr)), ".")
	if len(addr) == tokenLen {
		return addr
	}
	if len(addr) > tokenLen && addr[tokenLen] == '.' {
		return addr[:tokenLen]
	}
	return ""
}

// record attributes an observation to the token its traffic carried. Traffic
// with no known token is kept as unmatched noise — never attributed, never
// reported, but not silently dropped either.
func (s *Server) record(kind, detail, source string) {
	tok := s.findToken(detail)
	s.mu.Lock()
	defer s.mu.Unlock()
	at := time.Now()
	if tok == "" {
		s.unmatched = append(s.unmatched, Observation{Kind: kind, Detail: detail, Source: source, At: at})
		return
	}
	it := s.interacted[tok]
	switch kind {
	case "dns":
		it.DNS = true
	case "http":
		it.HTTP = true
	case "smtp":
		it.SMTP = true
	}
	it.Observed = append(it.Observed, Observation{Kind: kind, Detail: detail, Source: source, At: at})
}

// findToken scans a transcript for a label that names a known token. Splitting
// on every non-alphanumeric covers every embedding the corpus writes: dotted
// hostnames (`xff.<token>.<base>`), URLs, header values, mail addresses and
// SQL-ish strings alike.
func (s *Server) findToken(text string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, field := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		if len(field) == tokenLen {
			if _, ok := s.interacted[field]; ok {
				return field
			}
		}
	}
	return ""
}

// serve starts the per-protocol handler goroutines for the bound listeners.
func (s *Server) serve() {
	if s.httpLn != nil {
		hs := &http.Server{Handler: http.HandlerFunc(s.handleHTTP)}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = hs.Serve(s.httpLn) // returns ErrServerClosed once Close closes the listener
		}()
	}
	if s.dnsConn != nil {
		s.wg.Add(1)
		go s.serveDNS()
	}
	if s.smtpLn != nil {
		s.wg.Add(1)
		go s.serveSMTP()
	}
}

// handleHTTP records the request and acknowledges it. The Host header carries
// the token, so a target that fetched an injected `http://<token>.<base>/...`
// URL lands here attributed.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	s.record("http", r.Method+" "+r.URL.RequestURI()+" "+r.Proto+" host="+r.Host, r.RemoteAddr)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "interaction recorded\n")
}

// serveDNS answers A queries until the socket is closed. Names under the base
// get NOERROR with the A record pointing at the HTTP listener; AAAA gets
// NOERROR with no answer; anything else gets NXDOMAIN — the server is a
// collaborator, not an open resolver.
func (s *Server) serveDNS() {
	defer s.wg.Done()
	buf := make([]byte, 512)
	for {
		n, src, err := s.dnsConn.ReadFromUDP(buf)
		if err != nil {
			if s.closed.Load() {
				return
			}
			continue
		}
		id, labels, qtype, ok := parseDNSQuery(buf[:n])
		if !ok {
			continue
		}
		qname := strings.Join(labels, ".")
		s.record("dns", qname, src.String())
		resp := buildDNSResponse(id, labels, qtype, s.base, s.httpIP)
		_, _ = s.dnsConn.WriteToUDP(resp, src)
	}
}

// parseDNSQuery reads a single-question DNS query: the 12-byte header, then
// the question's QNAME (labels, with the compression pointer handled), QTYPE
// and QCLASS. Anything else returns ok=false and is ignored.
func parseDNSQuery(pkt []byte) (id uint16, labels []string, qtype uint16, ok bool) {
	if len(pkt) < 12 {
		return 0, nil, 0, false
	}
	id = binary.BigEndian.Uint16(pkt[0:2])
	if binary.BigEndian.Uint16(pkt[4:6]) == 0 { // QDCOUNT
		return 0, nil, 0, false
	}
	pos := 12
	for {
		if pos >= len(pkt) {
			return 0, nil, 0, false
		}
		l := int(pkt[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xC0 == 0xC0 {
			pos += 2 // compression pointer; question names never need following
			break
		}
		if l > 63 || pos+1+l > len(pkt) {
			return 0, nil, 0, false
		}
		labels = append(labels, strings.ToLower(string(pkt[pos+1:pos+1+l])))
		pos += 1 + l
	}
	if pos+4 > len(pkt) {
		return 0, nil, 0, false
	}
	qtype = binary.BigEndian.Uint16(pkt[pos : pos+2])
	return id, labels, qtype, true
}

// buildDNSResponse builds a single-answer response for the question. The TTL
// is deliberately short — an interaction address is one-shot and should not
// outlive the check that issued it.
func buildDNSResponse(id uint16, labels []string, qtype uint16, base string, ip net.IP) []byte {
	qname := strings.Join(labels, ".")
	flags := uint16(0x8183) // QR RD RA NXDOMAIN
	nx := true
	if qname == base || strings.HasSuffix(qname, "."+base) {
		flags = 0x8180 // QR RD RA NOERROR
		nx = false
	}
	answers := 0
	if !nx && qtype == 1 { // A
		answers = 1
	}
	out := make([]byte, 0, 64)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], 1)               // QDCOUNT
	binary.BigEndian.PutUint16(hdr[6:8], uint16(answers)) // ANCOUNT
	out = append(out, hdr[:]...)
	for _, l := range labels { // question name, uncompressed
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	out = append(out, 0)
	var qt [4]byte
	binary.BigEndian.PutUint16(qt[0:2], qtype)
	binary.BigEndian.PutUint16(qt[2:4], 1) // IN
	out = append(out, qt[:]...)
	if answers == 1 {
		out = append(out, 0xC0, 0x0C) // name pointer to the question
		var a [10]byte
		binary.BigEndian.PutUint16(a[0:2], 1)  // A
		binary.BigEndian.PutUint16(a[2:4], 1)  // IN
		binary.BigEndian.PutUint32(a[4:8], 60) // TTL
		binary.BigEndian.PutUint16(a[8:10], 4) // RDLENGTH
		out = append(out, a[:]...)
		ip4 := ip.To4()
		if ip4 == nil {
			ip4 = net.IPv4(127, 0, 0, 1)
		}
		out = append(out, ip4...)
	}
	return out
}

// serveSMTP accepts sessions and hands each to a goroutine.
func (s *Server) serveSMTP() {
	defer s.wg.Done()
	for {
		conn, err := s.smtpLn.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			continue
		}
		s.wg.Add(1)
		go s.handleSMTP(conn)
	}
}

// handleSMTP walks one client through a minimal transaction, recording the
// session transcript. The deadline bounds a stuck client so its goroutine
// cannot outlive the server. The token rides in whatever the client echoes —
// usually the RCPT or DATA lines — and attribution scans the whole transcript.
func (s *Server) handleSMTP(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	greet := func(line string) error {
		_, err := io.WriteString(conn, line)
		return err
	}
	if err := greet("220 burpsy interaction recorder ESMTP\r\n"); err != nil {
		return
	}
	var session strings.Builder
	br := bufio.NewReader(conn)
	inData := false
	done := false
	for !done {
		line, err := br.ReadString('\n')
		if err != nil {
			break // EOF or deadline: record what we saw
		}
		trimmed := strings.TrimRight(line, "\r\n")
		session.WriteString(trimmed)
		session.WriteByte('\n')
		switch {
		case inData:
			if trimmed == "." {
				inData = false
				if greet("250 OK\r\n") != nil {
					done = true
				}
			}
		case strings.HasPrefix(trimmed, "EHLO"):
			if greet("250-burpsy\r\n250 SIZE 10485760\r\n") != nil {
				done = true
			}
		case strings.HasPrefix(trimmed, "HELO"):
			if greet("250 burpsy\r\n") != nil {
				done = true
			}
		case strings.HasPrefix(trimmed, "MAIL FROM"), strings.HasPrefix(trimmed, "RCPT TO"):
			if greet("250 OK\r\n") != nil {
				done = true
			}
		case strings.HasPrefix(trimmed, "DATA"):
			if greet("354 go ahead\r\n") != nil {
				done = true
			} else {
				inData = true
			}
		case strings.HasPrefix(trimmed, "RSET"), strings.HasPrefix(trimmed, "NOOP"):
			if greet("250 OK\r\n") != nil {
				done = true
			}
		case strings.HasPrefix(trimmed, "QUIT"):
			_ = greet("221 bye\r\n")
			done = true
		}
	}
	s.record("smtp", session.String(), conn.RemoteAddr().String())
}
