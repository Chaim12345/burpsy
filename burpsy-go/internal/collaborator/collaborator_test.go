// Tests for the in-process interaction recorder: token issuance, per-protocol
// recording, and attribution. Every assertion inspects what the server
// actually observed — a test that only proved "the listener answered" would
// pass even if the store never recorded anything.
package collaborator

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// startTest binds every listener on an ephemeral port and registers cleanup.
func startTest(t *testing.T) *Server {
	t.Helper()
	srv, err := New(Config{Base: "burpsy.test", HTTP: "127.0.0.1:0", DNS: "127.0.0.1:0", SMTP: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func TestNewAddressIsUniqueAndScopedToTheBase(t *testing.T) {
	srv := startTest(t)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		a := srv.NewAddress()
		if !strings.HasSuffix(a, ".burpsy.test") {
			t.Fatalf("address %q not under the base domain", a)
		}
		if tok := tokenOf(a); len(tok) != tokenLen {
			t.Fatalf("address %q token %q is not %d hex chars", a, tok, tokenLen)
		}
		if seen[a] {
			t.Fatalf("duplicate address %q", a)
		}
		seen[a] = true
	}
}

func TestHTTPInteractionIsRecordedAndAttributedByToken(t *testing.T) {
	srv := startTest(t)
	addr := srv.NewAddress()
	other := srv.NewAddress()

	// Fetch through the HTTP listener with the issued address as the Host
	// header — exactly what a target that fetched `http://<addr>/probe`
	// produces once DNS resolves.
	req, err := http.NewRequest(http.MethodGet, "http://"+srv.HTTPAddr()+"/probe?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = addr
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetch through recorder: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("recorder answered %d, want 200", resp.StatusCode)
	}

	dns, httpHit, smtp := srv.Interactions([]string{addr})
	if !httpHit || dns || smtp {
		t.Fatalf("expected only an http interaction for %q, got dns=%v http=%v smtp=%v", addr, dns, httpHit, smtp)
	}
	// Attribution never bleeds to an untouched address, even though both live
	// under the same base and the server is shared.
	if d, h, s := srv.Interactions([]string{other}); d || h || s {
		t.Fatalf("untouched address %q reported interactions dns=%v http=%v smtp=%v", other, d, h, s)
	}
}

func TestDNSInteractionIsRecordedAndAnsweredWithAnARecord(t *testing.T) {
	srv := startTest(t)
	addr := srv.NewAddress()

	conn, err := net.Dial("udp", srv.DNSAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(dnsQuery(0xbeef, addr, 1)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no DNS answer: %v", err)
	}
	id, flags, ancount, aip, ok := parseDNSResponse(buf[:n])
	if !ok {
		t.Fatal("malformed DNS response")
	}
	if id != 0xbeef {
		t.Fatalf("answer id %#x, want 0xbeef", id)
	}
	if rcode := flags & 0xf; rcode != 0 {
		t.Fatalf("rcode %d, want NOERROR", rcode)
	}
	if ancount != 1 {
		t.Fatalf("ancount %d, want 1", ancount)
	}
	if aip == nil || !aip.Equal(srv.httpIP) {
		t.Fatalf("A record %v, want the HTTP listener %v", aip, srv.httpIP)
	}

	dns, httpHit, smtp := srv.Interactions([]string{addr})
	if !dns || httpHit || smtp {
		t.Fatalf("expected only a dns interaction, got dns=%v http=%v smtp=%v", dns, httpHit, smtp)
	}
}

func TestDNSRefusesNamesOutsideTheBaseAndDoesNotAttribute(t *testing.T) {
	srv := startTest(t)

	conn, err := net.Dial("udp", srv.DNSAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A foreign name is NXDOMAIN with no answer: the recorder is a collaborator
	// for its own base, not an open resolver.
	if _, err := conn.Write(dnsQuery(0x1111, "evil.example.com", 1)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no DNS reply: %v", err)
	}
	_, flags, ancount, _, ok := parseDNSResponse(buf[:n])
	if !ok {
		t.Fatal("malformed DNS response")
	}
	if rcode := flags & 0xf; rcode != 3 {
		t.Fatalf("rcode %d, want NXDOMAIN", rcode)
	}
	if ancount != 0 {
		t.Fatalf("ancount %d, want 0 for a refused name", ancount)
	}
	// The query was observed but never attributed — recorded as unmatched
	// noise, not as an interaction of some unknowable check.
	srv.mu.RLock()
	unmatched := len(srv.unmatched)
	srv.mu.RUnlock()
	if unmatched == 0 {
		t.Fatal("foreign query not recorded as unmatched noise")
	}
}

func TestSMTPInteractionIsRecordedFromTheSessionTranscript(t *testing.T) {
	srv := startTest(t)
	addr := srv.NewAddress()

	conn, err := net.Dial("tcp", srv.SMTPAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(conn)
	expect := func(prefix string) {
		t.Helper()
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("smtp read: %v", err)
		}
		if !strings.HasPrefix(line, prefix) {
			t.Fatalf("smtp expected a line starting %q, got %q", prefix, line)
		}
	}
	say := func(s string) {
		t.Helper()
		if _, err := io.WriteString(conn, s+"\r\n"); err != nil {
			t.Fatal(err)
		}
	}
	expect("220 ")
	say("EHLO tester")
	expect("250") // multi-line greeting: first line, then the SIZE continuation
	expect("250")
	say("MAIL FROM:<a@example.com>")
	expect("250")
	// The corpus's email-splitting checks put the interaction address in the
	// recipient; the recorder must find the token in the session transcript.
	say("RCPT TO:<" + addr + ">")
	expect("250")
	say("DATA")
	expect("354")
	say("Subject: look here")
	say("")
	say(".")
	expect("250")
	say("QUIT")
	expect("221")

	dns, httpHit, smtp := srv.Interactions([]string{addr})
	if !smtp || dns || httpHit {
		t.Fatalf("expected only an smtp interaction, got dns=%v http=%v smtp=%v", dns, httpHit, smtp)
	}
}

func TestNewRefusesAnEmptyBaseDomain(t *testing.T) {
	if _, err := New(Config{HTTP: "127.0.0.1:0"}); err == nil {
		t.Fatal("New with no base domain succeeded")
	}
}

func TestNewRefusesAnOccupiedListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, err := New(Config{Base: "x.test", HTTP: ln.Addr().String()}); err == nil {
		t.Fatal("New succeeded on an occupied port")
	}
}

func TestCloseStopsTheListeners(t *testing.T) {
	srv := startTest(t)
	addr := srv.NewAddress()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	conn, err := net.DialTimeout("tcp", srv.HTTPAddr(), time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("HTTP listener still accepting after Close")
	}
	// The store is the point of the server: Close must not destroy observations.
	dns, httpHit, smtp := srv.Interactions([]string{addr})
	if dns || httpHit || smtp {
		t.Fatalf("unexpected interactions after Close: dns=%v http=%v smtp=%v", dns, httpHit, smtp)
	}
}

// dnsQuery builds a single-question DNS query packet.
func dnsQuery(id uint16, name string, qtype uint16) []byte {
	out := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	out = append(out, byte(qtype>>8), byte(qtype))
	out = append(out, 0, 1) // IN
	return out
}

// parseDNSResponse reads the fields the tests assert on, skipping the question
// section (compression pointers and all) and returning the first answer's A
// record when present.
func parseDNSResponse(pkt []byte) (id, flags uint16, ancount uint16, aip net.IP, ok bool) {
	if len(pkt) < 12 {
		return 0, 0, 0, nil, false
	}
	id = binary.BigEndian.Uint16(pkt[0:2])
	flags = binary.BigEndian.Uint16(pkt[2:4])
	ancount = binary.BigEndian.Uint16(pkt[6:8])
	pos := 12
	// Question name(s): one per QDCOUNT, which our queries always set to 1.
	for pos < len(pkt) {
		l := int(pkt[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xC0 == 0xC0 {
			pos += 2
			break
		}
		pos += 1 + l
	}
	if pos+4 > len(pkt) {
		return id, flags, ancount, nil, false
	}
	pos += 4 // QTYPE + QCLASS
	if ancount == 0 {
		return id, flags, ancount, nil, true
	}
	if pos+10 > len(pkt) {
		return id, flags, ancount, nil, false
	}
	pos += 10 // name pointer + TYPE + CLASS + TTL
	if pos+2+4 > len(pkt) {
		return id, flags, ancount, nil, false
	}
	rdlen := int(binary.BigEndian.Uint16(pkt[pos : pos+2]))
	pos += 2
	if rdlen != 4 || pos+4 > len(pkt) {
		return id, flags, ancount, nil, false
	}
	return id, flags, ancount, net.IP(pkt[pos : pos+4]), true
}
