package sender

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// hostPort splits an address into host and numeric port for the sender's typed API.
func hostPort(addr string) (string, uint16, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, uint16(n), nil
}

// localServer answers every request with a fixed 200, recording nothing but proving bytes arrived.
func localServer(t *testing.T) (string, []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	addr := ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				// Read the head; the body (if any) is drained so the request fully arrives before
				// the response is written.
				head := ""
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					head += line
					if strings.HasSuffix(head, "\r\n\r\n") || strings.HasSuffix(head, "\n\n") {
						break
					}
				}
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()
	return addr, nil
}

func TestAnOutOfScopeRequestIsRefusedBeforeTheTransportIsReached(t *testing.T) {
	sc := core.NewScope()
	sc.AddExclude("127.0.0.1")
	// Port 1 is closed everywhere; reaching it would be a dial error, so a scope-shaped error
	// proves the transport was never touched.
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), "127.0.0.1", 1, false)
	_, err := a.Send(context.Background(), []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("want a scope refusal, got %v", err)
	}
	if a.Sent() != 0 {
		t.Fatalf("sent = %d, want 0: nothing passed the gate", a.Sent())
	}
	if a.Refused() != 1 {
		t.Fatalf("refused = %d, want 1", a.Refused())
	}
}

func TestAnInScopeRequestIsSentAndReturnsTheResponse(t *testing.T) {
	addr, _ := localServer(t)
	_, port, err := hostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	sc := core.NewScopeAllowEverything()
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), "127.0.0.1", port, false)
	res, err := a.Send(context.Background(), []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res.Status == nil || *res.Status != 200 {
		t.Fatalf("status = %v, want 200", res.Status)
	}
	if !strings.Contains(string(res.Raw), "ok") {
		t.Fatalf("response lost its body: %q", res.Raw)
	}
	if res.Duration <= 0 {
		t.Fatalf("duration = %v, want > 0", res.Duration)
	}
	if a.Sent() != 1 || a.Refused() != 0 {
		t.Fatalf("sent/refused = %d/%d, want 1/0", a.Sent(), a.Refused())
	}
}

// The named host is fully in scope; the request bytes are not. This is the sender half of the
// intruder guarantee: a payload spliced into a path position rewrites the request line, and only
// the bytes actually going on the wire can be trusted.
func TestTheSplicedBytesNotTheNamedTargetAreChecked(t *testing.T) {
	addr, _ := localServer(t)
	_, port, err := hostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	sc := core.NewScope()
	sc.AddInclude("127.0.0.1")
	sc.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "127.0.0.1", "/admin"))
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), "127.0.0.1", port, false)

	if _, err := a.Send(context.Background(), []byte("GET /admin/delete HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")); err == nil {
		t.Fatal("a request whose path is excluded must be refused even though the host is in scope")
	}
	if _, err := a.Send(context.Background(), []byte("GET /search HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")); err != nil {
		t.Fatalf("the in-scope path must be sent: %v", err)
	}
	if a.Sent() != 1 || a.Refused() != 1 {
		t.Fatalf("sent/refused = %d/%d, want 1/1", a.Sent(), a.Refused())
	}
}

// countingTarget is a target that counts what actually arrived, per path.
//
// A counter on the target is the only instrument that proves a refusal happened before the dial.
// AuthorisedSender.Refused() proves bookkeeping, and bookkeeping can be perfectly right while the
// request still goes out; only a silent target proves it did not.
type countingTarget struct {
	mu   sync.Mutex
	hits map[string]int
	url  string
	host string
	port uint16
}

func newCountingTarget(t *testing.T, handle http.HandlerFunc) *countingTarget {
	t.Helper()
	ct := &countingTarget{hits: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct.mu.Lock()
		ct.hits[r.URL.Path]++
		ct.mu.Unlock()
		if handle != nil {
			handle(w, r)
			return
		}
		w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	ct.url = srv.URL
	host, port, err := hostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("target address %q: %v", srv.URL, err)
	}
	ct.host, ct.port = host, port
	return ct
}

func (ct *countingTarget) hitCount(path string) int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return ct.hits[path]
}

func (ct *countingTarget) total() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	n := 0
	for _, c := range ct.hits {
		n += c
	}
	return n
}

// The typed path is gated by the same rule as the raw one, and the proof is a target that saw
// nothing. Sender.Send would have sent this: it authorises nothing at all.
func TestSendRequestRefusesAnOutOfScopePathAndTheTargetSeesNothing(t *testing.T) {
	target := newCountingTarget(t, nil)
	sc := core.NewScope()
	sc.AddInclude(target.host)
	sc.Add(core.NewScopeRuleWithPath(core.ScopeExclude, target.host, "/admin"))
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), target.host, target.port, false)

	_, err := a.SendRequest(context.Background(), &Request{Method: "POST", Path: "/admin/delete"})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("want a scope refusal, got %v", err)
	}
	if got := target.total(); got != 0 {
		t.Fatalf("the target saw %d requests, want 0: the refusal must happen before the dial", got)
	}
	if a.Sent() != 0 || a.Refused() != 1 {
		t.Fatalf("sent/refused = %d/%d, want 0/1", a.Sent(), a.Refused())
	}

	// The same sender still sends what is in scope, so the zero above is a refusal and not a sender
	// that cannot send.
	resp, err := a.SendRequest(context.Background(), &Request{Method: "GET", Path: "/search"})
	if err != nil {
		t.Fatalf("the in-scope path must be sent: %v", err)
	}
	if resp.StatusCode != 200 || string(resp.Body) != "ok" {
		t.Fatalf("resp = %d %q, want 200 ok", resp.StatusCode, resp.Body)
	}
	if got := target.hitCount("/search"); got != 1 {
		t.Fatalf("/search hit %d times, want 1", got)
	}
}

// A 30x is a response, not an instruction this sender acts on. The scope here allows everything on
// purpose: the guarantee must come from the transport never following, not from a scope rule catching
// a hop the gate was never asked about. Following inside the transport would dial the second
// authority with no gate in front of it, which is the redirect-to-internal-service escape.
func TestARedirectToAnotherAuthorityIsNotFollowed(t *testing.T) {
	elsewhere := newCountingTarget(t, nil)
	target := newCountingTarget(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", elsewhere.url+"/internal")
		w.WriteHeader(http.StatusFound)
	})
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), NewSender(DefaultSenderConfig()), target.host, target.port, false)

	resp, err := a.SendRequest(context.Background(), &Request{Method: "GET", Path: "/go"})
	if err != nil {
		t.Fatalf("a 30x must come back as a response, not an error: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302: the operator must see the redirect itself", resp.StatusCode)
	}
	if got := resp.Headers["Location"]; got != elsewhere.url+"/internal" {
		t.Fatalf("Location = %q, want the untouched redirect target", got)
	}
	if got := elsewhere.total(); got != 0 {
		t.Fatalf("the redirect target saw %d requests, want 0: no hop may be dialled without its own gate", got)
	}
	if a.Sent() != 1 {
		t.Fatalf("sent = %d, want 1: exactly the one request the caller asked for", a.Sent())
	}
}

// A bound sender's authority is not a suggestion. A caller that names another one is refused rather
// than quietly redirected to the bound target, because both silent outcomes are wrong: sending to the
// named host escapes the gate, and sending the named host's request to the bound host answers a
// question nobody asked.
func TestSendRequestRefusesARequestNamingAnotherAuthority(t *testing.T) {
	elsewhere := newCountingTarget(t, nil)
	target := newCountingTarget(t, nil)
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), NewSender(DefaultSenderConfig()), target.host, target.port, false)

	byURL := &Request{Method: "GET", URL: elsewhere.url + "/internal"}
	if _, err := a.SendRequest(context.Background(), byURL); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("an absolute URL naming another authority must be refused, got %v", err)
	}
	byPort := &Request{Method: "GET", Host: elsewhere.host, Port: elsewhere.port, Path: "/internal"}
	if _, err := a.SendRequest(context.Background(), byPort); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("a host/port naming another authority must be refused, got %v", err)
	}
	if got := elsewhere.total(); got != 0 {
		t.Fatalf("the named authority saw %d requests, want 0", got)
	}
	if got := target.total(); got != 0 {
		t.Fatalf("the bound target saw %d requests, want 0: a refused request is not silently rehomed", got)
	}
	if a.Refused() != 2 {
		t.Fatalf("refused = %d, want 2", a.Refused())
	}
}

// The gate reads the rendered request line, so a path assembled at send time — a session macro's
// {{token}} interpolated into a URL is the live case — is checked as what it became.
func TestSendRequestGatesTheRenderedRequestLineNotTheTemplate(t *testing.T) {
	target := newCountingTarget(t, nil)
	sc := core.NewScope()
	sc.AddInclude(target.host)
	sc.Add(core.NewScopeRuleWithPath(core.ScopeExclude, target.host, "/admin"))
	snd := NewSender(DefaultSenderConfig())

	raw, err := snd.Render(&Request{Method: "GET", Host: target.host, Port: target.port, Path: "/admin?next=/ok"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.HasPrefix(string(raw), "GET /admin?next=/ok HTTP/1.1\r\nHost: ") {
		t.Fatalf("rendered request line = %q, want the path as it will go on the wire", raw)
	}

	a := NewAuthorisedSender(sc, snd, target.host, target.port, false)
	if _, err := a.SendRequest(context.Background(), &Request{Method: "GET", Path: "/admin?next=/ok"}); err == nil {
		t.Fatal("the excluded path must be refused even though the query string names an allowed one")
	}
	if got := target.total(); got != 0 {
		t.Fatalf("the target saw %d requests, want 0", got)
	}
}

func TestConcurrentSendsDoNotLoseCounters(t *testing.T) {
	addr, _ := localServer(t)
	_, port, err := hostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	sc := core.NewScopeAllowEverything()
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), "127.0.0.1", port, false)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Send(context.Background(), []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
		}()
	}
	wg.Wait()
	if a.Sent() != 16 {
		t.Fatalf("sent = %d, want 16 (no counter may be lost under the race detector)", a.Sent())
	}
	if a.Refused() != 0 {
		t.Fatalf("refused = %d, want 0", a.Refused())
	}
}
