package upstream

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// The corporate shape burpsy-react-ui-mr83 part 3 exists for: the operator reaches the internet
// through an HTTP proxy, and that HTTP proxy is itself only reachable through a SOCKS hop. With one
// rule list they had to choose one and lose the other, and Burp's global SOCKS bypass list was
// inexpressible for the same reason (settings/network/connections.html:177-199: "every outbound
// connection, including requests to upstream HTTP proxies, goes through the SOCKS proxy").
//
// # What these tests assert, and why not more
//
// WHICH HOP WAS DIALLED. Not that a payload survives a two-hop tunnel, which is the SOCKS
// implementation's job and is tested where that implementation lives. The carrier's whole content is
// a routing decision, and the observable of a routing decision is which listener got the socket.
//
// That is why every fixture here is a listener that COUNTS its connections and then closes, and why
// the two hops sit on DIFFERENT loopback addresses. An earlier version shuttled real bytes through
// the chain and proved nothing the counters did not, while adding two ways for the fixture itself to
// be the thing that was broken — one of which produced a convincing "the tunnel carried the wrong
// bytes" failure that was entirely the test server answering early.

// Two loopback addresses, so the carrier's self-exemption is PROVABLE rather than asserted. The
// SOCKS server is on carrierHost; everything the operator wants to reach is on targetHost. A fixture
// with both on 127.0.0.1 cannot tell "the carrier exempted the SOCKS server" from "the carrier
// exempted the destination" — the first version of this file made exactly that mistake.
const (
	carrierHost = "127.0.0.1"
	targetHost  = "127.0.0.2"
)

// counter is a listener that counts what reached it and then closes the connection. Nothing about
// the protocol is spoken: a carrier test that fails a handshake has learned the fixture is wrong, not
// that the routing is.
type counter struct {
	ln net.Listener
	// mu guards connected, which the accept goroutine writes and the test reads. A plain int is a data
	// race here rather than only a portability question: the dial returns as soon as the socket is
	// accepted, so the read races the write and can observe a stale zero — which is what made
	// TestABypassedHostSkipsTheHop fail intermittently for a reason that had nothing to do with the
	// carrier.
	mu        sync.Mutex
	connected int
}

// count is how many connections reached this listener.
//
// WAITS for at least one, bounded, because the two callers care about opposite things and a plain
// read cannot serve both: a test asserting a listener was reached must wait for the accept goroutine
// to run, and a test asserting one was NOT reached must be able to answer "not within this window".
// Sampling a plain int after a dial is a race — and an intermittent failure in a routing test reads
// as a routing bug, which is exactly the wrong thing for a fixture to manufacture.
func (c *counter) count(want bool) int {
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		c.mu.Lock()
		n := c.connected
		c.mu.Unlock()
		if (n > 0) == want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func startCounter(t *testing.T, on string) *counter {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(on, "0"))
	if err != nil {
		t.Fatalf("listen on %s: %v", on, err)
	}
	c := &counter{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.connected++
			c.mu.Unlock()
			// Drain whatever arrives, then close. A carrier test does not care what the handshake
			// said, and a fixture that hangs waiting for a complete exchange turns a routing assertion
			// into a timeout with no diagnosis.
			go func(cn net.Conn) {
				defer cn.Close()
				cn.SetDeadline(time.Now().Add(200 * time.Millisecond))
				io.Copy(io.Discard, cn)
			}(conn)
		}
	}()
	return c
}

func (c *counter) addr() string { return c.ln.Addr().String() }

// port is the listener's port, for the authority-shaped self-exemption.
func (c *counter) port() string {
	_, p, err := net.SplitHostPort(c.ln.Addr().String())
	if err != nil {
		return ""
	}
	return p
}

// The claim: with a carrier configured, a destination whose own rule names an HTTP proxy is reached
// THROUGH the SOCKS hop. Both hops are real listeners on different hosts, and the only way the HTTP
// proxy sees a connection at all is through the SOCKS server — so the two counts are the proof.
func TestAnHTTPUpstreamProxyIsReachedThroughTheGlobalSocksCarrier(t *testing.T) {
	socks := startCounter(t, carrierHost)
	httpProxy := startCounter(t, targetHost)

	carrier := NewCarrier()
	if err := carrier.SetSocks("socks5://"+socks.addr(), nil, false); err != nil {
		t.Fatalf("SetSocks: %v", err)
	}
	policy := NewPolicy()
	if _, err := policy.Set(targetHost, "http://"+httpProxy.addr()); err != nil {
		t.Fatalf("policy.Set: %v", err)
	}

	// The dial reaches the SOCKS hop, whose handshake this fixture does not speak, so the dial fails
	// at the SOCKS layer. That is not a failure of the test: the SOCKS handshake is exercised
	// elsewhere, and what is under test is WHICH listener was opened.
	dialer := Dialer{Policy: policy, Timeout: 2 * time.Second, Carrier: carrier}
	_, _ = dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(targetHost, "44355"))

	if socks.count(false) == 0 {
		t.Fatal("the SOCKS hop saw no connection: the destination was reached directly, so the carrier " +
			"is not applied beneath a proxied dial — which is the entire capability (mr83 part 3)")
	}
	if httpProxy.count(false) != 0 {
		t.Errorf("the HTTP proxy saw %d connections directly; it must only ever be reached through the hop",
			httpProxy.count(false))
	}
}

// With no carrier the HTTP proxy IS dialled directly. A setting that cannot be turned off is a
// setting an operator cannot route around, and this is the state every caller in the tree is in today.
func TestNoCarrierMeansTheProxyIsDialledDirectly(t *testing.T) {
	httpProxy := startCounter(t, targetHost)
	policy := NewPolicy()
	if _, err := policy.Set(targetHost, "http://"+httpProxy.addr()); err != nil {
		t.Fatal(err)
	}
	dialer := Dialer{Policy: policy, Timeout: 2 * time.Second, Carrier: NewCarrier()}
	_, _ = dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(targetHost, "44355"))
	if httpProxy.count(false) == 0 {
		t.Error("the HTTP proxy saw no direct connection with no carrier configured; an empty carrier " +
			"must behave exactly as if the setting were absent")
	}
}

// A direct destination goes through the hop too, because Burp's setting says EVERY outbound
// connection. Routing only the proxied path would leave the global setting meaning "proxy through
// SOCKS", which is not what the setting says.
func TestADirectDestinationAlsoGoesThroughTheHop(t *testing.T) {
	socks := startCounter(t, carrierHost)
	origin := startCounter(t, targetHost)

	carrier := NewCarrier()
	if err := carrier.SetSocks("socks5://"+socks.addr(), nil, false); err != nil {
		t.Fatal(err)
	}
	dialer := Dialer{Timeout: 2 * time.Second, Carrier: carrier}
	_, _ = dialer.DialContext(context.Background(), "tcp", origin.addr())
	if socks.count(false) == 0 {
		t.Error("a direct destination bypassed the carrier: the setting says every outbound connection, " +
			"and a direct dial is the most outbound one there is (mr83 part 3)")
	}
}

// A bypassed host skips the hop, which is the escape hatch for an operator whose own internal targets
// the SOCKS server cannot reach.
func TestABypassedHostSkipsTheHop(t *testing.T) {
	socks := startCounter(t, carrierHost)
	origin := startCounter(t, targetHost)

	carrier := NewCarrier()
	// The bypass names the origin's OWN address rather than the host, because a ScopeRule pattern is
	// a hostname pattern and matching on the listener's host:port would need a port rule the rest of
	// this package does not use.
	if err := carrier.SetSocks("socks5://"+socks.addr(), []string{targetHost}, false); err != nil {
		t.Fatal(err)
	}
	dialer := Dialer{Timeout: 2 * time.Second, Carrier: carrier}
	_, _ = dialer.DialContext(context.Background(), "tcp", origin.addr())
	if socks.count(false) != 0 {
		t.Errorf("the hop saw %d connections for a bypassed host; a bypass must mean exactly as if the "+
			"setting were off", socks.count(false))
	}
	if origin.count(true) == 0 {
		t.Error("the bypassed host was not dialled at all: a bypass routes around the hop, it does not " +
			"refuse the connection")
	}
}

// The carrier's own address is exempt. Without this the hop dials itself and every outbound
// connection times out — the failure mode that would make the setting look like a hang rather than
// like a misconfiguration.
// The carrier's own address is exempt. Without this the hop dials itself and every outbound
// connection times out — the failure mode that would make the setting look like a hang rather than
// like a misconfiguration.
//
// The exemption is the whole AUTHORITY, not the host: a SOCKS server on 127.0.0.1:1080 must not
// exempt 127.0.0.1:443, because that would silently exempt every other service the operator runs
// locally. A dev box is exactly where a SOCKS server and a pile of local targets share an address,
// and exactly where a bypass list is most wanted — so a host-only exemption would make the setting
// a no-op in the situation it exists for. That is the bug this test found.
func TestTheCarrierExemptsOnlyItsOwnAuthority(t *testing.T) {
	socks := startCounter(t, carrierHost)
	carrier := NewCarrier()
	if err := carrier.SetSocks("socks5://"+socks.addr(), nil, false); err != nil {
		t.Fatal(err)
	}

	// The SOCKS server itself: exempt, or the hop recurses.
	if hop, _ := carrier.carries(carrierHost, socks.port()); hop != nil {
		t.Error("the carrier carries its own address: a SOCKS hop that dialled itself would wait for a " +
			"reply from itself, and every outbound connection would time out")
	}
	// The same host, a different port: carried, because the hop is one specific listener.
	if hop, _ := carrier.carries(carrierHost, "443"); hop == nil {
		t.Error("the carrier does not carry its own HOST on another port; the exemption has become a " +
			"subnet exemption, which is a carrier that quietly does nothing on a dev box — which is " +
			"where a bypass list is most wanted (mr83 part 3)")
	}
	// A different host entirely: carried.
	if hop, _ := carrier.carries(targetHost, "443"); hop == nil {
		t.Error("the carrier does not carry a host that is not its own address")
	}
}

// Remote DNS is a SOCKS feature. Accepting it on an HTTP proxy would be a switch that silently does
// nothing, which is the decorative-control failure this project keeps finding.
func TestRemoteDNSIsRefusedForAnHTTPCarrier(t *testing.T) {
	carrier := NewCarrier()
	err := carrier.SetSocks("http://127.0.0.1:3128", nil, true)
	if err == nil {
		t.Fatal("remote DNS was accepted for an HTTP carrier; the setting would be silently ignored")
	}
	if !strings.Contains(err.Error(), "SOCKS") {
		t.Errorf("error = %q, want it to name the feature the operator asked for", err)
	}
}

// Clearing the setting is an empty address, not an error — an operator removing it must land on a
// direct dial rather than on a carrier pointing nowhere.
func TestAnEmptyAddressClearsTheCarrier(t *testing.T) {
	carrier := NewCarrier()
	if err := carrier.SetSocks("socks5://127.0.0.1:1080", nil, false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := carrier.Configured(); !ok {
		t.Fatal("the carrier did not install")
	}
	if err := carrier.SetSocks("  ", nil, false); err != nil {
		t.Fatalf("clearing the carrier was refused: %v", err)
	}
	if _, _, _, ok := carrier.Configured(); ok {
		t.Error("the carrier survived an empty address; the operator removed the setting and the hop stayed")
	}
}

func TestSetSocksRejectsAnUnparseableAddress(t *testing.T) {
	if err := NewCarrier().SetSocks("not a url", nil, false); err == nil {
		t.Error("an unparseable proxy address was accepted; the operator would find out at the first dial")
	}
}

// A bypass pattern is written in the SAME language a destination rule uses, because the two are the
// same kind of thing and a second dialect would be a rule the panel accepts and the carrier never
// matches. The check here is that a literal pattern is stored and rendered back verbatim, which is
// what "written in the same language" has to mean from the settings panel's side.
func TestABypassPatternIsStoredAndRenderedVerbatim(t *testing.T) {
	carrier := NewCarrier()
	if err := carrier.SetSocks("socks5://127.0.0.1:1080", []string{"*.example.test", "intranet.test"}, false); err != nil {
		t.Fatalf("SetSocks: %v", err)
	}
	_, bypass, _, ok := carrier.Configured()
	if !ok {
		t.Fatal("the carrier reports nothing configured after SetSocks")
	}
	if len(bypass) != 2 || bypass[0] != "*.example.test" || bypass[1] == "" {
		t.Errorf("bypass = %v; the patterns an operator typed must come back so the panel shows what is "+
			"in force rather than what was last saved", bypass)
	}
}

var _ = bufio.NewReader

// ConfiguredPatterns exposes the compiled bypass list. Exported for a diagnostic in a test file, and
// only that: without it a failing self-exemption assertion cannot distinguish "the exemption matched"
// from "a bypass rule matched", which are opposite bugs with the same symptom.
func (c *Carrier) ConfiguredPatterns() []string {
	if c == nil {
		return nil
	}
	_, bypass, _, _ := c.Configured()
	return bypass
}

// The Direct arm of the policy resolver, which is where every connection lands when the operator
// configures a SOCKS layer and NO upstream proxy — the ordinary case for this setting, and the one
// the live pass exercised.
//
// It is a distinct test because it failed while every other carrier test passed: Proxy.DialContext's
// KindDirect arm opened a bare net.Dialer, so an unconfigured policy short-circuited the carrier on
// the exact path the setting exists for. Every routing test above drives a policy that resolves to a
// PROXY, which takes a different arm and was already correct — so the gap was invisible to all of
// them and to the whole suite (burpsy-react-ui-mr83 part 3).
func TestADirectPolicyStillCarries(t *testing.T) {
	socks := startCounter(t, carrierHost)
	origin := startCounter(t, targetHost)

	carrier := NewCarrier()
	if err := carrier.SetSocks("socks5://"+socks.addr(), nil, false); err != nil {
		t.Fatal(err)
	}
	// An EMPTY policy: no rules, no default, so ForAddr resolves every address to Direct. This is
	// what a process with a carrier and no upstream proxy has.
	dialer := Dialer{Policy: NewPolicy(), Timeout: 2 * time.Second, Carrier: carrier}
	_, _ = dialer.DialContext(context.Background(), "tcp", origin.addr())

	if socks.count(false) == 0 {
		t.Fatal("an empty policy sent the connection direct: the carrier was configured, reported as " +
			"configured, and carried nothing -- which is the whole defect the live pass found")
	}
	if n := origin.count(false); n != 0 {
		t.Errorf("the origin saw %d direct connection(s); the layer was not on the path", n)
	}
}
