package proxy

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// The proxy leg's network settings (burpsy-react-ui-o1eu).
//
// Both halves were unreachable from proxied traffic before the wiring: the resolution override and
// the 100-continue handling lived in sender.NetworkSettings and only the sender consulted them. The
// tests below drive the leg's own seams rather than the whole listener, because the listener needs
// a live origin and these two decisions are made in two small functions.

// TestAnInterimResponseIsReadPastWhenTheSettingIsOn is the 100-continue half. A peer that answers
// `Expect: 100-continue` with a 100 and then the real response must have the REAL response relayed:
// handing the client a bare "100 Continue" is a wrong answer that looks like a successful one.
func TestAnInterimResponseIsReadPastWhenTheSettingIsOn(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	go func() {
		// A 100 with no body, then the final response. This is what a compliant origin sends to an
		// `Expect: 100-continue` request.
		peer.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n"))
		peer.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
	}()

	got, _, err := readHTTPResponseSkippingInterim(client, true)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(string(got), "HTTP/1.1 200 OK") {
		t.Errorf("relayed %q, want the FINAL response. An interim 100 handed to a browser as its "+
			"response is a success that carries nothing", strings.SplitN(string(got), "\r\n", 2)[0])
	}
	if !strings.HasSuffix(string(got), "hi") {
		t.Error("the interim head was skipped but the final body was lost with it")
	}
}

// TestA101IsNeverSkipped: a 101 is not interim. It is the last HTTP response on the connection and
// the bytes after it belong to the upgraded protocol, so reading past it would consume the first
// WebSocket frames as though they were an HTTP head.
func TestA101IsNeverSkipped(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	go func() {
		peer.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	}()

	got, _, err := readHTTPResponseSkippingInterim(client, true)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(string(got), "HTTP/1.1 101") {
		t.Errorf("relayed %q; an upgrade answer must be returned as-is, frame bytes and all",
			strings.SplitN(string(got), "\r\n", 2)[0])
	}
}

// TestTheSettingOffReturnsTheInterimHeadVerbatim: the operator may deliberately be inspecting the
// interim exchange, and "off" must mean exactly the bytes the peer sent rather than a silent skip.
func TestTheSettingOffReturnsTheInterimHeadVerbatim(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	go func() {
		peer.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n"))
	}()

	got, _, err := readHTTPResponseSkippingInterim(client, false)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(string(got), "HTTP/1.1 100") {
		t.Errorf("with the setting off the interim head must be relayed verbatim, got %q",
			strings.SplitN(string(got), "\r\n", 2)[0])
	}
}

// TestInterimHeadsAreBounded: a peer answering with interim statuses forever needs a floor rather
// than a spin, and the error must name what happened so it is distinguishable from a slow peer.
func TestInterimHeadsAreBounded(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	go func() {
		for i := 0; i < maxInterimResponses+2; i++ {
			if _, err := peer.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n")); err != nil {
				return
			}
		}
	}()

	_, _, err := readHTTPResponseSkippingInterim(client, true)
	if err == nil {
		t.Fatal("an endless stream of interim heads was accepted; a peer keeping the connection " +
			"busy for nothing must be bounded")
	}
	if !strings.Contains(err.Error(), "interim") {
		t.Errorf("the error does not say what happened: %v", err)
	}
}

// TestTheResolutionOverrideIsAppliedToTheProxyDial is the other half: a split-horizon host is
// reached by the address the operator configured, not the one DNS answers with.
func TestTheResolutionOverrideIsAppliedToTheProxyDial(t *testing.T) {
	n := &NetworkSettings{
		Resolution: sender.ResolutionSettings{
			Overrides: []sender.HostOverride{
				{Host: "internal.app.test", Address: "10.9.8.7", Enabled: true},
			},
		},
	}

	if got := n.Resolution.DialAddress(t.Context(), "internal.app.test", 8443); got != "10.9.8.7:8443" {
		t.Errorf("dialled %q, want 10.9.8.7:8443. A hostname override that only the sender honours "+
			"is the setting silently not applying to the traffic the operator is watching", got)
	}
	// A host with no override is dialled as named — the override replaces the lookup, it does not
	// rewrite every address.
	if got := n.Resolution.DialAddress(t.Context(), "other.app.test", 80); got != "other.app.test:80" {
		t.Errorf("dialled %q for a host with no override; want it dialled as named", got)
	}
	// And a DISABLED override is not applied: an operator who turned one off must get the old
	// behaviour rather than a rule that still fires.
	n.Resolution.Overrides[0].Enabled = false
	if got := n.Resolution.DialAddress(t.Context(), "internal.app.test", 8443); got != "internal.app.test:8443" {
		t.Errorf("dialled %q for a DISABLED override; a switched-off rule must not apply", got)
	}
}

// TestTheExpectHeaderIsStrippedOnTheWayUpstream: a peer that stalls on `Expect: 100-continue`
// rather than answering it is what the setting is for, and the strip must be a splice that leaves
// every other byte of the request exactly as the browser sent it.
func TestTheExpectHeaderIsStrippedOnTheWayUpstream(t *testing.T) {
	req := []byte("POST /submit HTTP/1.1\r\nHost: app.test\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\nbody")

	got := string(withoutExpectHeader(req))
	if strings.Contains(got, "Expect:") {
		t.Error("the Expect header survived; the request will stall against a peer that waits for it")
	}
	if !strings.HasPrefix(got, "POST /submit HTTP/1.1\r\nHost: app.test\r\n") {
		t.Errorf("the request line or the preceding headers were altered: %q", got)
	}
	if !strings.HasSuffix(got, "\r\n\r\nbody") {
		t.Errorf("the head terminator or the body was altered: %q", got)
	}
	if strings.Count(got, "\r\n\r\n") != 1 {
		t.Error("the head terminator count changed; a second blank line would end the head early")
	}
}

func TestARequestWithoutExpectIsReturnedUnchanged(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: app.test\r\n\r\n")
	if got := withoutExpectHeader(req); string(got) != string(req) {
		t.Errorf("a request with no Expect header was altered: %q", got)
	}
}

func TestTheExpectStripKeepsABareLineFeedRequestBare(t *testing.T) {
	req := []byte("POST /x HTTP/1.1\nHost: app.test\nExpect: 100-continue\n\nbody")
	got := string(withoutExpectHeader(req))
	if strings.Contains(got, "Expect:") {
		t.Error("the Expect header survived in a bare-LF request")
	}
	if strings.Contains(got, "\r\n") {
		t.Error("a CRLF was introduced into a request that used bare line feeds; the bytes outside " +
			"the removed line must be the bytes that arrived")
	}
}

// TestTheHolderIsLiveNotACopy: the console edits these while the proxy runs, and this file's whole
// bug class is a setting that lapsed for part of the traffic. A value copied at construction would
// make every later edit a lie.
func TestTheHolderIsLiveNotACopy(t *testing.T) {
	c := NewProxyConfig(nil)
	if c.network == nil {
		t.Fatal("NewProxyConfig left the holder nil, so the console would need a nil check to push " +
			"an edit and the dial paths could not read it unconditionally")
	}
	if !c.network.Continue.Understand100 {
		t.Error("Understand100 is off by default; returning an interim 1xx as a result is wrong for " +
			"any client and both Burp and the sender default it on")
	}

	c.WithNetworkSettings(&NetworkSettings{})
	if c.network.Continue.Understand100 {
		t.Error("the explicit holder did not replace the default")
	}
	c.network.Set(sender.ResolutionSettings{}, sender.ContinueSettings{Understand100: true})
	if !c.network.Continue.Understand100 {
		t.Error("Set did not mutate the holder in place; the console's push would be invisible to " +
			"the dial and read paths")
	}
}

// TestTheInterimBoundMatchesTheSenders: two legs of one product with different floors for the same
// misbehaviour is a difference nobody could explain.
func TestTheInterimBoundMatchesTheSenders(t *testing.T) {
	if maxInterimResponses != 8 {
		t.Errorf("maxInterimResponses = %d; the sender's read.go uses 8 and the two legs should not "+
			"disagree about when a peer is misbehaving", maxInterimResponses)
	}
}

// guard against an unused import if the tests above change shape
var _ = bufio.NewReader
var _ = time.Second
