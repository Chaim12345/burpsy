package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// Burp's history carries an IP column ("the IP address of the destination server") and a Listener
// port column ("the listener port on which the request was received"). Neither fact was captured
// at all (burpsy-react-ui-mr4p, burpsy-react-ui-he81).
//
// Both are recorded at capture rather than derived when a row is listed, and the reason is stronger
// than the one Mime and Title have. Those could be re-derived from stored bytes at a cost; these
// describe sockets that are closed by the time anyone lists the row. Re-resolving the host later
// would answer "where does this name point now" — a different question, for a round-robin or a
// failover a different answer — and present it as a fact about this exchange.
//
// These tests assert the values are on the row after real traffic, which is also the guard that
// keeps them there: the proxy has five capture sites, and the reason this file exists rather than a
// unit test on the helpers is that a sixth site added later would otherwise record neither and
// nothing would notice.

func TestAProxiedExchangeRecordsTheServerIPAndListenerPort(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer origin.Close()
	ohost, oportStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	oport, _ := strconv.Atoi(oportStr)

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(core.NewScope()).
		WithLogger(zap.NewNop()))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()
	_, listenerPortStr, _ := net.SplitHostPort(ln.Addr().String())
	wantListenerPort, _ := strconv.Atoi(listenerPortStr)

	// Driven through THIS test's listener rather than driveThroughProxy's, because the port it
	// records is the whole subject of the second assertion below.
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
	}}
	resp, err := client.Get("http://" + net.JoinHostPort(ohost, strconv.Itoa(oport)) + "/page")
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	_ = resp.Body.Close()

	recorded := waitForExchanges(t, store, 1)
	if len(recorded) != 1 {
		t.Fatalf("recorded %d exchanges, want 1", len(recorded))
	}
	ex := recorded[0]

	// The origin is a loopback listener, so its resolved address is knowable and exact — this is
	// not asserting "something non-empty", which a helper that returned the client's own address
	// would also satisfy.
	if ex.ServerIP != "127.0.0.1" {
		t.Errorf("ServerIP = %q, want 127.0.0.1 (the destination the socket actually reached)", ex.ServerIP)
	}
	// And the listener port is this test's own ephemeral port, not the origin's and not a configured
	// bind — which is the distinction that matters once a listener can be rebound.
	if int(ex.ListenerPort) != wantListenerPort {
		t.Errorf("ListenerPort = %d, want %d (the port the client connected to)", ex.ListenerPort, wantListenerPort)
	}
	if int(ex.ListenerPort) == oport {
		t.Errorf("ListenerPort = %d, which is the ORIGIN's port; the column must name the listener", ex.ListenerPort)
	}
}

// The helpers must not invent an answer. A producer with no socket in hand records neither field,
// and "" / 0 are the honest values — a column that showed a plausible IP for a Repeater send would
// be worse than an empty one.
func TestTheSocketHelpersRefuseToGuess(t *testing.T) {
	if got := serverIPOf(nil); got != "" {
		t.Errorf("serverIPOf(nil) = %q, want empty", got)
	}
	if got := listenerPortOf(nil); got != 0 {
		t.Errorf("listenerPortOf(nil) = %d, want 0", got)
	}
}
