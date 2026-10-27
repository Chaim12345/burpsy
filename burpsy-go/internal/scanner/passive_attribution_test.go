package scanner

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// The built-in passive checks (security headers, information disclosure, cookie security) build
// their Finding literals by hand, and each one must name the exchange it read. When they did
// not, ExchangeID defaulted to 0: every downstream consumer — occurrence binding, report
// host/path/method, host-scoped dedup — attributed the finding to the first exchange in the
// store, so the second host's findings merged into the first host's issue.
func TestNativePassiveFindingsCarryTheirExchangeID(t *testing.T) {
	store := core.NewTrafficStore()
	ps := NewPassiveScanner(store, zap.NewNop())

	add := func(host string, port uint16, tls bool, path, response string) *core.Exchange {
		t.Helper()
		reqID, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
		if err != nil {
			t.Fatal(err)
		}
		respID, err := store.Put([]byte(response), core.DirectionResponse)
		if err != nil {
			t.Fatal(err)
		}
		ex := &core.Exchange{
			Host: host, Port: port, TLS: tls, Method: "GET", Path: path,
			Request: core.MsgPtr(reqID), Response: &respID,
		}
		store.AddExchange(ex)
		return ex
	}

	exA := add("alpha.invalid", 80, false, "/", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	// A TLS exchange with a bare Set-Cookie fires both header checks and all three cookie
	// checks: enough literals that a missed attribution cannot hide behind one lucky one.
	exB := add("beta.invalid", 443, true, "/app", "HTTP/1.1 200 OK\r\nSet-Cookie: s=1; Path=/\r\nContent-Length: 2\r\n\r\nok")

	findingsA := ps.Scan(exA)
	if len(findingsA) == 0 {
		t.Fatal("expected native findings on a bare response")
	}
	for _, f := range findingsA {
		if f.ExchangeID != exA.ID {
			t.Errorf("finding %q attributed to exchange %d, want %d (%s)", f.Name, f.ExchangeID, exA.ID, exA.Host)
		}
	}

	findingsB := ps.Scan(exB)
	if len(findingsB) < 5 {
		t.Fatalf("findings on the TLS cookie exchange = %d, want at least 5 (2 header + 3 cookie)", len(findingsB))
	}
	for _, f := range findingsB {
		if f.ExchangeID != exB.ID {
			// exB is not exchange 0, so the zero default lands here: this is the assertion
			// that fails when a literal omits ExchangeID.
			t.Errorf("finding %q attributed to exchange %d, want %d (%s)", f.Name, f.ExchangeID, exB.ID, exB.Host)
		}
	}
}
