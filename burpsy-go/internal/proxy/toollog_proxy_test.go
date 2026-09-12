package proxy

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"go.uber.org/zap"
)

// Relayed browser traffic belongs in the unified tool log (burpsy-react-ui-6dt): the log's
// subject is everything burpsy did, which is the whole difference between it and HTTP history's
// proxied-browser-only view ("Logger records all the HTTP traffic that Burp Suite generates […]
// by contrast, the HTTP history only displays traffic from a browser that is proxied").
//
// Driven through the real listen loop and a real origin rather than by calling record(): the
// question is whether a request arriving on the socket becomes a row, and a direct call would
// assume the answer.
func TestARelayedExchangeBecomesAProxyRowInTheToolLog(t *testing.T) {
	log := toollog.New()
	store := core.NewTrafficStore()
	host, port := originSaying(t, "hello from the origin")
	srv := NewServer(NewProxyConfig(store).WithLogger(zap.NewNop()).WithToolLog(log))
	addr := startLiveProxy(t, srv)

	head := proxiedGetWithHostHeader(t, addr, host, port)
	if !strings.Contains(head, "200") {
		t.Fatalf("the proxy did not relay the request, so there is no exchange to log: %q", head)
	}

	rows := log.All()
	if len(rows) != 1 {
		t.Fatalf("tool log holds %d rows, want 1 — a relayed exchange did not reach the unified log", len(rows))
	}
	row := rows[0]
	if row.Tool != toollog.ToolProxy {
		t.Errorf("row.Tool = %v, want proxy: relaying is the listener's act, and attributing it to another tool would put browser traffic under that tool's name", row.Tool)
	}
	if row.Host != host || row.Port != port || row.Path != "/invisible" {
		t.Errorf("row = %+v, want the relayed authority (%s:%d) and path (/invisible)", row, host, port)
	}
	// The exchange link is what makes the row actionable — Logger's viewer resolves the request
	// and response bytes through it — and it is also what distinguishes this row from a
	// transport failure that had no bytes to store.
	if row.Exchange == nil {
		t.Fatal("row.Exchange is nil; a stored exchange must be linked or the viewer has nothing to show")
	}
	if _, err := store.GetExchange(*row.Exchange); err != nil {
		t.Errorf("row.Exchange = %d does not resolve in the traffic store: %v", *row.Exchange, err)
	}
	if row.ResponseLen == nil || *row.ResponseLen == 0 {
		t.Errorf("row.ResponseLen = %v, want the relayed response's size; nil means \"no response\", which is not what happened here", row.ResponseLen)
	}
}

// The capture axis reaches proxy traffic exactly as it reaches every other tool's: switching it
// off stops the rows and counts what that cost. Two halves, both load-bearing — a stopped capture
// that read as an empty log would be the silent loss this log is built to avoid, and a switch that
// also stopped the relay would be a different feature.
func TestAProxyRowObeysTheCaptureAxis(t *testing.T) {
	log := toollog.New()
	log.SetCapturing(toollog.ToolProxy, false)
	store := core.NewTrafficStore()
	host, port := originSaying(t, "still relayed")
	srv := NewServer(NewProxyConfig(store).WithLogger(zap.NewNop()).WithToolLog(log))
	addr := startLiveProxy(t, srv)

	head := proxiedGetWithHostHeader(t, addr, host, port)
	if !strings.Contains(head, "200") {
		t.Fatalf("turning off logging changed what the proxy relays: %q", head)
	}
	if rows := log.All(); len(rows) != 0 {
		t.Errorf("capture is off for proxy but %d rows were recorded", len(rows))
	}
	if got := log.Uncaptured(toollog.ToolProxy); got != 1 {
		t.Errorf("Uncaptured(proxy) = %d, want 1 — the request was sent and deliberately not kept, and only the counter can say so", got)
	}
	if _, exchanges := store.Count(); exchanges != 1 {
		t.Errorf("store holds %d exchanges, want 1: the capture axis is a logging decision, not a relay one", exchanges)
	}
}

// No log attached is every embedder that owns none, including this package's own tests: the relay
// must behave exactly as it did before the listener was part of the log at all.
func TestAProxyWithoutAToolLogStillRelays(t *testing.T) {
	host, port := originSaying(t, "no log here")
	srv := NewServer(NewProxyConfig(core.NewTrafficStore()).WithLogger(zap.NewNop()))
	addr := startLiveProxy(t, srv)
	if head := proxiedGetWithHostHeader(t, addr, host, port); !strings.Contains(head, "200") {
		t.Errorf("a nil tool log changed the relay: %q", head)
	}
}
