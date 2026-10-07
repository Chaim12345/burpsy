package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// Burp's Set Connection header and Store full payloads (burpsy-react-ui-fmxv). The engine half
// landed in 29a7ee3 with no way to set either; these tests pin the wire, because a field the
// engine implements and no request can reach is the same gap wearing a different hat.

func fmxvServer(t *testing.T, target *httptest.Server) (*Server, int) {
	t.Helper()
	s := newTestServer()
	host, _ := targetHostPort(t, target.URL)
	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "include", "pattern": host}); rec.Code != http.StatusOK {
		t.Fatalf("scope: %d", rec.Code)
	}
	// A message with a point to attack: the bare path is the target, and the run refuses a request
	// that selects nothing rather than silently sending zero requests.
	reqID, err := s.store.Put([]byte("GET /p?q=1 HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	sender1 := sender.NewSender(sender.DefaultSenderConfig())
	s = s.WithScanner(scanner.NewActiveScanner(s.store, zap.NewNop()).WithSender(sender1).WithScope(s.scope))
	return s, int(reqID)
}

func TestFmxvSetConnectionCloseReachesTheEngine(t *testing.T) {
	var seen string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Connection")
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	s, msgID := fmxvServer(t, target)

	rec := postJSON(t, s, "/api/intruder/run", map[string]any{
		"msg_id":               msgID,
		"target":               target.URL[len("http://"):],
		"payloads":             []string{"a"},
		"mode":                 "sniper",
		"point_index":          0,
		"set_connection_close": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d (%s)", rec.Code, rec.Body.String())
	}
	// The attack runs asynchronously; wait for the target to be reached.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && seen == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if seen == "" {
		t.Fatal("the attack never reached the target, so the setting was never exercised")
	}
	if !strings.EqualFold(seen, "close") {
		t.Errorf("Connection = %q, want close: the setting the operator asked for did not reach the wire", seen)
	}
}

func TestFmxvAnAbsentSettingLeavesTheTemplateAlone(t *testing.T) {
	var seen string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Connection")
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	s, msgID := fmxvServer(t, target)

	rec := postJSON(t, s, "/api/intruder/run", map[string]any{
		"msg_id":      msgID,
		"target":      target.URL[len("http://"):],
		"payloads":    []string{"a"},
		"mode":        "sniper",
		"point_index": 0,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d (%s)", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && seen == "" && seen != "keep-alive" {
		time.Sleep(10 * time.Millisecond)
	}
	if strings.EqualFold(seen, "close") {
		t.Error("an attack that never mentioned the setting sent Connection: close: the off-state " +
			"wire shape must stay what every existing client already posts")
	}
}

func TestFmxvStoreFullPayloadsIsUnderstoodByTheWire(t *testing.T) {
	// A wire-shape test, not a behaviour one: the stored payloads land in the REPORT, and this
	// asserts the request is at least accepted and the field is recognised rather than dropped.
	// Whether Attempt.Payloads is populated is the engine's own test (29a7ee3).
	var body map[string]any
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	s, msgID := fmxvServer(t, target)

	req := map[string]any{
		"msg_id":              msgID,
		"target":              target.URL[len("http://"):],
		"payloads":            []string{"a"},
		"mode":                "sniper",
		"point_index":         0,
		"store_full_payloads": true,
	}
	raw, _ := json.Marshal(req)
	rec := httptest.NewRecorder()
	s.handleIntruderRun(rec, httptest.NewRequest(http.MethodPost, "/api/intruder/run", strings.NewReader(string(raw))))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST with store_full_payloads = %d (%s): the field must be accepted, not refused as unknown",
			rec.Code, rec.Body.String())
	}
	_ = body
}
