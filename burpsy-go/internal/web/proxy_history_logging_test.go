package web

import (
	"net/http"
	"strings"
	"testing"
)

// Burp's "Proxy history logging" (burpsy-react-ui-z80e): what adding to scope does about
// out-of-scope proxy logging. Persisted, so a restart over the same database answers the same choice.
func TestProxyHistoryLoggingRoundTripsAndSurvivesARestart(t *testing.T) {
	s := newTestServerWithPersist(t)
	if body := get(t, s, "/api/proxy/history-logging").Body.String(); !strings.Contains(body, `"mode":"ask"`) {
		t.Fatalf("a fresh project must answer ask: %s", body)
	}
	for _, mode := range []string{"stop", "nothing", "ask", "stop"} {
		if rec := postJSON(t, s, "/api/proxy/history-logging", map[string]any{"mode": mode}); rec.Code != http.StatusOK ||
			!strings.Contains(rec.Body.String(), `"mode":"`+mode+`"`) {
			t.Fatalf("POST %s = %d %s", mode, rec.Code, rec.Body.String())
		}
	}
	restarted := restartedTestServerWithPersist(s)
	if body := get(t, restarted, "/api/proxy/history-logging").Body.String(); !strings.Contains(body, `"mode":"stop"`) {
		t.Errorf("after a restart the choice reads %s, want stop", body)
	}
	if rec := postJSON(t, s, "/api/proxy/history-logging", map[string]any{"mode": "sometimes"}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown mode = %d, want 400", rec.Code)
	}
}

// Without persistence a read answers the default and a write is refused rather than kept in nowhere.
func TestProxyHistoryLoggingWithoutPersistence(t *testing.T) {
	s := newTestServer()
	if rec := get(t, s, "/api/proxy/history-logging"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ask"`) {
		t.Errorf("GET = %d %s", rec.Code, rec.Body.String())
	}
	if rec := postJSON(t, s, "/api/proxy/history-logging", map[string]any{"mode": "stop"}); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("POST = %d, want 503", rec.Code)
	}
}
