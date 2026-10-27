package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// postJSONRecord runs one POST through the mux and keeps the whole recorder, so a refusal
// can assert on its REASON: a 400 from the payload-source decoder ("unknown payload source
// type") and a 400 from checkPluginPayloadRef are different gates, and only the second
// proves the plugin branch is reachable (PR #363 review).
func postJSONRecord(t *testing.T, srv *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	return rec
}

// wantRefusal asserts a 400 whose body names the policy gate, not the JSON decoder.
func wantRefusal(t *testing.T, rec *httptest.ResponseRecorder, policyText string) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), policyText) {
		t.Errorf("refusal did not come from the policy check (want %q in body): %s", policyText, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "unknown payload source type") {
		t.Errorf("the refusal is the decoder rejecting the plugin type, so the policy check never ran: %s", rec.Body.String())
	}
}

// 0qwh, refusal half: a plugin payload source or rule that names a plugin the host has not
// loaded is a 400 at run creation, before any request goes out - the same bar as an
// uncompilable grep pattern. The happy path is covered at both ends of the glue: the host's
// GeneratePayload/ProcessPayload run against a real plugin process in internal/extension
// (payload_test.go), and the chain bridge runs against a fake in internal/intruder
// (payload_plugin_test.go). The kind-mismatch branch of checkPluginPayloadRef is reachable
// only with a loaded plugin; it repeats the check the host itself makes at call time.
func TestIntruderRunRefusesAPluginPayloadSourceWithNoLoadedPlugin(t *testing.T) {
	srv := NewServer(core.NewTrafficStore(), core.NewScope())
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	id := requestMessage(t, srv.store, raw)

	rec := postJSONRecord(t, srv, "/api/intruder/run", map[string]any{
		"msg_id": id,
		"target": "http://shop.test",
		"mode":   "sniper",
		"points": []int{0},
		"payload_sources": []map[string]any{{
			"type":   "plugin",
			"plugin": map[string]string{"plugin": "no-such-plugin", "registration": "tokens"},
		}},
	})
	wantRefusal(t, rec, "payload set 0 (plugin):")
}

func TestIntruderRunRefusesAPluginRuleWithNoLoadedPlugin(t *testing.T) {
	srv := NewServer(core.NewTrafficStore(), core.NewScope())
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	id := requestMessage(t, srv.store, raw)

	rec := postJSONRecord(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://shop.test",
		"mode":         "sniper",
		"points":       []int{0},
		"payload_sets": [][]string{{"one"}},
		"payload_rules": []map[string]any{{
			"rule":   "plugin",
			"plugin": map[string]string{"plugin": "no-such-plugin", "registration": "upper"},
		}},
	})
	wantRefusal(t, rec, "payload rule: ")
}

func TestIntruderRunRefusesAPluginSourceWithoutAnAddress(t *testing.T) {
	srv := NewServer(core.NewTrafficStore(), core.NewScope())
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	id := requestMessage(t, srv.store, raw)

	rec := postJSONRecord(t, srv, "/api/intruder/run", map[string]any{
		"msg_id": id,
		"target": "http://shop.test",
		"mode":   "sniper",
		"points": []int{0},
		"payload_sources": []map[string]any{{
			"type":   "plugin",
			"plugin": map[string]string{"plugin": "", "registration": ""},
		}},
	})
	wantRefusal(t, rec, "needs a plugin name and a registration ID")
}
