package web

import (
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

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

	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id": id,
		"target": "http://shop.test",
		"mode":   "sniper",
		"payload_sources": []map[string]any{{
			"type":   "plugin",
			"plugin": map[string]string{"plugin": "no-such-plugin", "registration": "tokens"},
		}},
	}, &struct{}{})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
}

func TestIntruderRunRefusesAPluginRuleWithNoLoadedPlugin(t *testing.T) {
	srv := NewServer(core.NewTrafficStore(), core.NewScope())
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	id := requestMessage(t, srv.store, raw)

	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://shop.test",
		"mode":         "sniper",
		"payload_sets": [][]string{{"one"}},
		"payload_rules": []map[string]any{{
			"rule":   "plugin",
			"plugin": map[string]string{"plugin": "no-such-plugin", "registration": "upper"},
		}},
	}, &struct{}{})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
}

func TestIntruderRunRefusesAPluginSourceWithoutAnAddress(t *testing.T) {
	srv := NewServer(core.NewTrafficStore(), core.NewScope())
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	id := requestMessage(t, srv.store, raw)

	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id": id,
		"target": "http://shop.test",
		"mode":   "sniper",
		"payload_sources": []map[string]any{{
			"type":   "plugin",
			"plugin": map[string]string{"plugin": "", "registration": ""},
		}},
	}, &struct{}{})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
}
