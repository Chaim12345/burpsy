package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/proxy"
)

// The live TLS interception switch: a process started without -intercept-tls can be switched to
// intercepting (generating the CA into -ca-dir the first time) and back, without a restart, and
// switching off keeps the CA so clients that trust it go on trusting it when it is switched back on.

func decodeInterception(t *testing.T, code int, body []byte) interceptionView {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var v interceptionView
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return v
}

func TestInterceptionSwitchesOnAndOffAtRuntimeAndKeepsTheCA(t *testing.T) {
	dir := t.TempDir()
	policy := proxy.NewTlsPolicy()
	s := NewServer(core.NewTrafficStore(), core.NewScope()).WithTlsPolicy(policy).WithTLSEngine(nil, dir)

	rec := getJSON(t, s, "/api/proxy/interception")
	if v := decodeInterception(t, rec.Code, rec.Body.Bytes()); v.Enabled || v.HasCA || v.CADir != dir {
		t.Fatalf("a server started without interception reports %+v", v)
	}

	rec = putJSON(t, s, "/api/proxy/interception", map[string]bool{"enabled": true})
	v := decodeInterception(t, rec.Code, rec.Body.Bytes())
	if !v.Enabled || !v.HasCA {
		t.Fatalf("after switching on: %+v", v)
	}
	engine := policy.Engine()
	if engine == nil {
		t.Fatal("switching on did not attach an engine to the policy the proxy reads")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no CA was written into %s (%v)", dir, err)
	}

	rec = putJSON(t, s, "/api/proxy/interception", map[string]bool{"enabled": false})
	if v := decodeInterception(t, rec.Code, rec.Body.Bytes()); v.Enabled || !v.HasCA {
		t.Fatalf("after switching off: %+v (the CA must stay loaded)", v)
	}
	if policy.Engine() != nil {
		t.Fatal("switching off left the engine on the policy, so CONNECTs would still be intercepted")
	}

	rec = putJSON(t, s, "/api/proxy/interception", map[string]bool{"enabled": true})
	decodeInterception(t, rec.Code, rec.Body.Bytes())
	if policy.Engine() != engine {
		t.Fatal("switching back on did not reuse the CA the clients already trust")
	}
}

func TestInterceptionRefusesABadBodyAndAServerWithoutPolicy(t *testing.T) {
	s := NewServer(core.NewTrafficStore(), core.NewScope()).WithTlsPolicy(proxy.NewTlsPolicy()).WithTLSEngine(nil, filepath.Join(t.TempDir(), "ca"))
	if rec := putJSON(t, s, "/api/proxy/interception", map[string]string{"enabled": "yes"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("a non-boolean enabled answered %d", rec.Code)
	}
	if rec := putJSON(t, s, "/api/proxy/interception", map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("a body without enabled answered %d", rec.Code)
	}
	bare := NewServer(core.NewTrafficStore(), core.NewScope())
	if rec := getJSON(t, bare, "/api/proxy/interception"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a server without a TLS policy answered %d", rec.Code)
	}
}
