package web

// The live task's own scan configuration and resource pool (burpsy-react-ui-chct).

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/pool"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

func TestTheLiveTaskTakesAScanConfigurationAndRefusesUnknownNames(t *testing.T) {
	s := newTestServerWithScanner(t).WithLiveAudit(NewLiveAuditState())
	name := scanner.BuiltInConfigNames()[0]
	if rec := postJSON(t, s, "/api/scanner/live", map[string]any{"enabled": false, "config": "no such configuration"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown configuration = %d, want 400", rec.Code)
	}
	if rec := postJSON(t, s, "/api/scanner/live", map[string]any{"enabled": false, "pool": "no such pool"}); rec.Code == http.StatusOK {
		t.Errorf("unknown pool accepted")
	}
	if rec := postJSON(t, s, "/api/scanner/live", map[string]any{"enabled": false, "config": name}); rec.Code != http.StatusOK {
		t.Fatalf("known configuration = %d %s", rec.Code, rec.Body.String())
	}
	var view struct {
		Config string `json:"config"`
		Pool   string `json:"pool"`
	}
	json.Unmarshal(get(t, s, "/api/scanner/live").Body.Bytes(), &view)
	if view.Config != name || view.Pool != "" {
		t.Errorf("status = %+v, want config %q and the default pool", view, name)
	}
	// Omitting the field leaves it; "" clears it.
	postJSON(t, s, "/api/scanner/live", map[string]any{"enabled": false})
	json.Unmarshal(get(t, s, "/api/scanner/live").Body.Bytes(), &view)
	if view.Config != name {
		t.Errorf("an unrelated update cleared the configuration: %+v", view)
	}
	postJSON(t, s, "/api/scanner/live", map[string]any{"enabled": false, "config": ""})
	json.Unmarshal(get(t, s, "/api/scanner/live").Body.Bytes(), &view)
	if view.Config != "" {
		t.Errorf("\"\" must clear the configuration: %+v", view)
	}
}

// The sweep tick reads the live task's settings: a pool deleted after it was chosen makes the next
// batch fall back to the global pace with a warning event — which the tick can only say if it is the
// tick resolving the setting.
func TestTheSweepTickResolvesTheLiveTasksPool(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())
	for i := 0; i < 2; i++ {
		proxiedCompleteExchange(t, s, "shop.test", "/p")
	}
	s.WithScanner(scanner.NewActiveScanner(s.store, zap.NewNop()).WithScope(s.scope))
	do(t, s, "POST", "/api/pools", pool.Pool{Name: "live-pool", MaxConcurrent: 1})
	if rec := postJSON(t, s, "/api/scanner/live", map[string]any{"enabled": true, "pool": "live-pool"}); rec.Code != http.StatusOK {
		t.Fatalf("set pool = %d %s", rec.Code, rec.Body.String())
	}
	do(t, s, "DELETE", "/api/pools/live-pool", nil)
	run := liveAuditRun{}
	s.liveAuditTick(context.Background(), &run)
	if s.liveAudit.Swept() == 0 {
		t.Fatal("the sweep audited nothing")
	}
	found := false
	for _, e := range s.events.Recent(50) {
		if strings.Contains(e.Detail, "resource pool no longer resolves") {
			found = true
		}
	}
	if !found {
		t.Error("the tick did not resolve the live task's pool (no fallback event after the pool was deleted)")
	}
}
