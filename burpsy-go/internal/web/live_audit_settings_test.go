package web

// The live task's own scan configuration and resource pool (burpsy-react-ui-chct).

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/scanner"
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
