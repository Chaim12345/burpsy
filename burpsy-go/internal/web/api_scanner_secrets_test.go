package web

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// burpsy-react-ui-8j0d: secret detection is off until switched on, says what it runs, and the switch
// survives a restart with the project.
func TestSecretDetectionSwitchIsOffByDefaultAndSavedWithTheProject(t *testing.T) {
	dir := t.TempDir()
	store, err := persist.Open(filepath.Join(dir, "p.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	traffic := core.NewTrafficStore()
	s := NewServer(traffic, core.NewScope()).WithLogger(zap.NewNop()).
		WithPassiveScanner(scanner.NewPassiveScanner(traffic, zap.NewNop())).WithPersist(store)

	g := get(t, s, "/api/scanner/secrets")
	if !strings.Contains(g.Body.String(), `"enabled":false`) || !strings.Contains(g.Body.String(), "gitleaks") {
		t.Errorf("GET = %s", g.Body.String())
	}
	if rec := putJSON(t, s, "/api/scanner/secrets", map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Errorf("a body without enabled = %d, want 400", rec.Code)
	}
	if rec := putJSON(t, s, "/api/scanner/secrets", map[string]any{"enabled": true}); rec.Code != http.StatusOK || !s.passiveScanner.SecretDetection() {
		t.Fatalf("PUT enabled = %d %s", rec.Code, rec.Body.String())
	}
	store.Close()

	reopened, err := persist.Open(filepath.Join(dir, "p.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	ps := scanner.NewPassiveScanner(traffic, zap.NewNop())
	NewServer(traffic, core.NewScope()).WithLogger(zap.NewNop()).WithPassiveScanner(ps).WithPersist(reopened)
	if !ps.SecretDetection() {
		t.Error("the switch did not survive the restart")
	}
}
