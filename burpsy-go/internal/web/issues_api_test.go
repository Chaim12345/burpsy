package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

func TestIssuesReportsEnabledWhenBChecksLoaded(t *testing.T) {
	dir := t.TempDir()
	const src = `
metadata:
  language: v1-beta
  name: "noop"
given response then
  if {latest.response.body} contains "never" then
      report issue:
          severity: info
          confidence: certain
          detail: "nope"
  end if
`
	if err := os.WriteFile(filepath.Join(dir, "noop.bcheck"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	store := core.NewTrafficStore()
	scope := core.NewScope()
	ps, err := scanner.LoadDir(dir, store, scope, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	s := newTestServer().WithPassiveScanner(ps).WithFindings(core.NewFindingStore())
	rec := get(t, s, "/api/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/issues: %d", rec.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["enabled"] != true {
		t.Errorf("enabled = %v, want true", body["enabled"])
	}
	if loaded, _ := body["loaded"].(float64); loaded != 1 {
		t.Errorf("loaded = %v, want 1", body["loaded"])
	}
}
