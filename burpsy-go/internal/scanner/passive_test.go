package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

const testPassiveBCheck = `
metadata:
  language: v1-beta
  name: "Test marker"
  description: "Fires when the response body contains the marker."
  author: "test"

given response then
  if {latest.response.body} contains "BURPSY_MARKER" then
      report issue:
          severity: high
          confidence: certain
          detail: "marker found"
          remediation: "remove the marker"
  end if
`

func TestLoadDirClassifiesPassiveChecks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker.bcheck"), []byte(testPassiveBCheck), 0o644); err != nil {
		t.Fatal(err)
	}

	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.AddInclude("*")

	ps, err := LoadDir(dir, store, scope, zap.NewNop())
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if got := ps.Loaded(); got != 1 {
		t.Fatalf("Loaded() = %d, want 1", got)
	}
	report := ps.Report()
	if report.Passive != 1 {
		t.Errorf("report.Passive = %d, want 1", report.Passive)
	}
	if report.Files != 1 {
		t.Errorf("report.Files = %d, want 1", report.Files)
	}
}

func TestPassiveScannerRunsBCheckOnExchange(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker.bcheck"), []byte(testPassiveBCheck), 0o644); err != nil {
		t.Fatal(err)
	}

	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.AddInclude("*")
	ps, err := LoadDir(dir, store, scope, zap.NewNop())
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	reqID, err := store.Put([]byte("GET / HTTP/1.1\r\nHost: x.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nBURPSY_MARKER"), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	status := uint16(200)
	ex := &core.Exchange{
		ID:       0,
		Request:  reqID,
		Response: &respID,
		Host:     "x.test",
		Port:     80,
		Method:   "GET",
		Path:     "/",
		Status:   &status,
	}
	store.AddExchange(ex)

	findings := ps.Scan(ex)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Description != "marker found" {
		t.Errorf("description = %q, want marker found", findings[0].Description)
	}
	if findings[0].Severity != "high" {
		t.Errorf("severity = %q, want high", findings[0].Severity)
	}
}

func TestPassiveScannerSkipsWhenMarkerAbsent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker.bcheck"), []byte(testPassiveBCheck), 0o644); err != nil {
		t.Fatal(err)
	}

	store := core.NewTrafficStore()
	ps, err := LoadDir(dir, store, core.NewScope(), zap.NewNop())
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	reqID, _ := store.Put([]byte("GET / HTTP/1.1\r\nHost: x.test\r\n\r\n"), core.DirectionRequest)
	respID, _ := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nclean"), core.DirectionResponse)
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: "x.test", Port: 80, Path: "/"}
	store.AddExchange(ex)

	if findings := ps.Scan(ex); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 on clean response", len(findings))
	}
}
