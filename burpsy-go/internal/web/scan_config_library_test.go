package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// Burp's Configuration library: named scan configurations the operator saves, clones, renames and
// deletes, and picks when launching. burpsy shipped six read-only presets and no way to keep a
// tuning that worked.

func libraryServer(t *testing.T) *Server {
	t.Helper()
	store, err := persist.Open(filepath.Join(t.TempDir(), "project.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("persist.Open: %v", err)
	}
	s := newTestServer()
	s.persist = store
	s.logger = zap.NewNop()
	return s
}

func configWrite(t *testing.T, s *Server, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/scanner/configs", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleScannerConfigs(rec, req)
	return rec
}

func configNames(t *testing.T, s *Server) map[string]bool {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleScannerConfigs(rec, httptest.NewRequest(http.MethodGet, "/api/scanner/configs", nil))
	var out struct {
		Configs []struct {
			Name    string `json:"name"`
			Shipped bool   `json:"shipped"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	names := map[string]bool{}
	for _, c := range out.Configs {
		names[c.Name] = c.Shipped
	}
	return names
}

// The whole round trip, because a library that can save but not rename is not a library.
func TestAScanConfigurationCanBeSavedClonedRenamedAndDeleted(t *testing.T) {
	s := libraryServer(t)

	if rec := configWrite(t, s, http.MethodPost, `{"action":"save","name":"engagement tuning"}`); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if shipped, ok := configNames(t, s)["engagement tuning"]; !ok || shipped {
		t.Error("a saved configuration is missing from the listing, or is marked shipped; the operator's own and burpsy's must be distinguishable in one list")
	}

	// Cloning from a SHIPPED preset is the ordinary way to start from Burp's tuning and adjust it.
	if rec := configWrite(t, s, http.MethodPost, `{"action":"clone","name":"from preset","from":"Crawl and Audit - Lightweight"}`); rec.Code != http.StatusOK {
		t.Fatalf("clone from a shipped preset: %d %s", rec.Code, rec.Body.String())
	}

	if rec := configWrite(t, s, http.MethodPut, `{"action":"rename","name":"renamed tuning","from":"engagement tuning"}`); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body.String())
	}
	names := configNames(t, s)
	if _, old := names["engagement tuning"]; old {
		t.Error("the old name survived a rename, so the library now holds two configurations where the operator has one")
	}
	if _, renamed := names["renamed tuning"]; !renamed {
		t.Error("the new name is absent after a rename — the configuration was lost")
	}

	if rec := configWrite(t, s, http.MethodDelete, `{"action":"delete","name":"renamed tuning"}`); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if _, still := configNames(t, s)["renamed tuning"]; still {
		t.Error("a deleted configuration is still listed")
	}
}

// A shipped preset is read-only. If a saved configuration could take a shipped name, the same name
// would resolve to two different configurations depending on which list a reader consulted — and an
// audit resolves names.
func TestAShippedConfigurationRefusesEveryWrite(t *testing.T) {
	s := libraryServer(t)
	for _, body := range []string{
		`{"action":"save","name":"Crawl and Audit - Lightweight"}`,
		`{"action":"clone","name":"Crawl and Audit - Lightweight","from":"Crawl and Audit - Lightweight"}`,
		`{"action":"rename","name":"Crawl and Audit - Lightweight","from":"anything"}`,
	} {
		rec := configWrite(t, s, http.MethodPost, body)
		if rec.Code != http.StatusConflict {
			t.Errorf("%s -> %d, want 409: a shipped configuration must be refused by name, not quietly shadowed", body, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "read-only") && !strings.Contains(rec.Body.String(), "ships") {
			t.Errorf("%s -> %q, which does not say WHY it was refused", body, rec.Body.String())
		}
	}
	// Renaming a shipped one away is refused too, and names the offender.
	rec := configWrite(t, s, http.MethodPut, `{"action":"rename","name":"mine","from":"Crawl and Audit - Lightweight"}`)
	if rec.Code != http.StatusConflict {
		t.Errorf("renaming a shipped configuration -> %d, want 409", rec.Code)
	}
}

// The acceptance criterion: the configuration that RAN is named in the run's own record. A library
// whose names do not reach the audit is a naming scheme, not a configuration library.
func TestAnAuditRunsUnderASavedConfigurationAndTheRunNamesIt(t *testing.T) {
	s := libraryServer(t)
	if rec := configWrite(t, s, http.MethodPost, `{"action":"clone","name":"my tuning","from":"Crawl and Audit - Deep"}`); rec.Code != http.StatusOK {
		t.Fatalf("clone: %d %s", rec.Code, rec.Body.String())
	}

	_, named, _, err := s.resolveAuditConfig("my tuning")
	if err != nil {
		t.Fatalf("a saved configuration did not resolve for a run: %v", err)
	}
	if named != "my tuning" {
		t.Errorf("the run would record %q, not the configuration the operator chose; a run that cannot say what it ran under cannot be reproduced", named)
	}

	// And an unknown name still refuses, listing what exists — now including saved ones, so the
	// message cannot send the operator looking for a configuration that is right there.
	if _, _, _, err := s.resolveAuditConfig("no such config"); err == nil {
		t.Error("an unknown configuration name was accepted; an audit would run under the default while the record named something else")
	} else if !strings.Contains(err.Error(), "my tuning") {
		t.Errorf("the refusal %q lists only the shipped names, so a saved configuration looks absent", err)
	}
}

// Without a database there is nowhere to keep a configuration, so the write says so rather than
// accepting one that would vanish with the process.
func TestTheLibraryRefusesToSaveWithNoDatabaseAttached(t *testing.T) {
	s := newTestServer()
	s.logger = zap.NewNop()
	rec := configWrite(t, s, http.MethodPost, `{"action":"save","name":"nowhere"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("save with no -db -> %d, want 503 naming the reason; silently accepting it would lose the configuration at exit", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "-db") {
		t.Errorf("the refusal %q does not tell the operator how to fix it", rec.Body.String())
	}
}
