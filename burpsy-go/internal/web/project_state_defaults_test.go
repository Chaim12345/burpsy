package web

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// burpsy-react-ui-scanconfig-persist-format: a project saved before a switch existed (or before it
// defaulted on) has no key for it in its stored scan configuration. Restoring that project must leave
// the switch at the LAUNCH default, not at Go's zero value: decoding the saved document into a fresh
// ScanConfig{} silently turned every default-on check the document did not mention off.
//
// The document is written straight into the settings table so the test controls exactly which keys
// are present; SaveScanConfig always writes every field and so cannot produce an older document.
func TestRestoredProjectKeepsDefaultOnSwitchesItsSavedConfigDoesNotMention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	st, err := persist.Open(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// An older project: it saved CheckSqli on and CheckXss off, knew nothing of CheckXXE or
	// CheckPassiveAnalysis, and carries a key a later build renamed away.
	const oldDoc = `{"MaxConcurrency":3,"CheckSqli":true,"CheckXss":false,"CheckRenamedAway":true}`
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR REPLACE INTO settings (key, value) VALUES ('scanconfig.overrides', ?)`, oldDoc); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	scan := scanner.NewActiveScanner(core.NewTrafficStore(), zap.NewNop())
	launch := scan.ConfigSnapshot()
	if !launch.CheckXXE || !launch.CheckPassiveAnalysis || !launch.CheckXss {
		t.Fatalf("precondition: CheckXXE, CheckPassiveAnalysis and CheckXss must default on; launch = %+v", launch)
	}

	p, err := persist.Open(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	newTestServer().WithScanner(scan).WithPersist(p)

	got := scan.ConfigSnapshot()
	if !got.CheckXXE {
		t.Error("CheckXXE restored OFF; the saved project never mentioned it, so it must keep its default-on value")
	}
	if !got.CheckPassiveAnalysis {
		t.Error("CheckPassiveAnalysis restored OFF; absent from the saved project, it must keep its default")
	}
	// What the project DID save still wins over the defaults.
	if got.CheckXss {
		t.Error("CheckXss restored ON; the project saved it off and that choice must survive")
	}
	if !got.CheckSqli || got.MaxConcurrency != 3 {
		t.Errorf("saved values lost: CheckSqli=%v MaxConcurrency=%d, want true and 3", got.CheckSqli, got.MaxConcurrency)
	}
}
