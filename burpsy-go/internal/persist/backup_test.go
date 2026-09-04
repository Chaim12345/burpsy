package persist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// ---- Store.Backup (W6 #2) -------------------------------------------------------------------
//
// W6 #2 (configPanelAutomaticProjectBackup) was state 0: persistence existed, nothing ever copied
// it. The test that earns its place here is the restore one — a backup nobody has opened is a claim,
// not a backup, and the failure mode of getting this wrong is a file that looks the right size and
// opens to a corrupt schema.

func TestBackupProducesADatabaseThatOpensAndHoldsTheData(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "project.db")

	store, err := Open(src, zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if store.Path() != src {
		t.Errorf("Path() = %q, want %q", store.Path(), src)
	}

	// Write something identifiable through the store's own API, so the backup is asserted against
	// data that went in the way real data does. Scope rules are the simplest such surface — a
	// StoredMessage needs a SegmentLog to read back, which would put this test's premise in the
	// message plumbing rather than in the backup.
	const marker = "backup-marker.test"
	store.SaveScope([]*core.ScopeRule{{Kind: core.ScopeInclude, Pattern: marker}})

	dest := filepath.Join(dir, "backup.db")
	if err := store.Backup(dest); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// A single file, with no WAL sidecar to carry along — the property that makes VACUUM INTO the
	// right primitive here.
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	for _, sidecar := range []string{dest + "-wal", dest + "-shm"} {
		if _, err := os.Stat(sidecar); err == nil {
			t.Errorf("%s exists; the snapshot should be self-contained", sidecar)
		}
	}

	// The real assertion: open the backup as a database and read the row back.
	restored, err := Open(dest, zap.NewNop())
	if err != nil {
		t.Fatalf("the backup does not open as a database: %v", err)
	}
	rules, err := restored.LoadScope()
	if err != nil {
		t.Fatalf("reading the marker back out of the backup: %v", err)
	}
	if len(rules) != 1 || rules[0].Pattern != marker {
		t.Errorf("backup holds %d rule(s) %+v, want one matching %q", len(rules), rules, marker)
	}
}

// The source must keep working afterwards. VACUUM INTO is a read of the source, but a backup that
// left the live database unusable would be worse than no backup.
func TestBackupLeavesTheLiveDatabaseWritable(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "project.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store.SaveScope([]*core.ScopeRule{{Kind: core.ScopeInclude, Pattern: "before.test"}})
	if err := store.Backup(filepath.Join(dir, "b1.db")); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	store.SaveScope([]*core.ScopeRule{{Kind: core.ScopeInclude, Pattern: "after.test"}})
	// SaveScope reports failures to the logger rather than returning, so the write is confirmed by
	// reading it back — which is the stronger check anyway.
	rules, err := store.LoadScope()
	if err != nil {
		t.Fatalf("the live store could not be read after a backup: %v", err)
	}
	if len(rules) != 1 || rules[0].Pattern != "after.test" {
		t.Errorf("the live store did not accept a write after a backup: %+v", rules)
	}
}

// Writes made after a backup must not appear in it. A snapshot that kept absorbing later writes
// would not be a snapshot, and an operator restoring it would get an unpredictable point in time.
func TestABackupIsAPointInTime(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "project.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store.SaveScope([]*core.ScopeRule{{Kind: core.ScopeInclude, Pattern: "in-the-backup.test"}})

	dest := filepath.Join(dir, "snapshot.db")
	if err := store.Backup(dest); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// SaveScope replaces the table, so after this the live store holds only the later rule.
	store.SaveScope([]*core.ScopeRule{{Kind: core.ScopeInclude, Pattern: "after-the-backup.test"}})

	restored, err := Open(dest, zap.NewNop())
	if err != nil {
		t.Fatalf("opening the snapshot: %v", err)
	}
	rules, err := restored.LoadScope()
	if err != nil {
		t.Fatalf("reading the snapshot: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("snapshot holds %d rules, want 1", len(rules))
	}
	if rules[0].Pattern != "in-the-backup.test" {
		t.Errorf("snapshot holds %q — it absorbed a write made after it was taken, so it is not a "+
			"point in time", rules[0].Pattern)
	}
}

// An existing destination must be refused rather than overwritten. Silently replacing a previous
// backup is how an operator ends up with one copy believing they have a series.
func TestBackupRefusesToOverwriteAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "project.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	dest := filepath.Join(dir, "taken.db")
	if err := os.WriteFile(dest, []byte("previous backup"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	err = store.Backup(dest)
	if err == nil {
		t.Fatal("an existing destination was overwritten")
	}
	// And the existing file is untouched.
	got, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("reading the destination back: %v", readErr)
	}
	if string(got) != "previous backup" {
		t.Error("the refused backup modified the existing file anyway")
	}
}

func TestBackupRejectsAnEmptyDestination(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "project.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := store.Backup(""); err == nil {
		t.Error("an empty destination was accepted")
	}
}

// A nil store must say so rather than panic: the web layer holds a *Store that is nil whenever the
// binary was started without -db, and the backup schedule has to refuse in that state.
func TestBackupOnANilStoreIsAnErrorNotAPanic(t *testing.T) {
	var store *Store
	err := store.Backup(filepath.Join(t.TempDir(), "x.db"))
	if err == nil {
		t.Fatal("a nil store accepted a backup")
	}
	if !strings.Contains(err.Error(), "no database") {
		t.Errorf("error does not name the problem: %v", err)
	}
	if store.Path() != "" {
		t.Errorf("Path() on a nil store = %q", store.Path())
	}
}

// A destination in a directory that does not exist must fail cleanly. The scheduled backup builds
// its path from operator input, so this is a reachable state rather than a hypothetical.
func TestBackupIntoAMissingDirectoryFailsCleanly(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "project.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	err = store.Backup(filepath.Join(dir, "no-such-dir", "b.db"))
	if err == nil {
		t.Fatal("a backup into a missing directory reported success")
	}
	if !strings.Contains(err.Error(), "backup to") {
		t.Errorf("the error does not say what it was trying to do: %v", err)
	}
}
