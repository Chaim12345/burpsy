package persist

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func userVersionOf(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	return v
}

// A fresh database ends at the latest schema version.
func TestOpenStampsTheLatestSchemaVersion(t *testing.T) {
	p, err := Open(filepath.Join(t.TempDir(), "p.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if got, want := userVersionOf(t, p.db), latestSchemaVersion(); got != want || want < 1 {
		t.Fatalf("user_version = %d, want latest %d (>= 1)", got, want)
	}
}

// A database written before versions existed (user_version 0, tables and rows already there) is
// migrated in place: rows survive and the version is stamped.
func TestAnUnversionedDatabaseIsMigratedInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	p, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`INSERT INTO settings (key, value) VALUES ('k', 'v')`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`PRAGMA user_version = 0`); err != nil { // what a pre-versioning build left
		t.Fatal(err)
	}
	p.Close()

	p, err = Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("reopen unversioned database: %v", err)
	}
	defer p.Close()
	var v string
	if err := p.db.QueryRow(`SELECT value FROM settings WHERE key = 'k'`).Scan(&v); err != nil || v != "v" {
		t.Fatalf("row after migration = %q, %v; want v", v, err)
	}
	if got := userVersionOf(t, p.db); got != latestSchemaVersion() {
		t.Fatalf("user_version = %d, want %d", got, latestSchemaVersion())
	}
}

// A database from a NEWER build is refused, named, and left untouched: an older binary must not
// write through a schema it does not understand.
func TestADatabaseFromANewerBuildIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newer.db")
	p, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	newer := latestSchemaVersion() + 5
	if _, err := p.db.Exec("PRAGMA user_version = " + strconv.Itoa(newer)); err != nil {
		t.Fatal(err)
	}
	p.Close()

	if _, err := Open(path, zap.NewNop()); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("Open of a newer-schema database = %v, want an error saying the database is newer", err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if got := userVersionOf(t, raw); got != newer {
		t.Fatalf("refused database's user_version = %d, want it untouched at %d", got, newer)
	}
}

// A failing migration stops the run, names itself, and does not advance the version past the last
// step that succeeded.
func TestAFailingMigrationDoesNotAdvanceTheVersion(t *testing.T) {
	p, err := Open(filepath.Join(t.TempDir(), "p.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	start := userVersionOf(t, p.db)
	steps := []migration{
		{version: start + 1, name: "ok step", up: func(s *Store) error { return nil }},
		{version: start + 2, name: "broken step", up: func(s *Store) error { return sql.ErrConnDone }},
		{version: start + 3, name: "never runs", up: func(s *Store) error { t.Error("ran after a failure"); return nil }},
	}
	err = p.runMigrations(steps)
	if err == nil || !strings.Contains(err.Error(), "broken step") {
		t.Fatalf("runMigrations = %v, want an error naming the broken step", err)
	}
	if got := userVersionOf(t, p.db); got != start+1 {
		t.Fatalf("user_version = %d, want %d (the last step that succeeded)", got, start+1)
	}
}
