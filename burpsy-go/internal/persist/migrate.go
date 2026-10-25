package persist

import (
	"fmt"
)

// migration is one schema step. Steps run in version order, each at most once per database; the
// database's PRAGMA user_version records the last step that completed.
type migration struct {
	version int
	name    string
	up      func(s *Store) error
}

// migrations is the whole history. Version 1 is everything that existed before versioning (the
// additive CREATE TABLE IF NOT EXISTS / addColumn code), which is idempotent and so also upgrades
// a database that has no user_version yet. Append new steps with the next number; never edit or
// reorder a released one.
var migrations = []migration{
	{version: 1, name: "additive schema (tables and columns)", up: (*Store).migrateAdditive},
	{version: 2, name: "repeater tab custom actions (1944)", up: (*Store).migrateRepeaterActions},
}

func latestSchemaVersion() int { return migrations[len(migrations)-1].version }

func (s *Store) migrate() error {
	var current int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if latest := latestSchemaVersion(); current > latest {
		// An older binary writing through a schema it does not understand can lose data in ways the
		// operator would not see, so it stops here and leaves the file untouched.
		return fmt.Errorf("database schema version %d is newer than this build understands (%d); open it with a newer burpsy",
			current, latest)
	}
	return s.runMigrations(migrations)
}

// runMigrations applies every step newer than the database's version, in order, stamping
// user_version after each one. A failing step stops the run, names itself, and leaves the version at
// the last step that succeeded, so the next open retries from there.
func (s *Store) runMigrations(steps []migration) error {
	var current int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for _, m := range steps {
		if m.version <= current {
			continue
		}
		if err := m.up(s); err != nil {
			return fmt.Errorf("schema migration %d (%s): %w", m.version, m.name, err)
		}
		// PRAGMA takes no bound parameters; the value is an int from this package.
		if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
			return fmt.Errorf("stamp schema version %d (%s): %w", m.version, m.name, err)
		}
		current = m.version
	}
	return nil
}
