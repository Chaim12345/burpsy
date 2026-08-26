package persist

// Durable storage for named resource pools and scheduled tasks.
//
// # Why these are two tables and not one settings blob
//
// Both are ordered lists of operator-typed objects with an identity, which is exactly the shape
// session_rules already has — and session_rules is the precedent this file follows, including its
// hard-won lesson: it stores an explicit `ord` column because the evaluation order is data, and a
// load without an ORDER BY left the restored order to whatever SQLite happened to return. The order
// matters less here than it does there (a tool names the pool it wants, so nothing is first-match),
// but a list that reshuffles itself on every restart is a list an operator cannot navigate, so it is
// persisted rather than re-derived.
//
// # Why these live outside Store.Restore
//
// Restore takes one positional argument per restored store and is already seven wide. Two more would
// have to be threaded through every call site — including main.go, which does not own either of
// these — to restore state owned entirely by the web server. So the web server calls LoadPools and
// LoadSchedules itself, in WithPersist, next to the sinks it installs for them. Nothing about the
// round trip changes; only who asks for it.
//
// # What is *not* persisted, and why
//
// A pool's identity is its name and its three bounds, and that is all that is stored: there is no
// saved "current" pool and no saved limiter state. A token bucket's fill level is a fact about a
// process that is no longer running, and restoring one would make the first request after a restart
// wait out a delay it never incurred.
//
// A schedule stores both halves — what the operator configured *and* what has happened to it — for
// the reason schedule.Schedule's doc gives: Runs, Failures and Missed are the record of a schedule
// that has been failing every night, and a restart that reset them would erase precisely the
// evidence an operator most needs. NextMs is stored with them, and it is normally in the past by the
// time it is read back; see schedule.Runner.Restore for why that is the point rather than a problem.

import (
	"encoding/json"
	"fmt"

	"github.com/burpsy-go/burpsy/internal/pool"
	"github.com/burpsy-go/burpsy/internal/schedule"
)

// poolSchema and scheduleSchema are applied by migrate alongside the rest.
//
// Both keep `ord` as the primary key rather than the name, matching scope_rules_v2 and
// matchreplace_rules: the position is what the row *is* in a list, and a name primary key would make
// a rename a delete-and-insert that loses the position. Uniqueness of the name is enforced by the
// registry that owns it (case-insensitively, which SQLite's default collation would not do) and
// re-checked on load, so a database hand-edited into holding two pools called "default" is refused
// with its reason rather than loaded as an exception to the rule.
const poolSchema = `
CREATE TABLE IF NOT EXISTS resource_pools (
	ord            INTEGER PRIMARY KEY,
	name           TEXT NOT NULL,
	max_concurrent INTEGER NOT NULL,
	delay_ms       INTEGER NOT NULL,
	throttle       TEXT
);
CREATE TABLE IF NOT EXISTS scheduled_tasks (
	ord           INTEGER PRIMARY KEY,
	name          TEXT NOT NULL,
	kind          TEXT NOT NULL,
	enabled       INTEGER NOT NULL,
	first_ms      INTEGER NOT NULL,
	interval_secs INTEGER NOT NULL,
	pool          TEXT,
	params        TEXT,
	next_ms       INTEGER NOT NULL,
	last_run_ms   INTEGER NOT NULL,
	runs          INTEGER NOT NULL,
	failures      INTEGER NOT NULL,
	missed        INTEGER NOT NULL,
	last_note     TEXT
);
`

// SavePools replaces the saved pool set, in the order given.
//
// Replace-then-insert rather than a diff, matching SaveSessionRules and SaveScope: the list is small
// and operator-sized (pool.MaxPools bounds it at 200), and a diff would have to reason about renames
// to get the order right. A failed DELETE returns before any insert, so a write error leaves the
// previous set intact rather than a truncated one.
func (s *Store) SavePools(pools []pool.Pool) {
	if _, err := s.db.Exec(`DELETE FROM resource_pools`); err != nil {
		s.log("pool clear", err)
		return
	}
	for i, p := range pools {
		// The throttle is one JSON column rather than four typed ones because it is a unit: "off" is
		// the absence of the whole thing, and four nullable columns would let a row exist that is
		// half-throttled. NULL means off, which is the same distinction pool.Pool.Throttle's nil makes.
		var throttle []byte
		if p.Throttle != nil {
			var err error
			throttle, err = json.Marshal(p.Throttle)
			if err != nil {
				s.log("pool throttle", err)
				return
			}
		}
		if _, err := s.db.Exec(
			`INSERT OR REPLACE INTO resource_pools (ord, name, max_concurrent, delay_ms, throttle)
			 VALUES (?, ?, ?, ?, ?)`,
			i, p.Name, p.MaxConcurrent, p.DelayMs, throttle); err != nil {
			s.log("pool", err)
			return
		}
	}
}

// LoadPools restores the pools in their persisted order.
//
// Validation is *not* done here and is not an omission: pool.Registry.Restore validates every pool
// and returns one error per refusal, which is a richer answer than this function's single error could
// carry — a database with one malformed pool should restore the other nineteen and say what it
// refused. So this reads rows and the registry judges them.
func (s *Store) LoadPools() ([]pool.Pool, error) {
	rows, err := s.db.Query(
		`SELECT name, max_concurrent, delay_ms, throttle FROM resource_pools ORDER BY ord`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pool.Pool
	for rows.Next() {
		var p pool.Pool
		var throttle []byte
		if err := rows.Scan(&p.Name, &p.MaxConcurrent, &p.DelayMs, &throttle); err != nil {
			return nil, err
		}
		if len(throttle) > 0 {
			t := &pool.Throttle{}
			if err := json.Unmarshal(throttle, t); err != nil {
				return nil, fmt.Errorf("pool %q: throttle: %w", p.Name, err)
			}
			p.Throttle = t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SaveSchedules replaces the saved schedule set, in the order given.
func (s *Store) SaveSchedules(schedules []schedule.Schedule) {
	if _, err := s.db.Exec(`DELETE FROM scheduled_tasks`); err != nil {
		s.log("schedule clear", err)
		return
	}
	for i, sc := range schedules {
		// Params are stored as the raw JSON they arrived as, not re-marshalled through a typed shape:
		// this layer does not know what a crawl's or an audit's parameters look like, and a round trip
		// through a type it invented would drop whatever field it had not heard of. Empty stays NULL so
		// "no params" and "the params were the empty object" stay distinguishable.
		var params []byte
		if len(sc.Params) > 0 {
			params = []byte(sc.Params)
		}
		if _, err := s.db.Exec(
			`INSERT OR REPLACE INTO scheduled_tasks
			 (ord, name, kind, enabled, first_ms, interval_secs, pool, params,
			  next_ms, last_run_ms, runs, failures, missed, last_note)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			i, sc.Name, sc.Kind, boolInt(sc.Enabled), sc.FirstMs, sc.IntervalSecs, sc.Pool, params,
			sc.NextMs, sc.LastRunMs, sc.Runs, sc.Failures, sc.Missed, sc.LastNote); err != nil {
			s.log("schedule", err)
			return
		}
	}
}

// LoadSchedules restores the schedules in their persisted order, counters and all.
func (s *Store) LoadSchedules() ([]schedule.Schedule, error) {
	rows, err := s.db.Query(
		`SELECT name, kind, enabled, first_ms, interval_secs, pool, params,
		        next_ms, last_run_ms, runs, failures, missed, last_note
		 FROM scheduled_tasks ORDER BY ord`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []schedule.Schedule
	for rows.Next() {
		var sc schedule.Schedule
		var enabled int
		var params []byte
		// Scanned through pointers so a NULL column reads as absent rather than failing the scan: both
		// were written by a row that had nothing to say, and "" is the honest value for each.
		var poolName, note *string
		if err := rows.Scan(&sc.Name, &sc.Kind, &enabled, &sc.FirstMs, &sc.IntervalSecs, &poolName, &params,
			&sc.NextMs, &sc.LastRunMs, &sc.Runs, &sc.Failures, &sc.Missed, &note); err != nil {
			return nil, err
		}
		sc.Enabled = enabled != 0
		if poolName != nil {
			sc.Pool = *poolName
		}
		if note != nil {
			sc.LastNote = *note
		}
		if len(params) > 0 {
			sc.Params = json.RawMessage(params)
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}
