// Package persist is the durable layer for burpsy's state. The runtime model is
// deliberately asymmetric: in-memory stores are authoritative and fast, and SQLite
// is a write-through mirror that survives restarts. Every mutation the stores
// make (messages, exchanges, findings, scope rules, match & replace rules, session
// rules, organizer items, tool log) is written to the database; on startup the
// database is loaded back into the in-memory stores. Nothing is read from SQLite
// at runtime except the one-time restore.
//
// A failed write is logged, never fatal: traffic must not be dropped because the
// durable mirror hiccuped. That trade is the point of the split.
package persist

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/organizer"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"github.com/burpsy-go/burpsy/internal/upstream"
	"go.uber.org/zap"

	_ "modernc.org/sqlite"
)

// Store owns the SQLite connection. Writes are serialised through one
// connection (SQLite is a single-writer database) and kept simple: WAL mode,
// synchronous=NORMAL, busy_timeout so a concurrent reader never sees torn
// state and a second process never trips on a lock.
type Store struct {
	db     *sql.DB
	logger *zap.Logger
	// path is where this database lives, kept so a backup can name itself after it and so the
	// backup endpoint can report which file it snapshotted. Open is the only writer.
	path string
}

// Path is the database file this store was opened on.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Open opens (creating if necessary) the database at path and ensures the
// schema exists. Pass a logger for mirror-write diagnostics.
func Open(path string, logger *zap.Logger) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL: %w", err)
	}
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("set synchronous: %w", err)
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		db.Close()
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}
	s := &Store{db: db, logger: logger, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Backup writes a consistent snapshot of the database to dest.
//
// # Why VACUUM INTO and not a file copy
//
// This store runs in WAL mode (see Open). A live WAL database is *two or three* files — the main
// database, the -wal, and the -shm — and the main file alone is not a database anyone can open:
// committed pages may exist only in the WAL. Copying it while the proxy is recording produces a
// backup that is either stale, internally inconsistent, or torn mid-page, and the operator would not
// discover which until they tried to restore it. Under a `cp`-style backup the failure mode is a
// file that looks the right size and opens to a corrupt schema.
//
// VACUUM INTO takes SQLite's own read snapshot and writes a complete, defragmented, single-file
// database — no WAL to carry alongside it, and consistent by construction. It is also the only
// option here that needs no second connection and no driver-specific backup API, which matters
// because modernc.org/sqlite is a translation of the C source rather than a binding and does not
// expose the online-backup handle.
//
// The cost is real and worth stating: VACUUM INTO reads the whole database and writes the whole
// snapshot, so it is O(size) in both time and disk. That is why the scheduled backup exists as a
// schedule rather than as something that fires on every write.
//
// dest must not exist — SQLite refuses to overwrite, and that refusal is kept rather than worked
// around, because silently replacing a previous backup is how an operator ends up with one copy
// when they believed they had a series.
func (s *Store) Backup(dest string) error {
	if s == nil || s.db == nil {
		return errors.New("no database is open, so there is nothing to back up")
	}
	if dest == "" {
		return errors.New("backup destination is empty")
	}
	// The parameter is bound rather than interpolated. VACUUM INTO takes an expression, so a bound
	// value works, and a path is operator input — it arrives from a schedule's params.
	if _, err := s.db.Exec(`VACUUM INTO ?`, dest); err != nil {
		return fmt.Errorf("backup to %s: %w", dest, err)
	}
	return nil
}

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS messages (
	id         INTEGER PRIMARY KEY,
	direction  INTEGER NOT NULL,
	raw        BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS exchanges (
	id            INTEGER PRIMARY KEY,
	request_msg   INTEGER NOT NULL,
	response_msg  INTEGER,
	host          TEXT NOT NULL,
	port          INTEGER NOT NULL,
	tls           INTEGER NOT NULL,
	method        TEXT NOT NULL,
	path          TEXT NOT NULL,
	status        INTEGER,
	response_len  INTEGER NOT NULL,
	started_ms    INTEGER NOT NULL,
	duration_ms   INTEGER NOT NULL,
	notes         TEXT,
	protocol      INTEGER NOT NULL,
	related       TEXT,
	cookies       TEXT,
	title         TEXT
);
CREATE TABLE IF NOT EXISTS findings (
	id          INTEGER PRIMARY KEY,
	name        TEXT NOT NULL,
	severity    INTEGER NOT NULL,
	confidence  INTEGER NOT NULL,
	description TEXT NOT NULL,
	remediation TEXT NOT NULL,
	occurrences TEXT,
	inserted    TEXT,
	timestamp   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scope_rules (
	kind    INTEGER NOT NULL,
	pattern TEXT NOT NULL,
	port    INTEGER,
	PRIMARY KEY (kind, pattern)
);
CREATE TABLE IF NOT EXISTS scope_rules_v2 (
	ord         INTEGER PRIMARY KEY,
	kind        TEXT NOT NULL,
	pattern     TEXT NOT NULL,
	port        INTEGER,
	path_prefix TEXT
);
CREATE TABLE IF NOT EXISTS scope_rules_v3 (
	ord         INTEGER PRIMARY KEY,
	kind        TEXT NOT NULL,
	pattern     TEXT NOT NULL,
	port        INTEGER,
	path_prefix TEXT,
	protocol    TEXT,
	enabled     INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS matchreplace_rules (
	ord      INTEGER PRIMARY KEY,
	target   INTEGER NOT NULL,
	category INTEGER NOT NULL,
	match    TEXT NOT NULL,
	replace  TEXT NOT NULL,
	comment  TEXT NOT NULL,
	enabled  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS session_rules (
	id           INTEGER PRIMARY KEY,
	name         TEXT NOT NULL,
	enabled      INTEGER NOT NULL,
	scope_hosts  TEXT NOT NULL,
	scope_params TEXT NOT NULL DEFAULT '',
	macro        TEXT NOT NULL,
	validity     TEXT,
	max_attempts INTEGER NOT NULL,
	extractions  TEXT
);
CREATE TABLE IF NOT EXISTS organizer_items (
	id        INTEGER PRIMARY KEY,
	exchange  INTEGER NOT NULL,
	title     TEXT NOT NULL,
	note      TEXT NOT NULL,
	highlight TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS organizer_collections (
	id   INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS platform_auth (
	ord      INTEGER PRIMARY KEY,
	host     TEXT NOT NULL,
	scheme   TEXT NOT NULL,
	username TEXT NOT NULL,
	password TEXT NOT NULL,
	realm    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS client_certs (
	ord        INTEGER PRIMARY KEY,
	host       TEXT NOT NULL,
	path       TEXT NOT NULL,
	passphrase TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_log (
	id          INTEGER PRIMARY KEY,
	tool        INTEGER NOT NULL,
	host        TEXT NOT NULL,
	port        INTEGER NOT NULL,
	tls         INTEGER NOT NULL,
	method      TEXT NOT NULL,
	path        TEXT NOT NULL,
	status      INTEGER NOT NULL,
	started_ms  INTEGER NOT NULL,
	duration_ms INTEGER NOT NULL,
	note        TEXT NOT NULL,
	comment     TEXT NOT NULL DEFAULT '',
	highlight   TEXT NOT NULL DEFAULT ''
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	// Resource pools and scheduled tasks, kept in pools.go beside their own load and save so the
	// three halves of one round trip are read together. Applied as a second statement rather than
	// appended to the string above for that reason alone — CREATE TABLE IF NOT EXISTS is idempotent
	// either way.
	if _, err := s.db.Exec(poolSchema); err != nil {
		return fmt.Errorf("create pool schema: %w", err)
	}
	// messages gained (segment, offset, length) when the store stopped keeping
	// payload bytes on the heap: with a capture directory the bytes are already
	// durable in a segment file, so mirroring them into SQLite as well stored
	// every byte three times over. On a 419 MB capture that was a 436 MB
	// database against a 2.7 MB one, and a restart of 3.1s/623 MB against
	// 288ms/22 MB.
	//
	// The columns are added rather than the table rewritten, so a database
	// written by an older build still opens: its rows carry bytes and no span,
	// and load back as resident messages. raw stays NOT NULL because SQLite
	// cannot relax that with ALTER TABLE — a span row writes a zero-length blob
	// into it, which costs nothing.
	for _, col := range []struct{ name, decl string }{
		{"segment", "TEXT"},
		{"offset", "INTEGER"},
		{"length", "INTEGER"},
		{"shape", "BLOB"},
	} {
		if err := s.addColumn("messages", col.name, col.decl); err != nil {
			return err
		}
	}
	// session_rules gained `ord` because the evaluation order is data, not something to re-derive.
	// Coordinator.MatchingRule walks its rules in order and returns the *first* one covering a host, so
	// the order decides which login macro runs. The table had no order column and the load had no ORDER
	// BY, which left the restored order to whatever the query happened to return — a restart could
	// silently promote a different rule to first. A legacy row has ord NULL and is ordered by id, which
	// is the order such a row was written in.
	if err := s.addColumn("session_rules", "ord", "INTEGER"); err != nil {
		return err
	}
	// session_rules gained scope_params for Burp's parameter scope (burpsy-react-ui-9hip):
	// a rule that updates a named parameter across requests — the canonical CSRF-token rule —
	// must apply only where that parameter exists. Empty is the unrestricted rule every row
	// written before this column carried, which is the only safe default: reading a legacy
	// rule as parameter-restricted would silently stop every existing login macro from
	// matching.
	if err := s.addColumn("session_rules", "scope_params", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// exchanges gained duration_us so that "fast" and "never measured" stop being the same row.
	// duration_ms is a whole-millisecond count, so a sub-millisecond exchange stored 0 — exactly what an
	// exchange nobody timed stores. NULL here means unmeasured and a number means measured, including
	// the measured zero. duration_ms is still written for what it is worth to an older build reading
	// this database, and is the only thing a *legacy* row has: see LoadExchanges for how one is read.
	if err := s.addColumn("exchanges", "duration_us", "INTEGER"); err != nil {
		return err
	}
	// findings gained param so a finding can say which parameter it was observed at. Empty means
	// the finding is about a resource, not one of its inputs — NULL reads back as empty, so a
	// legacy row and a resource finding are indistinguishable, which is correct because they mean
	// the same thing on the wire.
	if err := s.addColumn("findings", "param", "TEXT"); err != nil {
		return err
	}
	// tool_log gained response_len so a restored row can say how many response bytes came back. The
	// column is nullable and every other column on this table is NOT NULL deliberately: NULL means no
	// response was measured — a send that failed, a row standing for a whole run — which is a different
	// fact from a response of zero bytes, and the distinction is the whole point of the field (see
	// toollog.Entry.ResponseLen). A row written by an older build has no length at all, so it reads back
	// as NULL, which is exactly the truth about it: unknown, not empty.
	if err := s.addColumn("tool_log", "response_len", "INTEGER"); err != nil {
		return err
	}
	// tool_log gained comment for operator annotations on tool rows. NULL reads back as "".
	if err := s.addColumn("tool_log", "comment", "TEXT"); err != nil {
		return err
	}
	// tool_log gained highlight for the same reason: the colour tag, sharing the
	// organizer's vocabulary. NULL reads back as "" (no highlight).
	if err := s.addColumn("tool_log", "highlight", "TEXT"); err != nil {
		return err
	}
	// tool_log gained exchange_id so a restored row keeps its link to the traffic-store exchange its
	// bytes live under — Logger's message viewer resolves request/response through it. Nullable for the
	// same reason response_len is: NULL means no linked exchange (a transport failure, a whole-run row,
	// or anything written before this column existed), and a viewer must show that as "no bytes to
	// show", not as exchange 0 — the stores are position-is-the-id counters from zero, so 0 is a real
	// exchange.
	if err := s.addColumn("tool_log", "exchange_id", "INTEGER"); err != nil {
		return err
	}
	// exchanges gained highlight for the same reason notes did: an operator annotation, not traffic,
	// so it lives beside notes rather than in its own table. NULL and "" both read back as "" (no
	// highlight) — a legacy row written before this column existed never has an opinion either way, so
	// there is nothing to distinguish it from an exchange explicitly cleared.
	if err := s.addColumn("exchanges", "highlight", "TEXT"); err != nil {
		return err
	}
	// organizer_items gained status for the user-applied workflow status (Burp's New / In progress /
	// Postponed / Done / Ignored). NULL reads back as "new": a legacy row was saved before the field
	// existed, and "the operator never triaged this item" is exactly what "new" means — so a restored
	// pre-status item shows up in the same untriaged state it was in, rather than as some invented
	// default that looks like a decision.
	if err := s.addColumn("organizer_items", "status", "TEXT"); err != nil {
		return err
	}
	// organizer_items gained collection so an item can say which collection it sits in. 0 means
	// the inbox — which is what every legacy row is, because collections did not exist when it was
	// written and the inbox is where Burp's docs say messages appear before anyone organises them.
	if err := s.addColumn("organizer_items", "collection", "INTEGER"); err != nil {
		return err
	}
	// exchanges gained source so HTTP history can keep tool-originated sends (Repeater, Intruder,
	// Scanner) out of what is proxy traffic by attribution, not by luck. NULL reads back as the
	// unattributed zero value — the same fail-safe direction the Source type itself takes: a legacy
	// row claims no producer, and an unattributed row stays visible in history rather than being
	// dropped as though a tool had owned it.
	if err := s.addColumn("exchanges", "source", "TEXT"); err != nil {
		return err
	}
	// exchanges gained mime because the History MIME column and its type filter had been shipped
	// against a field nothing ever populated — the filter matched no row for any value an operator
	// could pick, and emptied the table instead of saying so. The value is the response's media type,
	// computed once at capture from bytes already in hand (core.MimeEssence) rather than derived at
	// list time, because /api/history must not open a response body to render a row.
	//
	// NULL and "" both read back as "" and neither is an error. That is the same shape as highlight,
	// and here it collapses two states that the row itself keeps apart anyway: a legacy row written
	// before this column existed, and a response that named no Content-Type. Neither can be told from
	// the other by this column, and neither needs to be — response_msg is what distinguishes "nothing
	// came back" from "something came back untyped", which is the distinction a reader actually acts
	// on. Backfilling old rows is deliberately not attempted: it would mean reading every stored
	// response at startup, which is the exact cost this column exists to avoid paying at list time.
	if err := s.addColumn("exchanges", "mime", "TEXT"); err != nil {
		return err
	}
	// exchanges gained cookies and title for the History Cookies and Title columns, denormalised
	// at capture like mime and for the same reason: a list-time derivation would read response
	// bytes per row. NULL reads back as unattributed (no cookies / no title), and backfilling
	// is not attempted for the same cost reason mime documents above.
	if err := s.addColumn("exchanges", "cookies", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumn("exchanges", "title", "TEXT"); err != nil {
		return err
	}
	// findings gained a target and a param set, both for deduplication (core.FindingStore.Add). The
	// target is the second half of the dedup key, so without it a restored finding cannot attract new
	// occurrences after a restart — it would start a second finding beside itself. params is the set
	// a merged finding folded together, and it is the field that makes the merge non-lossy: one
	// reflected-XSS finding covering five parameters is only better than five findings if it can still
	// name the five. All four read back as NULL on a legacy row, which correctly means "written before
	// this build knew about targets": such a row is left out of the dedup index rather than guessed
	// into it.
	if err := s.addColumn("findings", "target_host", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumn("findings", "target_port", "INTEGER"); err != nil {
		return err
	}
	if err := s.addColumn("findings", "target_tls", "INTEGER"); err != nil {
		return err
	}
	if err := s.addColumn("findings", "target_path", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumn("findings", "params", "TEXT"); err != nil {
		return err
	}
	// task_id is the run that produced the finding. It was carried in memory and dropped on the way
	// to disk, so the link between a coverage summary and the findings it produced survived only
	// until a restart: the dashboard could say an audit swept 200 exchanges and that 12 findings
	// exist, and after a reload nothing related the two. NULL on a legacy row reads back as 0, which
	// is the same "nothing tracked it" the in-memory zero already means.
	if err := s.addColumn("findings", "task_id", "INTEGER"); err != nil {
		return err
	}
	// Triage columns (burpsy-react-ui-pwd): the operator's severity/confidence override, the
	// false-positive mark and a note must survive a restart exactly like the finding they modify.
	// severity_override is NULL when the engine's own severity stands; false_positive defaults to 0
	// so a legacy row reads as not-a-false-positive without a rewrite.
	if err := s.addColumn("findings", "severity_override", "INTEGER"); err != nil {
		return err
	}
	if err := s.addColumn("findings", "confidence_override", "INTEGER"); err != nil {
		return err
	}
	if err := s.addColumn("findings", "false_positive", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.addColumn("findings", "comment", "TEXT"); err != nil {
		return err
	}
	// scope_rules_v3 gained enabled for the per-rule disable switch (burpsy-react-ui-1xb).
	// NOT NULL with a default of 1 because ALTER TABLE cannot add a NOT NULL column without
	// one, and 1 is the only safe value: every row written before this column existed was an
	// active rule, and reading one back as disabled would silently shrink an engagement's
	// scope across a restart.
	if err := s.addColumn("scope_rules_v3", "enabled", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}
	return nil
}

// addColumn adds a column unless it is already there, so migrate stays
// idempotent across restarts.
func (s *Store) addColumn(table, name, decl string) error {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return fmt.Errorf("inspect %s: %w", table, err)
	}
	present := false
	for rows.Next() {
		var cid, notNull, pk int
		var colName, colType string
		var dflt any
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("inspect %s: %w", table, err)
		}
		if colName == name {
			present = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("inspect %s: %w", table, err)
	}
	// Closed before the ALTER, not deferred: the pool is capped at one
	// connection, so an open Rows would block the write and deadlock.
	rows.Close()
	if present {
		return nil
	}
	if _, err := s.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, name, decl)); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, name, err)
	}
	return nil
}

// Close closes the underlying connection.
func (s *Store) Close() error { return s.db.Close() }

// log mirrors a write error without letting it surface to the caller.
func (s *Store) log(op string, err error) {
	if s.logger != nil {
		s.logger.Warn("persist write failed", zap.String("op", op), zap.Error(err))
	}
}

// note reports something wrong with what was *read back*, which log cannot: its message says a write
// failed, and a restore-time finding logged under that wording sends whoever reads it looking for a
// failure that never happened.
func (s *Store) note(op string, err error) {
	if s.logger != nil {
		s.logger.Warn("persist read inconsistency", zap.String("op", op), zap.Error(err))
	}
}

// ---- Messages + exchanges ----------------------------------------------------------------------

// SaveMessage mirrors one stored message: its shape always, and then either the
// span its bytes occupy or the bytes themselves.
//
// Both halves of that are the point of the split. When the bytes are already
// durable in a segment file, mirroring them again is pure duplication — it makes
// them no safer, and it is what made restarting cost hundreds of megabytes.
// Storing the shape is what stops the restore having to read those bytes back
// just to re-derive spans from them.
//
// Without a capture directory there is no segment file, so SQLite is the only
// durable copy and the bytes have to go in.
func (s *Store) SaveMessage(m *core.StoredMessage) {
	shape := core.EncodeShape(m.Shape)
	loc := m.Location()
	if loc.Segment != "" {
		_, err := s.db.Exec(
			`INSERT OR REPLACE INTO messages (id, direction, raw, segment, offset, length, shape)
			 VALUES (?, ?, X'', ?, ?, ?, ?)`,
			uint64(m.ID), int(m.Shape.Direction), loc.Segment, loc.Offset, loc.Length, shape)
		if err != nil {
			s.log("message", err)
		}
		return
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO messages (id, direction, raw, segment, offset, length, shape)
		 VALUES (?, ?, ?, NULL, NULL, NULL, ?)`,
		uint64(m.ID), int(m.Shape.Direction), m.Raw(), shape)
	if err != nil {
		s.log("message", err)
	}
}

// SaveExchange mirrors one exchange.
//
// The duration is written twice on purpose: duration_us is the real value, NULL when nothing measured
// it, and duration_ms is the rounded count the column has always held. Keeping duration_ms written
// means a build older than this column still reads a sane row out of the same database, and it costs
// four bytes; dropping it would silently turn every exchange into a zero-duration one over there. Which
// column a *reader* trusts is decided in LoadExchanges.
func (s *Store) SaveExchange(ex *core.Exchange) {
	related, err := json.Marshal(ex.Related)
	if err != nil {
		related = nil
	}
	cookies, err := json.Marshal(ex.Cookies)
	if err != nil {
		cookies = nil
	}
	var status any
	if ex.Status != nil {
		status = int(*ex.Status)
	}
	var durationUs any
	if ex.Duration.Measured {
		durationUs = int64(ex.Duration.Us)
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO exchanges
		 (id, request_msg, response_msg, host, port, tls, method, path, status,
		  response_len, started_ms, duration_ms, notes, protocol, related, duration_us, highlight, source, mime, cookies, title)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ex.ID, uint64(ex.Request), nullMsg(ex.Response), ex.Host, int(ex.Port),
		boolInt(ex.TLS), ex.Method, ex.Path, status, ex.ResponseLen,
		ex.StartedMs, ex.Duration.Millis(), nullStr(ex.Notes), int(ex.Protocol), related, durationUs,
		ex.Highlight, string(ex.Source), ex.Mime, cookies, ex.Title)
	if err != nil {
		s.log("exchange", err)
	}
}

// LoadMessages restores every stored message.
//
// A row carrying a span is restored as a disk-backed message resolved against
// src, and one carrying a persisted shape is restored without reading its bytes
// at all: a shape is only spans, so there is nothing left to derive from the
// payload. That is what makes restart cost independent of how much traffic was
// captured — the index is read, the capture is not.
//
// A row with no shape was written before shapes were persisted, so its bytes are
// read and re-parsed. A row with no span — written before spans existed, or by a
// store with no capture directory — comes back resident, as it must: there is
// nowhere else for those bytes to live.
func (s *Store) LoadMessages(src *core.SegmentLog) ([]*core.StoredMessage, error) {
	rows, err := s.db.Query(`SELECT id, direction, raw, segment, offset, length, shape FROM messages ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*core.StoredMessage
	for rows.Next() {
		var id uint64
		var dir int
		var raw []byte
		var segment sql.NullString
		var offset, length sql.NullInt64
		var encodedShape []byte
		if err := rows.Scan(&id, &dir, &raw, &segment, &offset, &length, &encodedShape); err != nil {
			return nil, err
		}

		onDisk := segment.Valid && segment.String != ""
		if onDisk && src == nil {
			return nil, fmt.Errorf("message %d is recorded at %s offset %d but this store has no segment log to resolve it against",
				id, segment.String, offset.Int64)
		}
		loc := core.Location{Segment: segment.String, Offset: offset.Int64, Length: length.Int64}

		shape, err := s.shapeFor(id, encodedShape, raw, dir, onDisk, loc, src)
		if err != nil {
			return nil, err
		}
		if onDisk {
			out = append(out, core.NewDiskMessage(core.MsgId(id), shape, loc, src))
			continue
		}
		out = append(out, core.NewResidentMessage(core.MsgId(id), raw, shape))
	}
	return out, rows.Err()
}

// shapeFor decodes the persisted shape, or re-derives it from the bytes for a row
// written before shapes were stored.
func (s *Store) shapeFor(id uint64, encoded, raw []byte, dir int, onDisk bool,
	loc core.Location, src *core.SegmentLog) (core.MessageShape, error) {
	if len(encoded) > 0 {
		shape, err := core.DecodeShape(encoded)
		if err != nil {
			return core.MessageShape{}, fmt.Errorf("message %d shape: %w", id, err)
		}
		return shape, nil
	}
	bytes := raw
	if onDisk {
		var err error
		if bytes, err = src.ReadAt(loc); err != nil {
			return core.MessageShape{}, fmt.Errorf("message %d does not resolve: %w", id, err)
		}
	}
	shape, err := core.Parse(bytes, core.Direction(dir))
	if err != nil {
		return core.MessageShape{}, fmt.Errorf("message %d: %w", id, err)
	}
	return shape, nil
}

// LoadExchanges restores every exchange in id order (ids are positional).
//
// # Reading the duration of a row this build did not write
//
// duration_us is the truth when it is present. When it is NULL the row predates the column, and such a
// row carries only a whole-millisecond count — from which the two states core.ExchangeDuration keeps
// apart genuinely cannot be recovered. So the reading is stated rather than guessed:
//
//   - duration_ms > 0 loads as measured, at millisecond precision (ms x 1000). The precision it never
//     had is not invented; it is simply coarse.
//   - duration_ms == 0 loads as *unmeasured*. It is ambiguous in the old data — it could have been a
//     genuine sub-millisecond exchange — and "no evidence" is the fail-safe answer, the same direction
//     CheckCoverage takes by treating an unrecorded check as never dispatched rather than as clean.
//     Reporting it as a measured zero would be inventing a measurement nobody made.
func (s *Store) LoadExchanges() ([]*core.Exchange, error) {
	rows, err := s.db.Query(
		`SELECT id, request_msg, response_msg, host, port, tls, method, path, status,
		        response_len, started_ms, duration_ms, notes, protocol, related, duration_us, highlight, source, mime, cookies, title
		 FROM exchanges ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*core.Exchange
	for rows.Next() {
		ex := &core.Exchange{}
		var request uint64
		var response any
		var port int
		var tls int
		var status any
		var notes any
		var protocol int
		var related []byte
		var durationMs uint64
		var durationUs sql.NullInt64
		var highlight sql.NullString
		var source sql.NullString
		var mime sql.NullString
		var cookies []byte
		var title sql.NullString
		if err := rows.Scan(&ex.ID, &request, &response, &ex.Host, &port, &tls,
			&ex.Method, &ex.Path, &status, &ex.ResponseLen, &ex.StartedMs,
			&durationMs, &notes, &protocol, &related, &durationUs, &highlight, &source, &mime, &cookies, &title); err != nil {
			return nil, err
		}
		ex.Highlight = highlight.String
		// NullString rather than string for the same reason source uses one: a row written before the
		// column existed scans as NULL, and scanning NULL into a string is an error that would fail the
		// whole restore of a legacy database rather than losing one cell of it. "" is the right reading
		// — this build cannot know what type that response declared, and will not guess.
		ex.Mime = mime.String
		// Same NULL-tolerant shape as Related: a legacy row scans NULL bytes, which unmarshal
		// to nothing, and the row keeps its zero values rather than failing the restore.
		if len(cookies) > 0 {
			if err := json.Unmarshal(cookies, &ex.Cookies); err != nil {
				return nil, err
			}
		}
		ex.Title = title.String
		// NULL reads back as the unattributed zero value, not a guess: see the migrate note on this
		// column. History keeps such rows — losing the attribution must not masquerade as tool traffic
		// being dropped.
		ex.Source = core.Source(source.String)
		switch {
		case durationUs.Valid && durationUs.Int64 >= 0:
			ex.Duration = core.MeasuredMicros(uint64(durationUs.Int64))
		case durationMs > 0:
			ex.Duration = core.MeasuredMicros(durationMs * 1000)
		default:
			ex.Duration = core.UnmeasuredDuration()
		}
		ex.Request = core.MsgId(request)
		if v, ok := response.(int64); ok {
			msg := core.MsgId(v)
			ex.Response = &msg
		}
		ex.Port = uint16(port)
		ex.TLS = tls != 0
		if v, ok := status.(int64); ok {
			sc := uint16(v)
			ex.Status = &sc
		}
		if v, ok := notes.(string); ok {
			ex.Notes = &v
		}
		ex.Protocol = core.Protocol(protocol)
		if len(related) > 0 {
			if err := json.Unmarshal(related, &ex.Related); err != nil {
				return nil, err
			}
		}
		out = append(out, ex)
	}
	return out, rows.Err()
}

// ---- Findings ----------------------------------------------------------------------------------

// SaveFinding mirrors one finding.
//
// INSERT OR REPLACE keyed on the id, which is what lets a merge (core.FindingStore.Add folding a new
// observation into an existing finding) come through this same slot: the store re-offers the changed
// finding, this rewrites its row, and the mirror holds the merged state rather than a stale copy
// plus a phantom second row.
func (s *Store) SaveFinding(f *core.Finding) {
	occ, err := json.Marshal(f.Occurrences)
	if err != nil {
		occ = nil
	}
	var ins []byte
	if f.Inserted != nil {
		ins, err = json.Marshal(f.Inserted)
		if err != nil {
			ins = nil
		}
	}
	var params []byte
	if len(f.Params) > 0 {
		params, err = json.Marshal(f.Params)
		if err != nil {
			params = nil
		}
	}
	tls := 0
	if f.Target.TLS {
		tls = 1
	}
	// severity_override is written as NULL whenever no override stands, so a finding whose override
	// is cleared reads back as NULL rather than as a stale value.
	var sevOverride interface{}
	if f.SeverityOverride != nil {
		sevOverride = int(*f.SeverityOverride)
	}
	var confOverride interface{}
	if f.ConfidenceOverride != nil {
		confOverride = int(*f.ConfidenceOverride)
	}
	fp := 0
	if f.FalsePositive {
		fp = 1
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO findings
		 (id, name, severity, confidence, description, remediation, occurrences, inserted, timestamp, param,
		  target_host, target_port, target_tls, target_path, params, task_id,
		  severity_override, confidence_override, false_positive, comment)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.Name, int(f.Severity), int(f.Confidence), f.Description,
		f.Remediation, occ, ins, f.Timestamp, f.Param,
		f.Target.Host, int(f.Target.Port), tls, f.Target.Path, params, f.TaskID,
		sevOverride, confOverride, fp, f.Comment)
	if err != nil {
		s.log("finding", err)
	}
}

// LoadFindings restores every finding.
func (s *Store) LoadFindings() ([]*core.Finding, error) {
	rows, err := s.db.Query(
		`SELECT id, name, severity, confidence, description, remediation, occurrences, inserted, timestamp, param,
		        target_host, target_port, target_tls, target_path, params, task_id,
		        severity_override, confidence_override, false_positive, comment
		 FROM findings ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*core.Finding
	for rows.Next() {
		f := &core.Finding{}
		var sev, conf, ts int
		var occ, ins, params []byte
		// Nullable because a row written before these columns existed has no value for them, and a
		// zero target is exactly the right reading of that: unknown, so not eligible to merge.
		var tHost, tPath sql.NullString
		var tPort, tTLS, taskID sql.NullInt64
		// Triage columns are nullable: severity_override/confidence_override are NULL while the
		// engine's own values stand, and every row written before they existed has NULLs for all
		// four, which must load as "no triage" rather than fail the whole restore.
		var sevOverride, confOverride, fp sql.NullInt64
		var comment sql.NullString
		if err := rows.Scan(&f.ID, &f.Name, &sev, &conf, &f.Description, &f.Remediation, &occ, &ins, &ts, &f.Param,
			&tHost, &tPort, &tTLS, &tPath, &params, &taskID,
			&sevOverride, &confOverride, &fp, &comment); err != nil {
			return nil, err
		}
		// NULL on a legacy row becomes 0, which is what an untracked finding already means in memory.
		f.TaskID = uint64(taskID.Int64)
		f.Severity = core.Severity(sev)
		f.Confidence = core.Confidence(conf)
		f.Timestamp = uint64(ts)
		if sevOverride.Valid {
			over := core.Severity(sevOverride.Int64)
			f.SeverityOverride = &over
		}
		if confOverride.Valid {
			over := core.Confidence(confOverride.Int64)
			f.ConfidenceOverride = &over
		}
		f.FalsePositive = fp.Int64 != 0
		if comment.Valid {
			f.Comment = comment.String
		}
		f.Target = core.FindingTarget{
			Host: tHost.String,
			Port: uint16(tPort.Int64),
			TLS:  tTLS.Int64 != 0,
			Path: tPath.String,
		}
		if len(params) > 0 {
			if err := json.Unmarshal(params, &f.Params); err != nil {
				return nil, err
			}
		} else if f.Param != "" {
			// A row from before params existed still knows its single param. Reconstructing the set
			// from it keeps Params usable as "the parameters this finding covers" for every row,
			// rather than leaving legacy findings looking parameter-less next to new ones.
			f.Params = []string{f.Param}
		}
		if len(occ) > 0 {
			if err := json.Unmarshal(occ, &f.Occurrences); err != nil {
				return nil, err
			}
		}
		if len(ins) > 0 {
			inserted := &core.Inserted{}
			if err := json.Unmarshal(ins, inserted); err != nil {
				return nil, err
			}
			f.Inserted = inserted
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// DeleteFinding drops one finding's mirror row. Wired as core.FindingStore's delete sink
// (SetDeleteSink): the in-memory store is authoritative, but without this a finding deleted in the
// UI walks straight back in on the next restart, restored from the row this file kept.
func (s *Store) DeleteFinding(id uint64) {
	if _, err := s.db.Exec(`DELETE FROM findings WHERE id = ?`, id); err != nil {
		s.log("finding", err)
	}
}

// ---- Scope -------------------------------------------------------------------------------------

// SaveScopeDropOutOfScope persists Burp's "Drop all out-of-scope requests" switch, a scope
// setting rather than a rule — it changes egress behaviour, not membership, so it rides the
// settings table like every other toggle rather than scope_rules_v3.
func (s *Store) SaveScopeDropOutOfScope(on bool) {
	if err := s.setSetting("scope.drop_out_of_scope", fmt.Sprint(on)); err != nil {
		s.log("scope drop_out_of_scope", err)
	}
}

// LoadScopeDropOutOfScope restores the switch. Absent reads as off, the seed both core.NewScope
// and a fresh Burp project use; a missing row is a first run, not a corruption.
func (s *Store) LoadScopeDropOutOfScope() bool {
	v, err := s.getSetting("scope.drop_out_of_scope")
	if err != nil || v == "" {
		return false
	}
	return v == "true"
}

// SaveScope replaces the scope rule set (small table; delete-and-reinsert is fine).
//
// # Why there are two tables, and why the old one is still written
//
// The original scope_rules keys on (kind, pattern) and has columns for neither the path prefix nor an
// order. Both of those cost an operator's scope its meaning, in the direction that matters:
//
//   - Two rules with the same kind and host and *different ports* — `include app.test:80` and
//     `include app.test:443`, an ordinary pair — collide on that key, so the second silently replaced
//     the first and one of the two authorised ports was gone after a restart.
//   - core.ScopeRule.PathPrefix had nowhere to go at all, so `include app.test` limited to `/api` came
//     back covering the whole host: an authorisation boundary widened by a restart.
//
// SQLite cannot alter a primary key, so the rule set moved to scope_rules_v2, which has no natural key
// at all — the set is replaced wholesale, so a key was only ever an opportunity to lose a row — and
// carries port, path prefix and order.
//
// The legacy table is still written, best-effort and as lossily as it always was, for one reason: an
// older build reads *only* that table, and core.Scope with no rules is default-allow. Stopping the
// legacy write would turn a downgrade into an engagement with no scope at all, which is the one failure
// direction worth carrying a duplicate table to avoid. scope_rules_v2 is mirrored for the same reason:
// a v2-era build reads only v2, so dropping its write would hand that downgrade an empty scope.
func (s *Store) SaveScope(rules []*core.ScopeRule) {
	if _, err := s.db.Exec(`DELETE FROM scope_rules_v3`); err != nil {
		s.log("scope clear", err)
		return
	}
	if _, err := s.db.Exec(`DELETE FROM scope_rules_v2`); err != nil {
		// Not fatal: the v3 table is the one that will be read back.
		s.log("scope clear v2", err)
	}
	if _, err := s.db.Exec(`DELETE FROM scope_rules`); err != nil {
		s.log("scope clear legacy", err)
		// Not fatal: the v3 table is the one that will be read back.
	}
	for i, r := range rules {
		var port any
		if r.Port != nil {
			port = int(*r.Port)
		}
		var pathPrefix any
		if r.PathPrefix != nil {
			pathPrefix = *r.PathPrefix
		}
		var protocol any
		if r.Protocol != nil {
			protocol = *r.Protocol
		}
		kind := scopeKindName(r.Kind)
		if _, err := s.db.Exec(
			`INSERT INTO scope_rules_v3 (ord, kind, pattern, port, path_prefix, protocol, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			i, kind, r.Pattern, port, pathPrefix, protocol, boolInt(r.Enabled)); err != nil {
			// Returning here would leave the durable scope narrower *or* wider than the live one with no
			// record of which rules made it, so every remaining rule is still attempted and every failure
			// is named.
			s.log("scope rule", fmt.Errorf("rule %d (%s %s): %w", i, kind, r.Pattern, err))
			continue
		}
		// The v2 mirror drops the protocol arm — a scheme-wide rule on a downgraded build is wider than
		// the operator set, but it is what a build without the column can represent, and the alternative
		// is no rule at all. A failure here costs that build one rule, not this one.
		if _, err := s.db.Exec(
			`INSERT INTO scope_rules_v2 (ord, kind, pattern, port, path_prefix) VALUES (?, ?, ?, ?, ?)`,
			i, kind, r.Pattern, port, pathPrefix); err != nil {
			s.log("scope rule v2 mirror", err)
		}
		// The legacy mirror, whose key cannot hold two rules that differ only by port or path. A failure
		// here is logged and stepped over: it costs a downgraded build one rule, not this one.
		if _, err := s.db.Exec(
			`INSERT OR REPLACE INTO scope_rules (kind, pattern, port) VALUES (?, ?, ?)`,
			kind, r.Pattern, port); err != nil {
			s.log("scope rule legacy mirror", err)
		}
	}
}

func scopeKindName(k core.ScopeRuleKind) string {
	if k == core.ScopeExclude {
		return "exclude"
	}
	return "include"
}

// LoadScope restores scope rules, in the order they were saved.
//
// scope_rules_v3 is authoritative when it holds anything; v2 is read when v3 is **empty** — a database
// written by a v2-era build, whose rows cannot carry a protocol, so those rules come back scheme-wide.
// The legacy table is read when both are empty, which is a database written before v2 existed — and
// such a row cannot carry a path prefix either, so the rule comes back host-and-port-wide. Both widenings
// are stated rather than papered over: they are what the newer tables exist to stop, and they cannot be
// recovered from data that never held them.
//
// Note "empty", not "absent": migrate creates every generation on open, so an old database arrives here
// with empty current tables beside populated older ones. Treating "v3 exists" as reason enough to read
// only v3 would hand core.Scope zero rules, and an empty core.Scope is default-allow — the fallbacks are
// what stop an upgrade from failing open. Pinned by TestLoadScopeFallsBackToAnEmptyV2AndAPopulatedLegacyTable
// and TestAV2EraDatabaseStillRestoresItsRules.
func (s *Store) LoadScope() ([]*core.ScopeRule, error) {
	rows, err := s.db.Query(`SELECT kind, pattern, port, path_prefix, protocol, enabled FROM scope_rules_v3 ORDER BY ord`)
	if err != nil {
		return nil, err
	}
	out, err := scanScopeRows(rows, true, true, true)
	if err != nil {
		return nil, err
	}
	if len(out) > 0 {
		s.checkLegacyScopeDivergence(out)
		return out, nil
	}
	v2rows, err := s.db.Query(`SELECT kind, pattern, port, path_prefix, NULL FROM scope_rules_v2 ORDER BY ord`)
	if err != nil {
		return nil, err
	}
	out, err = scanScopeRows(v2rows, true, false, false)
	if err != nil {
		return nil, err
	}
	if len(out) > 0 {
		s.checkLegacyScopeDivergence(out)
		return out, nil
	}
	legacy, err := s.db.Query(`SELECT kind, pattern, port, NULL, NULL FROM scope_rules`)
	if err != nil {
		return nil, err
	}
	return scanScopeRows(legacy, false, false, false)
}

// checkLegacyScopeDivergence reports a legacy scope row that this build did not write.
//
// # The one silent path the two tables still leave, and why this is only a warning
//
// An older build writes the scope to the legacy table alone, because v2 does not exist for it. So a
// project opened by an older binary *after* this one — an operator switching between two builds against
// one database — has its most recent scope edit in the legacy table while v2 holds the older set. This
// loader prefers v2 and would therefore restore a stale scope, in an unknown direction, saying nothing.
// That is the same class of failure as the port this file used to drop, so it does not get to be silent.
//
// The signal is sound rather than a heuristic. SaveScope mirrors every v2 rule into the legacy table with
// the same kind, pattern and port; the legacy key can only ever *drop* one of two rules that share a
// (kind, pattern), never invent one. So for any database written only by this build, the legacy triples
// are a subset of v2's. A legacy triple that is not in v2 is proof that something else wrote it.
//
// It warns rather than switching tables because which set is current genuinely cannot be recovered from
// the data: preferring the legacy rows would discard the path prefixes v2 holds, and merging the two
// would widen every include — failing open, the direction this file must never fail in. So the operator
// is told, by rule, that an edit made under another build is not in effect, and their next scope edit
// re-syncs both tables.
func (s *Store) checkLegacyScopeDivergence(current []*core.ScopeRule) {
	rows, err := s.db.Query(`SELECT kind, pattern, port FROM scope_rules`)
	if err != nil {
		// Nothing to say: the legacy table is a mirror, and failing to read it is not a reason to distrust
		// the table that is authoritative.
		return
	}
	defer rows.Close()
	held := make(map[string]bool, len(current))
	for _, r := range current {
		held[scopeTriple(scopeKindName(r.Kind), r.Pattern, r.Port)] = true
	}
	var orphans []string
	for rows.Next() {
		var kind, pattern string
		var port sql.NullInt64
		if err := rows.Scan(&kind, &pattern, &port); err != nil {
			return
		}
		var p *uint16
		if port.Valid && port.Int64 > 0 && port.Int64 <= 65535 {
			v := uint16(port.Int64)
			p = &v
		}
		key := scopeTriple(kind, pattern, p)
		if !held[key] {
			orphans = append(orphans, key)
		}
	}
	if len(orphans) == 0 {
		return
	}
	s.note("scope tables diverge", fmt.Errorf(
		"the legacy scope table holds %d rule(s) the current one does not (%s); an older build wrote the "+
			"scope after this one did, so its edit is NOT in effect and the restored scope is the older set — "+
			"re-apply the change and save the scope to bring both tables back into step",
		len(orphans), strings.Join(orphans, ", ")))
}

// scopeTriple is the identity SaveScope mirrors into the legacy table: kind, pattern and port. The path
// prefix is deliberately not part of it, because the legacy table cannot hold one.
func scopeTriple(kind, pattern string, port *uint16) string {
	if port == nil {
		return kind + " " + pattern + " :any"
	}
	return fmt.Sprintf("%s %s :%d", kind, pattern, *port)
}

// scanScopeRows builds rules from a (kind, pattern, port, path_prefix) result set.
//
// Port and path prefix are applied here rather than being scanned and dropped, which is what the load
// path used to do with the port: it selected the column, scanned it into a variable and then built the
// rule from the pattern alone. A rule restricted to one port therefore came back matching every port on
// that host — silently authorising traffic the operator had not authorised, for an include rule, and
// silently excluding traffic they had allowed, for an exclude one.
func scanScopeRows(rows *sql.Rows, withPath, hasProtocol, hasEnabled bool) ([]*core.ScopeRule, error) {
	defer rows.Close()
	var out []*core.ScopeRule
	for rows.Next() {
		var kind, pattern string
		var port sql.NullInt64
		var pathPrefix sql.NullString
		var protocol sql.NullString
		// enabled is scanned into a raw int rather than sql.NullInt64: older generations never
		// select it, so the caller's hasEnabled flag decides whether the column exists at all,
		// and the column itself is NOT NULL DEFAULT 1 wherever it does.
		var enabled int
		var scanArgs []any
		if hasEnabled {
			scanArgs = []any{&kind, &pattern, &port, &pathPrefix, &protocol, &enabled}
		} else {
			scanArgs = []any{&kind, &pattern, &port, &pathPrefix, &protocol}
		}
		if err := rows.Scan(scanArgs...); err != nil {
			return nil, err
		}
		// kind is stored as a string ("include"/"exclude") for readability.
		k := core.ScopeInclude
		if kind == "exclude" {
			k = core.ScopeExclude
		}
		r := core.NewScopeRule(k, pattern)
		// A row from an older generation (no enabled column, or a NULL the column predates)
		// reads back active: that is what the rule was when it was written.
		r.Enabled = true
		if hasEnabled && enabled == 0 {
			r.Enabled = false
		}
		if port.Valid && port.Int64 > 0 && port.Int64 <= 65535 {
			p := uint16(port.Int64)
			r.Port = &p
		}
		if withPath && pathPrefix.Valid && pathPrefix.String != "" {
			prefix := pathPrefix.String
			r.PathPrefix = &prefix
		}
		if hasProtocol && protocol.Valid && protocol.String != "" {
			scheme := protocol.String
			r.Protocol = &scheme
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- Interception startup state -----------------------------------------------------------------

// SaveInterceptStartup persists Burp's "Default Proxy interception state"
// (user_options.misc.enable_proxy_interception_at_startup and friends): what the
// intercept switch should read when a server starts. Three modes, Burp's three:
// "on", "off", and "restore" — the last reuses the last live state, which is
// recorded here on every toggle so a restart can honour it.
func (s *Store) SaveInterceptStartup(mode string) {
	if err := s.setSetting("intercept.startup_mode", mode); err != nil {
		s.log("intercept startup mode", err)
	}
}

// LoadInterceptStartup reads the mode. Absent reads as "off", the seed both the
// engine and every existing session used — a preference nobody wrote must not
// turn interception on by surprise.
func (s *Store) LoadInterceptStartup() string {
	v, err := s.getSetting("intercept.startup_mode")
	if err != nil || v == "" {
		return "off"
	}
	switch v {
	case "on", "off", "restore":
		return v
	}
	return "off"
}

// SaveInterceptLive records the intercept switch's current state, for the
// "restore" startup mode. Written by the enable endpoint alongside the live
// toggle, best-effort like every other persistence sink.
func (s *Store) SaveInterceptLive(on bool) {
	if err := s.setSetting("intercept.live", fmt.Sprint(on)); err != nil {
		s.log("intercept live state", err)
	}
}

// LoadInterceptLive reads the last live state. Absent reads as off.
func (s *Store) LoadInterceptLive() bool {
	v, err := s.getSetting("intercept.live")
	if err != nil || v == "" {
		return false
	}
	return v == "true"
}

// ---- Match & Replace ---------------------------------------------------------------------------

// SaveMatchRules replaces the match & replace rule set and content-length flag.
func (s *Store) SaveMatchRules(rules []*matchreplace.Rule, updateContentLength bool) {
	if _, err := s.db.Exec(`DELETE FROM matchreplace_rules`); err != nil {
		s.log("matchreplace clear", err)
		return
	}
	for i, r := range rules {
		if _, err := s.db.Exec(
			`INSERT OR REPLACE INTO matchreplace_rules
			 (ord, target, category, match, replace, comment, enabled)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			i, int(r.Target), int(r.Category), r.StringMatch, r.StringReplace,
			r.Comment, boolInt(r.Enabled)); err != nil {
			s.log("matchreplace rule", err)
			return
		}
	}
	if err := s.setSetting("matchreplace.update_content_length", fmt.Sprint(updateContentLength)); err != nil {
		s.log("matchreplace flag", err)
	}
}

// LoadMatchRules restores the rule set (recompiling regexes) and the flag.
func (s *Store) LoadMatchRules() ([]*matchreplace.Rule, bool, error) {
	rows, err := s.db.Query(`SELECT target, category, match, replace, comment, enabled FROM matchreplace_rules ORDER BY ord`)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var rules []*matchreplace.Rule
	for rows.Next() {
		var target, cat int
		var match, replace, comment string
		var enabled int
		if err := rows.Scan(&target, &cat, &match, &replace, &comment, &enabled); err != nil {
			return nil, false, err
		}
		r, err := matchreplace.NewRule(matchreplace.Target(target), matchreplace.Category(cat), match, replace, comment)
		if err != nil {
			return nil, false, err
		}
		r.Enabled = enabled != 0
		rules = append(rules, r)
	}
	flag := false
	if v, err := s.getSetting("matchreplace.update_content_length"); err == nil && v != "" {
		flag = v == "true"
	}
	return rules, flag, nil
}

// ---- Network authentication: platform credentials and client certificates ----------------------

// The two tables written below are the only secret-bearing rows in this database.
//
// They hold plaintext: a platform-authentication password, and the passphrase to a
// PKCS#12 file. That is a deliberate decision and it is stated here rather than in a
// commit message nobody will find. There is no key-management story in this tool to
// encrypt them under — no keyring dependency, no operator-supplied master
// passphrase, no OS credential store binding — and a local obfuscation (an XOR, a
// hard-coded AES key in the binary) would be trivially reversible by anyone holding
// the file while looking like protection to the operator reading about it. The
// honest arrangement is plaintext plus this notice: the SQLite mirror is
// secret-bearing, and an operator who cannot accept that should run without -db,
// which leaves the credentials in memory for the life of the process and nowhere
// else.
//
// Note what is *not* stored: the decoded private key from a PKCS#12 file. Only the
// path and the passphrase are kept, so the operator's file stays the single
// authority for the identity and deleting it removes the identity everywhere —
// rather than burpsy holding a second copy with a second lifetime that survives the
// revocation.

// SavePlatformAuth replaces the platform-authentication rule set.
//
// Order is preserved because it is semantic: netauth.Credentials is first-match-wins,
// so a restore that reordered the rules would change which credential a host gets.
func (s *Store) SavePlatformAuth(rows []netauth.CredentialRow) {
	if _, err := s.db.Exec(`DELETE FROM platform_auth`); err != nil {
		s.log("platform auth clear", err)
		return
	}
	for i, row := range rows {
		if _, err := s.db.Exec(
			`INSERT OR REPLACE INTO platform_auth (ord, host, scheme, username, password, realm)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			i, row.Host, row.Scheme, row.Username, row.Password, row.Realm); err != nil {
			// The op name carries the host but never the password. Every error path in this
			// file goes through s.log to zap, which is exactly the sink a secret must not
			// reach — a logged credential outlives the session in a file nobody redacts.
			s.log("platform auth rule for "+row.Host, err)
			return
		}
	}
}

// LoadPlatformAuth restores the persisted platform-authentication rows in rule order.
//
// Returns rows, not a live store: rebuilding the store is netauth.RestoreCredentials'
// job, and it re-validates every row rather than trusting one. A row whose scheme this
// build no longer implements must be dropped and named, not coerced into Basic, and
// this package has no business deciding that.
//
// An empty database yields an empty slice and a nil error. "Nothing stored" is not a
// failure — it is what a first run looks like.
func (s *Store) LoadPlatformAuth() ([]netauth.CredentialRow, error) {
	rows, err := s.db.Query(`SELECT host, scheme, username, password, realm FROM platform_auth ORDER BY ord`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netauth.CredentialRow
	for rows.Next() {
		var row netauth.CredentialRow
		if err := rows.Scan(&row.Host, &row.Scheme, &row.Username, &row.Password, &row.Realm); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// SaveClientCerts replaces the client-certificate binding set.
func (s *Store) SaveClientCerts(rows []netauth.ClientCertRow) {
	if _, err := s.db.Exec(`DELETE FROM client_certs`); err != nil {
		s.log("client certs clear", err)
		return
	}
	for i, row := range rows {
		if _, err := s.db.Exec(
			`INSERT OR REPLACE INTO client_certs (ord, host, path, passphrase) VALUES (?, ?, ?, ?)`,
			i, row.Host, row.Path, row.Passphrase); err != nil {
			s.log("client cert binding for "+row.Host, err)
			return
		}
	}
}

// LoadClientCerts restores the persisted client-certificate bindings in match order.
//
// Same shape and same reason as LoadPlatformAuth: rows out, and
// netauth.RestoreClientCerts re-reads each PKCS#12 file. A file the operator deleted
// between sessions therefore fails at restore and is *reported*, rather than
// producing a binding that sits on the panel and is never presented.
func (s *Store) LoadClientCerts() ([]netauth.ClientCertRow, error) {
	rows, err := s.db.Query(`SELECT host, path, passphrase FROM client_certs ORDER BY ord`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netauth.ClientCertRow
	for rows.Next() {
		var row netauth.ClientCertRow
		if err := rows.Scan(&row.Host, &row.Path, &row.Passphrase); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ---- Session rules -----------------------------------------------------------------------------

// SaveSessionRules replaces the session rule set.
func (s *Store) SaveSessionRules(rules []*session.SessionRule) {
	if _, err := s.db.Exec(`DELETE FROM session_rules`); err != nil {
		s.log("session clear", err)
		return
	}
	// The index is written as `ord` so the evaluation order survives the round trip. The caller passes
	// Coordinator.AllRules(), which is already in evaluation order.
	for i, r := range rules {
		hosts, err := json.Marshal(r.ScopeHosts)
		if err != nil {
			hosts = nil
		}
		params, err := json.Marshal(r.ScopeParams)
		if err != nil {
			params = nil
		}
		macro, err := json.Marshal(r.Steps)
		if err != nil {
			macro = nil
		}
		var validity []byte
		if r.Validity != nil {
			validity, _ = json.Marshal(r.Validity)
		}
		var exts []byte
		if len(r.Extractions) > 0 {
			exts, _ = json.Marshal(r.Extractions)
		}
		if _, err := s.db.Exec(
			`INSERT OR REPLACE INTO session_rules
			 (id, name, enabled, scope_hosts, scope_params, macro, validity, max_attempts, extractions, ord)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			int64(r.ID), r.Name, boolInt(r.Enabled), hosts, params, macro, validity, r.MaxAttempts, exts, i); err != nil {
			s.log("session rule", err)
			return
		}
	}
}

// LoadSessionRules restores session rules **in their persisted evaluation order**, recompiling each
// extraction's matcher.
//
// The ORDER BY is load-bearing, not tidiness. Coordinator.MatchingRule returns the first rule whose
// scope covers a host, so the order decides which login macro runs; this query had no ORDER BY at all,
// which left it to whatever SQLite returned. COALESCE(ord, id) covers a database written before the
// order column existed: such a row was written in id order, so id is the honest fallback for it.
func (s *Store) LoadSessionRules() ([]*session.SessionRule, error) {
	rows, err := s.db.Query(
		`SELECT id, name, enabled, scope_hosts, scope_params, macro, validity, max_attempts, extractions
		 FROM session_rules ORDER BY COALESCE(ord, id), id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*session.SessionRule
	for rows.Next() {
		r := &session.SessionRule{}
		var id int64
		var enabled int
		var hosts, params, macro, validity, exts []byte
		var maxAttempts int
		if err := rows.Scan(&id, &r.Name, &enabled, &hosts, &params, &macro, &validity, &maxAttempts, &exts); err != nil {
			return nil, err
		}
		r.ID = session.RuleID(id)
		r.Enabled = enabled != 0
		r.MaxAttempts = maxAttempts
		if len(hosts) > 0 {
			if err := json.Unmarshal(hosts, &r.ScopeHosts); err != nil {
				return nil, err
			}
		}
		// A NULL from a legacy-generation row (or the DEFAULT '' as []byte("")?) reads as
		// unrestricted: empty params is the meaning every pre-9hip rule carries.
		if len(params) > 0 {
			if err := json.Unmarshal(params, &r.ScopeParams); err != nil {
				return nil, err
			}
		}
		if len(macro) > 0 {
			if err := json.Unmarshal(macro, &r.Steps); err != nil {
				return nil, err
			}
		}
		if len(validity) > 0 {
			v := &session.ValidityRule{}
			if err := json.Unmarshal(validity, v); err != nil {
				return nil, err
			}
			r.Validity = v
		}
		if len(exts) > 0 {
			var parsed []*session.Extraction
			if err := json.Unmarshal(exts, &parsed); err != nil {
				return nil, err
			}
			// Recompile in place rather than rebuilding through NewExtraction from the handful of
			// fields this loop happens to name: a field added to session.Extraction later (the owning
			// step index and the header name both were) would otherwise be dropped on every load, so
			// a rule would come back "restored" with its extractions bound to the wrong step.
			for _, ex := range parsed {
				if err := ex.Recompile(); err != nil {
					return nil, err
				}
			}
			r.Extractions = parsed
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- Organizer ---------------------------------------------------------------------------------

// SaveOrganizer replaces the organizer item list.
func (s *Store) SaveOrganizer(items []organizer.Item) {
	if _, err := s.db.Exec(`DELETE FROM organizer_items`); err != nil {
		s.log("organizer clear", err)
		return
	}
	for _, it := range items {
		// An empty Status is stored as the empty string and reads back as "new": LoadOrganizer
		// treats "" and NULL alike, and the column is nullable, so a NULL written by an
		// earlier build lands in the same state. That is the honest fallback — a caller that
		// never set a status never triaged the item — as opposed to inventing a default that
		// would look like a decision.
		if _, err := s.db.Exec(
			`INSERT OR REPLACE INTO organizer_items (id, exchange, title, note, highlight, status, collection)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			it.ID, it.Exchange, it.Title, it.Note, it.Highlight, string(it.Status), it.Collection); err != nil {
			s.log("organizer item", err)
			return
		}
	}
}

// SaveOrganizerCollections replaces the collection registry. Items carry their collection id
// separately (organizer_items.collection), so this table holds only the group's own identity.
func (s *Store) SaveOrganizerCollections(collections []organizer.Collection) {
	if _, err := s.db.Exec(`DELETE FROM organizer_collections`); err != nil {
		s.log("organizer collections clear", err)
		return
	}
	for _, c := range collections {
		if _, err := s.db.Exec(
			`INSERT OR REPLACE INTO organizer_collections (id, name, note) VALUES (?, ?, ?)`,
			c.ID, c.Name, c.Note); err != nil {
			s.log("organizer collection", err)
			return
		}
	}
}

// LoadOrganizerCollections restores the collection registry, ordered by id.
func (s *Store) LoadOrganizerCollections() ([]organizer.Collection, error) {
	rows, err := s.db.Query(`SELECT id, name, note FROM organizer_collections ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []organizer.Collection
	for rows.Next() {
		c := organizer.Collection{}
		if err := rows.Scan(&c.ID, &c.Name, &c.Note); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LoadOrganizer restores organizer items.
func (s *Store) LoadOrganizer() ([]organizer.Item, error) {
	rows, err := s.db.Query(`SELECT id, exchange, title, note, highlight, status, collection FROM organizer_items ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []organizer.Item
	for rows.Next() {
		it := organizer.Item{}
		// status is nullable: NULL and "" both mean "never triaged", which is what StatusNew
		// is for. A value that is not one of the five valid statuses is also read as "new"
		// rather than passed through — a status nobody defined is a wire/storage fault, and
		// rendering it would present an operator a state they cannot set or filter on.
		var status *string
		var collection int
		if err := rows.Scan(&it.ID, &it.Exchange, &it.Title, &it.Note, &it.Highlight, &status, &collection); err != nil {
			return nil, err
		}
		it.Collection = collection
		if status != nil && organizer.ValidStatus(organizer.Status(*status)) {
			it.Status = organizer.Status(*status)
		} else {
			it.Status = organizer.StatusNew
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ---- Tool log ----------------------------------------------------------------------------------

// SaveToolLog mirrors one tool log entry.
func (s *Store) SaveToolLog(e *toollog.Entry) {
	// nil stays NULL rather than becoming 0, so the durable row keeps the distinction the in-memory
	// entry makes between a response of no bytes and no response at all.
	var responseLen any
	if e.ResponseLen != nil {
		responseLen = int64(*e.ResponseLen)
	}
	// Same for the exchange link: NULL is "no linked exchange", and 0 is exchange 0, which is a real
	// row in a position-is-the-id store.
	var exchangeID any
	if e.Exchange != nil {
		exchangeID = int64(*e.Exchange)
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO tool_log
		 (id, tool, host, port, tls, method, path, status, started_ms, duration_ms, note, response_len, comment, highlight, exchange_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, int(e.Tool), e.Host, int(e.Port), boolInt(e.TLS), e.Method, e.Path,
		int(e.Status), e.StartedMs, e.DurationMs, e.Note, responseLen, e.Comment, e.Highlight, exchangeID)
	if err != nil {
		s.log("tool_log", err)
	}
}

// LoadToolLog restores the tool log in id order.
//
// A NULL response_len restores as nil, which covers both the rows written that way on purpose and
// every row in a database written before the column existed. Defaulting those to zero would resurrect
// the exact claim this field was added to stop making: that the response was empty.
func (s *Store) LoadToolLog() ([]*toollog.Entry, error) {
	rows, err := s.db.Query(
		`SELECT id, tool, host, port, tls, method, path, status, started_ms, duration_ms, note, response_len, comment, highlight, exchange_id
		 FROM tool_log ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*toollog.Entry
	for rows.Next() {
		e := &toollog.Entry{}
		var tool, port, tls, status int
		var responseLen, exchangeID sql.NullInt64
		var comment, highlight sql.NullString
		if err := rows.Scan(&e.ID, &tool, &e.Host, &port, &tls, &e.Method, &e.Path, &status, &e.StartedMs, &e.DurationMs, &e.Note, &responseLen, &comment, &highlight, &exchangeID); err != nil {
			return nil, err
		}
		e.Tool = toollog.Tool(tool)
		e.Port = uint16(port)
		e.TLS = tls != 0
		e.Status = status
		if responseLen.Valid {
			n := int(responseLen.Int64)
			e.ResponseLen = &n
		}
		e.Comment = comment.String
		e.Highlight = highlight.String
		// NULL reads back as no link — a row that never had one, or one written by an older build. It must
		// not become exchange 0: the traffic store counts rows from zero, so 0 is a real exchange and
		// defaulting to it would show the viewer the wrong message pair.
		if exchangeID.Valid {
			id := core.ExchangeID(exchangeID.Int64)
			e.Exchange = &id
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- Settings ----------------------------------------------------------------------------------

func (s *Store) setSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, key, value)
	return err
}

func (s *Store) getSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SaveTlsPassthrough replaces the persisted TLS passthrough host-pattern list.
//
// One settings value holding a JSON array rather than its own table: this is a
// single small ordered list whose rows have no identity of their own, so a table
// would be ceremony without being structure. The save is whole-list because the
// web endpoint mirrors the policy's live list after every mutation — an
// incremental add/remove API would give the mirror a second chance to drift from
// what the proxy actually matches against.
func (s *Store) SaveTlsPassthrough(patterns []string) {
	if patterns == nil {
		patterns = []string{}
	}
	encoded, err := json.Marshal(patterns)
	if err != nil {
		s.log("tls passthrough encode", err)
		return
	}
	if err := s.setSetting("tls.passthrough", string(encoded)); err != nil {
		s.log("tls passthrough save", err)
	}
}

// LoadTlsPassthrough restores the pattern list. A database that never saved one
// yields an empty list and no error: absence of state is the empty state, not a
// failure worth waking the operator up for.
func (s *Store) LoadTlsPassthrough() ([]string, error) {
	v, err := s.getSetting("tls.passthrough")
	if err != nil || v == "" {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SaveScanConfig persists the scan-configuration overrides as one settings value. Same reasoning
// as SaveTlsPassthrough: one small JSON blob with no per-row identity, saved whole by the web
// endpoint after every edit so the durable copy cannot drift from what the running scanner obeys.
func (s *Store) SaveScanConfig(cfg scanner.ScanConfig) error {
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.setSetting("scanconfig.overrides", string(encoded))
}

// LoadScanConfig restores the persisted overrides. Absence of state yields a nil config and no
// error — an old database simply means "use NewActiveScanner's defaults", and a nil lets the
// caller skip the apply instead of clobbering those defaults with a zero struct.
func (s *Store) LoadScanConfig() (*scanner.ScanConfig, error) {
	v, err := s.getSetting("scanconfig.overrides")
	if err != nil || v == "" {
		return nil, err
	}
	cfg := &scanner.ScanConfig{}
	if err := json.Unmarshal([]byte(v), cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// SaveProxyOptions persists the proxy response-modification switches as one settings value.
//
// Same shape and reasoning as SaveTlsPassthrough: one small flag document with no per-row
// identity, written whole by the web endpoint after every accepted edit so the durable copy
// cannot drift from what the relay obeys.
//
// # What is deliberately not saved
//
// The outcome counters. They are the record of what this process observed — considered,
// modified, skipped-compressed, skipped-not-HTML — and restoring them would present another
// run's observations as this one's. `options.go` keeps the counters precisely so a rule that
// fired zero times is distinguishable from a rule that was never allowed to look; a restored
// non-zero count would destroy exactly that distinction on the first request after a restart.
// Flags are configuration and survive; counters are measurement and start at zero.
func (s *Store) SaveProxyOptions(flags map[string]bool) {
	if flags == nil {
		flags = map[string]bool{}
	}
	encoded, err := json.Marshal(flags)
	if err != nil {
		s.log("proxy options encode", err)
		return
	}
	if err := s.setSetting("proxy.options", string(encoded)); err != nil {
		s.log("proxy options save", err)
	}
}

// LoadProxyOptions restores the persisted switches. A database that never saved any yields a
// nil map and no error: absence of state is "every rule off", which is what NewOptions already
// built, so the caller skips the apply rather than writing a pile of explicit falses.
//
// Unknown keys are returned as they were stored rather than filtered here. The caller owns the
// vocabulary and is the only layer that can say *which* key it did not recognise — dropping
// them silently at this level would turn a renamed or retired option into a switch that
// vanished without explanation, and the restore path reports them instead.
func (s *Store) LoadProxyOptions() (map[string]bool, error) {
	v, err := s.getSetting("proxy.options")
	if err != nil || v == "" {
		return nil, err
	}
	out := map[string]bool{}
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SaveNetworkSettings persists the network settings as one settings value.
//
// Same shape as SaveScanConfig and for the same reason: one small document with no per-row identity,
// written whole by the web endpoint after every accepted edit. Written whole also settles what a
// removed row means — an override deleted from the table is absent from the next save rather than
// lingering as a row nothing referenced, which is what an incremental API would have had to remember.
//
// The value stored is the *confirmed* settings the sender is running, not the patch that produced them,
// so a restore reproduces the state the operator last saw rather than replaying a sequence of edits.
func (s *Store) SaveNetworkSettings(n sender.NetworkSettings) error {
	encoded, err := json.Marshal(n)
	if err != nil {
		return err
	}
	return s.setSetting("network.settings", string(encoded))
}

// LoadNetworkSettings restores the persisted network settings.
//
// Absence yields a nil and no error — an old database means "use sender's own defaults", and a nil lets
// the caller skip the apply rather than overwrite those defaults with a zero struct whose every timeout
// is zero. That distinction is load-bearing here in a way it is not for most settings: a zero-valued
// NetworkSettings is not a neutral starting point, it is "no connect bound, no read bound, redirects
// with an unnamed mode", and applying one would be refused by Validate at best and silently change
// every timeout at worst.
//
// A stored document that no longer parses is returned as an error rather than dropped. Refuse-by-default
// on unparseable input: an operator whose resolution overrides failed to load must be told, because the
// alternative is requests quietly going where DNS points instead of where they said.
func (s *Store) LoadNetworkSettings() (*sender.NetworkSettings, error) {
	v, err := s.getSetting("network.settings")
	if err != nil || v == "" {
		return nil, err
	}
	out := &sender.NetworkSettings{}
	if err := json.Unmarshal([]byte(v), out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- Upstream proxy ----------------------------------------------------------------------------

// upstreamProxyKey is the settings row the upstream proxy policy lives in.
//
// A key/value row rather than a table of its own, following matchreplace.update_content_length and the
// scan-config override: the whole policy is a handful of strings replaced wholesale on every edit, so a
// table would buy ordering and per-row updates that nothing here needs, and would need a migration the
// settings row does not.
const upstreamProxyKey = "network.proxy"

// SaveUpstreamProxy mirrors the upstream proxy policy into the settings row, replacing whatever was
// there.
//
// # Credentials are written in the clear, and that is stated rather than hidden
//
// The snapshot carries any proxy password, because a policy restored without it would come back looking
// configured and start failing authentication — the same class of lie as a rule that silently stopped
// proxying. The database this writes to already holds every captured request, Authorization headers
// included, so it is not a new secret-bearing artefact; it does mean the -db file must be treated as
// engagement material. The API never serves these values back and no log line carries them — see
// upstream.Proxy.Display, and upstream.Proxy.Raw for why this is the one caller that sees them.
func (s *Store) SaveUpstreamProxy(policy *upstream.Policy) {
	raw, err := json.Marshal(policy.Snapshot())
	if err != nil {
		s.log("upstream proxy marshal", err)
		return
	}
	if err := s.setSetting(upstreamProxyKey, string(raw)); err != nil {
		s.log("upstream proxy", err)
	}
}

// LoadUpstreamProxy restores the upstream proxy policy from the settings row into policy.
//
// An absent row is not an error and leaves the policy untouched: no row means no proxy was ever
// configured, which is the same state as a fresh policy. A row that does not parse *is* an error and is
// returned rather than swallowed — the caller decides whether to start under a policy it could not
// read, and starting with traffic silently going out direct is not a decision to make behind an
// operator's back.
func (s *Store) LoadUpstreamProxy(policy *upstream.Policy) error {
	if policy == nil {
		return nil
	}
	raw, err := s.getSetting(upstreamProxyKey)
	if err != nil {
		return fmt.Errorf("reading %s: %w", upstreamProxyKey, err)
	}
	if raw == "" {
		return nil
	}
	var snap upstream.Snapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return fmt.Errorf("stored upstream proxy policy is not readable JSON: %w", err)
	}
	return policy.Restore(snap)
}

// ---- Restore -----------------------------------------------------------------------------------

// Restore loads every table into the given in-memory stores. It is the one
// runtime read path. Missing tables (empty DB) yield empty slices. A nil store
// is skipped, so an owner that does not yet hold that store can defer its
// restore to whoever does.
func (s *Store) Restore(
	store *core.TrafficStore,
	findings *core.FindingStore,
	scope *core.Scope,
	mr *matchreplace.RuleSet,
	sess *session.Coordinator,
	org *organizer.Store,
	toolLog *toollog.ToolLog,
) error {
	if store != nil {
		// Resolved against the store's own log: a span means nothing without
		// the segment files it was recorded from.
		messages, err := s.LoadMessages(store.SegmentLog())
		if err != nil {
			return fmt.Errorf("load messages: %w", err)
		}
		exchanges, err := s.LoadExchanges()
		if err != nil {
			return fmt.Errorf("load exchanges: %w", err)
		}
		store.Restore(messages, exchanges)
	}

	if findings != nil {
		findingList, err := s.LoadFindings()
		if err != nil {
			return fmt.Errorf("load findings: %w", err)
		}
		findings.Restore(findingList)
	}

	if scope != nil {
		scopeRules, err := s.LoadScope()
		if err != nil {
			return fmt.Errorf("load scope: %w", err)
		}
		for _, r := range scopeRules {
			scope.Add(r)
		}
		// Burp's "Drop all out-of-scope requests" survives the restart with the rules it
		// governs: an egress fence that lapses because the process restarted is worse than
		// one that was never raised, because the panel says it is up.
		scope.SetDropOutOfScope(s.LoadScopeDropOutOfScope())
	}

	if mr != nil {
		mrRules, flag, err := s.LoadMatchRules()
		if err != nil {
			return fmt.Errorf("load matchreplace: %w", err)
		}
		mr.SetRules(mrRules)
		mr.SetUpdateContentLength(flag)
	}

	if sess != nil {
		sessionRules, err := s.LoadSessionRules()
		if err != nil {
			return fmt.Errorf("load session rules: %w", err)
		}
		// A saved rule goes back through the same validation a freshly-typed one does, so a rule written
		// before a check existed can be refused on load. Each refusal is logged with its reason and
		// then counted in a summary, because a rule dropped in silence leaves an operator with a
		// project that looks fully restored and a target that has quietly stopped being
		// authenticated. Restore keeps going rather than returning here: aborting on one bad session
		// rule would take the organizer and the tool log down with it.
		//
		// RestoreRule, not AddRule: AddRule mints a fresh id from the coordinator's counter, so a rule
		// saved as id 3 came back as id 1 and every RuleID anyone had written down — a note, a log line,
		// a `POST /api/session/rules/3/run` — silently named a different rule's login macro. The rules
		// are installed in the order LoadSessionRules returned them, which is the persisted evaluation
		// order, and RestoreRule appends in call order, so that order is what survives.
		//
		// Id collisions are counted apart from validation refusals: the two are different faults with
		// different fixes, and rolling them into one number would tell an operator to go and check the
		// wrong thing.
		refused, collided := 0, 0
		for _, r := range sessionRules {
			err := sess.RestoreRule(r)
			if err == nil {
				continue
			}
			s.log("restore session rule", err)
			if errors.Is(err, session.ErrDuplicateRuleID) {
				collided++
				continue
			}
			refused++
		}
		if refused > 0 {
			s.log("restore session rules", fmt.Errorf(
				"%d of %d saved session rule(s) no longer validate and were not installed; fix or "+
					"delete them, or every request to the hosts they covered goes out unauthenticated",
				refused, len(sessionRules)))
		}
		if collided > 0 {
			s.log("restore session rules", fmt.Errorf(
				"%d of %d saved session rule(s) carry an id another rule already holds and were not installed; "+
					"this database has duplicate session rule ids and one rule per collision is missing, so a "+
					"request the missing rule covered goes out unauthenticated",
				collided, len(sessionRules)))
		}
	}

	if org != nil {
		items, err := s.LoadOrganizer()
		if err != nil {
			return fmt.Errorf("load organizer: %w", err)
		}
		collections, err := s.LoadOrganizerCollections()
		if err != nil {
			return fmt.Errorf("load organizer collections: %w", err)
		}
		org.Restore(items, collections)
	}

	if toolLog != nil {
		entries, err := s.LoadToolLog()
		if err != nil {
			return fmt.Errorf("load tool log: %w", err)
		}
		toolLog.Restore(entries)
	}
	return nil
}

func nullMsg(id *core.MsgId) any {
	if id == nil {
		return nil
	}
	return uint64(*id)
}

func nullStr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
