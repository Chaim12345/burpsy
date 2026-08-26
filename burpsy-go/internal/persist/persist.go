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
	"github.com/burpsy-go/burpsy/internal/organizer"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
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
	s := &Store{db: db, logger: logger}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
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
	related       TEXT
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
	protocol    TEXT
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
	note        TEXT NOT NULL
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
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
	// exchanges gained highlight for the same reason notes did: an operator annotation, not traffic,
	// so it lives beside notes rather than in its own table. NULL and "" both read back as "" (no
	// highlight) — a legacy row written before this column existed never has an opinion either way, so
	// there is nothing to distinguish it from an exchange explicitly cleared.
	if err := s.addColumn("exchanges", "highlight", "TEXT"); err != nil {
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
		  response_len, started_ms, duration_ms, notes, protocol, related, duration_us, highlight, source)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ex.ID, uint64(ex.Request), nullMsg(ex.Response), ex.Host, int(ex.Port),
		boolInt(ex.TLS), ex.Method, ex.Path, status, ex.ResponseLen,
		ex.StartedMs, ex.Duration.Millis(), nullStr(ex.Notes), int(ex.Protocol), related, durationUs,
		ex.Highlight, string(ex.Source))
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
		        response_len, started_ms, duration_ms, notes, protocol, related, duration_us, highlight, source
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
		if err := rows.Scan(&ex.ID, &request, &response, &ex.Host, &port, &tls,
			&ex.Method, &ex.Path, &status, &ex.ResponseLen, &ex.StartedMs,
			&durationMs, &notes, &protocol, &related, &durationUs, &highlight, &source); err != nil {
			return nil, err
		}
		ex.Highlight = highlight.String
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
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO findings
		 (id, name, severity, confidence, description, remediation, occurrences, inserted, timestamp, param,
		  target_host, target_port, target_tls, target_path, params, task_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.Name, int(f.Severity), int(f.Confidence), f.Description,
		f.Remediation, occ, ins, f.Timestamp, f.Param,
		f.Target.Host, int(f.Target.Port), tls, f.Target.Path, params, f.TaskID)
	if err != nil {
		s.log("finding", err)
	}
}

// LoadFindings restores every finding.
func (s *Store) LoadFindings() ([]*core.Finding, error) {
	rows, err := s.db.Query(
		`SELECT id, name, severity, confidence, description, remediation, occurrences, inserted, timestamp, param,
		        target_host, target_port, target_tls, target_path, params, task_id
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
		if err := rows.Scan(&f.ID, &f.Name, &sev, &conf, &f.Description, &f.Remediation, &occ, &ins, &ts, &f.Param,
			&tHost, &tPort, &tTLS, &tPath, &params, &taskID); err != nil {
			return nil, err
		}
		// NULL on a legacy row becomes 0, which is what an untracked finding already means in memory.
		f.TaskID = uint64(taskID.Int64)
		f.Severity = core.Severity(sev)
		f.Confidence = core.Confidence(conf)
		f.Timestamp = uint64(ts)
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

// ---- Scope -------------------------------------------------------------------------------------

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
			`INSERT INTO scope_rules_v3 (ord, kind, pattern, port, path_prefix, protocol) VALUES (?, ?, ?, ?, ?, ?)`,
			i, kind, r.Pattern, port, pathPrefix, protocol); err != nil {
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
	rows, err := s.db.Query(`SELECT kind, pattern, port, path_prefix, protocol FROM scope_rules_v3 ORDER BY ord`)
	if err != nil {
		return nil, err
	}
	out, err := scanScopeRows(rows, true, true)
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
	out, err = scanScopeRows(v2rows, true, false)
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
	return scanScopeRows(legacy, false, false)
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
func scanScopeRows(rows *sql.Rows, withPath, hasProtocol bool) ([]*core.ScopeRule, error) {
	defer rows.Close()
	var out []*core.ScopeRule
	for rows.Next() {
		var kind, pattern string
		var port sql.NullInt64
		var pathPrefix sql.NullString
		var protocol sql.NullString
		if err := rows.Scan(&kind, &pattern, &port, &pathPrefix, &protocol); err != nil {
			return nil, err
		}
		// kind is stored as a string ("include"/"exclude") for readability.
		k := core.ScopeInclude
		if kind == "exclude" {
			k = core.ScopeExclude
		}
		r := core.NewScopeRule(k, pattern)
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
			 (id, name, enabled, scope_hosts, macro, validity, max_attempts, extractions, ord)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			int64(r.ID), r.Name, boolInt(r.Enabled), hosts, macro, validity, r.MaxAttempts, exts, i); err != nil {
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
		`SELECT id, name, enabled, scope_hosts, macro, validity, max_attempts, extractions
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
		var hosts, macro, validity, exts []byte
		var maxAttempts int
		if err := rows.Scan(&id, &r.Name, &enabled, &hosts, &macro, &validity, &maxAttempts, &exts); err != nil {
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
		if _, err := s.db.Exec(
			`INSERT OR REPLACE INTO organizer_items (id, exchange, title, note, highlight)
			 VALUES (?, ?, ?, ?, ?)`,
			it.ID, it.Exchange, it.Title, it.Note, it.Highlight); err != nil {
			s.log("organizer item", err)
			return
		}
	}
}

// LoadOrganizer restores organizer items.
func (s *Store) LoadOrganizer() ([]organizer.Item, error) {
	rows, err := s.db.Query(`SELECT id, exchange, title, note, highlight FROM organizer_items ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []organizer.Item
	for rows.Next() {
		it := organizer.Item{}
		if err := rows.Scan(&it.ID, &it.Exchange, &it.Title, &it.Note, &it.Highlight); err != nil {
			return nil, err
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
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO tool_log
		 (id, tool, host, port, tls, method, path, status, started_ms, duration_ms, note, response_len)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, int(e.Tool), e.Host, int(e.Port), boolInt(e.TLS), e.Method, e.Path,
		int(e.Status), e.StartedMs, e.DurationMs, e.Note, responseLen)
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
		`SELECT id, tool, host, port, tls, method, path, status, started_ms, duration_ms, note, response_len
		 FROM tool_log ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*toollog.Entry
	for rows.Next() {
		e := &toollog.Entry{}
		var tool, port, tls, status int
		var responseLen sql.NullInt64
		if err := rows.Scan(&e.ID, &tool, &e.Host, &port, &tls, &e.Method, &e.Path, &status, &e.StartedMs, &e.DurationMs, &e.Note, &responseLen); err != nil {
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
		org.Restore(items)
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
