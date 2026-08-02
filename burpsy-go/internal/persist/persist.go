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
	"fmt"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/organizer"
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

// ---- Messages + exchanges ----------------------------------------------------------------------

// SaveMessage mirrors one stored message.
func (s *Store) SaveMessage(id core.MsgId, raw []byte, direction core.Direction) {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO messages (id, direction, raw) VALUES (?, ?, ?)`,
		uint64(id), int(direction), raw)
	if err != nil {
		s.log("message", err)
	}
}

// SaveExchange mirrors one exchange.
func (s *Store) SaveExchange(ex *core.Exchange) {
	related, err := json.Marshal(ex.Related)
	if err != nil {
		related = nil
	}
	var status any
	if ex.Status != nil {
		status = int(*ex.Status)
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO exchanges
		 (id, request_msg, response_msg, host, port, tls, method, path, status,
		  response_len, started_ms, duration_ms, notes, protocol, related)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ex.ID, uint64(ex.Request), nullMsg(ex.Response), ex.Host, int(ex.Port),
		boolInt(ex.TLS), ex.Method, ex.Path, status, ex.ResponseLen,
		ex.StartedMs, ex.DurationMs, nullStr(ex.Notes), int(ex.Protocol), related)
	if err != nil {
		s.log("exchange", err)
	}
}

// LoadMessages restores every stored message, re-parsing shapes from raw bytes.
func (s *Store) LoadMessages() ([]*core.StoredMessage, error) {
	rows, err := s.db.Query(`SELECT id, direction, raw FROM messages ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*core.StoredMessage
	for rows.Next() {
		var id uint64
		var dir int
		var raw []byte
		if err := rows.Scan(&id, &dir, &raw); err != nil {
			return nil, err
		}
		shape, err := core.Parse(raw, core.Direction(dir))
		if err != nil {
			return nil, fmt.Errorf("message %d: %w", id, err)
		}
		out = append(out, &core.StoredMessage{ID: core.MsgId(id), Raw: raw, Shape: shape})
	}
	return out, rows.Err()
}

// LoadExchanges restores every exchange in id order (ids are positional).
func (s *Store) LoadExchanges() ([]*core.Exchange, error) {
	rows, err := s.db.Query(
		`SELECT id, request_msg, response_msg, host, port, tls, method, path, status,
		        response_len, started_ms, duration_ms, notes, protocol, related
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
		if err := rows.Scan(&ex.ID, &request, &response, &ex.Host, &port, &tls,
			&ex.Method, &ex.Path, &status, &ex.ResponseLen, &ex.StartedMs,
			&ex.DurationMs, &notes, &protocol, &related); err != nil {
			return nil, err
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
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO findings
		 (id, name, severity, confidence, description, remediation, occurrences, inserted, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.Name, int(f.Severity), int(f.Confidence), f.Description,
		f.Remediation, occ, ins, f.Timestamp)
	if err != nil {
		s.log("finding", err)
	}
}

// LoadFindings restores every finding.
func (s *Store) LoadFindings() ([]*core.Finding, error) {
	rows, err := s.db.Query(
		`SELECT id, name, severity, confidence, description, remediation, occurrences, inserted, timestamp
		 FROM findings ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*core.Finding
	for rows.Next() {
		f := &core.Finding{}
		var sev, conf, ts int
		var occ, ins []byte
		if err := rows.Scan(&f.ID, &f.Name, &sev, &conf, &f.Description, &f.Remediation, &occ, &ins, &ts); err != nil {
			return nil, err
		}
		f.Severity = core.Severity(sev)
		f.Confidence = core.Confidence(conf)
		f.Timestamp = uint64(ts)
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
func (s *Store) SaveScope(rules []*core.ScopeRule) {
	if _, err := s.db.Exec(`DELETE FROM scope_rules`); err != nil {
		s.log("scope clear", err)
		return
	}
	for _, r := range rules {
		var port any
		if r.Port != nil {
			port = int(*r.Port)
		}
		kind := "include"
		if r.Kind == core.ScopeExclude {
			kind = "exclude"
		}
		if _, err := s.db.Exec(
			`INSERT OR REPLACE INTO scope_rules (kind, pattern, port) VALUES (?, ?, ?)`,
			kind, r.Pattern, port); err != nil {
			s.log("scope rule", err)
			return
		}
	}
}

// LoadScope restores scope rules.
func (s *Store) LoadScope() ([]*core.ScopeRule, error) {
	rows, err := s.db.Query(`SELECT kind, pattern, port FROM scope_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*core.ScopeRule
	for rows.Next() {
		var kind, pattern string
		var port any
		if err := rows.Scan(&kind, &pattern, &port); err != nil {
			return nil, err
		}
		// kind is stored as a string ("include"/"exclude") for readability.
		r := core.NewScopeRule(core.ScopeInclude, pattern)
		if kind == "exclude" {
			r = core.NewScopeRule(core.ScopeExclude, pattern)
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
	for _, r := range rules {
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
			 (id, name, enabled, scope_hosts, macro, validity, max_attempts, extractions)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			int64(r.ID), r.Name, boolInt(r.Enabled), hosts, macro, validity, r.MaxAttempts, exts); err != nil {
			s.log("session rule", err)
			return
		}
	}
}

// LoadSessionRules restores session rules, recompiling extraction regexes.
func (s *Store) LoadSessionRules() ([]*session.SessionRule, error) {
	rows, err := s.db.Query(
		`SELECT id, name, enabled, scope_hosts, macro, validity, max_attempts, extractions FROM session_rules`)
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
			for i, ex := range parsed {
				rebuilt, err := session.NewExtraction(ex.Name, ex.From, ex.Pattern, ex.Group)
				if err != nil {
					return nil, err
				}
				parsed[i] = rebuilt
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
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO tool_log
		 (id, tool, host, port, tls, method, path, status, started_ms, duration_ms, note)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, int(e.Tool), e.Host, int(e.Port), boolInt(e.TLS), e.Method, e.Path,
		int(e.Status), e.StartedMs, e.DurationMs, e.Note)
	if err != nil {
		s.log("tool_log", err)
	}
}

// LoadToolLog restores the tool log in id order.
func (s *Store) LoadToolLog() ([]*toollog.Entry, error) {
	rows, err := s.db.Query(
		`SELECT id, tool, host, port, tls, method, path, status, started_ms, duration_ms, note
		 FROM tool_log ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*toollog.Entry
	for rows.Next() {
		e := &toollog.Entry{}
		var tool, port, tls, status int
		if err := rows.Scan(&e.ID, &tool, &e.Host, &port, &tls, &e.Method, &e.Path, &status, &e.StartedMs, &e.DurationMs, &e.Note); err != nil {
			return nil, err
		}
		e.Tool = toollog.Tool(tool)
		e.Port = uint16(port)
		e.TLS = tls != 0
		e.Status = status
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
		messages, err := s.LoadMessages()
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
		for _, r := range sessionRules {
			sess.AddRule(r)
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
