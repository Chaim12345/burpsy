package persist

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// The distinction survives the durable round trip: a sub-millisecond exchange comes back measured,
// and an untimed one comes back untimed.
//
// duration_ms alone could not carry this — both are 0 milliseconds — so a restart used to turn every
// fast exchange into an untimed one and every untimed one into an instantaneous exchange, whichever way
// the reader chose to read it.
func TestExchangeDurationRoundTripsSubMillisecondAndUnmeasured(t *testing.T) {
	p := newTestStore(t)
	store := core.NewTrafficStore()
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)
	req, resp := putPair(t, store)

	store.AddExchange(&core.Exchange{
		Request: req, Response: &resp, Host: "fast.test", Port: 80, Method: "GET", Path: "/quick",
		Duration: core.MeasuredDuration(400 * time.Microsecond),
	})
	store.AddExchange(&core.Exchange{
		Request: req, Response: &resp, Host: "untimed.test", Port: 80, Method: "GET", Path: "/unknown",
		Duration: core.UnmeasuredDuration(),
	})

	loaded, err := p.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d exchanges, want 2", len(loaded))
	}
	fast, untimed := loaded[0], loaded[1]
	if !fast.Duration.Measured {
		t.Error("the sub-millisecond exchange came back unmeasured")
	}
	if untimed.Duration.Measured {
		t.Error("the untimed exchange came back carrying a measurement")
	}
	if fast.Duration == untimed.Duration {
		t.Fatal("the two are the same value after a round trip, which is the defect")
	}
	if fast.Duration.Millis() != 0 {
		t.Errorf("the fast exchange rounds to %d ms; the test is not exercising the sub-millisecond case",
			fast.Duration.Millis())
	}
}

// A millisecond-scale duration keeps its precision, so the new column is not only about small numbers.
func TestExchangeDurationRoundTripsAMeasuredMillisecondValue(t *testing.T) {
	p := newTestStore(t)
	store := core.NewTrafficStore()
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)
	req, resp := putPair(t, store)

	store.AddExchange(&core.Exchange{
		Request: req, Response: &resp, Host: "slow.test", Port: 80, Method: "GET", Path: "/",
		Duration: core.MeasuredMicros(12_345),
	})
	loaded, err := p.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if got := loaded[0].Duration; !got.Measured || got.Us != 12_345 {
		t.Fatalf("duration = %+v, want a measured 12345µs", got)
	}
	if got := loaded[0].Duration.Millis(); got != 12 {
		t.Fatalf("millis = %d, want 12", got)
	}
}

// A row written before duration_us existed still loads, and its ambiguity is resolved in the fail-safe
// direction rather than by inventing a measurement.
//
// A legacy row is exactly a row with duration_us NULL, which is what this writes directly.
func TestExchangeDurationReadsALegacyRow(t *testing.T) {
	p := newTestStore(t)
	// One row that recorded 7 ms, one that recorded 0 — the second being the ambiguous case: it could
	// have been a genuine sub-millisecond exchange or an untimed one, and the old schema cannot say.
	for i, ms := range []int{7, 0} {
		if _, err := p.db.Exec(
			`INSERT INTO exchanges (id, request_msg, response_msg, host, port, tls, method, path, status,
			                        response_len, started_ms, duration_ms, notes, protocol, related, duration_us)
			 VALUES (?, 0, NULL, ?, 80, 0, 'GET', '/', NULL, 0, 0, ?, NULL, 0, NULL, NULL)`,
			i, "legacy.test", ms); err != nil {
			t.Fatalf("insert legacy row: %v", err)
		}
	}
	loaded, err := p.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d rows, want 2", len(loaded))
	}
	if got := loaded[0].Duration; !got.Measured || got.Us != 7000 {
		t.Errorf("a legacy 7ms row loaded as %+v, want a measured 7000µs", got)
	}
	if got := loaded[1].Duration; got.Measured {
		t.Errorf("a legacy 0ms row loaded as %+v; the old schema cannot tell a fast exchange from an "+
			"untimed one, and \"no evidence\" is the only honest reading", got)
	}
}

// A database created by a build that had no duration_us column opens, migrates and loads.
//
// The table is created here with the exact pre-migration column list, so this fails if the migration
// stops being additive — the same property the messages table's span columns rely on.
func TestAnOldDatabaseWithoutTheDurationColumnStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE exchanges (
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
	)`); err != nil {
		t.Fatalf("create old-schema table: %v", err)
	}
	// Also the old session_rules shape, so the ord migration is covered by the same old database.
	if _, err := db.Exec(`CREATE TABLE session_rules (
		id           INTEGER PRIMARY KEY,
		name         TEXT NOT NULL,
		enabled      INTEGER NOT NULL,
		scope_hosts  TEXT NOT NULL,
		macro        TEXT NOT NULL,
		validity     TEXT,
		max_attempts INTEGER NOT NULL,
		extractions  TEXT
	)`); err != nil {
		t.Fatalf("create old-schema session_rules: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO exchanges (id, request_msg, response_msg, host, port, tls, method, path, status,
		                        response_len, started_ms, duration_ms, notes, protocol, related)
		 VALUES (0, 0, NULL, 'old.test', 80, 0, 'GET', '/', NULL, 0, 0, 3, NULL, 0, NULL)`); err != nil {
		t.Fatalf("insert old row: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO session_rules (id, name, enabled, scope_hosts, macro, validity, max_attempts, extractions)
		 VALUES (?, 'old rule', 1, '[]', ?, NULL, 3, NULL)`,
		6, `[{"method":"POST","url":"https://old.test/login","headers":{},"body":""}]`); err != nil {
		t.Fatalf("insert old session rule: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw sqlite: %v", err)
	}

	p, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("Open an old database: %v", err)
	}
	defer p.Close()

	loaded, err := p.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges from an old database: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d rows, want 1", len(loaded))
	}
	if got := loaded[0].Duration; !got.Measured || got.Us != 3000 {
		t.Fatalf("the old row's duration loaded as %+v, want a measured 3000µs", got)
	}
	// The other additive migration on the exchanges table: user_edited (burpsy-react-ui-sd0d). A row
	// written before the column existed must read back as "nobody edited this". The opposite default
	// would mark every row in an existing database as a hand edit, which is the false badge the column
	// was added to remove — so the NOT NULL DEFAULT 0 is the behaviour under test, not an implementation
	// detail of addColumn.
	if loaded[0].UserEdited {
		t.Error("a row from a database that predates the edited column loaded as edited by the operator; history would show the whole of the operator's existing capture as hand-modified")
	}

	// The other additive migration in the same release: session_rules.ord. An old row has none, and its
	// id is the honest fallback ordering.
	rules, err := p.LoadSessionRules()
	if err != nil {
		t.Fatalf("LoadSessionRules from an old database: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != 6 {
		t.Fatalf("loaded %+v, want one rule still at id 6", rules)
	}
}

// putPair stores a request/response pair and returns their ids.
func putPair(t *testing.T, store *core.TrafficStore) (core.MsgId, core.MsgId) {
	t.Helper()
	req, err := store.Put([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("Put request: %v", err)
	}
	resp, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("Put response: %v", err)
	}
	return req, resp
}
